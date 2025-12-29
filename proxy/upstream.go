package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"

	"github.com/cnfatal/proxy/iptables"
	"golang.org/x/net/proxy"
)

func bypassControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, iptables.BypassMark)
	})
}

func newBypassDialer() *net.Dialer {
	return &net.Dialer{
		Control: bypassControl,
	}
}

// Upstream handles connections to upstream proxy servers
type Upstream struct {
	url *url.URL
}

// NewUpstream creates a new upstream proxy handler
func NewUpstream(proxyURL *url.URL) *Upstream {
	return &Upstream{url: proxyURL}
}

// Connect establishes a connection to the target through the upstream proxy
// Returns a net.Conn that can be used to communicate with the target
func (u *Upstream) Connect(ctx context.Context, targetAddr string) (net.Conn, error) {
	switch u.url.Scheme {
	case "http":
		return u.connectHTTP(ctx, targetAddr)
	case "socks5":
		return u.connectSOCKS5(ctx, targetAddr)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.url.Scheme)
	}
}

// connectHTTP establishes a tunnel through an HTTP proxy using CONNECT
func (u *Upstream) connectHTTP(ctx context.Context, targetAddr string) (net.Conn, error) {
	proxyAddr := u.url.Host
	if u.url.Port() == "" {
		proxyAddr = net.JoinHostPort(u.url.Hostname(), "8080")
	}

	// Connect to the HTTP proxy
	dialer := newBypassDialer()
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to HTTP proxy: %w", err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	// Send CONNECT request
	req := (&http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: make(http.Header),
	}).WithContext(ctx)

	// Add proxy authentication if present
	if u.url.User != nil {
		password, _ := u.url.User.Password()
		req.SetBasicAuth(u.url.User.Username(), password)
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	// Read response
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	// Note: Do NOT close resp.Body here - the connection is the tunnel
	// and we need it to remain open for data transfer

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("CONNECT failed with status: %s", resp.Status)
	}

	// Always wrap with bufferedConn to ensure proper handling of any buffered data
	// The bufio.Reader may have read ahead during HTTP header parsing
	return &bufferedConn{Conn: conn, reader: br}, nil
}

// connectSOCKS5 establishes a connection through a SOCKS5 proxy
func (u *Upstream) connectSOCKS5(ctx context.Context, targetAddr string) (net.Conn, error) {
	proxyAddr := u.url.Host
	if u.url.Port() == "" {
		proxyAddr = net.JoinHostPort(u.url.Hostname(), "1080")
	}

	var auth *proxy.Auth
	if u.url.User != nil {
		password, _ := u.url.User.Password()
		auth = &proxy.Auth{
			User:     u.url.User.Username(),
			Password: password,
		}
	}

	dialer := newBypassDialer()

	socks5Dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, dialer)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	var conn net.Conn
	if cd, ok := socks5Dialer.(proxy.ContextDialer); ok {
		conn, err = cd.DialContext(ctx, "tcp", targetAddr)
	} else {
		conn, err = socks5Dialer.Dial("tcp", targetAddr)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect through SOCKS5: %w", err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	return conn, nil
}

// bufferedConn wraps a net.Conn with a buffered reader
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// DirectConnect establishes a direct connection to the target
func DirectConnect(ctx context.Context, targetAddr string) (net.Conn, error) {
	dialer := newBypassDialer()
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect directly: %w", err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}
	return conn, nil
}

// Relay copies data bidirectionally between two connections
func Relay(dst, src net.Conn, pool BufferPool) {
	copy := func(to, from net.Conn, done chan struct{}) {
		defer func() { done <- struct{}{} }()

		buf := pool.Get()
		defer pool.Put(buf)

		_, err := io.CopyBuffer(to, from, buf)
		if err != nil && err != io.EOF {
			// Only log if it's not a normal closure
			if !isClosedError(err) {
				slog.Debug("Relay error", "from", from.RemoteAddr(), "to", to.RemoteAddr(), "error", err)
			}
		}

		if cw, ok := to.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}

	done := make(chan struct{}, 2)
	go copy(dst, src, done)
	go copy(src, dst, done)

	// Wait for both directions to complete
	<-done
	<-done
}

func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "connection reset by peer") ||
		strings.Contains(err.Error(), "broken pipe")
}
