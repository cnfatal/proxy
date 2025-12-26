package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/proxy"
)

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
func (u *Upstream) Connect(targetAddr string) (net.Conn, error) {
	switch u.url.Scheme {
	case "http":
		return u.connectHTTP(targetAddr)
	case "socks5":
		return u.connectSOCKS5(targetAddr)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.url.Scheme)
	}
}

// connectHTTP establishes a tunnel through an HTTP proxy using CONNECT
func (u *Upstream) connectHTTP(targetAddr string) (net.Conn, error) {
	proxyAddr := u.url.Host
	if u.url.Port() == "" {
		proxyAddr = net.JoinHostPort(u.url.Hostname(), "8080")
	}

	// Connect to the HTTP proxy
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to HTTP proxy: %w", err)
	}

	// Send CONNECT request
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: make(http.Header),
	}

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
func (u *Upstream) connectSOCKS5(targetAddr string) (net.Conn, error) {
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

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect through SOCKS5: %w", err)
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

// DirectConnect establishes a direct connection to the target
func DirectConnect(targetAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect directly: %w", err)
	}
	return conn, nil
}

// Relay copies data bidirectionally between two connections
func Relay(dst, src net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(dst, src)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(src, dst)
		done <- struct{}{}
	}()

	// Wait for either direction to complete
	<-done
}
