package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cnfatal/proxy/config"
	"github.com/cnfatal/proxy/rules"
	"golang.org/x/sync/errgroup"
)

const (
	// IP_RECVORIGDSTADDR is the socket option to receive the original destination address
	IP_RECVORIGDSTADDR = 20
	// IPV6_RECVORIGDSTADDR is the IPv6 version of IP_RECVORIGDSTADDR
	IPV6_RECVORIGDSTADDR = 74
	// SniffTimeout is the timeout for sniffing domain names
	SniffTimeout = 150 * time.Millisecond
	// UDPSessionCleanupInterval is the interval for cleaning up stale UDP sessions
	UDPSessionCleanupInterval = 30 * time.Second
	// UDPSessionTimeout is the timeout for inactive UDP sessions
	UDPSessionTimeout = 60 * time.Second
)

// TransparentProxy handles transparent proxy connections
type TransparentProxy struct {
	listenAddr  string
	dnsConfig   config.DNSConfig
	upstream    *Upstream
	matcher     *rules.Matcher
	udpConn     *net.UDPConn
	sniffer     Sniffer
	pool        BufferPool
	udpSessions map[string]*udpSession
	udpMu       sync.Mutex
}

type udpSession struct {
	remoteConn net.PacketConn
	lastActive time.Time
}

// NewTransparentProxy creates a new transparent proxy
func NewTransparentProxy(cfg *config.Config, matcher *rules.Matcher, pool BufferPool) *TransparentProxy {
	var upstream *Upstream
	if cfg.UpstreamURL != nil {
		upstream = NewUpstream(cfg.UpstreamURL)
	}

	return &TransparentProxy{
		listenAddr:  cfg.Listen,
		dnsConfig:   cfg.DNS,
		upstream:    upstream,
		matcher:     matcher,
		sniffer:     NewSniffer(pool, SniffTimeout),
		pool:        pool,
		udpSessions: make(map[string]*udpSession),
	}
}

// Run begins listening for connections and runs until context is cancelled
func (tp *TransparentProxy) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return tp.runTCP(ctx)
	})

	g.Go(func() error {
		return tp.runUDP(ctx)
	})

	return g.Wait()
}

func (tp *TransparentProxy) runTCP(ctx context.Context) error {
	// Start TCP listener with IP_TRANSPARENT to support TPROXY
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, syscall.TCP_NODELAY, 1)
			})
		},
	}

	listener, err := lc.Listen(ctx, "tcp", tp.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", tp.listenAddr, err)
	}
	defer listener.Close()

	slog.Info("Transparent TCP proxy listening", "addr", tp.listenAddr)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				if _, ok := err.(net.Error); ok {
					continue
				}
				return err
			}
		}

		go tp.handleConnection(ctx, conn)
	}
}

func (tp *TransparentProxy) runUDP(ctx context.Context) error {
	// Start UDP listener for DNS and general UDP
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, IP_RECVORIGDSTADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, 1)
			})
		},
	}

	packetConn, err := lc.ListenPacket(ctx, "udp", tp.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", tp.listenAddr, err)
	}
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("expected *net.UDPConn, got %T", packetConn)
	}
	tp.udpConn = udpConn
	defer udpConn.Close()

	slog.Info("Transparent UDP proxy listening", "addr", tp.listenAddr)

	go tp.cleanupUDPSessions(ctx)

	go func() {
		<-ctx.Done()
		udpConn.Close()
	}()

	tp.udpLoop(ctx)
	return nil
}

func (tp *TransparentProxy) udpLoop(ctx context.Context) {
	buf := make([]byte, 65535)
	oob := make([]byte, 1024)
	for {
		n, oobn, _, srcAddr, err := tp.udpConn.ReadMsgUDP(buf, oob)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			slog.Error("UDP read error", "error", err)
			continue
		}

		origDst := tp.getOriginalUDPAddr(oob[:oobn])
		if origDst == nil {
			continue
		}

		// Loop detection: if the original destination is the proxy itself, ignore it
		listenPort, _ := GetListenPort(tp.listenAddr)
		if origDst.Port == listenPort {
			if origDst.IP.IsLoopback() || origDst.IP.IsUnspecified() {
				continue
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		if origDst.Port == 53 {
			go tp.handleDNSUDP(ctx, srcAddr, origDst, data)
		} else {
			go tp.handleGeneralUDP(ctx, srcAddr, origDst, data)
		}
	}
}

func (tp *TransparentProxy) getOriginalUDPAddr(oob []byte) *net.UDPAddr {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, msg := range msgs {
		if msg.Header.Level == syscall.IPPROTO_IP && msg.Header.Type == IP_RECVORIGDSTADDR {
			if len(msg.Data) >= 16 {
				port := binary.BigEndian.Uint16(msg.Data[2:4])
				ip := net.IP(msg.Data[4:8])
				return &net.UDPAddr{IP: ip, Port: int(port)}
			}
		} else if msg.Header.Level == syscall.IPPROTO_IPV6 && msg.Header.Type == IPV6_RECVORIGDSTADDR {
			if len(msg.Data) >= 28 {
				port := binary.BigEndian.Uint16(msg.Data[2:4])
				ip := net.IP(msg.Data[8:24])
				return &net.UDPAddr{IP: ip, Port: int(port)}
			}
		}
	}
	return nil
}

func (tp *TransparentProxy) handleGeneralUDP(ctx context.Context, srcAddr net.Addr, origDst *net.UDPAddr, data []byte) {
	result := tp.matcher.Match("", origDst.IP)
	switch result.Policy {
	case config.PolicyReject:
		slog.Info("Rejecting UDP connection", "target", origDst.String(), "ip", origDst.IP)
		return
	case config.PolicyProxy:
		slog.Warn("UDP proxy is not supported, dropping packet", "target", origDst.String(), "ip", origDst.IP, "port", origDst.Port, "upstream", tp.upstreamScheme())
		if origDst.Port == 443 {
			slog.Info("Dropping UDP/443 traffic because transparent UDP proxying is unsupported", "target", origDst.String(), "ip", origDst.IP)
		}
		return
	}

	key := fmt.Sprintf("%s-%s", srcAddr.String(), origDst.String())

	tp.udpMu.Lock()
	session, ok := tp.udpSessions[key]
	if !ok {
		// Create new session
		lc := net.ListenConfig{
			Control: bypassControl,
		}
		remoteConn, err := lc.ListenPacket(ctx, "udp", "")
		if err != nil {
			tp.udpMu.Unlock()
			slog.Error("Failed to create UDP session", "error", err)
			return
		}

		session = &udpSession{
			remoteConn: remoteConn,
			lastActive: time.Now(),
		}
		tp.udpSessions[key] = session
		tp.udpMu.Unlock()

		// Start relay from remote to client
		go func() {
			buf := make([]byte, 65535)
			for {
				n, _, err := remoteConn.ReadFrom(buf)
				if err != nil {
					return
				}

				tp.udpMu.Lock()
				session.lastActive = time.Now()
				tp.udpMu.Unlock()

				if _, err := tp.udpConn.WriteTo(buf[:n], srcAddr); err != nil {
					return
				}
			}
		}()
	} else {
		session.lastActive = time.Now()
		tp.udpMu.Unlock()
	}

	_, _ = session.remoteConn.WriteTo(data, origDst)
}

func (tp *TransparentProxy) upstreamScheme() string {
	if tp.upstream == nil || tp.upstream.url == nil {
		return ""
	}
	return tp.upstream.url.Scheme
}

func (tp *TransparentProxy) cleanupUDPSessions(ctx context.Context) {
	ticker := time.NewTicker(UDPSessionCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tp.udpMu.Lock()
			now := time.Now()
			for key, session := range tp.udpSessions {
				if now.Sub(session.lastActive) > UDPSessionTimeout {
					session.remoteConn.Close()
					delete(tp.udpSessions, key)
				}
			}
			tp.udpMu.Unlock()
		}
	}
}

// handleConnection handles a single incoming connection
func (tp *TransparentProxy) handleConnection(ctx context.Context, client net.Conn) {
	defer func() {
		client.Close()
	}()

	// Set TCP_NODELAY to reduce latency
	if tcpConn, ok := client.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	// Get the original destination address
	origDst, ok := client.LocalAddr().(*net.TCPAddr)
	if !ok {
		slog.Error("Failed to get original destination: not a TCP address")
		return
	}

	// Loop detection: if the original destination is the proxy itself, ignore it
	// This happens if a connection is made directly to the proxy port
	listenPort, _ := GetListenPort(tp.listenAddr)
	if origDst.Port == listenPort {
		if origDst.IP.IsLoopback() || origDst.IP.IsUnspecified() {
			slog.Debug("Ignoring direct connection to proxy port", "addr", origDst.String())
			return
		}
	}

	if origDst.Port == 53 {
		tp.handleDNSTCP(ctx, client)
		return // client will be closed by handleDNSTCP
	}

	targetAddr := origDst.String()
	clientAddr := client.RemoteAddr().String()

	slog.Debug("New connection", "from", clientAddr, "to", targetAddr)

	// Sniff domain from the connection (TLS SNI or HTTP Host)
	domain, peeked, err := tp.sniffer.Sniff(client)
	if err != nil {
		slog.Debug("Failed to sniff domain", "error", err)
	}

	// Wrap the connection with peeked data so it can be read again
	if len(peeked) > 0 {
		client = NewPeekedConn(client, peeked, tp.pool)
	}

	ip := origDst.IP

	// Match against rules
	result := tp.matcher.Match(domain, ip)

	var serverConn net.Conn

	switch result.Policy {
	case config.PolicyReject:
		slog.Info("Rejecting connection", "target", targetAddr, "domain", domain, "ip", ip)
		return

	case config.PolicyDirect:
		slog.Debug("Direct connection", "target", targetAddr, "domain", domain)
		serverConn, err = DirectConnect(ctx, targetAddr)

	case config.PolicyProxy:
		if tp.upstream == nil {
			slog.Warn("No upstream proxy configured, using direct connection")
			serverConn, err = DirectConnect(ctx, targetAddr)
		} else {
			upstreamTargetAddr := buildUpstreamTargetAddr(domain, origDst)
			slog.Debug("Proxying connection", "target", targetAddr, "upstream_target", upstreamTargetAddr, "domain", domain, "policy", result.Policy)
			serverConn, err = tp.upstream.Connect(ctx, upstreamTargetAddr)
		}
	}

	if err != nil {
		slog.Error("Failed to connect", "target", targetAddr, "error", err)
		return
	}
	defer serverConn.Close()

	// Relay data between client and server
	Relay(serverConn, client, tp.pool)

	slog.Debug("Relay completed", "target", targetAddr)
}

func buildUpstreamTargetAddr(domain string, origDst *net.TCPAddr) string {
	if domain == "" {
		return origDst.String()
	}
	return net.JoinHostPort(domain, strconv.Itoa(origDst.Port))
}

// GetListenPort extracts the port number from the listen address
func GetListenPort(listenAddr string) (int, error) {
	_, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		// Try parsing as just a port
		if _, err := strconv.Atoi(listenAddr); err == nil {
			return strconv.Atoi(listenAddr)
		}
		return 0, fmt.Errorf("invalid listen address: %s", listenAddr)
	}
	return strconv.Atoi(portStr)
}
