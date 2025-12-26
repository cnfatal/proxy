package proxy

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/cnfatal/proxy/config"
	"github.com/cnfatal/proxy/rules"
)

const (
	// SO_ORIGINAL_DST is the socket option to get the original destination
	SO_ORIGINAL_DST = 80
)

// TransparentProxy handles transparent proxy connections
type TransparentProxy struct {
	listenAddr string
	upstream   *Upstream
	matcher    *rules.Matcher
	listener   net.Listener
}

// NewTransparentProxy creates a new transparent proxy
func NewTransparentProxy(cfg *config.Config, matcher *rules.Matcher) *TransparentProxy {
	var upstream *Upstream
	if cfg.UpstreamURL != nil {
		upstream = NewUpstream(cfg.UpstreamURL)
	}

	return &TransparentProxy{
		listenAddr: cfg.Listen,
		upstream:   upstream,
		matcher:    matcher,
	}
}

// Start begins listening for connections
func (tp *TransparentProxy) Start() error {
	listener, err := net.Listen("tcp", tp.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", tp.listenAddr, err)
	}
	tp.listener = listener

	slog.Info("Transparent proxy listening", "addr", tp.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}

		go tp.handleConnection(conn.(*net.TCPConn))
	}
}

// Stop stops the proxy server
func (tp *TransparentProxy) Stop() error {
	if tp.listener != nil {
		return tp.listener.Close()
	}
	return nil
}

// handleConnection handles a single incoming connection
func (tp *TransparentProxy) handleConnection(clientConn *net.TCPConn) {
	defer clientConn.Close()

	// Get the original destination address
	origDst, err := getOriginalDst(clientConn)
	if err != nil {
		slog.Error("Failed to get original destination", "error", err)
		return
	}

	targetAddr := origDst.String()
	clientAddr := clientConn.RemoteAddr().String()

	slog.Debug("New connection", "from", clientAddr, "to", targetAddr)

	// Resolve domain if possible (for better rule matching)
	domain := ""
	ip := origDst.IP

	// Try reverse DNS lookup
	names, err := net.LookupAddr(ip.String())
	if err == nil && len(names) > 0 {
		domain = names[0]
		// Remove trailing dot
		if len(domain) > 0 && domain[len(domain)-1] == '.' {
			domain = domain[:len(domain)-1]
		}
	}

	// Match against rules
	result := tp.matcher.Match(domain, ip)

	var serverConn net.Conn

	switch result.Policy {
	case config.PolicyReject:
		slog.Info("Rejecting connection", "target", targetAddr, "domain", domain, "ip", ip)
		return

	case config.PolicyDirect:
		slog.Debug("Direct connection", "target", targetAddr)
		serverConn, err = DirectConnect(targetAddr)

	case config.PolicyProxy:
		if tp.upstream == nil {
			slog.Warn("No upstream proxy configured, using direct connection")
			serverConn, err = DirectConnect(targetAddr)
		} else {
			slog.Debug("Proxying connection", "target", targetAddr, "policy", result.Policy)
			serverConn, err = tp.upstream.Connect(targetAddr)
		}
	}

	if err != nil {
		slog.Error("Failed to connect", "target", targetAddr, "error", err)
		return
	}
	defer serverConn.Close()

	// Relay data between client and server
	Relay(serverConn, clientConn)

	slog.Debug("Relay completed", "target", targetAddr)
}

// getOriginalDst retrieves the original destination address from a redirected connection
func getOriginalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	// Get the underlying file descriptor
	file, err := conn.File()
	if err != nil {
		return nil, fmt.Errorf("failed to get file descriptor: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// Try IPv4 first
	addr, err := getOriginalDstIPv4(fd)
	if err == nil {
		return addr, nil
	}

	// Try IPv6
	addr, err = getOriginalDstIPv6(fd)
	if err == nil {
		return addr, nil
	}

	return nil, fmt.Errorf("failed to get original destination for both IPv4 and IPv6")
}

// sockaddr_in represents the C sockaddr_in structure
type sockaddrIn struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

// sockaddr_in6 represents the C sockaddr_in6 structure
type sockaddrIn6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

// getOriginalDstIPv4 gets the original destination for IPv4
func getOriginalDstIPv4(fd int) (*net.TCPAddr, error) {
	var addr sockaddrIn
	addrLen := uint32(unsafe.Sizeof(addr))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IP),
		uintptr(SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)

	if errno != 0 {
		return nil, errno
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:]))

	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}, nil
}

// IP6T_SO_ORIGINAL_DST is the IPv6 version of SO_ORIGINAL_DST
const IP6T_SO_ORIGINAL_DST = 80

// getOriginalDstIPv6 gets the original destination for IPv6
func getOriginalDstIPv6(fd int) (*net.TCPAddr, error) {
	var addr sockaddrIn6
	addrLen := uint32(unsafe.Sizeof(addr))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IPV6),
		uintptr(IP6T_SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)

	if errno != 0 {
		return nil, errno
	}

	ip := make(net.IP, 16)
	copy(ip, addr.Addr[:])
	port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:]))

	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}, nil
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
