//go:build e2e
// +build e2e

package e2e

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
)

// MockProxy is a simple HTTP CONNECT proxy for testing
type MockProxy struct {
	listener    net.Listener
	addr        string
	connections int
	targets     []string
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewMockProxy creates a new mock HTTP proxy server
func NewMockProxy() *MockProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &MockProxy{
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start starts the mock proxy bound to all interfaces (accessible from other network namespaces).
func (p *MockProxy) Start() error {
	return p.StartAt("0.0.0.0:0")
}

// StartAt starts the mock proxy on a specific address.
func (p *MockProxy) StartAt(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.listener = listener
	p.addr = listener.Addr().String()

	go p.serve()
	return nil
}

// Addr returns the proxy address (host:port)
func (p *MockProxy) Addr() string {
	return p.addr
}

// URL returns the proxy URL for configuration using the given host IP.
// Use this instead of Addr() when the proxy must be reached from a different
// network namespace where 0.0.0.0 resolves differently.
func (p *MockProxy) URLFor(hostIP string) string {
	_, port, _ := net.SplitHostPort(p.addr)
	return fmt.Sprintf("http://%s:%s", hostIP, port)
}

// URL returns the proxy URL (with 127.0.0.1 for same-host use)
func (p *MockProxy) URL() string {
	_, port, _ := net.SplitHostPort(p.addr)
	return fmt.Sprintf("http://127.0.0.1:%s", port)
}

// ConnectionCount returns number of connections handled
func (p *MockProxy) ConnectionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connections
}

// AllTargets returns the CONNECT targets seen so far (host:port).
func (p *MockProxy) AllTargets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.targets))
	copy(out, p.targets)
	return out
}

// Reset clears connection counters and target history.
func (p *MockProxy) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connections = 0
	p.targets = nil
}

// Stop stops the mock proxy
func (p *MockProxy) Stop() {
	p.cancel()
	if p.listener != nil {
		p.listener.Close()
	}
}

func (p *MockProxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				continue
			}
		}
		go p.handleConnection(conn)
	}
}

func (p *MockProxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	p.mu.Lock()
	p.connections++
	p.mu.Unlock()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method == "CONNECT" {
		p.handleConnect(conn, req)
	} else {
		p.handleHTTP(conn, req)
	}
}

func (p *MockProxy) handleConnect(conn net.Conn, req *http.Request) {
	p.mu.Lock()
	p.targets = append(p.targets, req.Host)
	p.mu.Unlock()

	// Connect to target
	targetConn, err := net.Dial("tcp", req.Host)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// Send success response
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Relay data
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, conn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, targetConn)
	}()

	wg.Wait()
}

func (p *MockProxy) handleHTTP(conn net.Conn, req *http.Request) {
	// Forward regular HTTP request
	client := &http.Client{}
	req.RequestURI = ""

	resp, err := client.Do(req)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer resp.Body.Close()

	resp.Write(conn)
}

// MockTargetServer is a simple HTTP server for testing
type MockTargetServer struct {
	server   *http.Server
	listener net.Listener
	addr     string
	requests int
	mu       sync.Mutex
	response string
}

// NewMockTargetServer creates a new mock target server
func NewMockTargetServer(response string) *MockTargetServer {
	m := &MockTargetServer{response: response}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.requests++
		m.mu.Unlock()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	})

	m.server = &http.Server{
		Handler:  mux,
		ErrorLog: log.New(io.Discard, "", 0),
	}

	return m
}

// Start starts the mock target server bound to all interfaces.
func (m *MockTargetServer) Start() error {
	return m.StartAt("0.0.0.0:0")
}

// StartAt starts the mock target server on the given address.
func (m *MockTargetServer) StartAt(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	m.listener = listener
	m.addr = listener.Addr().String()

	go m.server.Serve(listener)
	return nil
}

// Addr returns the server address
func (m *MockTargetServer) Addr() string {
	return m.addr
}

// Port returns just the port number.
func (m *MockTargetServer) Port() string {
	_, port, _ := net.SplitHostPort(m.addr)
	return port
}

// URLFor returns the HTTP URL using the given host IP (use when accessed from another namespace).
func (m *MockTargetServer) URLFor(hostIP string) string {
	return fmt.Sprintf("http://%s:%s/", hostIP, m.Port())
}

// URL returns the local HTTP URL.
func (m *MockTargetServer) URL() string {
	return fmt.Sprintf("http://%s/", m.addr)
}

// RequestCount returns number of requests handled.
func (m *MockTargetServer) RequestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests
}

// Stop stops the mock target server.
func (m *MockTargetServer) Stop() {
	if m.server != nil {
		m.server.Close()
	}
}

// NewMockProxy creates a new mock HTTP proxy server
