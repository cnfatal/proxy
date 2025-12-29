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

// Start starts the mock proxy on a random port
func (p *MockProxy) Start() error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
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

// URL returns the proxy URL for configuration
func (p *MockProxy) URL() string {
	return fmt.Sprintf("http://%s", p.addr)
}

// ConnectionCount returns number of connections handled
func (p *MockProxy) ConnectionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connections
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
}

// NewMockTargetServer creates a new mock target server
func NewMockTargetServer(response string) *MockTargetServer {
	m := &MockTargetServer{}

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

// Start starts the mock target server
func (m *MockTargetServer) Start() error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
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

// URL returns the server URL
func (m *MockTargetServer) URL() string {
	return fmt.Sprintf("http://%s", m.addr)
}

// RequestCount returns number of requests handled
func (m *MockTargetServer) RequestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests
}

// Stop stops the mock target server
func (m *MockTargetServer) Stop() {
	if m.server != nil {
		m.server.Close()
	}
}
