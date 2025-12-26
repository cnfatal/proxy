package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestSniffHTTP(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		host     string
		expected string
	}{
		{
			"Standard GET",
			"GET",
			"google.com",
			"google.com",
		},
		{
			"Host with port",
			"POST",
			"example.org:8080",
			"example.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, "http://"+tt.host+"/", nil)
			var buf bytes.Buffer
			req.Write(&buf)

			domain := sniffHTTP(buf.Bytes())
			if domain != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, domain)
			}
		})
	}

	// Test cases for invalid/missing data
	t.Run("No Host header", func(t *testing.T) {
		data := []byte("GET / HTTP/1.1\nUser-Agent: curl/7.68.0\n\n")
		domain := sniffHTTP(data)
		if domain != "" {
			t.Errorf("Expected empty string, got '%s'", domain)
		}
	})

	t.Run("Invalid HTTP", func(t *testing.T) {
		domain := sniffHTTP([]byte("NOT A REQUEST"))
		if domain != "" {
			t.Errorf("Expected empty string, got '%s'", domain)
		}
	})
}

func TestSniffSNI(t *testing.T) {
	tests := []struct {
		name   string
		server string
	}{
		{"Example", "example.com"},
		{"Google", "www.google.com"},
		{"Long domain", "this.is.a.very.long.domain.name.test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()

			// Start a TLS client in a goroutine to send ClientHello
			go func() {
				config := &tls.Config{
					ServerName: tt.server,
				}
				client := tls.Client(c1, config)
				// Handshake will fail because there's no server, but it will send ClientHello first
				client.Handshake()
			}()

			// Read ClientHello from the other end of the pipe
			buf := make([]byte, 4096)
			n, err := c2.Read(buf)
			if err != nil {
				t.Fatalf("Failed to read ClientHello: %v", err)
			}

			domain := sniffSNI(buf[:n])
			if domain != tt.server {
				t.Errorf("Expected '%s', got '%s'", tt.server, domain)
			}
		})
	}
}

func TestPeekedConn(t *testing.T) {
	// Create a pipe to simulate a connection
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	peekedData := []byte("hello ")
	remainingData := []byte("world")

	go func() {
		c2.Write(remainingData)
	}()

	pool := NewBufferPool()
	pc := NewPeekedConn(c1, peekedData, pool)

	buf := make([]byte, 11)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if n != 6 {
		t.Errorf("Expected 6 bytes from first read, got %d", n)
	}

	n2, err := pc.Read(buf[n:])
	if err != nil {
		t.Fatalf("Second read failed: %v", err)
	}

	if n+n2 != 11 {
		t.Errorf("Expected total 11 bytes, got %d", n+n2)
	}

	if string(buf) != "hello world" {
		t.Errorf("Expected 'hello world', got '%s'", string(buf))
	}
}

func TestSniffDomain(t *testing.T) {
	pool := NewBufferPool()
	sniffer := NewSniffer(pool, time.Second)

	t.Run("TLS SNI", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		serverName := "example.com"
		go func() {
			config := &tls.Config{ServerName: serverName}
			tls.Client(c1, config).Handshake()
		}()

		domain, peeked, err := sniffer.Sniff(c2)
		if err != nil {
			t.Fatalf("Sniff failed: %v", err)
		}
		if domain != serverName {
			t.Errorf("Expected %s, got %s", serverName, domain)
		}
		if len(peeked) == 0 {
			t.Error("Expected non-empty peeked data")
		}
	})

	t.Run("HTTP Host", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		host := "example.org"
		go func() {
			c1.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))
		}()

		domain, peeked, err := sniffer.Sniff(c2)
		if err != nil {
			t.Fatalf("Sniff failed: %v", err)
		}
		if domain != host {
			t.Errorf("Expected %s, got %s", host, domain)
		}
		if len(peeked) == 0 {
			t.Error("Expected non-empty peeked data")
		}
	})

	t.Run("Exceed MaxSniffSize", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		go func() {
			// Send more than SmallBufferSize of garbage
			garbage := make([]byte, SmallBufferSize+100)
			c1.Write(garbage)
		}()

		domain, peeked, err := sniffer.Sniff(c2)
		if err != nil && err != io.EOF {
			// EOF or timeout is expected if we stop reading
		}
		if domain != "" {
			t.Errorf("Expected empty domain for garbage data, got %s", domain)
		}
		if len(peeked) > SmallBufferSize {
			t.Errorf("Peeked data size %d exceeds SmallBufferSize %d", len(peeked), SmallBufferSize)
		}
	})
}
