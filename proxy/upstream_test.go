package proxy

import (
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewUpstream(t *testing.T) {
	u, _ := url.Parse("http://proxy:8080")
	upstream := NewUpstream(u)

	if upstream.url.Host != "proxy:8080" {
		t.Errorf("Host = %v, want proxy:8080", upstream.url.Host)
	}
}

func TestRelay(t *testing.T) {
	// 创建两个连接来测试数据中继
	server, client := net.Pipe()

	testData := "Hello, World!"
	var wg sync.WaitGroup
	wg.Add(2)

	// 服务端发送数据
	go func() {
		defer wg.Done()
		server.Write([]byte(testData))
		server.Close()
	}()

	// 客户端接收数据
	var received strings.Builder
	go func() {
		defer wg.Done()
		io.Copy(&received, client)
		client.Close()
	}()

	wg.Wait()

	if received.String() != testData {
		t.Errorf("Received = %q, want %q", received.String(), testData)
	}
}

func TestDirectConnect(t *testing.T) {
	// 创建一个测试 TCP 服务器
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// 接受连接的 goroutine
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte("OK"))
		conn.Close()
	}()

	// 测试 DirectConnect
	conn, err := DirectConnect(listener.Addr().String())
	if err != nil {
		t.Fatalf("DirectConnect error = %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 2)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "OK" {
		t.Errorf("Response = %q, want OK", string(buf[:n]))
	}
}

func TestDirectConnect_Failure(t *testing.T) {
	// 尝试连接一个不存在的地址
	_, err := DirectConnect("127.0.0.1:1") // 端口 1 通常不可用
	if err == nil {
		t.Error("Expected error for invalid address")
	}
}

func TestGetListenPort(t *testing.T) {
	tests := []struct {
		input    string
		wantPort int
		wantErr  bool
	}{
		{":12345", 12345, false},
		{"0.0.0.0:8080", 8080, false},
		{"127.0.0.1:443", 443, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			port, err := GetListenPort(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetListenPort(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if port != tt.wantPort {
				t.Errorf("GetListenPort(%q) = %v, want %v", tt.input, port, tt.wantPort)
			}
		})
	}
}

// TestUpstreamHTTP_Mock 使用 mock HTTP 代理测试 CONNECT
func TestUpstreamHTTP_Mock(t *testing.T) {
	// 创建 TCP 服务器模拟 HTTP CONNECT 代理
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// 读取 CONNECT 请求
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if !strings.Contains(string(buf[:n]), "CONNECT") {
			return
		}

		// 发送 200 响应表示隧道建立成功
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		// 模拟目标服务器响应
		conn.Write([]byte("target response"))
	}()

	// 解析代理 URL
	proxyURL, _ := url.Parse("http://" + listener.Addr().String())
	upstream := NewUpstream(proxyURL)

	// 测试连接
	conn, err := upstream.Connect("example.com:80")
	if err != nil {
		t.Fatalf("Connect error = %v", err)
	}
	defer conn.Close()

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(time.Second))

	// 读取响应
	buf := make([]byte, 100)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "target response") {
		t.Errorf("Response = %q, want 'target response'", string(buf[:n]))
	}
}
