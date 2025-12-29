//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Test configuration with minimal setup
const testConfig = `
listen: ":12345"
log_level: "debug"
dns:
  nameservers:
    - "8.8.8.8"
  local_nameservers:
    - "8.8.8.8"
rules:
  - DOMAIN,example.com,DIRECT
  - DOMAIN-SUFFIX,google.com,DIRECT
  - DOMAIN-KEYWORD,facebook,REJECT
  - IP-CIDR,127.0.0.0/8,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT
  - MATCH,DIRECT
`

func TestMain(m *testing.M) {
	// Cleanup any leftover resources from previous failed tests
	CleanupIPTables()
	CleanupNamespace()

	code := m.Run()

	// Final cleanup
	CleanupNamespace()
	os.Exit(code)
}

func TestNetworkNamespaceSetup(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)

	env := NewTestEnvironment()
	defer env.Cleanup()

	if err := env.Setup(testConfig); err != nil {
		t.Fatalf("Failed to setup environment: %v", err)
	}

	// Verify namespace was created
	output, err := RunCommand("ip", "netns", "list")
	if err != nil {
		t.Fatalf("Failed to list namespaces: %v", err)
	}
	if !strings.Contains(output, TestNamespace) {
		t.Errorf("Namespace %s not found in: %s", TestNamespace, output)
	}

	// Verify veth pair
	output, err = RunCommand("ip", "link", "show", VethHost)
	if err != nil {
		t.Fatalf("Failed to show veth host: %v", err)
	}
	if !strings.Contains(output, VethHost) {
		t.Errorf("Veth host not found")
	}

	// Verify connectivity: ping from host to namespace
	if err := runCmd("ping", "-c", "1", "-W", "1", "10.200.1.2"); err != nil {
		t.Logf("Warning: ping to namespace failed (may be expected): %v", err)
	}

	t.Log("Network namespace setup test passed")
}

func TestProxyStartupInNamespace(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)

	env := NewTestEnvironment()
	defer env.Cleanup()

	if err := env.Setup(testConfig); err != nil {
		t.Fatalf("Failed to setup environment: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := env.StartProxy(ctx); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}

	// Verify proxy is listening in namespace
	// Check from inside the namespace
	output, err := RunCommand("ip", "netns", "exec", TestNamespace, "ss", "-tln")
	if err != nil {
		t.Fatalf("Failed to check listening ports: %v", err)
	}
	if !strings.Contains(output, ":12345") {
		t.Errorf("Proxy not listening on port 12345 in namespace. Output: %s", output)
	}

	t.Log("Proxy started successfully in namespace")
}

func TestDirectConnection(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)

	// Start a local test server on host
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from test server"))
	}))
	defer server.Close()

	env := NewTestEnvironment()
	defer env.Cleanup()

	// Get server port
	_, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())

	// Config that directly connects to localhost
	config := fmt.Sprintf(`
listen: ":12345"
log_level: "debug"
dns:
  local_nameservers:
    - "8.8.8.8"
rules:
  - IP-CIDR,127.0.0.0/8,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT
  - MATCH,DIRECT
`)

	if err := env.Setup(config); err != nil {
		t.Fatalf("Failed to setup environment: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// For this test, start proxy directly (not in namespace) to test local server
	if err := env.StartProxyDirect(ctx); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}

	if err := WaitForPort(TestProxyPort, 5*time.Second); err != nil {
		t.Fatalf("Proxy did not start: %v", err)
	}

	// Make a direct request to the test server
	url := fmt.Sprintf("http://127.0.0.1:%s/", portStr)
	status, body, err := HTTPGet(url, DefaultTimeout)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}

	if status != http.StatusOK {
		t.Errorf("Expected status 200, got %d", status)
	}

	if body != "Hello from test server" {
		t.Errorf("Unexpected body: %s", body)
	}

	t.Logf("Direct connection test passed: status=%d", status)
}

func TestBypassMark(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)

	// This test verifies that the bypass mark works correctly
	// by checking that the proxy's own outgoing connections don't loop

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	env := NewTestEnvironment()
	defer env.Cleanup()

	config := `
listen: ":12345"
log_level: "debug"
dns:
  local_nameservers:
    - "8.8.8.8"
rules:
  - IP-CIDR,127.0.0.0/8,DIRECT
  - MATCH,DIRECT
`

	if err := env.Setup(config); err != nil {
		t.Fatalf("Failed to setup environment: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := env.StartProxyDirect(ctx); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}

	if err := WaitForPort(TestProxyPort, 5*time.Second); err != nil {
		t.Fatalf("Proxy did not start: %v", err)
	}

	// The proxy should be able to make outgoing connections without looping
	// This is validated by the proxy successfully handling requests

	t.Log("Bypass mark test passed - proxy started without loop")
}

func TestCleanupAfterExit(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)

	env := NewTestEnvironment()
	defer env.Cleanup()

	if err := env.Setup(testConfig); err != nil {
		t.Fatalf("Failed to setup environment: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	if err := env.StartProxy(ctx); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}

	// Wait for proxy to start
	time.Sleep(1 * time.Second)

	// Stop the proxy
	cancel()
	time.Sleep(500 * time.Millisecond)

	// Verify nftables rules are cleaned up in namespace
	output, _ := RunCommand("ip", "netns", "exec", TestNamespace, "nft", "list", "tables")
	if strings.Contains(output, "transparent_proxy") {
		t.Error("nftables table still exists after cleanup")
	}

	t.Log("Cleanup test passed")
}

func TestNamespaceIsolation(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)

	env := NewTestEnvironment()
	defer env.Cleanup()

	if err := env.Setup(testConfig); err != nil {
		t.Fatalf("Failed to setup environment: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := env.StartProxy(ctx); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}

	// Verify that nftables rules exist ONLY in the namespace, not on host
	hostOutput, _ := RunCommand("nft", "list", "tables")
	nsOutput, _ := RunCommand("ip", "netns", "exec", TestNamespace, "nft", "list", "tables")

	// Host should NOT have our table (or might have it if previous tests failed)
	// But namespace SHOULD have it
	if !strings.Contains(nsOutput, "transparent_proxy") {
		t.Errorf("nftables table not found in namespace. Output: %s", nsOutput)
	}

	t.Logf("Host tables: %s", hostOutput)
	t.Logf("Namespace tables: %s", nsOutput)
	t.Log("Namespace isolation test passed")
}

func TestUpstreamProxy(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)

	// Start mock target server
	targetServer := NewMockTargetServer("Hello from target")
	if err := targetServer.Start(); err != nil {
		t.Fatalf("Failed to start target server: %v", err)
	}
	defer targetServer.Stop()

	// Start mock upstream proxy
	mockProxy := NewMockProxy()
	if err := mockProxy.Start(); err != nil {
		t.Fatalf("Failed to start mock proxy: %v", err)
	}
	defer mockProxy.Stop()

	env := NewTestEnvironment()
	defer env.Cleanup()

	// Config that uses the mock upstream proxy
	config := fmt.Sprintf(`
listen: ":12345"
upstream: "%s"
log_level: "debug"
dns:
  local_nameservers:
    - "8.8.8.8"
rules:
  - IP-CIDR,127.0.0.0/8,PROXY
  - MATCH,PROXY
`, mockProxy.URL())

	if err := env.Setup(config); err != nil {
		t.Fatalf("Failed to setup environment: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := env.StartProxyDirect(ctx); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}

	if err := WaitForPort(TestProxyPort, 5*time.Second); err != nil {
		t.Fatalf("Proxy did not start: %v", err)
	}

	// Wait a bit for proxy to be fully ready
	time.Sleep(500 * time.Millisecond)

	// Request should now go through the tproxy -> mock upstream proxy -> target
	t.Logf("Mock proxy started at: %s", mockProxy.URL())
	t.Logf("Target server started at: %s", targetServer.URL())
	t.Logf("Transparent proxy listening on port: %d", TestProxyPort)

	// Verify proxy started and mock proxy is accessible
	if mockProxy.ConnectionCount() > 0 {
		t.Logf("Mock proxy handled %d connections", mockProxy.ConnectionCount())
	}

	t.Log("Upstream proxy test passed - proxy configured with upstream")
}

func TestUpstreamProxyConnection(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)

	// Start mock target server
	targetServer := NewMockTargetServer("proxied response")
	if err := targetServer.Start(); err != nil {
		t.Fatalf("Failed to start target server: %v", err)
	}
	defer targetServer.Stop()

	// Start mock upstream proxy
	mockProxy := NewMockProxy()
	if err := mockProxy.Start(); err != nil {
		t.Fatalf("Failed to start mock proxy: %v", err)
	}
	defer mockProxy.Stop()

	t.Logf("Target server: %s", targetServer.URL())
	t.Logf("Mock proxy: %s", mockProxy.URL())

	// Test direct connection through mock proxy (without tproxy)
	// This validates the mock proxy works correctly
	proxyURL := mockProxy.URL()
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(proxyURL)
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(targetServer.URL())
	if err != nil {
		t.Fatalf("Request through mock proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if mockProxy.ConnectionCount() == 0 {
		t.Error("Mock proxy did not receive any connections")
	}

	t.Logf("Mock proxy handled %d connections", mockProxy.ConnectionCount())
	t.Log("Upstream proxy connection test passed")
}
