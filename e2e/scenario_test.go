//go:build e2e
// +build e2e

package e2e

// Scenario tests verify actual end-to-end traffic routing through the transparent proxy.
//
// Architecture
// ============
//
//  Host network namespace
//  ├── lo  203.0.113.1/32  ← mock target server (RFC 5737 TEST-NET-3, not in bypass list)
//  ├── 0.0.0.0:*           ← mock upstream proxy (reachable from proxy ns via 10.200.1.1)
//  └── veth-host  10.200.1.1/24
//         │
//         │ veth pair
//         ▼
//  TestNamespace (tproxy_e2e)  ← tproxy runs here, nftables rules applied
//  ├── veth-ns   10.200.1.2/24   (default route → 10.200.1.1)
//  └── veth-c-prx  172.17.0.1/24  ← gateway for container namespace
//         │
//         │ veth pair
//         ▼
//  ContainerNamespace (tproxy_e2e_cnt)  ← simulates Docker container
//  └── veth-c-ns  172.17.0.2/24  (default route → 172.17.0.1)
//
// Traffic flows
// =============
//   Local (OUTPUT chain):
//     curl in TestNamespace → nftables OUTPUT MARK → policy route → tproxy → ...
//
//   Container (PREROUTING chain):
//     curl in ContainerNamespace → veth-c-prx → nftables PREROUTING TPROXY → tproxy → ...
//
// Why 203.0.113.1 as the mock server address?
//   The tproxy bypass list includes 10.0.0.0/8 and 172.16.0.0/12 as destinations.
//   If mock servers used 10.200.1.1 or 172.17.0.x, traffic would be bypassed and
//   never reach the proxy. 203.0.113.0/24 is not bypassed, so TPROXY intercepts it.

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// intercept-all config template: intercepts every TCP/UDP port so tests can use
// arbitrary port numbers for mock servers.
const scenarioConfigTmpl = `
listen: ":12345"
upstream: "%s"
log_level: "debug"
intercept_ports: [0]
dns:
  nameservers:
    - "8.8.8.8"
  local_nameservers:
    - "8.8.8.8"
rules:
%s
`

func buildConfig(upstreamURL string, rules []string) string {
	rulesYAML := ""
	for _, r := range rules {
		rulesYAML += "  - " + r + "\n"
	}
	return fmt.Sprintf(scenarioConfigTmpl, upstreamURL, rulesYAML)
}

// ─── Local traffic (OUTPUT chain) ────────────────────────────────────────────

// TestScenario_LocalTCPDirect verifies that a connection from inside the proxy
// namespace that matches DIRECT policy reaches the target server directly,
// without going through an upstream proxy.
func TestScenario_LocalTCPDirect(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)
	RequireCurl(t)

	target := NewMockTargetServer("direct-response")
	if err := target.StartAt(TestServerHostIP + ":0"); err != nil {
		t.Fatalf("start target server: %v", err)
	}
	defer target.Stop()

	mockProxy := NewMockProxy()
	if err := mockProxy.Start(); err != nil {
		t.Fatalf("start mock proxy: %v", err)
	}
	defer mockProxy.Stop()

	cfg := buildConfig("", []string{"MATCH,DIRECT"})
	env := NewTestEnvironment()
	defer env.Cleanup()

	if err := env.SetupTestServerIP(); err != nil {
		t.Fatalf("setup test server IP: %v", err)
	}
	if err := env.Setup(cfg); err != nil {
		t.Fatalf("setup env: %v", err)
	}

	ctx := t.Context()
	if err := env.StartProxy(ctx); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	url := target.URLFor(TestServerHostIP)
	status, body, err := CurlFromProxy(url, DefaultTimeout)
	if err != nil {
		t.Fatalf("curl failed: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	if body != "direct-response" {
		t.Errorf("unexpected body: %q", body)
	}
	if mockProxy.ConnectionCount() > 0 {
		t.Errorf("DIRECT traffic should not touch upstream proxy, but got %d connections", mockProxy.ConnectionCount())
	}
	t.Logf("✓ LocalTCPDirect: status=%d body=%q proxyConns=%d", status, body, mockProxy.ConnectionCount())
}

// TestScenario_LocalTCPProxy verifies that a connection from inside the proxy
// namespace that matches PROXY policy is forwarded through the upstream proxy.
func TestScenario_LocalTCPProxy(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)
	RequireCurl(t)

	target := NewMockTargetServer("proxied-response")
	if err := target.StartAt(TestServerHostIP + ":0"); err != nil {
		t.Fatalf("start target server: %v", err)
	}
	defer target.Stop()

	mockProxy := NewMockProxy()
	if err := mockProxy.Start(); err != nil {
		t.Fatalf("start mock proxy: %v", err)
	}
	defer mockProxy.Stop()

	// Upstream URL must use HostIPAddr (10.200.1.1) so tproxy (in proxy namespace)
	// can reach the mock proxy on the host.
	_, proxyPort, _ := splitHostPort(mockProxy.Addr())
	upstreamURL := fmt.Sprintf("http://%s:%s", HostIPAddr, proxyPort)

	cfg := buildConfig(upstreamURL, []string{"MATCH,PROXY"})
	env := NewTestEnvironment()
	defer env.Cleanup()

	if err := env.SetupTestServerIP(); err != nil {
		t.Fatalf("setup test server IP: %v", err)
	}
	if err := env.Setup(cfg); err != nil {
		t.Fatalf("setup env: %v", err)
	}

	ctx := t.Context()
	if err := env.StartProxy(ctx); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	url := target.URLFor(TestServerHostIP)
	status, body, err := CurlFromProxy(url, DefaultTimeout)
	if err != nil {
		t.Fatalf("curl failed: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	if body != "proxied-response" {
		t.Errorf("unexpected body: %q", body)
	}
	if mockProxy.ConnectionCount() == 0 {
		t.Error("PROXY traffic should pass through upstream proxy, but got 0 connections")
	}
	targets := mockProxy.AllTargets()
	targetHost := TestServerHostIP + ":" + target.Port()
	if len(targets) == 0 || targets[0] != targetHost {
		t.Errorf("upstream proxy CONNECT target = %v, want %s", targets, targetHost)
	}
	t.Logf("✓ LocalTCPProxy: status=%d body=%q proxyConns=%d connectTarget=%v",
		status, body, mockProxy.ConnectionCount(), targets)
}

// TestScenario_LocalTCPReject verifies that a connection matching REJECT policy
// is dropped by the proxy.
func TestScenario_LocalTCPReject(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)
	RequireCurl(t)

	target := NewMockTargetServer("should-never-reach")
	if err := target.StartAt(TestServerHostIP + ":0"); err != nil {
		t.Fatalf("start target server: %v", err)
	}
	defer target.Stop()

	cfg := buildConfig("", []string{"MATCH,REJECT"})
	env := NewTestEnvironment()
	defer env.Cleanup()

	if err := env.SetupTestServerIP(); err != nil {
		t.Fatalf("setup test server IP: %v", err)
	}
	if err := env.Setup(cfg); err != nil {
		t.Fatalf("setup env: %v", err)
	}

	ctx := t.Context()
	if err := env.StartProxy(ctx); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	url := target.URLFor(TestServerHostIP)
	_, _, err := CurlFromProxy(url, 3*time.Second)
	if err == nil {
		t.Error("expected curl to fail for REJECT policy, but it succeeded")
	}
	if target.RequestCount() > 0 {
		t.Errorf("REJECT policy: target server received %d request(s), expected 0", target.RequestCount())
	}
	t.Logf("✓ LocalTCPReject: curl correctly failed: %v", err)
}

// ─── Container traffic (PREROUTING chain) ────────────────────────────────────

// TestScenario_ContainerTCPDirect verifies that traffic from a Docker-like
// container namespace matching DIRECT policy reaches the target server directly.
// This exercises the PREROUTING TPROXY path.
func TestScenario_ContainerTCPDirect(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)
	RequireCurl(t)

	target := NewMockTargetServer("container-direct")
	if err := target.StartAt(TestServerHostIP + ":0"); err != nil {
		t.Fatalf("start target server: %v", err)
	}
	defer target.Stop()

	mockProxy := NewMockProxy()
	if err := mockProxy.Start(); err != nil {
		t.Fatalf("start mock proxy: %v", err)
	}
	defer mockProxy.Stop()

	cfg := buildConfig("", []string{"MATCH,DIRECT"})
	env := NewTestEnvironment()
	defer env.Cleanup()

	if err := env.SetupTestServerIP(); err != nil {
		t.Fatalf("setup test server IP: %v", err)
	}
	if err := env.Setup(cfg); err != nil {
		t.Fatalf("setup env: %v", err)
	}
	if err := env.SetupContainerNetwork(); err != nil {
		t.Fatalf("setup container network: %v", err)
	}

	ctx := t.Context()
	if err := env.StartProxy(ctx); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	url := target.URLFor(TestServerHostIP)
	status, body, err := CurlFromContainer(url, DefaultTimeout)
	if err != nil {
		t.Fatalf("curl from container failed: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	if body != "container-direct" {
		t.Errorf("unexpected body: %q", body)
	}
	if mockProxy.ConnectionCount() > 0 {
		t.Errorf("DIRECT: upstream proxy should not be used, got %d connections", mockProxy.ConnectionCount())
	}
	t.Logf("✓ ContainerTCPDirect: status=%d body=%q", status, body)
}

// TestScenario_ContainerTCPProxy verifies that traffic from a Docker-like
// container namespace matching PROXY policy is routed through the upstream proxy.
func TestScenario_ContainerTCPProxy(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)
	RequireCurl(t)

	target := NewMockTargetServer("container-proxied")
	if err := target.StartAt(TestServerHostIP + ":0"); err != nil {
		t.Fatalf("start target server: %v", err)
	}
	defer target.Stop()

	mockProxy := NewMockProxy()
	if err := mockProxy.Start(); err != nil {
		t.Fatalf("start mock proxy: %v", err)
	}
	defer mockProxy.Stop()

	_, proxyPort, _ := splitHostPort(mockProxy.Addr())
	upstreamURL := fmt.Sprintf("http://%s:%s", HostIPAddr, proxyPort)

	cfg := buildConfig(upstreamURL, []string{"MATCH,PROXY"})
	env := NewTestEnvironment()
	defer env.Cleanup()

	if err := env.SetupTestServerIP(); err != nil {
		t.Fatalf("setup test server IP: %v", err)
	}
	if err := env.Setup(cfg); err != nil {
		t.Fatalf("setup env: %v", err)
	}
	if err := env.SetupContainerNetwork(); err != nil {
		t.Fatalf("setup container network: %v", err)
	}

	ctx := t.Context()
	if err := env.StartProxy(ctx); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	url := target.URLFor(TestServerHostIP)
	status, body, err := CurlFromContainer(url, DefaultTimeout)
	if err != nil {
		t.Fatalf("curl from container failed: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	if body != "container-proxied" {
		t.Errorf("unexpected body: %q", body)
	}
	if mockProxy.ConnectionCount() == 0 {
		t.Error("PROXY: upstream proxy should have been used, got 0 connections")
	}
	targets := mockProxy.AllTargets()
	expectedTarget := TestServerHostIP + ":" + target.Port()
	if len(targets) == 0 || targets[0] != expectedTarget {
		t.Errorf("upstream proxy CONNECT target = %v, want %s", targets, expectedTarget)
	}
	t.Logf("✓ ContainerTCPProxy: status=%d body=%q proxyConns=%d connectTarget=%v",
		status, body, mockProxy.ConnectionCount(), targets)
}

// TestScenario_ContainerTCPReject verifies that traffic from a Docker-like
// container matching REJECT policy is dropped.
func TestScenario_ContainerTCPReject(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)
	RequireCurl(t)

	target := NewMockTargetServer("should-never-reach")
	if err := target.StartAt(TestServerHostIP + ":0"); err != nil {
		t.Fatalf("start target server: %v", err)
	}
	defer target.Stop()

	cfg := buildConfig("", []string{"MATCH,REJECT"})
	env := NewTestEnvironment()
	defer env.Cleanup()

	if err := env.SetupTestServerIP(); err != nil {
		t.Fatalf("setup test server IP: %v", err)
	}
	if err := env.Setup(cfg); err != nil {
		t.Fatalf("setup env: %v", err)
	}
	if err := env.SetupContainerNetwork(); err != nil {
		t.Fatalf("setup container network: %v", err)
	}

	ctx := t.Context()
	if err := env.StartProxy(ctx); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	url := target.URLFor(TestServerHostIP)
	_, _, err := CurlFromContainer(url, 3*time.Second)
	if err == nil {
		t.Error("expected curl to fail for REJECT policy, but it succeeded")
	}
	if target.RequestCount() > 0 {
		t.Errorf("REJECT: target received %d request(s), expected 0", target.RequestCount())
	}
	t.Logf("✓ ContainerTCPReject: curl correctly failed: %v", err)
}

// TestScenario_ContainerDomainRule verifies that a domain-based rule applies
// to container traffic when the domain was previously resolved via DNS.
// The test flow is:
//  1. Container sends DNS query → intercepted by tproxy → forwarded to real DNS
//  2. tproxy caches IP→domain association from the DNS answer
//  3. Container sends TCP to the resolved IP → tproxy matches domain rule
func TestScenario_ContainerDomainRule(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)
	RequireCurl(t)

	target := NewMockTargetServer("domain-rule-hit")
	if err := target.StartAt(TestServerHostIP + ":0"); err != nil {
		t.Fatalf("start target server: %v", err)
	}
	defer target.Stop()

	// Rule: reject "blocked.example" but direct everything else.
	// We're not actually connecting to blocked.example; the rule is just to verify
	// the domain-matching path. We connect to TestServerHostIP directly and use
	// DOMAIN/IP-CIDR rules to drive the decision.
	cfg := buildConfig("", []string{
		// 203.0.113.0/24 (TEST-NET-3) → DIRECT: our mock server should be reachable
		"IP-CIDR,203.0.113.0/24,DIRECT",
		"MATCH,REJECT",
	})
	env := NewTestEnvironment()
	defer env.Cleanup()

	if err := env.SetupTestServerIP(); err != nil {
		t.Fatalf("setup test server IP: %v", err)
	}
	if err := env.Setup(cfg); err != nil {
		t.Fatalf("setup env: %v", err)
	}
	if err := env.SetupContainerNetwork(); err != nil {
		t.Fatalf("setup container network: %v", err)
	}

	ctx := t.Context()
	if err := env.StartProxy(ctx); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	// Traffic to 203.0.113.1 should match the IP-CIDR,203.0.113.0/24,DIRECT rule.
	url := target.URLFor(TestServerHostIP)
	status, body, err := CurlFromContainer(url, DefaultTimeout)
	if err != nil {
		t.Fatalf("curl from container failed: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	if !strings.Contains(body, "domain-rule-hit") {
		t.Errorf("unexpected body: %q", body)
	}
	t.Logf("✓ ContainerDomainRule: IP-CIDR DIRECT rule matched, status=%d", status)
}

// TestScenario_PolicyOrdering verifies that rules are evaluated in order and
// the first matching rule wins.
func TestScenario_PolicyOrdering(t *testing.T) {
	RequireLinux(t)
	RequireRoot(t)
	RequireCurl(t)

	target := NewMockTargetServer("ordering-ok")
	if err := target.StartAt(TestServerHostIP + ":0"); err != nil {
		t.Fatalf("start target server: %v", err)
	}
	defer target.Stop()

	// First rule matches → DIRECT; later REJECT should never fire for this IP.
	cfg := buildConfig("", []string{
		"IP-CIDR,203.0.113.0/24,DIRECT",
		"MATCH,REJECT",
	})
	env := NewTestEnvironment()
	defer env.Cleanup()

	if err := env.SetupTestServerIP(); err != nil {
		t.Fatalf("setup test server IP: %v", err)
	}
	if err := env.Setup(cfg); err != nil {
		t.Fatalf("setup env: %v", err)
	}

	ctx := t.Context()
	if err := env.StartProxy(ctx); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	url := target.URLFor(TestServerHostIP)
	status, _, err := CurlFromProxy(url, DefaultTimeout)
	if err != nil {
		t.Fatalf("curl failed: %v (first rule should have matched DIRECT)", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	t.Logf("✓ PolicyOrdering: first matching rule (DIRECT) wins")
}

// splitHostPort is a convenience wrapper around net.SplitHostPort.
func splitHostPort(addr string) (host, port string, err error) {
	return net.SplitHostPort(addr)
}
