//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netns"
)

const (
	// TestNamespace is the network namespace name for e2e tests (runs the proxy).
	TestNamespace = "tproxy_e2e"
	// ContainerNamespace simulates a Docker-like container network namespace.
	ContainerNamespace = "tproxy_e2e_cnt"

	// TestProxyPort is the port the proxy listens on during tests
	TestProxyPort = 12345
	// DefaultTimeout for HTTP requests in tests
	DefaultTimeout = 5 * time.Second

	// VethHost is the host-side veth interface (host ↔ proxy namespace)
	VethHost = "veth-host"
	// VethNS is the proxy-namespace-side veth interface
	VethNS = "veth-ns"
	// HostIP is the IP address for the host side of veth
	HostIP = "10.200.1.1/24"
	// NSIP is the IP address for the namespace side of veth
	NSIP = "10.200.1.2/24"

	// VethContainerProxy is the proxy-namespace end of the container veth pair.
	VethContainerProxy = "veth-c-prx"
	// VethContainerNS is the container-namespace end of the container veth pair.
	VethContainerNS = "veth-c-ns"
	// ContainerGatewayIP is the proxy-namespace interface IP (gateway for containers).
	ContainerGatewayIP = "172.17.0.1/24"
	// ContainerIP is the container namespace's IP.
	ContainerIP = "172.17.0.2/24"

	// TestServerHostIP is an RFC 5737 TEST-NET-3 address added to the host loopback.
	// It is NOT in any bypassDestinationCIDR, so traffic to this IP will be
	// intercepted by TPROXY as intended.
	TestServerHostIP = "203.0.113.1"
	// HostIPAddr is HostIP without the CIDR suffix.
	HostIPAddr = "10.200.1.1"
	// NSIPAddr is NSIP without the CIDR suffix.
	NSIPAddr = "10.200.1.2"
)

// TestEnvironment manages the e2e test environment with network namespace isolation
type TestEnvironment struct {
	ProxyCmd   *exec.Cmd
	ConfigPath string
	BinaryPath string
	Namespace  netns.NsHandle
	OriginalNS netns.NsHandle
	CleanupFns []func()
}

// RequireRoot skips the test if not running as root
func RequireRoot(t interface{ Skip(...any) }) {
	if os.Getuid() != 0 {
		t.Skip("E2E tests require root privileges. Run with: sudo go test -v -tags=e2e ./e2e/...")
	}
}

// RequireLinux skips the test if not running on Linux
func RequireLinux(t interface{ Skip(...any) }) {
	if runtime.GOOS != "linux" {
		t.Skip("E2E tests require Linux")
	}
}

// RequireCurl skips the test if curl is not available.
func RequireCurl(t interface{ Skip(...any) }) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not found in PATH")
	}
}

// NewTestEnvironment creates a new test environment with namespace isolation
func NewTestEnvironment() *TestEnvironment {
	// Find binary path (relative to e2e directory)
	binaryPath := "../build/tproxy"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		binaryPath = "./build/tproxy"
	}

	return &TestEnvironment{
		BinaryPath: binaryPath,
		CleanupFns: make([]func(), 0),
	}
}

// Setup prepares the test environment with network namespace
func (env *TestEnvironment) Setup(configContent string) error {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	absPath, err := filepath.Abs(env.BinaryPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return fmt.Errorf("binary not found at %s - run 'make build' first", absPath)
	}
	env.BinaryPath = absPath

	tmpDir, err := os.MkdirTemp("", "tproxy-e2e-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	env.CleanupFns = append(env.CleanupFns, func() {
		os.RemoveAll(tmpDir)
	})

	env.ConfigPath = filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(env.ConfigPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	if err := env.setupNetworkNamespace(); err != nil {
		return fmt.Errorf("failed to setup network namespace: %w", err)
	}

	return nil
}

// SetupTestServerIP adds TestServerHostIP (203.0.113.1) to the host loopback.
// This address is outside all bypassDestinationCIDRs so traffic to it will be
// intercepted by TPROXY. Mock servers should be started with StartAt(TestServerHostIP+":0").
func (env *TestEnvironment) SetupTestServerIP() error {
	if err := runCmd("ip", "addr", "add", TestServerHostIP+"/32", "dev", "lo"); err != nil {
		if !strings.Contains(err.Error(), "File exists") && !strings.Contains(err.Error(), "RTNETLINK") {
			return fmt.Errorf("failed to add test server IP: %w", err)
		}
	}
	env.CleanupFns = append(env.CleanupFns, func() {
		runCmd("ip", "addr", "del", TestServerHostIP+"/32", "dev", "lo")
	})
	return nil
}

// SetupContainerNetwork adds a simulated Docker-like container namespace to the test
// environment. Call this after Setup(). It creates:
//
//	proxy_ns  (TestNamespace):  veth-c-prx  172.17.0.1/24  (gateway)
//	container_ns (ContainerNamespace): veth-c-ns  172.17.0.2/24
//
// The container's default route points to the proxy namespace, so all traffic from
// ContainerNamespace transits through TestNamespace's PREROUTING chain where TPROXY
// intercepts it — exactly how Docker bridge networking works.
func (env *TestEnvironment) SetupContainerNetwork() error {
	// Enable IP forwarding in proxy namespace so it can route container traffic.
	if err := runCmdInNS(TestNamespace, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("failed to enable ip_forward in proxy namespace: %w", err)
	}

	// Clean up any leftover container namespace from previous runs.
	netns.DeleteNamed(ContainerNamespace)
	runCmd("ip", "link", "del", VethContainerProxy) // also deletes VethContainerNS peer

	// Create container namespace.
	cns, err := netns.NewNamed(ContainerNamespace)
	if err != nil {
		return fmt.Errorf("failed to create container namespace: %w", err)
	}
	cns.Close()
	env.CleanupFns = append(env.CleanupFns, func() {
		netns.DeleteNamed(ContainerNamespace)
	})

	// Create the veth pair in the host namespace.
	if err := runCmd("ip", "link", "add", VethContainerProxy, "type", "veth", "peer", "name", VethContainerNS); err != nil {
		return fmt.Errorf("failed to create container veth pair: %w", err)
	}
	env.CleanupFns = append(env.CleanupFns, func() {
		runCmd("ip", "link", "del", VethContainerProxy)
	})

	// Move proxy end into the proxy namespace.
	if err := runCmd("ip", "link", "set", VethContainerProxy, "netns", TestNamespace); err != nil {
		return fmt.Errorf("failed to move veth to proxy namespace: %w", err)
	}
	// Move container end into the container namespace.
	if err := runCmd("ip", "link", "set", VethContainerNS, "netns", ContainerNamespace); err != nil {
		return fmt.Errorf("failed to move veth to container namespace: %w", err)
	}

	// Configure proxy-namespace side (gateway for containers).
	if err := runCmdInNS(TestNamespace, "ip", "addr", "add", ContainerGatewayIP, "dev", VethContainerProxy); err != nil {
		if !strings.Contains(err.Error(), "File exists") {
			return fmt.Errorf("failed to configure proxy-side veth: %w", err)
		}
	}
	if err := runCmdInNS(TestNamespace, "ip", "link", "set", VethContainerProxy, "up"); err != nil {
		return fmt.Errorf("failed to bring up proxy container veth: %w", err)
	}

	// Configure container-namespace side.
	gatewayIP := strings.Split(ContainerGatewayIP, "/")[0] // 172.17.0.1
	if err := runCmdInNS(ContainerNamespace, "ip", "addr", "add", ContainerIP, "dev", VethContainerNS); err != nil {
		if !strings.Contains(err.Error(), "File exists") {
			return fmt.Errorf("failed to configure container veth: %w", err)
		}
	}
	if err := runCmdInNS(ContainerNamespace, "ip", "link", "set", VethContainerNS, "up"); err != nil {
		return fmt.Errorf("failed to bring up container veth: %w", err)
	}
	if err := runCmdInNS(ContainerNamespace, "ip", "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("failed to bring up container loopback: %w", err)
	}
	// Default route: all container traffic goes through the proxy namespace.
	if err := runCmdInNS(ContainerNamespace, "ip", "route", "add", "default", "via", gatewayIP); err != nil {
		if !strings.Contains(err.Error(), "File exists") {
			return fmt.Errorf("failed to add container default route: %w", err)
		}
	}

	return nil
}

// setupNetworkNamespace creates an isolated network namespace with veth pair
func (env *TestEnvironment) setupNetworkNamespace() error {
	origNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get original namespace: %w", err)
	}
	env.OriginalNS = origNS

	if _, err := netns.GetFromName(TestNamespace); err == nil {
		netns.DeleteNamed(TestNamespace)
	}

	newNS, err := netns.NewNamed(TestNamespace)
	if err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}
	env.Namespace = newNS

	env.CleanupFns = append(env.CleanupFns, func() {
		netns.DeleteNamed(TestNamespace)
	})

	if err := netns.Set(origNS); err != nil {
		return fmt.Errorf("failed to switch back to original ns: %w", err)
	}

	if err := runCmd("ip", "link", "add", VethHost, "type", "veth", "peer", "name", VethNS); err != nil {
		if !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("failed to create veth pair: %w", err)
		}
	}

	env.CleanupFns = append(env.CleanupFns, func() {
		runCmd("ip", "link", "del", VethHost)
	})

	if err := runCmd("ip", "link", "set", VethNS, "netns", TestNamespace); err != nil {
		return fmt.Errorf("failed to move veth to namespace: %w", err)
	}

	if err := runCmd("ip", "addr", "add", HostIP, "dev", VethHost); err != nil {
		if !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("failed to add host IP: %w", err)
		}
	}
	if err := runCmd("ip", "link", "set", VethHost, "up"); err != nil {
		return fmt.Errorf("failed to bring up host veth: %w", err)
	}

	if err := runCmdInNS(TestNamespace, "ip", "addr", "add", NSIP, "dev", VethNS); err != nil {
		if !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("failed to add ns IP: %w", err)
		}
	}
	if err := runCmdInNS(TestNamespace, "ip", "link", "set", VethNS, "up"); err != nil {
		return fmt.Errorf("failed to bring up ns veth: %w", err)
	}
	if err := runCmdInNS(TestNamespace, "ip", "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("failed to bring up loopback: %w", err)
	}

	hostIPAddr := strings.Split(HostIP, "/")[0]
	if err := runCmdInNS(TestNamespace, "ip", "route", "add", "default", "via", hostIPAddr); err != nil {
		if !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("failed to add default route: %w", err)
		}
	}

	return nil
}

// StartProxy starts the proxy process in the test namespace
func (env *TestEnvironment) StartProxy(ctx context.Context) error {
	env.ProxyCmd = exec.CommandContext(ctx, "ip", "netns", "exec", TestNamespace,
		env.BinaryPath, "-config", env.ConfigPath)
	env.ProxyCmd.Stdout = os.Stdout
	env.ProxyCmd.Stderr = os.Stderr

	if err := env.ProxyCmd.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	env.CleanupFns = append(env.CleanupFns, func() {
		if env.ProxyCmd.Process != nil {
			env.ProxyCmd.Process.Signal(syscall.SIGTERM)
			env.ProxyCmd.Wait()
		}
	})

	return WaitForProxyInNS(TestProxyPort, 5*time.Second)
}

// StartProxyDirect starts the proxy without namespace (for tests that need direct access)
func (env *TestEnvironment) StartProxyDirect(ctx context.Context) error {
	env.ProxyCmd = exec.CommandContext(ctx, env.BinaryPath, "-config", env.ConfigPath)
	env.ProxyCmd.Stdout = os.Stdout
	env.ProxyCmd.Stderr = os.Stderr

	if err := env.ProxyCmd.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	env.CleanupFns = append(env.CleanupFns, func() {
		if env.ProxyCmd.Process != nil {
			env.ProxyCmd.Process.Signal(syscall.SIGTERM)
			env.ProxyCmd.Wait()
		}
	})

	time.Sleep(500 * time.Millisecond)
	return nil
}

// Cleanup tears down the test environment
func (env *TestEnvironment) Cleanup() {
	for i := len(env.CleanupFns) - 1; i >= 0; i-- {
		env.CleanupFns[i]()
	}
}

// WaitForPort waits for a port to be available on localhost.
func WaitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}

	return fmt.Errorf("port %d not available after %v", port, timeout)
}

// WaitForProxyInNS waits for the proxy port to be available inside the test namespace.
// It polls by trying to reach it from the host via the veth IP.
func WaitForProxyInNS(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort(NSIPAddr, fmt.Sprintf("%d", port))

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("proxy port %d in namespace not available after %v", port, timeout)
}

// HTTPGet performs an HTTP GET request with timeout
func HTTPGet(url string, timeout time.Duration) (int, string, error) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}

	return resp.StatusCode, string(body), nil
}

// CurlFromNamespace runs curl inside the given network namespace and returns
// (statusCode, responseBody, error). Returns error if curl fails (e.g., connection refused).
func CurlFromNamespace(ns, url string, timeout time.Duration) (int, string, error) {
	timeoutSec := strconv.Itoa(int(timeout.Seconds()))
	out, err := RunCommand("ip", "netns", "exec", ns,
		"curl", "-s", "--max-time", timeoutSec,
		"-w", "\n%{http_code}",
		"-o", "-",
		url,
	)
	if err != nil {
		return 0, "", fmt.Errorf("curl failed: %w (output: %s)", err, out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 0 {
		return 0, "", fmt.Errorf("empty curl output")
	}
	statusStr := lines[len(lines)-1]
	status, convErr := strconv.Atoi(statusStr)
	if convErr != nil {
		return 0, out, fmt.Errorf("could not parse http status from curl output: %q", out)
	}
	body := strings.Join(lines[:len(lines)-1], "\n")
	return status, body, nil
}

// CurlFromProxy runs curl inside the proxy namespace (tests OUTPUT chain / local traffic).
func CurlFromProxy(url string, timeout time.Duration) (int, string, error) {
	return CurlFromNamespace(TestNamespace, url, timeout)
}

// CurlFromContainer runs curl inside the container namespace (tests PREROUTING chain / transit traffic).
func CurlFromContainer(url string, timeout time.Duration) (int, string, error) {
	return CurlFromNamespace(ContainerNamespace, url, timeout)
}

// RunCommand runs a command and returns its output
func RunCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// runCmd is a helper to run commands
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}

// runCmdInNS runs a command in a network namespace
func runCmdInNS(nsName string, name string, args ...string) error {
	fullArgs := append([]string{"netns", "exec", nsName, name}, args...)
	return runCmd("ip", fullArgs...)
}

// CleanupIPTables removes any leftover nftables rules from failed tests
func CleanupIPTables() error {
	exec.Command("nft", "delete", "table", "inet", "transparent_proxy").Run()
	exec.Command("ip", "netns", "exec", TestNamespace, "nft", "delete", "table", "inet", "transparent_proxy").Run()
	return nil
}

// CleanupNamespace removes the test namespaces
func CleanupNamespace() {
	runCmd("ip", "link", "del", VethHost)
	runCmd("ip", "link", "del", VethContainerProxy)
	netns.DeleteNamed(TestNamespace)
	netns.DeleteNamed(ContainerNamespace)
	runCmd("ip", "addr", "del", TestServerHostIP+"/32", "dev", "lo")
}
