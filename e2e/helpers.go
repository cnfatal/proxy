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
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netns"
)

const (
	// TestNamespace is the network namespace name for e2e tests
	TestNamespace = "tproxy_e2e"
	// TestProxyPort is the port the proxy listens on during tests
	TestProxyPort = 12345
	// DefaultTimeout for HTTP requests in tests
	DefaultTimeout = 5 * time.Second
	// VethHost is the host-side veth interface name
	VethHost = "veth-host"
	// VethNS is the namespace-side veth interface name
	VethNS = "veth-ns"
	// HostIP is the IP address for the host side of veth
	HostIP = "10.200.1.1/24"
	// NSIP is the IP address for the namespace side of veth
	NSIP = "10.200.1.2/24"
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

// NewTestEnvironment creates a new test environment with namespace isolation
func NewTestEnvironment() *TestEnvironment {
	// Find binary path (relative to e2e directory)
	binaryPath := "../build/tproxy"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		// Try from project root
		binaryPath = "./build/tproxy"
	}

	return &TestEnvironment{
		BinaryPath: binaryPath,
		CleanupFns: make([]func(), 0),
	}
}

// Setup prepares the test environment with network namespace
func (env *TestEnvironment) Setup(configContent string) error {
	// Suppress log output during tests
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Check binary exists
	absPath, err := filepath.Abs(env.BinaryPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return fmt.Errorf("binary not found at %s - run 'make build' first", absPath)
	}
	env.BinaryPath = absPath

	// Create temp config file
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

	// Setup network namespace
	if err := env.setupNetworkNamespace(); err != nil {
		return fmt.Errorf("failed to setup network namespace: %w", err)
	}

	return nil
}

// setupNetworkNamespace creates an isolated network namespace with veth pair
func (env *TestEnvironment) setupNetworkNamespace() error {
	// Save original namespace
	origNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get original namespace: %w", err)
	}
	env.OriginalNS = origNS

	// Delete existing namespace if exists
	if _, err := netns.GetFromName(TestNamespace); err == nil {
		netns.DeleteNamed(TestNamespace)
	}

	// Create new namespace
	newNS, err := netns.NewNamed(TestNamespace)
	if err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}
	env.Namespace = newNS

	env.CleanupFns = append(env.CleanupFns, func() {
		netns.DeleteNamed(TestNamespace)
	})

	// Switch back to original namespace for setup
	if err := netns.Set(origNS); err != nil {
		return fmt.Errorf("failed to switch back to original ns: %w", err)
	}

	// Create veth pair
	if err := runCmd("ip", "link", "add", VethHost, "type", "veth", "peer", "name", VethNS); err != nil {
		// Ignore if already exists
		if !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("failed to create veth pair: %w", err)
		}
	}

	env.CleanupFns = append(env.CleanupFns, func() {
		runCmd("ip", "link", "del", VethHost)
	})

	// Move veth-ns to the new namespace
	if err := runCmd("ip", "link", "set", VethNS, "netns", TestNamespace); err != nil {
		return fmt.Errorf("failed to move veth to namespace: %w", err)
	}

	// Configure host side
	if err := runCmd("ip", "addr", "add", HostIP, "dev", VethHost); err != nil {
		if !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("failed to add host IP: %w", err)
		}
	}
	if err := runCmd("ip", "link", "set", VethHost, "up"); err != nil {
		return fmt.Errorf("failed to bring up host veth: %w", err)
	}

	// Configure namespace side
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

	// Add default route in namespace (via host)
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
	// Run proxy in the network namespace
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

	// Wait for proxy to be ready
	time.Sleep(500 * time.Millisecond)

	return nil
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
	// Run cleanup functions in reverse order
	for i := len(env.CleanupFns) - 1; i >= 0; i-- {
		env.CleanupFns[i]()
	}
}

// WaitForPort waits for a port to be available (in namespace)
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

// WaitForPortInNS waits for a port to be available in the test namespace
func WaitForPortInNS(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("10.200.1.2:%d", port)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}

	return fmt.Errorf("port %d in namespace not available after %v", port, timeout)
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
	// Clean in default namespace
	exec.Command("nft", "delete", "table", "inet", "transparent_proxy").Run()

	// Clean in test namespace if exists
	exec.Command("ip", "netns", "exec", TestNamespace, "nft", "delete", "table", "inet", "transparent_proxy").Run()

	return nil
}

// CleanupNamespace removes the test namespace
func CleanupNamespace() {
	runCmd("ip", "link", "del", VethHost)
	netns.DeleteNamed(TestNamespace)
}
