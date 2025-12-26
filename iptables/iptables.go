package iptables

import (
	"fmt"
	"log/slog"
	"net"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
)

const (
	tableName       = "transparent_proxy"
	preroutingChain = "prerouting"
	outputChain     = "output"

	// fwmark value used to mark packets that should bypass the proxy
	// Packets from proxy process are marked with this to prevent loops
	fwMark       = 0x1
	routingTable = 100
)

// Manager manages nftables rules and policy routing for transparent proxying
type Manager struct {
	listenPort uint16
	listenIP   net.IP
	ports      []uint16 // Target ports to redirect (e.g., 80, 443)
	proxyUID   uint32   // UID of proxy process (to exclude from redirection)
	conn       *nftables.Conn
	table      *nftables.Table
}

// NewManager creates a new nftables manager
func NewManager(listenPort int, targetPorts []int) *Manager {
	ports := make([]uint16, len(targetPorts))
	for i, p := range targetPorts {
		ports[i] = uint16(p)
	}

	return &Manager{
		listenPort: uint16(listenPort),
		listenIP:   net.IPv4(127, 0, 0, 1),
		ports:      ports,
		proxyUID:   uint32(syscall.Getuid()),
	}
}

// DefaultPorts returns the default ports to redirect (80 and 443)
func DefaultPorts() []int {
	return []int{80, 443}
}

// Setup configures nftables rules and policy routing to redirect traffic to the proxy
// Uses fwmark + policy routing to prevent traffic loops
func (m *Manager) Setup() error {
	slog.Info("Setting up nftables rules",
		"ports", m.ports,
		"listenPort", m.listenPort,
		"proxyUID", m.proxyUID,
	)

	// Create netlink connection
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to create nftables connection: %w", err)
	}
	m.conn = conn

	// First cleanup any existing rules
	m.cleanupExisting()

	// Setup policy routing first
	if err := m.setupPolicyRouting(); err != nil {
		return fmt.Errorf("failed to setup policy routing: %w", err)
	}

	// Create nftables table
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   tableName,
	}
	m.table = m.conn.AddTable(table)

	// Create OUTPUT chain (for locally generated traffic)
	outputChain := &nftables.Chain{
		Name:     outputChain,
		Table:    m.table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
	}
	m.conn.AddChain(outputChain)

	// Add rules to OUTPUT chain
	for _, port := range m.ports {
		if err := m.addOutputRule(outputChain, port); err != nil {
			m.Cleanup()
			return err
		}
	}

	// Apply all nftables changes
	if err := m.conn.Flush(); err != nil {
		m.cleanupPolicyRouting()
		return fmt.Errorf("failed to apply nftables rules: %w", err)
	}

	slog.Info("nftables rules and policy routing configured successfully")
	return nil
}

// addOutputRule adds a redirect rule for OUTPUT chain
// Excludes traffic from the proxy process (by UID) to prevent loops
func (m *Manager) addOutputRule(chain *nftables.Chain, dstPort uint16) error {
	rule := &nftables.Rule{
		Table: m.table,
		Chain: chain,
		Exprs: []expr.Any{
			// Check L4 protocol is TCP
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{6}, // TCP
			},
			// Exclude traffic from proxy UID (prevent loop)
			&expr.Meta{
				Key:      expr.MetaKeySKUID,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     binaryUint32(m.proxyUID),
			},
			// Check destination port
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // Destination port offset in TCP header
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryPort(dstPort),
			},
			// Set mark (for policy routing of return traffic)
			&expr.Immediate{
				Register: 1,
				Data:     binaryUint32(fwMark),
			},
			&expr.Meta{
				Key:            expr.MetaKeyMARK,
				SourceRegister: true,
				Register:       1,
			},
			// Redirect to proxy port
			&expr.Immediate{
				Register: 1,
				Data:     binaryPort(m.listenPort),
			},
			&expr.Redir{
				RegisterProtoMin: 1,
				RegisterProtoMax: 1,
			},
		},
	}

	m.conn.AddRule(rule)
	return nil
}

// setupPolicyRouting configures ip rule and routing table
// Marked packets will be routed to local loopback
func (m *Manager) setupPolicyRouting() error {
	// Add ip rule: fwmark 0x1 lookup table 100
	rule := netlink.NewRule()
	rule.Mark = fwMark
	rule.Table = routingTable
	rule.Priority = 100

	if err := netlink.RuleAdd(rule); err != nil {
		// Ignore if rule already exists
		if err.Error() != "file exists" {
			return fmt.Errorf("failed to add ip rule: %w", err)
		}
	}

	// Add route in table 100: default via 127.0.0.1
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get loopback interface: %w", err)
	}

	// Use gateway-based route instead of RTN_LOCAL
	route := &netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Gw:        net.IPv4(127, 0, 0, 1),
		Table:     routingTable,
	}

	if err := netlink.RouteAdd(route); err != nil {
		// Ignore if route already exists
		if err.Error() != "file exists" {
			return fmt.Errorf("failed to add route: %w", err)
		}
	}

	slog.Debug("Policy routing configured", "mark", fmt.Sprintf("0x%x", fwMark), "table", routingTable)
	return nil
}

// cleanupPolicyRouting removes the policy routing rules
func (m *Manager) cleanupPolicyRouting() {
	// Remove ip rule
	rule := netlink.NewRule()
	rule.Mark = fwMark
	rule.Table = routingTable
	rule.Priority = 100
	netlink.RuleDel(rule)

	// Remove route from table
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return
	}

	route := &netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Dst:       nil,
		Table:     routingTable,
		Scope:     netlink.SCOPE_HOST,
		Type:      syscall.RTN_LOCAL,
	}
	netlink.RouteDel(route)
}

// binaryPort converts a port number to network byte order (big-endian)
func binaryPort(port uint16) []byte {
	return []byte{byte(port >> 8), byte(port & 0xff)}
}

// binaryUint32 converts a uint32 to bytes (native byte order for UID)
func binaryUint32(v uint32) []byte {
	return []byte{
		byte(v),
		byte(v >> 8),
		byte(v >> 16),
		byte(v >> 24),
	}
}

// Cleanup removes the nftables rules and policy routing
func (m *Manager) Cleanup() error {
	slog.Info("Cleaning up nftables rules and policy routing")

	if m.conn == nil {
		conn, err := nftables.New()
		if err != nil {
			return fmt.Errorf("failed to create nftables connection: %w", err)
		}
		m.conn = conn
	}

	m.cleanupExisting()
	m.cleanupPolicyRouting()

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to cleanup nftables rules: %w", err)
	}

	slog.Debug("Cleanup completed")
	return nil
}

// cleanupExisting removes our table if it exists
func (m *Manager) cleanupExisting() {
	if m.conn == nil {
		return
	}

	// Get all tables
	tables, err := m.conn.ListTables()
	if err != nil {
		return
	}

	// Find and delete our table
	for _, t := range tables {
		if t.Name == tableName && t.Family == nftables.TableFamilyIPv4 {
			m.conn.DelTable(t)
			break
		}
	}
}

// Status returns the current nftables rules for debugging
func (m *Manager) Status() (string, error) {
	if m.conn == nil {
		conn, err := nftables.New()
		if err != nil {
			return "", fmt.Errorf("failed to create nftables connection: %w", err)
		}
		m.conn = conn
	}

	tables, err := m.conn.ListTables()
	if err != nil {
		return "", fmt.Errorf("failed to list tables: %w", err)
	}

	result := "nftables tables:\n"
	for _, t := range tables {
		result += fmt.Sprintf("  - %s (family: %v)\n", t.Name, t.Family)
	}

	// Show policy routing info
	rules, _ := netlink.RuleList(netlink.FAMILY_V4)
	result += "\nPolicy routing rules:\n"
	for _, r := range rules {
		if r.Mark == fwMark {
			result += fmt.Sprintf("  - mark 0x%x -> table %d\n", r.Mark, r.Table)
		}
	}

	return result, nil
}

// CheckRoot checks if running as root (required for nftables)
func CheckRoot() error {
	// Try to create an nftables connection - this will fail if not root
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables requires root privileges: %w", err)
	}

	// Try to list tables to verify permissions
	_, err = conn.ListTables()
	if err != nil {
		return fmt.Errorf("nftables requires root privileges: %w", err)
	}

	return nil
}

// CheckAvailable checks if nftables is available
func CheckAvailable() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables not available: %w", err)
	}

	// Try a simple operation to verify it works
	_, err = conn.ListTables()
	if err != nil {
		return fmt.Errorf("nftables not functional: %w", err)
	}

	slog.Debug("nftables is available")
	return nil
}
