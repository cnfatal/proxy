package iptables

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
)

const (
	tableName       = "transparent_proxy"
	preroutingChain = "prerouting"
	outputChain     = "output"

	// FWMark is used to mark packets that should be handled by policy routing
	FWMark = 0x1
	// BypassMark is used to mark packets that should bypass the proxy
	BypassMark   = 0xff
	routingTable = 100
)

// TProxyRule defines a traffic interception rule
type TProxyRule struct {
	Protocols string   // "tcp" or "udp"
	Ports     []uint16 // Source port to intercept (0 for all ports)
	DstPort   uint16   // Destination port on local machine (proxy port)
}

// Manager manages nftables rules and policy routing for transparent proxying
type Manager struct {
	rules []TProxyRule
	conn  *nftables.Conn
	table *nftables.Table
}

// NewManager creates a new nftables manager
func NewManager(rules []TProxyRule) *Manager {
	return &Manager{
		rules: rules,
	}
}

// Setup configures nftables rules and policy routing to intercept traffic to the proxy
func (m *Manager) Setup() error {
	slog.Info("Setting up nftables rules", "rules", m.rules)

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

	// Create nftables table (Inet family handles both IPv4 and IPv6)
	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	}
	m.table = m.conn.AddTable(table)

	// Create OUTPUT chain (for locally generated traffic)
	outputCh := &nftables.Chain{
		Name:     outputChain,
		Table:    m.table,
		Type:     nftables.ChainTypeRoute,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle,
	}
	m.conn.AddChain(outputCh)

	// Create PREROUTING chain (for traffic from other devices)
	preroutingCh := &nftables.Chain{
		Name:     preroutingChain,
		Table:    m.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
	}
	m.conn.AddChain(preroutingCh)

	// Add bypass rule to OUTPUT chain
	m.addBypassRule(outputCh)

	// Add rules to both chains
	for _, rule := range m.rules {
		if err := m.addRule(outputCh, rule, true); err != nil {
			m.Cleanup()
			return err
		}
		if err := m.addRule(preroutingCh, rule, false); err != nil {
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

// addBypassRule adds a rule to bypass proxy for its own traffic
func (m *Manager) addBypassRule(chain *nftables.Chain) {
	m.conn.AddRule(&nftables.Rule{
		Table: m.table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyMARK,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryUint32(BypassMark),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})
}

// addRule adds a tproxy rule for a specific chain
func (m *Manager) addRule(chain *nftables.Chain, r TProxyRule, isOutput bool) error {
	if r.Protocols == "" {
		return nil
	}

	// If no ports specified or contains 0, match all ports (represented by a single rule with port 0)
	ports := r.Ports
	if len(ports) == 0 || slices.Contains(ports, 0) {
		ports = []uint16{0}
	}

	for _, port := range ports {
		exprs := []expr.Any{}

		// 1. Protocol matching
		exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{ternary(r.Protocols == "udp", byte(17), byte(6))},
		})

		// 2. Port matching (skip if port is 0)
		if port != 0 {
			exprs = append(exprs, &expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // Destination port offset in TCP/UDP header
				Len:          2,
			})
			exprs = append(exprs, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryPort(port),
			})
		}

		// 3. Set mark
		exprs = append(exprs, &expr.Immediate{
			Register: 1,
			Data:     binaryUint32(FWMark),
		}, &expr.Meta{
			Key:            expr.MetaKeyMARK,
			SourceRegister: true,
			Register:       1,
		})

		// 4. TProxy or Mark
		if isOutput {
			exprs = append(exprs, &expr.Verdict{
				Kind: expr.VerdictAccept,
			})
			m.conn.AddRule(&nftables.Rule{
				Table: m.table,
				Chain: chain,
				Exprs: exprs,
			})
		} else {
			// For PREROUTING, add two rules: one for IPv4 and one for IPv6

			// IPv4 rule
			exprs4 := append([]expr.Any{}, exprs...)
			exprs4 = append(exprs4, &expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1})
			exprs4 = append(exprs4, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{byte(nftables.TableFamilyIPv4)},
			})
			exprs4 = append(exprs4, &expr.Immediate{
				Register: 1,
				Data:     binaryPort(r.DstPort),
			}, &expr.TProxy{
				Family:      byte(nftables.TableFamilyIPv4),
				TableFamily: byte(nftables.TableFamilyINet),
				RegPort:     1,
			}, &expr.Verdict{
				Kind: expr.VerdictAccept,
			})
			m.conn.AddRule(&nftables.Rule{
				Table: m.table,
				Chain: chain,
				Exprs: exprs4,
			})

			// IPv6 rule
			exprs6 := append([]expr.Any{}, exprs...)
			exprs6 = append(exprs6, &expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1})
			exprs6 = append(exprs6, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{byte(nftables.TableFamilyIPv6)},
			})
			exprs6 = append(exprs6, &expr.Immediate{
				Register: 1,
				Data:     binaryPort(r.DstPort),
			}, &expr.TProxy{
				Family:      byte(nftables.TableFamilyIPv6),
				TableFamily: byte(nftables.TableFamilyINet),
				RegPort:     1,
			}, &expr.Verdict{
				Kind: expr.VerdictAccept,
			})
			m.conn.AddRule(&nftables.Rule{
				Table: m.table,
				Chain: chain,
				Exprs: exprs6,
			})
		}
	}

	return nil
}

// setupPolicyRouting configures ip rule and routing table
func (m *Manager) setupPolicyRouting() error {
	// Add IPv4 rule: fwmark FWMark lookup table 100
	rule4 := netlink.NewRule()
	rule4.Mark = FWMark
	rule4.Table = routingTable
	rule4.Priority = 100
	rule4.Family = netlink.FAMILY_V4

	if err := netlink.RuleAdd(rule4); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("failed to add ipv4 rule: %w", err)
		}
	}

	// Add IPv6 rule: fwmark FWMark lookup table 100
	rule6 := netlink.NewRule()
	rule6.Mark = FWMark
	rule6.Table = routingTable
	rule6.Priority = 100
	rule6.Family = netlink.FAMILY_V6

	if err := netlink.RuleAdd(rule6); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("failed to add ipv6 rule: %w", err)
		}
	}

	// Add routes in table 100: default via 127.0.0.1 / ::1
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get loopback interface: %w", err)
	}

	// IPv4 route
	_, defaultNet4, _ := net.ParseCIDR("0.0.0.0/0")
	route4 := &netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Type:      syscall.RTN_LOCAL,
		Dst:       defaultNet4,
		Table:     routingTable,
		Family:    netlink.FAMILY_V4,
		Scope:     netlink.SCOPE_HOST,
	}

	if err := netlink.RouteAdd(route4); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("failed to add ipv4 route: %w", err)
		}
	}

	// IPv6 route
	_, defaultNet6, _ := net.ParseCIDR("::/0")
	route6 := &netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Type:      syscall.RTN_LOCAL,
		Dst:       defaultNet6,
		Table:     routingTable,
		Family:    netlink.FAMILY_V6,
		Scope:     netlink.SCOPE_HOST,
	}

	if err := netlink.RouteAdd(route6); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("failed to add ipv6 route: %w", err)
		}
	}

	slog.Debug("Policy routing configured", "mark", fmt.Sprintf("0x%x", FWMark), "table", routingTable)
	return nil
}

// cleanupPolicyRouting removes the policy routing rules
func (m *Manager) cleanupPolicyRouting() {
	// Remove IPv4 rule
	rule4 := netlink.NewRule()
	rule4.Mark = FWMark
	rule4.Table = routingTable
	rule4.Priority = 100
	rule4.Family = netlink.FAMILY_V4
	if err := netlink.RuleDel(rule4); err != nil {
		slog.Debug("Failed to delete IPv4 rule", "error", err)
	}

	// Remove IPv6 rule
	rule6 := netlink.NewRule()
	rule6.Mark = FWMark
	rule6.Table = routingTable
	rule6.Priority = 100
	rule6.Family = netlink.FAMILY_V6
	if err := netlink.RuleDel(rule6); err != nil {
		slog.Debug("Failed to delete IPv6 rule", "error", err)
	}

	// Remove routes from table
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return
	}

	route4 := &netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Table:     routingTable,
		Family:    netlink.FAMILY_V4,
	}
	if err := netlink.RouteDel(route4); err != nil {
		slog.Debug("Failed to delete IPv4 route", "error", err)
	}

	route6 := &netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Table:     routingTable,
		Family:    netlink.FAMILY_V6,
	}
	if err := netlink.RouteDel(route6); err != nil {
		slog.Debug("Failed to delete IPv6 route", "error", err)
	}
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
		if t.Name == tableName && (t.Family == nftables.TableFamilyIPv4 || t.Family == nftables.TableFamilyINet) {
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
	rules4, _ := netlink.RuleList(netlink.FAMILY_V4)
	rules6, _ := netlink.RuleList(netlink.FAMILY_V6)
	result += "\nPolicy routing rules (IPv4):\n"
	for _, r := range rules4 {
		if r.Mark == FWMark {
			result += fmt.Sprintf("  - mark 0x%x -> table %d\n", r.Mark, r.Table)
		}
	}
	result += "\nPolicy routing rules (IPv6):\n"
	for _, r := range rules6 {
		if r.Mark == FWMark {
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

func ternary[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
