package rules

import (
	"net"
	"strings"

	"github.com/cnfatal/proxy/config"
)

// Matcher matches traffic against rules
type Matcher struct {
	rules []*Rule
}

// NewMatcher creates a new rule matcher
func NewMatcher(rules []*Rule) *Matcher {
	return &Matcher{rules: rules}
}

// MatchResult contains the result of a rule match
type MatchResult struct {
	Policy config.Policy
	Rule   *Rule
}

// Match finds the first matching rule for the given domain and/or IP
// Returns PolicyDirect if no rules match
func (m *Matcher) Match(domain string, ip net.IP) MatchResult {
	domain = strings.ToLower(domain)

	for _, rule := range m.rules {
		if m.matchRule(rule, domain, ip) {
			return MatchResult{
				Policy: rule.Policy,
				Rule:   rule,
			}
		}
	}

	// Default to DIRECT if no rules match
	return MatchResult{
		Policy: config.PolicyDirect,
		Rule:   nil,
	}
}

// matchRule checks if a single rule matches
func (m *Matcher) matchRule(rule *Rule, domain string, ip net.IP) bool {
	switch rule.Type {
	case RuleTypeDomain:
		// Exact domain match
		return strings.EqualFold(domain, rule.Value)

	case RuleTypeDomainSuffix:
		// Domain ends with the suffix
		suffix := strings.ToLower(rule.Value)
		if domain == suffix {
			return true
		}
		return strings.HasSuffix(domain, "."+suffix)

	case RuleTypeDomainKeyword:
		// Domain contains the keyword
		return strings.Contains(domain, strings.ToLower(rule.Value))

	case RuleTypeIPCIDR, RuleTypeIPCIDR6:
		// IP is within the CIDR range
		if ip == nil || rule.Network == nil {
			return false
		}
		return rule.Network.Contains(ip)

	case RuleTypeMatch:
		// Always matches (catch-all)
		return true

	default:
		return false
	}
}
