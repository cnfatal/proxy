package rules

import (
	"fmt"
	"net"
	"strings"

	"github.com/cnfatal/proxy/config"
)

// RuleType represents the type of a rule
type RuleType string

const (
	RuleTypeDomain        RuleType = "DOMAIN"
	RuleTypeDomainSuffix  RuleType = "DOMAIN-SUFFIX"
	RuleTypeDomainKeyword RuleType = "DOMAIN-KEYWORD"
	RuleTypeIPCIDR        RuleType = "IP-CIDR"
	RuleTypeIPCIDR6       RuleType = "IP-CIDR6"
	RuleTypeMatch         RuleType = "MATCH"
)

// Rule represents a parsed rule
type Rule struct {
	Type    RuleType
	Value   string
	Policy  config.Policy
	Network *net.IPNet // Parsed CIDR for IP-CIDR rules
}

// ParseRules parses a list of Clash-format rule strings
func ParseRules(ruleStrings []string) ([]*Rule, error) {
	rules := make([]*Rule, 0, len(ruleStrings))

	for i, ruleStr := range ruleStrings {
		rule, err := ParseRule(ruleStr)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// ParseRule parses a single Clash-format rule string
// Format: TYPE,ARGUMENT,POLICY or MATCH,POLICY
func ParseRule(ruleStr string) (*Rule, error) {
	ruleStr = strings.TrimSpace(ruleStr)
	parts := strings.Split(ruleStr, ",")

	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid rule format: %s", ruleStr)
	}

	ruleType := RuleType(strings.ToUpper(strings.TrimSpace(parts[0])))

	var value string
	var policyStr string

	if ruleType == RuleTypeMatch {
		// MATCH,POLICY format
		policyStr = strings.TrimSpace(parts[1])
	} else {
		// TYPE,VALUE,POLICY format
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid rule format, expected TYPE,VALUE,POLICY: %s", ruleStr)
		}
		value = strings.TrimSpace(parts[1])
		policyStr = strings.TrimSpace(parts[2])
	}

	policy := config.Policy(strings.ToUpper(policyStr))
	if policy != config.PolicyProxy && policy != config.PolicyDirect && policy != config.PolicyReject {
		return nil, fmt.Errorf("invalid policy: %s (must be PROXY, DIRECT, or REJECT)", policyStr)
	}

	rule := &Rule{
		Type:   ruleType,
		Value:  value,
		Policy: policy,
	}

	// Parse CIDR for IP rules
	switch ruleType {
	case RuleTypeIPCIDR, RuleTypeIPCIDR6:
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %s", value)
		}
		rule.Network = network
	case RuleTypeDomain, RuleTypeDomainSuffix, RuleTypeDomainKeyword, RuleTypeMatch:
		// Valid rule types
	default:
		return nil, fmt.Errorf("unsupported rule type: %s", ruleType)
	}

	return rule, nil
}
