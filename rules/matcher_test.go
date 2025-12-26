package rules

import (
	"net"
	"testing"

	"github.com/cnfatal/proxy/config"
)

func TestMatcher_DomainMatch(t *testing.T) {
	rules := []*Rule{
		{Type: RuleTypeDomain, Value: "example.com", Policy: config.PolicyProxy},
		{Type: RuleTypeDomainSuffix, Value: "google.com", Policy: config.PolicyProxy},
		{Type: RuleTypeDomainKeyword, Value: "youtube", Policy: config.PolicyProxy},
		{Type: RuleTypeMatch, Policy: config.PolicyDirect},
	}

	matcher := NewMatcher(rules)

	tests := []struct {
		name   string
		domain string
		want   config.Policy
	}{
		{"exact match", "example.com", config.PolicyProxy},
		{"exact match case insensitive", "EXAMPLE.COM", config.PolicyProxy},
		{"suffix match", "www.google.com", config.PolicyProxy},
		{"suffix exact match", "google.com", config.PolicyProxy},
		{"suffix no match", "notgoogle.com", config.PolicyDirect},
		{"keyword match", "www.youtube.com", config.PolicyProxy},
		{"keyword match anywhere", "myyoutubesite.com", config.PolicyProxy},
		{"no match falls through", "unknown.org", config.PolicyDirect},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matcher.Match(tt.domain, nil)
			if result.Policy != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.domain, result.Policy, tt.want)
			}
		})
	}
}

func TestMatcher_IPMatch(t *testing.T) {
	_, network1, _ := net.ParseCIDR("192.168.0.0/16")
	_, network2, _ := net.ParseCIDR("10.0.0.0/8")

	rules := []*Rule{
		{Type: RuleTypeIPCIDR, Value: "192.168.0.0/16", Network: network1, Policy: config.PolicyDirect},
		{Type: RuleTypeIPCIDR, Value: "10.0.0.0/8", Network: network2, Policy: config.PolicyDirect},
		{Type: RuleTypeMatch, Policy: config.PolicyProxy},
	}

	matcher := NewMatcher(rules)

	tests := []struct {
		name string
		ip   string
		want config.Policy
	}{
		{"192.168.x match", "192.168.1.100", config.PolicyDirect},
		{"10.x match", "10.0.0.1", config.PolicyDirect},
		{"external ip", "8.8.8.8", config.PolicyProxy},
		{"another external", "1.1.1.1", config.PolicyProxy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := matcher.Match("", ip)
			if result.Policy != tt.want {
				t.Errorf("Match(ip=%q) = %v, want %v", tt.ip, result.Policy, tt.want)
			}
		})
	}
}

func TestMatcher_RuleOrder(t *testing.T) {
	// 测试规则按顺序匹配，第一个匹配的规则生效
	_, network, _ := net.ParseCIDR("0.0.0.0/0")

	rules := []*Rule{
		{Type: RuleTypeDomainSuffix, Value: "google.com", Policy: config.PolicyProxy},
		{Type: RuleTypeIPCIDR, Value: "0.0.0.0/0", Network: network, Policy: config.PolicyDirect},
	}

	matcher := NewMatcher(rules)

	// google.com 应该匹配第一条规则
	result := matcher.Match("www.google.com", net.ParseIP("8.8.8.8"))
	if result.Policy != config.PolicyProxy {
		t.Errorf("Expected PROXY for google.com, got %v", result.Policy)
	}
}

func TestMatcher_EmptyRules(t *testing.T) {
	matcher := NewMatcher([]*Rule{})

	result := matcher.Match("example.com", net.ParseIP("1.2.3.4"))
	if result.Policy != config.PolicyDirect {
		t.Errorf("Empty rules should default to DIRECT, got %v", result.Policy)
	}
}

func TestMatcher_RejectPolicy(t *testing.T) {
	rules := []*Rule{
		{Type: RuleTypeDomainKeyword, Value: "ads", Policy: config.PolicyReject},
		{Type: RuleTypeMatch, Policy: config.PolicyDirect},
	}

	matcher := NewMatcher(rules)

	result := matcher.Match("ads.example.com", nil)
	if result.Policy != config.PolicyReject {
		t.Errorf("Expected REJECT for ads domain, got %v", result.Policy)
	}
}
