package rules

import (
	"net"
	"testing"

	"github.com/cnfatal/proxy/config"
)

func TestParseRule_Domain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantType RuleType
		wantVal  string
		wantPol  config.Policy
		wantErr  bool
	}{
		{
			name:     "domain rule",
			input:    "DOMAIN,example.com,PROXY",
			wantType: RuleTypeDomain,
			wantVal:  "example.com",
			wantPol:  config.PolicyProxy,
		},
		{
			name:     "domain suffix",
			input:    "DOMAIN-SUFFIX,google.com,PROXY",
			wantType: RuleTypeDomainSuffix,
			wantVal:  "google.com",
			wantPol:  config.PolicyProxy,
		},
		{
			name:     "domain keyword",
			input:    "DOMAIN-KEYWORD,youtube,DIRECT",
			wantType: RuleTypeDomainKeyword,
			wantVal:  "youtube",
			wantPol:  config.PolicyDirect,
		},
		{
			name:     "lowercase policy",
			input:    "DOMAIN,test.com,proxy",
			wantType: RuleTypeDomain,
			wantVal:  "test.com",
			wantPol:  config.PolicyProxy,
		},
		{
			name:    "invalid format",
			input:   "DOMAIN,only-two-parts",
			wantErr: true,
		},
		{
			name:    "invalid policy",
			input:   "DOMAIN,test.com,INVALID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := ParseRule(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if rule.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", rule.Type, tt.wantType)
			}
			if rule.Value != tt.wantVal {
				t.Errorf("Value = %v, want %v", rule.Value, tt.wantVal)
			}
			if rule.Policy != tt.wantPol {
				t.Errorf("Policy = %v, want %v", rule.Policy, tt.wantPol)
			}
		})
	}
}

func TestParseRule_IPCIDR(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantType    RuleType
		wantNetwork string
		wantErr     bool
	}{
		{
			name:        "ip-cidr",
			input:       "IP-CIDR,192.168.0.0/16,DIRECT",
			wantType:    RuleTypeIPCIDR,
			wantNetwork: "192.168.0.0/16",
		},
		{
			name:        "ip-cidr6",
			input:       "IP-CIDR6,::1/128,DIRECT",
			wantType:    RuleTypeIPCIDR6,
			wantNetwork: "::1/128",
		},
		{
			name:    "invalid cidr",
			input:   "IP-CIDR,invalid-cidr,DIRECT",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := ParseRule(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if rule.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", rule.Type, tt.wantType)
			}
			if rule.Network == nil {
				t.Error("Network is nil")
				return
			}
			_, expectedNet, _ := net.ParseCIDR(tt.wantNetwork)
			if rule.Network.String() != expectedNet.String() {
				t.Errorf("Network = %v, want %v", rule.Network, expectedNet)
			}
		})
	}
}

func TestParseRule_Match(t *testing.T) {
	rule, err := ParseRule("MATCH,DIRECT")
	if err != nil {
		t.Fatalf("ParseRule() error = %v", err)
	}
	if rule.Type != RuleTypeMatch {
		t.Errorf("Type = %v, want %v", rule.Type, RuleTypeMatch)
	}
	if rule.Policy != config.PolicyDirect {
		t.Errorf("Policy = %v, want %v", rule.Policy, config.PolicyDirect)
	}
}

func TestParseRules(t *testing.T) {
	ruleStrings := []string{
		"IP-CIDR,127.0.0.0/8,DIRECT",
		"DOMAIN-SUFFIX,google.com,PROXY",
		"MATCH,DIRECT",
	}

	rules, err := ParseRules(ruleStrings)
	if err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}
	if len(rules) != 3 {
		t.Errorf("len(rules) = %v, want 3", len(rules))
	}
}
