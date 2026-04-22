package proxy

import (
	"net"
	"net/url"
	"testing"

	"github.com/cnfatal/proxy/config"
	"github.com/cnfatal/proxy/rules"
)

func TestTransparentProxy_UDPPolicyByIP(t *testing.T) {
	_, directNet, _ := net.ParseCIDR("10.0.0.0/8")
	_, rejectNet, _ := net.ParseCIDR("192.0.2.0/24")

	matcher := rules.NewMatcher([]*rules.Rule{
		{Type: rules.RuleTypeIPCIDR, Value: "10.0.0.0/8", Network: directNet, Policy: config.PolicyDirect},
		{Type: rules.RuleTypeIPCIDR, Value: "192.0.2.0/24", Network: rejectNet, Policy: config.PolicyReject},
		{Type: rules.RuleTypeMatch, Policy: config.PolicyProxy},
	})

	tp := &TransparentProxy{matcher: matcher}

	tests := []struct {
		name string
		ip   string
		want config.Policy
	}{
		{name: "direct ip stays direct", ip: "10.1.2.3", want: config.PolicyDirect},
		{name: "reject ip is rejected", ip: "192.0.2.44", want: config.PolicyReject},
		{name: "unmatched ip falls to proxy", ip: "8.8.8.8", want: config.PolicyProxy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tp.matcher.Match("", net.ParseIP(tt.ip)).Policy
			if got != tt.want {
				t.Fatalf("Match(%s) = %s, want %s", tt.ip, got, tt.want)
			}
		})
	}
}

func TestTransparentProxy_UpstreamScheme(t *testing.T) {
	tp := &TransparentProxy{}
	if got := tp.upstreamScheme(); got != "" {
		t.Fatalf("upstreamScheme() = %q, want empty", got)
	}

	proxyURL, err := url.Parse("socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}

	tp.upstream = NewUpstream(proxyURL)
	if got := tp.upstreamScheme(); got != "socks5" {
		t.Fatalf("upstreamScheme() = %q, want socks5", got)
	}
}

func TestBuildUpstreamTargetAddr(t *testing.T) {
	origDst := &net.TCPAddr{IP: net.ParseIP("104.244.43.104"), Port: 443}

	if got := buildUpstreamTargetAddr("chatgpt.com", origDst); got != "chatgpt.com:443" {
		t.Fatalf("buildUpstreamTargetAddr(domain) = %q, want %q", got, "chatgpt.com:443")
	}

	if got := buildUpstreamTargetAddr("", origDst); got != "104.244.43.104:443" {
		t.Fatalf("buildUpstreamTargetAddr(ip) = %q, want %q", got, "104.244.43.104:443")
	}
}
