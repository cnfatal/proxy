package rules

import (
	"net"
	"strings"

	"github.com/cnfatal/proxy/config"
)

// Matcher matches traffic against rules
type Matcher struct {
	rules        []*Rule
	domainTrie   *DomainTrie
	ipTree       *IPTree
	keywordRules []keywordRule
	prefixRules  []prefixRule
	matchRule    *Rule
	matchIndex   int
}

type keywordRule struct {
	rule  *Rule
	index int
}

type prefixRule struct {
	rule  *Rule
	index int
}

// NewMatcher creates a new rule matcher
func NewMatcher(rules []*Rule) *Matcher {
	m := &Matcher{
		rules:      rules,
		domainTrie: NewDomainTrie(),
		ipTree:     NewIPTree(),
		matchIndex: -1,
	}

	for i, rule := range rules {
		switch rule.Type {
		case RuleTypeDomain, RuleTypeDomainSuffix:
			m.domainTrie.Insert(rule.Value, rule, i, rule.Type == RuleTypeDomainSuffix)
		case RuleTypeDomainPrefix:
			m.prefixRules = append(m.prefixRules, prefixRule{rule: rule, index: i})
		case RuleTypeDomainKeyword:
			m.keywordRules = append(m.keywordRules, keywordRule{rule: rule, index: i})
		case RuleTypeIPCIDR, RuleTypeIPCIDR6:
			m.ipTree.Insert(rule.Network, rule, i)
		case RuleTypeMatch:
			if m.matchRule == nil {
				m.matchRule = rule
				m.matchIndex = i
			}
		}
	}

	return m
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

	var bestRule *Rule
	bestIndex := -1

	// 1. Check Domain Trie (DOMAIN and DOMAIN-SUFFIX)
	if domain != "" {
		if r, idx := m.domainTrie.Search(domain); r != nil {
			bestRule = r
			bestIndex = idx
		}

		// 2. Check Domain Prefixes
		for _, pr := range m.prefixRules {
			if bestIndex != -1 && pr.index >= bestIndex {
				break
			}
			if strings.HasPrefix(domain, strings.ToLower(pr.rule.Value)) {
				bestRule = pr.rule
				bestIndex = pr.index
			}
		}

		// 3. Check Domain Keywords
		for _, kr := range m.keywordRules {
			if bestIndex != -1 && kr.index >= bestIndex {
				break
			}
			if strings.Contains(domain, strings.ToLower(kr.rule.Value)) {
				bestRule = kr.rule
				bestIndex = kr.index
				break
			}
		}
	}

	// 4. Check IP Tree
	if ip != nil {
		if r, idx := m.ipTree.Search(ip); r != nil {
			if bestIndex == -1 || idx < bestIndex {
				bestRule = r
				bestIndex = idx
			}
		}
	}

	// 5. Check MATCH rule
	if m.matchRule != nil {
		if bestIndex == -1 || m.matchIndex < bestIndex {
			bestRule = m.matchRule
			bestIndex = m.matchIndex
		}
	}

	if bestRule != nil {
		return MatchResult{
			Policy: bestRule.Policy,
			Rule:   bestRule,
		}
	}

	// Default to DIRECT if no rules match
	return MatchResult{
		Policy: config.PolicyDirect,
		Rule:   nil,
	}
}
