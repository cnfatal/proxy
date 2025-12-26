package rules

import (
	"strings"
)

type trieNode struct {
	children    map[string]*trieNode
	exactRule   *Rule
	exactIndex  int
	suffixRule  *Rule
	suffixIndex int
}

type DomainTrie struct {
	root *trieNode
}

func NewDomainTrie() *DomainTrie {
	return &DomainTrie{
		root: &trieNode{
			children:    make(map[string]*trieNode),
			exactIndex:  -1,
			suffixIndex: -1,
		},
	}
}

func (t *DomainTrie) Insert(domain string, rule *Rule, index int, isSuffix bool) {
	parts := strings.Split(domain, ".")
	node := t.root

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if _, ok := node.children[part]; !ok {
			node.children[part] = &trieNode{
				children:    make(map[string]*trieNode),
				exactIndex:  -1,
				suffixIndex: -1,
			}
		}
		node = node.children[part]
	}

	if isSuffix {
		if node.suffixRule == nil || index < node.suffixIndex {
			node.suffixRule = rule
			node.suffixIndex = index
		}
	} else {
		if node.exactRule == nil || index < node.exactIndex {
			node.exactRule = rule
			node.exactIndex = index
		}
	}
}

// Search finds the best matching rule for a domain
func (t *DomainTrie) Search(domain string) (*Rule, int) {
	parts := strings.Split(domain, ".")
	node := t.root

	var bestRule *Rule
	bestIndex := -1

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		next, ok := node.children[part]
		if !ok {
			break
		}
		node = next

		// Check for suffix match at this level
		if node.suffixRule != nil {
			if bestIndex == -1 || node.suffixIndex < bestIndex {
				bestRule = node.suffixRule
				bestIndex = node.suffixIndex
			}
		}
	}

	// Check for exact match at the final level
	if node != nil && node.exactRule != nil {
		if bestIndex == -1 || node.exactIndex < bestIndex {
			bestRule = node.exactRule
			bestIndex = node.exactIndex
		}
	}

	return bestRule, bestIndex
}
