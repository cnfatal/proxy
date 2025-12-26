package rules

import (
	"net"
)

type ipNode struct {
	children [2]*ipNode
	rule     *Rule
	index    int
}

type IPTree struct {
	root *ipNode
}

func NewIPTree() *IPTree {
	return &IPTree{
		root: &ipNode{index: -1},
	}
}

func (t *IPTree) Insert(network *net.IPNet, rule *Rule, index int) {
	if network == nil {
		return
	}

	ones, _ := network.Mask.Size()
	ip := network.IP.To4()
	isIPv6 := false
	if ip == nil {
		ip = network.IP.To16()
		isIPv6 = true
	}

	node := t.root
	for i := 0; i < ones; i++ {
		bit := getBit(ip, i, isIPv6)
		if node.children[bit] == nil {
			node.children[bit] = &ipNode{index: -1}
		}
		node = node.children[bit]
	}

	if node.rule == nil || index < node.index {
		node.rule = rule
		node.index = index
	}
}

func (t *IPTree) Search(ip net.IP) (*Rule, int) {
	if ip == nil {
		return nil, -1
	}

	ip4 := ip.To4()
	isIPv6 := false
	bits := 32
	if ip4 == nil {
		ip4 = ip.To16()
		isIPv6 = true
		bits = 128
	}

	node := t.root
	var bestRule *Rule
	bestIndex := -1

	for i := 0; i < bits; i++ {
		if node.rule != nil {
			if bestIndex == -1 || node.index < bestIndex {
				bestRule = node.rule
				bestIndex = node.index
			}
		}

		bit := getBit(ip4, i, isIPv6)
		if node.children[bit] == nil {
			break
		}
		node = node.children[bit]
	}

	// Check the last node
	if node.rule != nil {
		if bestIndex == -1 || node.index < bestIndex {
			bestRule = node.rule
			bestIndex = node.index
		}
	}

	return bestRule, bestIndex
}

func getBit(ip []byte, bitIdx int, isIPv6 bool) int {
	byteIdx := bitIdx / 8
	shift := 7 - (bitIdx % 8)
	return int((ip[byteIdx] >> shift) & 1)
}
