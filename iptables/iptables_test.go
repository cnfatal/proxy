package iptables

import (
	"bytes"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestDestinationCIDRExprsIPv4(t *testing.T) {
	exprs, err := destinationCIDRExprs("172.16.0.0/12")
	if err != nil {
		t.Fatalf("destinationCIDRExprs failed: %v", err)
	}
	if len(exprs) != 5 {
		t.Fatalf("expected 5 expressions, got %d", len(exprs))
	}

	familyCmp, ok := exprs[1].(*expr.Cmp)
	if !ok {
		t.Fatalf("expected family cmp, got %T", exprs[1])
	}
	if !bytes.Equal(familyCmp.Data, []byte{byte(nftables.TableFamilyIPv4)}) {
		t.Fatalf("unexpected family data: %v", familyCmp.Data)
	}

	payload, ok := exprs[2].(*expr.Payload)
	if !ok {
		t.Fatalf("expected payload, got %T", exprs[2])
	}
	if payload.Offset != 16 || payload.Len != 4 {
		t.Fatalf("unexpected ipv4 payload offset/len: %d/%d", payload.Offset, payload.Len)
	}

	bitwise, ok := exprs[3].(*expr.Bitwise)
	if !ok {
		t.Fatalf("expected bitwise, got %T", exprs[3])
	}
	if !bytes.Equal(bitwise.Mask, []byte{0xff, 0xf0, 0x00, 0x00}) {
		t.Fatalf("unexpected ipv4 mask: %v", bitwise.Mask)
	}

	addrCmp, ok := exprs[4].(*expr.Cmp)
	if !ok {
		t.Fatalf("expected address cmp, got %T", exprs[4])
	}
	if !bytes.Equal(addrCmp.Data, []byte{172, 16, 0, 0}) {
		t.Fatalf("unexpected ipv4 address: %v", addrCmp.Data)
	}
}

func TestDestinationCIDRExprsIPv6(t *testing.T) {
	exprs, err := destinationCIDRExprs("fc00::/7")
	if err != nil {
		t.Fatalf("destinationCIDRExprs failed: %v", err)
	}
	if len(exprs) != 5 {
		t.Fatalf("expected 5 expressions, got %d", len(exprs))
	}

	familyCmp, ok := exprs[1].(*expr.Cmp)
	if !ok {
		t.Fatalf("expected family cmp, got %T", exprs[1])
	}
	if !bytes.Equal(familyCmp.Data, []byte{byte(nftables.TableFamilyIPv6)}) {
		t.Fatalf("unexpected family data: %v", familyCmp.Data)
	}

	payload, ok := exprs[2].(*expr.Payload)
	if !ok {
		t.Fatalf("expected payload, got %T", exprs[2])
	}
	if payload.Offset != 24 || payload.Len != 16 {
		t.Fatalf("unexpected ipv6 payload offset/len: %d/%d", payload.Offset, payload.Len)
	}

	bitwise, ok := exprs[3].(*expr.Bitwise)
	if !ok {
		t.Fatalf("expected bitwise, got %T", exprs[3])
	}
	wantMask := []byte{0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(bitwise.Mask, wantMask) {
		t.Fatalf("unexpected ipv6 mask: %v", bitwise.Mask)
	}

	addrCmp, ok := exprs[4].(*expr.Cmp)
	if !ok {
		t.Fatalf("expected address cmp, got %T", exprs[4])
	}
	wantAddr := []byte{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(addrCmp.Data, wantAddr) {
		t.Fatalf("unexpected ipv6 address: %v", addrCmp.Data)
	}
}
