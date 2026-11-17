package service

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/rheic/sandboxes-core/sandbox"

	"github.com/rheic/sandboxes-daemon/internal/store"
)

func TestOAuthProxyAddressPolicyDenyWins(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "oauth-policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	op, err := svc.Create(ctx, CreateRequest{Name: "oauth-policy"})
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr("8.8.8.8")
	check := svc.proxyAddressAuthorizer(op.SandboxID, "chatgpt.com")
	allowed, err := check(ctx, address)
	if err != nil || !allowed {
		t.Fatalf("default allow: %v %v", allowed, err)
	}
	_, err = svc.MutatePolicy(ctx, op.SandboxID, "deny", sandbox.NetworkRule{Protocol: "tcp", Domain: "chatgpt.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	allowed, err = check(ctx, address)
	if err != nil || allowed {
		t.Fatalf("domain deny: %v %v", allowed, err)
	}
}
