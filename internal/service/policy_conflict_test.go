package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	core "github.com/gyrel/sandboxes-core"
	"github.com/gyrel/sandboxes-core/sandbox"

	"github.com/gyrel/sandboxes-daemon/internal/store"
)

func newPolicyConflictService(t *testing.T) (*Service, string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, nil)
	op, err := svc.Create(ctx, CreateRequest{Name: "policy-conflict"})
	if err != nil {
		t.Fatal(err)
	}
	return svc, op.SandboxID
}

func TestPolicyOppositeActionConflictMatrix(t *testing.T) {
	for _, scope := range []string{"global", "sandbox"} {
		for _, first := range []string{"allow", "deny"} {
			t.Run(scope+"/"+first, func(t *testing.T) {
				ctx := context.Background()
				svc, id := newPolicyConflictService(t)
				mutate := func(action string, rule sandbox.NetworkRule) error {
					if scope == "global" {
						_, _, err := svc.MutateGlobalPolicy(ctx, action, rule)
						return err
					}
					_, err := svc.MutatePolicy(ctx, id, action, rule)
					return err
				}
				rule := sandbox.NetworkRule{Protocol: "tcp", Domain: "example.test", Port: 443}
				equivalent := sandbox.NetworkRule{Domain: "EXAMPLE.TEST.", Port: 443}
				if err := mutate(first, rule); err != nil {
					t.Fatal(err)
				}
				opposite := policyActionDeny
				if first == policyActionDeny {
					opposite = policyActionAllow
				}
				err := mutate(opposite, equivalent)
				if !errors.Is(err, core.ErrConflict) {
					t.Fatalf("opposite mutation: %v", err)
				}
				var conflict *PolicyConflictError
				if !errors.As(err, &conflict) {
					t.Fatalf("error %T is not *PolicyConflictError", err)
				}
				for _, want := range []string{"rul_", "example.test", scope} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("conflict error %q does not name %q", err, want)
					}
				}
				if conflict.ExistingAction == conflict.IncomingAction {
					t.Fatalf("conflict did not name opposite actions: %+v", conflict)
				}
				if err := mutate(first, rule); !errors.Is(err, core.ErrConflict) {
					t.Fatalf("original rule missing after rejection: %v", err)
				}
				distinct := sandbox.NetworkRule{Protocol: "tcp", Domain: "other.example.test", Port: 443}
				if err := mutate(opposite, distinct); err != nil {
					t.Fatalf("distinct rule: %v", err)
				}
				if err := mutate("rm", rule); err != nil {
					t.Fatalf("remove original: %v", err)
				}
				if err := mutate(opposite, rule); err != nil {
					t.Fatalf("opposite after removal: %v", err)
				}
			})
		}
	}
}

func TestPolicyConflictCanonicalizesCIDRHostBits(t *testing.T) {
	ctx := context.Background()
	svc, _ := newPolicyConflictService(t)
	if _, _, err := svc.MutateGlobalPolicy(ctx, policyActionAllow, sandbox.NetworkRule{Protocol: "tcp", CIDR: "192.0.2.5/24", Port: 443}); err != nil {
		t.Fatal(err)
	}
	_, _, err := svc.MutateGlobalPolicy(ctx, policyActionDeny, sandbox.NetworkRule{Protocol: "tcp", CIDR: "192.0.2.0/24", Port: 443})
	if !errors.Is(err, core.ErrConflict) {
		t.Fatalf("unmasked CIDR selector did not conflict: %v", err)
	}
}

func TestPolicyConflictMatrixDistinctSelectorsCompose(t *testing.T) {
	tests := []struct {
		name string
		a    sandbox.NetworkRule
		b    sandbox.NetworkRule
	}{
		{"different domain", sandbox.NetworkRule{Protocol: "tcp", Domain: "a.example.test", Port: 443}, sandbox.NetworkRule{Protocol: "tcp", Domain: "b.example.test", Port: 443}},
		{"different port", sandbox.NetworkRule{Protocol: "tcp", Domain: "a.example.test", Port: 443}, sandbox.NetworkRule{Protocol: "tcp", Domain: "a.example.test", Port: 8443}},
		{"different protocol", sandbox.NetworkRule{Protocol: "tcp", Domain: "a.example.test", Port: 443}, sandbox.NetworkRule{Protocol: "udp", Domain: "a.example.test", Port: 443}},
		{"different CIDR", sandbox.NetworkRule{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}, sandbox.NetworkRule{Protocol: "tcp", CIDR: "10.9.0.0/16", Port: 443}},
		{"unmasked CIDR is a different selector key", sandbox.NetworkRule{Protocol: "tcp", CIDR: "192.0.2.0/24", Port: 443}, sandbox.NetworkRule{Protocol: "tcp", CIDR: "192.0.3.0/24", Port: 443}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			svc, id := newPolicyConflictService(t)
			if _, _, err := svc.MutateGlobalPolicy(ctx, policyActionAllow, tt.a); err != nil {
				t.Fatal(err)
			}
			if _, _, err := svc.MutateGlobalPolicy(ctx, policyActionDeny, tt.b); err != nil {
				t.Fatalf("distinct selector denied: %v", err)
			}
			if _, err := svc.MutatePolicy(ctx, id, policyActionAllow, tt.a); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.MutatePolicy(ctx, id, policyActionDeny, tt.b); err != nil {
				t.Fatalf("distinct sandbox selector denied: %v", err)
			}
		})
	}
}

func TestPolicyOppositeActionsInDifferentScopesCompose(t *testing.T) {
	ctx := context.Background()
	svc, id := newPolicyConflictService(t)
	rule := sandbox.NetworkRule{Protocol: "tcp", Domain: "allow.example.test", Port: 443}
	if _, _, err := svc.MutateGlobalPolicy(ctx, policyActionAllow, rule); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MutatePolicy(ctx, id, policyActionDeny, rule); err != nil {
		t.Fatalf("sandbox deny over global allow: %v", err)
	}
	other := sandbox.NetworkRule{Protocol: "tcp", Domain: "deny.example.test", Port: 443}
	if _, _, err := svc.MutateGlobalPolicy(ctx, policyActionDeny, other); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MutatePolicy(ctx, id, policyActionAllow, other); err != nil {
		t.Fatalf("sandbox allow over global deny: %v", err)
	}
}

func TestConcurrentOppositePolicyMutations(t *testing.T) {
	for _, scope := range []string{"global", "sandbox"} {
		t.Run(scope, func(t *testing.T) {
			ctx := context.Background()
			svc, id := newPolicyConflictService(t)
			rule := sandbox.NetworkRule{Protocol: "tcp", Domain: "example.test", Port: 443}
			results := make(chan error, 2)
			var wg sync.WaitGroup
			for _, action := range []string{policyActionAllow, policyActionDeny} {
				wg.Go(func() {
					if scope == "global" {
						_, _, err := svc.MutateGlobalPolicy(ctx, action, rule)
						results <- err
						return
					}
					_, err := svc.MutatePolicy(ctx, id, action, rule)
					results <- err
				})
			}
			wg.Wait()
			close(results)
			success, conflicts := 0, 0
			for err := range results {
				switch {
				case err == nil:
					success++
				case errors.Is(err, core.ErrConflict):
					conflicts++
				default:
					t.Fatal(err)
				}
			}
			if success != 1 || conflicts != 1 {
				t.Fatalf("success=%d conflicts=%d", success, conflicts)
			}
		})
	}
}
