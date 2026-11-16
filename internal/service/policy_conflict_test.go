package service

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

// Opposite actions for the same normalized rule must not silently coexist.
// The failed mutation must leave the earlier rule in place and allow removal.
func TestPolicyOppositeActionConflict(t *testing.T) {
	for _, scope := range []string{"global", "sandbox"} {
		for _, first := range []string{"allow", "deny"} {
			t.Run(scope+"/"+first, func(t *testing.T) {
				ctx := context.Background()
				st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = st.Close() }()
				svc := New(st, nil)
				var id string
				if scope == "sandbox" {
					op, err := svc.Create(ctx, CreateRequest{Name: "policy-conflict"})
					if err != nil {
						t.Fatal(err)
					}
					id = op.SandboxID
				}
				mutate := func(action string, r sandbox.NetworkRule) error {
					if scope == "global" {
						_, _, err := svc.MutateGlobalPolicy(ctx, action, r)
						return err
					}
					_, err := svc.MutatePolicy(ctx, id, action, r)
					return err
				}
				rule := sandbox.NetworkRule{Protocol: "tcp", Domain: "example.test", Port: 443}
				equivalent := sandbox.NetworkRule{Domain: "EXAMPLE.TEST", Port: 443}
				if err := mutate(first, rule); err != nil {
					t.Fatal(err)
				}
				opposite := "deny"
				if first == "deny" {
					opposite = "allow"
				}
				if err := mutate(opposite, equivalent); !errors.Is(err, core.ErrConflict) {
					t.Fatalf("opposite mutation: %v", err)
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

func TestConcurrentOppositePolicyMutations(t *testing.T) {
	for _, scope := range []string{"global", "sandbox"} {
		t.Run(scope, func(t *testing.T) {
			ctx := context.Background()
			st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			svc := New(st, nil)
			var id string
			if scope == "sandbox" {
				op, err := svc.Create(ctx, CreateRequest{Name: "concurrent-conflict"})
				if err != nil {
					t.Fatal(err)
				}
				id = op.SandboxID
			}
			rule := sandbox.NetworkRule{Protocol: "tcp", Domain: "example.test", Port: 443}
			results := make(chan error, 2)
			var wg sync.WaitGroup
			for _, action := range []string{"allow", "deny"} {
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

// Policy scopes are independent: a sandbox may override a global rule.
func TestPolicyOppositeActionsInDifferentScopes(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	op, err := svc.Create(ctx, CreateRequest{Name: "separate-policy-scopes"})
	if err != nil {
		t.Fatal(err)
	}
	allow := sandbox.NetworkRule{Protocol: "tcp", Domain: "allow.example.test", Port: 443}
	deny := sandbox.NetworkRule{Protocol: "tcp", Domain: "deny.example.test", Port: 443}
	if _, _, err := svc.MutateGlobalPolicy(ctx, "allow", allow); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "deny", allow); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.MutateGlobalPolicy(ctx, "deny", deny); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "allow", deny); err != nil {
		t.Fatal(err)
	}
}
