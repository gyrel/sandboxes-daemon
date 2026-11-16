package service

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/rheic/sandboxes-core/sandbox"

	"github.com/rheic/sandboxes-daemon/internal/store"
)

func TestResolvedRegistryEgressMatchesCustomPort(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "registry-port-policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	op, err := svc.Create(ctx, CreateRequest{Name: "registry-port-policy", PolicyProfile: policyProfileDenyAll})
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr("192.0.2.10")
	if decision, err := svc.checkResolvedEgress(ctx, op.SandboxID, "registry.example.test", address, 5000); err != nil || decision.Allowed {
		t.Fatalf("default-deny custom port decision=%+v err=%v", decision, err)
	}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "allow", sandbox.NetworkRule{
		Protocol: "tcp", Domain: "registry.example.test", Port: 5000,
	}); err != nil {
		t.Fatal(err)
	}
	decision, err := svc.checkResolvedEgress(ctx, op.SandboxID, "registry.example.test", address, 5000)
	if err != nil || !decision.Allowed {
		t.Fatalf("custom-port allow decision=%+v err=%v", decision, err)
	}
	decision, err = svc.checkResolvedEgress(ctx, op.SandboxID, "registry.example.test", address, 443)
	if err != nil || decision.Allowed {
		t.Fatalf("port 443 reused custom-port allow decision=%+v err=%v", decision, err)
	}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "deny", sandbox.NetworkRule{
		Protocol: "tcp", Domain: "registry.example.test", Port: 5000,
	}); err == nil {
		t.Fatal("opposite-action deny was accepted next to the allow")
	}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "rm", sandbox.NetworkRule{
		Protocol: "tcp", Domain: "registry.example.test", Port: 5000,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "deny", sandbox.NetworkRule{
		Protocol: "tcp", Domain: "registry.example.test", Port: 5000,
	}); err != nil {
		t.Fatal(err)
	}
	decision, err = svc.checkResolvedEgress(ctx, op.SandboxID, "registry.example.test", address, 5000)
	if err != nil || decision.Allowed {
		t.Fatalf("custom-port deny decision=%+v err=%v", decision, err)
	}
}

func TestPrivateRegistryPrefixesUseConfiguredPortForPolicy(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "private-registry-port-policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	op, err := svc.Create(ctx, CreateRequest{Name: "private-registry-port-policy", PolicyProfile: policyProfileDenyAll})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "allow", sandbox.NetworkRule{
		Protocol: "tcp", CIDR: "192.0.2.10/32", Port: 5000,
	}); err != nil {
		t.Fatal(err)
	}
	factory := privateRegistryTransportFactory{service: svc, sandboxID: op.SandboxID}
	prefixes, err := factory.prefixes(ctx, "192.0.2.10:5000")
	if err != nil || len(prefixes) != 1 || prefixes[0].Addr() != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("custom-port private registry prefixes=%v err=%v", prefixes, err)
	}
	if _, err := factory.prefixes(ctx, "192.0.2.10:443"); err == nil {
		t.Fatal("private registry egress reused the port-5000 rule for port 443")
	}
}
