package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gyrel/sandboxes-daemon/internal/registrycredentials"
	"github.com/gyrel/sandboxes-daemon/internal/store"
)

func TestAccountUsernameResolution(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, &fakeRuntime{})
	registryStore, err := registrycredentials.NewStore(&mapVault{items: make(map[string]string)})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetRegistryCredentialStore(registryStore)

	if username, err := svc.AccountUsername(ctx, dockerAccountProvider); err != nil || username != "" {
		t.Fatalf("signed-out: %q, %v", username, err)
	}
	// A sandbox-scoped Hub credential is not the signed-in identity.
	if _, err := svc.LoginRegistry(ctx, registrycredentials.Credential{
		Registry: dockerHubRegistry, Username: "sandbox-user", Password: []byte("synthetic"),
		Scope: registrycredentials.ScopeSandbox, SandboxName: "demo",
	}); err != nil {
		t.Fatal(err)
	}
	if username, err := svc.AccountUsername(ctx, dockerAccountProvider); err != nil || username != "" {
		t.Fatalf("sandbox scope must not resolve: %q, %v", username, err)
	}
	if _, err := svc.LoginRegistry(ctx, registrycredentials.Credential{
		Registry: dockerHubRegistry, Username: "hub-user", Password: []byte("synthetic"),
		Scope: registrycredentials.ScopeHostOnly,
	}); err != nil {
		t.Fatal(err)
	}
	if username, err := svc.AccountUsername(ctx, dockerAccountProvider); err != nil || username != "hub-user" {
		t.Fatalf("host scope identity: %q, %v", username, err)
	}
	// Providers without a stored label stay empty.
	if username, err := svc.AccountUsername(ctx, "openai"); err != nil || username != "" {
		t.Fatalf("openai: %q, %v", username, err)
	}
}
