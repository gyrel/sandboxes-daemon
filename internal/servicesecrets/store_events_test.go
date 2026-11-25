package servicesecrets

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"testing"

	"github.com/rheic/sandboxes-core/ids"
)

type failingBackend struct{ err error }

func (f *failingBackend) Set(_, _, _ string) error        { return f.err }
func (f *failingBackend) Get(_, _ string) (string, error) { return "", f.err }
func (f *failingBackend) Delete(_, _ string) error        { return f.err }

func wantBackendName() string {
	switch runtime.GOOS {
	case "darwin":
		return "keychain"
	case "windows":
		return "credman"
	default:
		return "secretservice"
	}
}

func TestSecretWriteEventsRedactValues(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx := ids.WithReqID(ids.WithOpID(context.Background(), ids.NewOpID()), ids.NewReqID())
	op, req := ids.FromContext(ctx)

	store, err := NewStore(NativeVault{Backend: &fakeBackend{items: make(map[string]string)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(ctx, "openai", ScopeSandbox, "dev", []byte("sk-synthetic-value-canary")); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{
		`"event":"rheic.secret.write"`, `"outcome":"ok"`, `"placeholder_issued":false`,
		`"vault_backend":"` + wantBackendName() + `"`, op, req,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	for _, canary := range []string{"sk-synthetic-value-canary", "openai", "dev"} {
		if strings.Contains(got, canary) {
			t.Fatalf("write event leaked %q: %s", canary, got)
		}
	}

	output.Reset()
	failing, err := NewStore(NativeVault{Backend: &failingBackend{err: errors.New("keychain exploded with sk-another-canary")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.Save(ctx, "github", ScopeGlobal, "", []byte("value")); err == nil {
		t.Fatal("failing backend accepted the write")
	}
	got = output.String()
	for _, want := range []string{`"event":"rheic.secret.write"`, `"outcome":"failed"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "keychain exploded") {
		t.Fatalf("backend error text leaked: %s", got)
	}
}

func TestSecretWriteEventOnSourceSave(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx := context.Background()
	store, err := NewStore(NativeVault{Backend: &fakeBackend{items: make(map[string]string)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveSource(ctx, "github", ScopeGlobal, "", Source{
		Reference: "op://vault/synthetic-reference-canary/field", NoVerify: true,
	}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, `"event":"rheic.secret.write"`) || !strings.Contains(got, `"outcome":"ok"`) {
		t.Fatalf("source write not recorded: %s", got)
	}
	if strings.Contains(got, "synthetic-reference-canary") {
		t.Fatalf("source reference leaked: %s", got)
	}
}
