package customsecrets

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"testing"

	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
)

func TestSecretWriteEventsRedactRecordMaterial(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx := context.Background()

	store, vault := newMemoryStore(t)
	record := Record{Placeholder: "rheic-placeholder-canary-9f3c", Value: "synthetic-value-canary-4e77"}
	if err := store.Save(ctx, "api.example.test", servicesecrets.ScopeGlobal, "", record); err != nil {
		t.Fatal(err)
	}
	backend := "secretservice"
	switch runtime.GOOS {
	case "darwin":
		backend = "keychain"
	case "windows":
		backend = "credman"
	}
	got := output.String()
	for _, want := range []string{
		`"event":"rheic.secret.write"`, `"outcome":"ok"`, `"placeholder_issued":true`, `"vault_backend":"` + backend + `"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	for _, canary := range []string{"rheic-placeholder-canary-9f3c", "synthetic-value-canary-4e77"} {
		if strings.Contains(got, canary) {
			t.Fatalf("write event leaked %q: %s", canary, got)
		}
	}

	output.Reset()
	vault.fail = errors.New("backend exploded with synthetic-value-canary-4e77 in its message")
	if err := store.Save(ctx, "api.example.test", servicesecrets.ScopeGlobal, "", record); !errors.Is(err, ErrKeychain) {
		t.Fatalf("err = %v", err)
	}
	got = output.String()
	for _, want := range []string{`"event":"rheic.secret.write"`, `"outcome":"failed"`, `"placeholder_issued":false`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "backend exploded") {
		t.Fatalf("backend error text leaked: %s", got)
	}
}
