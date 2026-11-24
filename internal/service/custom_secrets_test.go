package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/rheic/sandboxes-core"

	"github.com/rheic/sandboxes-daemon/internal/customsecrets"
	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

type customMemoryVault struct{ items map[string]string }

func (v *customMemoryVault) Set(_ context.Context, service, account, secret string) error {
	if v.items == nil {
		v.items = make(map[string]string)
	}
	v.items[service+"/"+account] = secret
	return nil
}

func (v *customMemoryVault) Get(_ context.Context, service, account string) (string, error) {
	value, ok := v.items[service+"/"+account]
	if !ok {
		return "", servicesecrets.ErrNotFound
	}
	return value, nil
}

func (v *customMemoryVault) Delete(_ context.Context, service, account string) error {
	if _, ok := v.items[service+"/"+account]; !ok {
		return servicesecrets.ErrNotFound
	}
	delete(v.items, service+"/"+account)
	return nil
}

func newCustomSecretTestService(t *testing.T) (*Service, *customMemoryVault, string) {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	vault := &customMemoryVault{items: make(map[string]string)}
	customStore, err := customsecrets.NewStore(vault, servicesecrets.ErrNotFound)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(st, nil)
	svc.SetCustomSecretStore(customStore)
	return svc, vault, dbPath
}

// captureLogs routes the default slog logger into a buffer for one test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

// scanFilesFor reports which needles appear in the SQLite database or its WAL
// and shared-memory sidecars. A positive control must be run by the caller.
func scanFilesFor(t *testing.T, dbPath string, needles ...string) []string {
	t.Helper()
	var found []string
	for _, path := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, needle := range needles {
			if bytes.Contains(data, []byte(needle)) {
				found = append(found, filepath.Base(path)+":"+needle)
			}
		}
	}
	return found
}

func (s *Service) resolveForTest(t *testing.T, sandbox, host string) []secretproxy.Substitution {
	t.Helper()
	subs, err := s.resolveCustomSubstitutions(context.Background(), sandbox, host)
	if err != nil {
		t.Fatal(err)
	}
	return subs
}

func placeholdersOf(subs []secretproxy.Substitution) []string {
	out := make([]string, 0, len(subs))
	for _, sub := range subs {
		out = append(out, sub.Placeholder+"="+string(sub.Value))
	}
	return out
}

func TestCustomSecretStoresValueOnlyInKeychainAndMaskedInSQLite(t *testing.T) {
	ctx := context.Background()
	svc, vault, dbPath := newCustomSecretTestService(t)
	const canary = "synthetic-custom-canary-value-7f3a"
	const explicit = "sk-canary-placeholder-9c21"
	summary, placeholder, _, err := svc.SetCustomSecret(ctx, CustomSecretSetRequest{
		Scope: servicesecrets.ScopeGlobal, Value: []byte(canary), Env: "EXAMPLE_KEY", Placeholder: explicit,
		Hosts: []string{"API.example.test", "*.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Service != "api.example.test" || placeholder != explicit || summary.PlaceholderMasked != strings.Repeat("*", 12)+"9c21" {
		t.Fatalf("summary=%+v placeholder=%q", summary, placeholder)
	}
	stored := false
	for _, value := range vault.items {
		stored = stored || strings.Contains(value, canary)
	}
	if !stored {
		t.Fatal("positive control: value was not written to the host keychain")
	}
	if leaks := scanFilesFor(t, dbPath, canary, explicit); len(leaks) != 0 {
		t.Fatalf("secret material persisted in SQLite: %v", leaks)
	}
	if hits := scanFilesFor(t, dbPath, strings.Repeat("*", 12)+"9c21"); len(hits) == 0 {
		t.Fatal("positive control: masked placeholder was not persisted")
	}
	list, err := svc.ListCustomSecrets(ctx)
	if err != nil || len(list) != 1 || list[0].PlaceholderMasked == explicit || list[0].EnvName != "EXAMPLE_KEY" {
		t.Fatalf("list=%+v err=%v", list, err)
	}
}

func TestCustomSecretRejectsUnsafeRequestsWithoutStoringAnything(t *testing.T) {
	ctx := context.Background()
	const value = "synthetic-rejected-value-canary"
	cases := map[string]struct {
		request CustomSecretSetRequest
		want    error
	}{
		"reference source": {
			request: CustomSecretSetRequest{Scope: servicesecrets.ScopeGlobal, Hosts: []string{"api.example.test"},
				Source: &servicesecrets.Source{Reference: "op://vault/item/field"}},
			want: nil,
		},
		"command source": {
			request: CustomSecretSetRequest{Scope: servicesecrets.ScopeGlobal, Hosts: []string{"api.example.test"},
				Source: &servicesecrets.Source{Command: "echo synthetic"}},
			want: nil,
		},
		"url host": {
			request: CustomSecretSetRequest{Value: []byte(value), Hosts: []string{"https://api.example.test"}},
			want:    customsecrets.ErrInvalidHost,
		},
		"bare wildcard": {
			request: CustomSecretSetRequest{Value: []byte(value), Hosts: []string{"*"}},
			want:    customsecrets.ErrInvalidHost,
		},
		"bad env": {
			request: CustomSecretSetRequest{Value: []byte(value), Hosts: []string{"api.example.test"}, Env: "1BAD"},
			want:    customsecrets.ErrInvalidInput,
		},
		"placeholder equals value": {
			request: CustomSecretSetRequest{Value: []byte(value), Hosts: []string{"api.example.test"}, Placeholder: value},
			want:    customsecrets.ErrInvalidPlaceholder,
		},
		"reserved built-in name": {
			request: CustomSecretSetRequest{Service: "openai", Value: []byte(value), Hosts: []string{"api.openai.com"}},
			want:    customsecrets.ErrInvalidInput,
		},
		"sandbox scope without name": {
			request: CustomSecretSetRequest{Scope: servicesecrets.ScopeSandbox, Value: []byte(value), Hosts: []string{"api.example.test"}},
			want:    customsecrets.ErrInvalidInput,
		},
		"NUL in value": {
			request: CustomSecretSetRequest{Value: []byte("bad\x00" + value), Hosts: []string{"api.example.test"}},
			want:    customsecrets.ErrInvalidInput,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			svc, vault, _ := newCustomSecretTestService(t)
			_, _, _, err := svc.SetCustomSecret(ctx, tc.request)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if len(vault.items) != 0 {
				t.Fatalf("keychain written by rejected request: %d items", len(vault.items))
			}
			list, err := svc.ListCustomSecrets(ctx)
			if err != nil || len(list) != 0 {
				t.Fatalf("index written by rejected request: %+v, %v", list, err)
			}
		})
	}
}

func TestCustomSecretSubstitutionBindsExactHostsAndScopes(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newCustomSecretTestService(t)
	mustSet := func(request CustomSecretSetRequest) {
		t.Helper()
		if _, _, _, err := svc.SetCustomSecret(ctx, request); err != nil {
			t.Fatal(err)
		}
	}
	mustSet(CustomSecretSetRequest{Service: "global-key", Scope: servicesecrets.ScopeGlobal, Value: []byte("global-value-canary"),
		Placeholder: "rheic-global-ph-0001", Hosts: []string{"*.example.test"}})
	mustSet(CustomSecretSetRequest{Service: "dev-key", Scope: servicesecrets.ScopeSandbox, SandboxName: "dev", Value: []byte("dev-value-canary"),
		Placeholder: "rheic-dev-ph-0002", Hosts: []string{"api.example.test"}})
	mustSet(CustomSecretSetRequest{Service: "other-key", Scope: servicesecrets.ScopeSandbox, SandboxName: "other", Value: []byte("other-value-canary"),
		Placeholder: "rheic-other-ph-0003", Hosts: []string{"api.example.test"}})

	cases := []struct {
		sandbox, host string
		want          []string
	}{
		{"dev", "api.example.test", []string{"rheic-dev-ph-0002=dev-value-canary", "rheic-global-ph-0001=global-value-canary"}},
		{"dev", "cli.example.test", []string{"rheic-global-ph-0001=global-value-canary"}},
		{"dev", "example.test", nil},
		{"dev", "a.b.example.test", nil},
		{"dev", "api.example.test.evil.test", nil},
		{"other", "api.example.test", []string{"rheic-other-ph-0003=other-value-canary", "rheic-global-ph-0001=global-value-canary"}},
		{"unlisted", "api.example.test", []string{"rheic-global-ph-0001=global-value-canary"}},
	}
	for _, tc := range cases {
		got := placeholdersOf(svc.resolveForTest(t, tc.sandbox, tc.host))
		if !sameStringSet(got, tc.want) {
			t.Errorf("resolve(%s, %s) = %v, want %v", tc.sandbox, tc.host, got, tc.want)
		}
	}
}

func sameStringSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]int, len(got))
	for _, value := range got {
		seen[value]++
	}
	for _, value := range want {
		if seen[value] == 0 {
			return false
		}
		seen[value]--
	}
	return true
}

func TestCustomSecretRemovalInvalidatesFutureSubstitution(t *testing.T) {
	ctx := context.Background()
	svc, vault, _ := newCustomSecretTestService(t)
	if _, _, _, err := svc.SetCustomSecret(ctx, CustomSecretSetRequest{Service: "dev-key", Scope: servicesecrets.ScopeSandbox,
		SandboxName: "dev", Value: []byte("removal-value-canary"), Placeholder: "rheic-removal-ph-1", Hosts: []string{"api.example.test"}}); err != nil {
		t.Fatal(err)
	}
	if got := svc.resolveForTest(t, "dev", "api.example.test"); len(got) != 1 {
		t.Fatalf("positive control before removal: %d bindings", len(got))
	}
	removed, err := svc.RemoveCustomSecret(ctx, "dev-key", servicesecrets.ScopeSandbox, "dev")
	if err != nil || !removed {
		t.Fatalf("remove = %t, %v", removed, err)
	}
	if got := svc.resolveForTest(t, "dev", "api.example.test"); len(got) != 0 {
		t.Fatalf("removed secret still substitutes: %v", placeholdersOf(got))
	}
	if len(vault.items) != 0 {
		t.Fatalf("keychain still holds %d items after removal", len(vault.items))
	}
	again, err := svc.RemoveCustomSecret(ctx, "dev-key", servicesecrets.ScopeSandbox, "dev")
	if err != nil || again {
		t.Fatalf("second remove = %t, %v; want false, nil", again, err)
	}
}

func TestCustomSecretMissingKeychainRecordFailsClosedAtSubstitution(t *testing.T) {
	ctx := context.Background()
	svc, vault, _ := newCustomSecretTestService(t)
	if _, _, _, err := svc.SetCustomSecret(ctx, CustomSecretSetRequest{Service: "orphan-key", Scope: servicesecrets.ScopeGlobal,
		Value: []byte("orphan-value-canary"), Placeholder: "rheic-orphan-ph-1", Hosts: []string{"api.example.test"}}); err != nil {
		t.Fatal(err)
	}
	vault.items = map[string]string{}
	if got := svc.resolveForTest(t, "dev", "api.example.test"); len(got) != 0 {
		t.Fatalf("index row without keychain record substituted: %v", placeholdersOf(got))
	}
}

func TestCustomCreateEnvCarriesPlaceholdersOnlyForApplicableSecrets(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newCustomSecretTestService(t)
	for _, request := range []CustomSecretSetRequest{
		{Service: "global-env", Scope: servicesecrets.ScopeGlobal, Value: []byte("global-env-value-canary"),
			Placeholder: "rheic-global-env-1", Env: "GLOBAL_KEY", Hosts: []string{"api.example.test"}},
		{Service: "dev-env", Scope: servicesecrets.ScopeSandbox, SandboxName: "dev", Value: []byte("dev-env-value-canary"),
			Placeholder: "rheic-dev-env-2", Env: "DEV_KEY", Hosts: []string{"api.dev.example.test"}},
		{Service: "other-env", Scope: servicesecrets.ScopeSandbox, SandboxName: "other", Value: []byte("other-env-value-canary"),
			Placeholder: "rheic-other-env-3", Env: "OTHER_KEY", Hosts: []string{"api.other.example.test"}},
	} {
		if _, _, _, err := svc.SetCustomSecret(ctx, request); err != nil {
			t.Fatal(err)
		}
	}
	env, err := svc.customCreateEnv(ctx, "dev", []string{"PATH=/usr/bin"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PATH=/usr/bin", "DEV_KEY=rheic-dev-env-2", "GLOBAL_KEY=rheic-global-env-1"}
	if !sameStringSet(env, want) {
		t.Fatalf("env = %v, want %v", env, want)
	}
	for _, entry := range env {
		if strings.Contains(entry, "value-canary") {
			t.Fatalf("env carries a value: %q", entry)
		}
	}
	if _, err := svc.customCreateEnv(ctx, "dev", []string{"DEV_KEY=user-value"}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("env collision err = %v, want ErrConflict", err)
	}
}

func TestCustomSecretSandboxCleanupRemovesOnlyOwnedEntries(t *testing.T) {
	ctx := context.Background()
	svc, vault, _ := newCustomSecretTestService(t)
	for _, request := range []CustomSecretSetRequest{
		{Service: "global-clean", Scope: servicesecrets.ScopeGlobal, Value: []byte("global-clean-value"), Placeholder: "rheic-global-clean-1", Hosts: []string{"api.example.test"}},
		{Service: "dev-clean", Scope: servicesecrets.ScopeSandbox, SandboxName: "dev", Value: []byte("dev-clean-value"), Placeholder: "rheic-dev-clean-2", Hosts: []string{"api.example.test"}},
		{Service: "other-clean", Scope: servicesecrets.ScopeSandbox, SandboxName: "other", Value: []byte("other-clean-value"), Placeholder: "rheic-other-clean-3", Hosts: []string{"api.example.test"}},
	} {
		if _, _, _, err := svc.SetCustomSecret(ctx, request); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.cleanupSandboxCustomSecrets(ctx, "dev"); err != nil {
		t.Fatal(err)
	}
	list, err := svc.ListCustomSecrets(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("after cleanup list=%+v err=%v", list, err)
	}
	for _, summary := range list {
		if summary.Service == "dev-clean" {
			t.Fatal("sandbox-scoped secret survived its sandbox")
		}
	}
	if len(vault.items) != 2 {
		t.Fatalf("keychain items after cleanup = %d, want 2", len(vault.items))
	}
}

func TestCustomSecretLargeValueIsChunkedAndSubstitutable(t *testing.T) {
	ctx := context.Background()
	svc, vault, _ := newCustomSecretTestService(t)
	large := strings.Repeat("L", 6000)
	if _, _, _, err := svc.SetCustomSecret(ctx, CustomSecretSetRequest{Service: "large-key", Scope: servicesecrets.ScopeGlobal,
		Value: []byte(large), Placeholder: "rheic-large-ph-1", Hosts: []string{"api.example.test"}}); err != nil {
		t.Fatal(err)
	}
	if len(vault.items) < 3 {
		t.Fatalf("large custom secret used %d keychain items; want chunks", len(vault.items))
	}
	got := svc.resolveForTest(t, "dev", "api.example.test")
	if len(got) != 1 || string(got[0].Value) != large {
		t.Fatalf("chunked substitution mismatch: %d bindings", len(got))
	}
}

func TestCustomSecretLogsAndErrorsNeverCarryValuesOrPlaceholders(t *testing.T) {
	ctx := context.Background()
	logs := captureLogs(t)
	svc, _, _ := newCustomSecretTestService(t)
	const canary = "synthetic-log-canary-value-42"
	_, placeholder, _, err := svc.SetCustomSecret(ctx, CustomSecretSetRequest{Service: "log-key", Scope: servicesecrets.ScopeGlobal,
		Value: []byte(canary), Hosts: []string{"api.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RemoveCustomSecret(ctx, "log-key", servicesecrets.ScopeGlobal, ""); err != nil {
		t.Fatal(err)
	}
	//nolint:dogsled // placeholder unused on the rejected path
	_, _, _, err = svc.SetCustomSecret(ctx, CustomSecretSetRequest{Value: []byte(canary), Hosts: []string{"https://" + canary + ".test"}})
	if err == nil {
		t.Fatal("invalid host accepted")
	}
	output := logs.String()
	if !strings.Contains(output, "custom secret stored") || !strings.Contains(output, "custom secret removed") {
		t.Fatalf("positive control: audit events missing: %s", output)
	}
	for _, needle := range []string{canary, placeholder} {
		if strings.Contains(output, needle) || strings.Contains(err.Error(), needle) {
			t.Fatalf("log or error leaked %q", needle)
		}
	}
}

func TestCustomSecretRotationKeepsPlaceholderUnlessReplaced(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newCustomSecretTestService(t)
	request := CustomSecretSetRequest{Service: "rotate-key", Scope: servicesecrets.ScopeGlobal, Env: "ROTATE_KEY",
		Value: []byte("rotation-value-one"), Hosts: []string{"api.example.test"}}
	_, first, _, err := svc.SetCustomSecret(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	request.Value = []byte("rotation-value-two")
	_, second, _, err := svc.SetCustomSecret(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("rotation without a placeholder changed it: %q -> %q", first, second)
	}
	if got := svc.resolveForTest(t, "dev", "api.example.test"); len(got) != 1 || string(got[0].Value) != "rotation-value-two" || got[0].Placeholder != first {
		t.Fatalf("rotated binding = %v", placeholdersOf(got))
	}
	request.Placeholder = "rheic-explicit-after-rotation"
	request.Value = []byte("rotation-value-three")
	_, third, _, err := svc.SetCustomSecret(ctx, request)
	if err != nil || third != request.Placeholder {
		t.Fatalf("explicit placeholder = %q, %v", third, err)
	}
	list, err := svc.ListCustomSecrets(ctx)
	if err != nil || len(list) != 1 || list[0].PlaceholderMasked != strings.Repeat("*", 12)+"tion" {
		t.Fatalf("list after explicit rotation = %+v, %v", list, err)
	}
}
