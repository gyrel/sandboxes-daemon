package customsecrets

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
)

var errSyntheticNotFound = errors.New("synthetic not found")

type memoryVault struct {
	values map[string]string
	fail   error
}

func (v *memoryVault) Set(ctx context.Context, service, account, secret string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.fail != nil {
		return v.fail
	}
	v.values[service+"|"+account] = secret
	return nil
}

func (v *memoryVault) Get(ctx context.Context, service, account string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if v.fail != nil {
		return "", v.fail
	}
	value, ok := v.values[service+"|"+account]
	if !ok {
		return "", errSyntheticNotFound
	}
	return value, nil
}

func (v *memoryVault) Delete(ctx context.Context, service, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.fail != nil {
		return v.fail
	}
	if _, ok := v.values[service+"|"+account]; !ok {
		return errSyntheticNotFound
	}
	delete(v.values, service+"|"+account)
	return nil
}

func newMemoryStore(t *testing.T) (*Store, *memoryVault) {
	t.Helper()
	vault := &memoryVault{values: make(map[string]string)}
	store, err := NewStore(vault, errSyntheticNotFound)
	if err != nil {
		t.Fatal(err)
	}
	return store, vault
}

func TestStoreRoundTripScopesAndRemoval(t *testing.T) {
	ctx := context.Background()
	store, _ := newMemoryStore(t)
	record := Record{Placeholder: "rheic-placeholder-1234", Value: "synthetic-secret-value-do-not-print"}
	if err := store.Save(ctx, "api.example.test", servicesecrets.ScopeGlobal, "", record); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(ctx, "api.example.test", servicesecrets.ScopeGlobal, "")
	if err != nil || got != record {
		t.Fatalf("global load = %+v, %v", got, err)
	}
	if _, err := store.Load(ctx, "api.example.test", servicesecrets.ScopeSandbox, "dev"); !IsNotFound(err) {
		t.Fatalf("global record leaked into sandbox scope: %v", err)
	}
	sandbox := Record{Placeholder: "rheic-placeholder-5678", Value: "synthetic-sandbox-value-1"}
	if err := store.Save(ctx, "api.example.test", servicesecrets.ScopeSandbox, "dev", sandbox); err != nil {
		t.Fatal(err)
	}
	if other, err := store.Load(ctx, "api.example.test", servicesecrets.ScopeSandbox, "other"); !IsNotFound(err) {
		t.Fatalf("sandbox record visible to other sandbox: %+v, %v", other, err)
	}
	if err := store.Delete(ctx, "api.example.test", servicesecrets.ScopeSandbox, "dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, "api.example.test", servicesecrets.ScopeSandbox, "dev"); !IsNotFound(err) {
		t.Fatalf("removed record still loads: %v", err)
	}
	if err := store.Delete(ctx, "api.example.test", servicesecrets.ScopeSandbox, "dev"); !IsNotFound(err) {
		t.Fatalf("second delete err = %v, want ErrNotFound", err)
	}
}

func TestStoreChunksLargeValues(t *testing.T) {
	ctx := context.Background()
	store, vault := newMemoryStore(t)
	value := strings.Repeat("v", 6000)
	if err := store.Save(ctx, "api.example.test", servicesecrets.ScopeGlobal, "", Record{Placeholder: "rheic-large-placeholder", Value: value}); err != nil {
		t.Fatal(err)
	}
	if len(vault.values) < 3 {
		t.Fatalf("large record used %d keychain items; want manifest plus chunks", len(vault.values))
	}
	got, err := store.Load(ctx, "api.example.test", servicesecrets.ScopeGlobal, "")
	if err != nil || got.Value != value {
		t.Fatalf("chunked load mismatch: %v", err)
	}
	if err := store.Delete(ctx, "api.example.test", servicesecrets.ScopeGlobal, ""); err != nil || len(vault.values) != 0 {
		t.Fatalf("chunked delete err=%v items=%d", err, len(vault.values))
	}
}

func TestStoreKeychainFailuresAreGenericAndNeverEchoBackend(t *testing.T) {
	ctx := context.Background()
	store, vault := newMemoryStore(t)
	vault.fail = errors.New("synthetic backend detail account=api.example.test/global")
	err := store.Save(ctx, "api.example.test", servicesecrets.ScopeGlobal, "", Record{Placeholder: "rheic-placeholder", Value: "v"})
	if !errors.Is(err, ErrKeychain) || strings.Contains(err.Error(), "synthetic backend") {
		t.Fatalf("save err = %v, want generic ErrKeychain", err)
	}
	if _, err := store.Load(ctx, "api.example.test", servicesecrets.ScopeGlobal, ""); !errors.Is(err, ErrKeychain) {
		t.Fatalf("load err = %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Save(canceled, "api.example.test", servicesecrets.ScopeGlobal, "", Record{Placeholder: "rheic-placeholder", Value: "v"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled save err = %v", err)
	}
}

func TestStoreRejectsUnusableConstructorAndInputs(t *testing.T) {
	if _, err := NewStore(nil, errSyntheticNotFound); err == nil {
		t.Fatal("nil vault accepted")
	}
	if _, err := NewStore(&memoryVault{values: map[string]string{}}, nil); err == nil {
		t.Fatal("missing not-found sentinel accepted")
	}
	if err := ValidateValue(nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty value err = %v", err)
	}
	if err := ValidateValue([]byte("a\x00b")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NUL value err = %v", err)
	}
	if err := ValidateValue([]byte(strings.Repeat("x", MaxValueBytes+1))); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized value err = %v", err)
	}
	if _, _, err := ValidateScope(servicesecrets.ScopeGlobal, "dev"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("global scope with sandbox err = %v", err)
	}
	if _, _, err := ValidateScope(servicesecrets.ScopeSandbox, "a/b"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("sandbox path separator err = %v", err)
	}
	if err := ValidateEnvName("OPENAI_KEY_2"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"1BAD", "BAD-NAME", "${X}"} {
		if err := ValidateEnvName(name); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("env name %q accepted: %v", name, err)
		}
	}
	if err := ValidateServiceName("Upper"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("uppercase service name accepted: %v", err)
	}
}
