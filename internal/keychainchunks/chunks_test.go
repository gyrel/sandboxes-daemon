package keychainchunks

import (
	"context"
	"errors"
	"strings"
	"testing"
)

var errMissing = errors.New("synthetic missing item")

type fakeVault struct {
	values map[string]string
}

func (v *fakeVault) Set(_ context.Context, service, account, secret string) error {
	v.values[service+"/"+account] = secret
	return nil
}

func (v *fakeVault) Get(_ context.Context, service, account string) (string, error) {
	value, ok := v.values[service+"/"+account]
	if !ok {
		return "", errMissing
	}
	return value, nil
}

func (v *fakeVault) Delete(_ context.Context, service, account string) error {
	if _, ok := v.values[service+"/"+account]; !ok {
		return errMissing
	}
	delete(v.values, service+"/"+account)
	return nil
}

func newTestStore() (Store, *fakeVault) {
	vault := &fakeVault{values: make(map[string]string)}
	return Store{Vault: vault, Service: "test.service", NotFound: errMissing}, vault
}

func payloadOf(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte('a' + i%26)
	}
	return out
}

func TestInlineRecordRoundTripAndDelete(t *testing.T) {
	ctx := context.Background()
	store, vault := newTestStore()
	if err := store.Save(ctx, "acct", []byte(`{"value":"synthetic"}`)); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(ctx, "acct")
	if err != nil || got != `{"value":"synthetic"}` {
		t.Fatalf("inline load = %q, %v", got, err)
	}
	if len(vault.values) != 1 {
		t.Fatalf("inline record used %d items", len(vault.values))
	}
	if err := store.Delete(ctx, "acct"); err != nil || len(vault.values) != 0 {
		t.Fatalf("delete err=%v items=%d", err, len(vault.values))
	}
}

func TestLargeRecordIsChunkedAndReplacedWithoutLeaks(t *testing.T) {
	ctx := context.Background()
	store, vault := newTestStore()
	first := payloadOf(4097 + 10)
	if err := store.Save(ctx, "acct", first); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Load(ctx, "acct"); err != nil || got != string(first) {
		t.Fatalf("chunked load mismatch: err=%v", err)
	}
	// One manifest plus three chunks: 4107 bytes need ceil(4107/1800) = 3 items.
	if len(vault.values) != 4 {
		t.Fatalf("chunked record used %d items, want 4", len(vault.values))
	}
	second := payloadOf(5000)
	if err := store.Save(ctx, "acct", second); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Load(ctx, "acct"); err != nil || got != string(second) {
		t.Fatalf("replaced load mismatch: err=%v", err)
	}
	if len(vault.values) != 4 {
		t.Fatalf("replacement left %d items, want 4", len(vault.values))
	}
	if err := store.Delete(ctx, "acct"); err != nil || len(vault.values) != 0 {
		t.Fatalf("delete err=%v items=%d", err, len(vault.values))
	}
}

func TestLoadRejectsTamperedAndIncompleteChunks(t *testing.T) {
	ctx := context.Background()
	store, vault := newTestStore()
	if err := store.Save(ctx, "acct", payloadOf(4000)); err != nil {
		t.Fatal(err)
	}
	manifest, ok := ParseManifest(vault.values["test.service/acct"])
	if !ok {
		t.Fatal("manifest not committed")
	}
	chunkKey := "test.service/" + ChunkAccount("acct", manifest, 1)
	original := vault.values[chunkKey]

	vault.values[chunkKey] = strings.Repeat("x", len(original))
	if _, err := store.Load(ctx, "acct"); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("digest mismatch accepted: %v", err)
	}
	delete(vault.values, chunkKey)
	if _, err := store.Load(ctx, "acct"); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("missing chunk accepted: %v", err)
	}
}

func TestSaveRejectsOversizedAndManifestLookalikePayloads(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore()
	if err := store.Save(ctx, "acct", payloadOf(MaxChunks*ChunkSize+1)); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("oversized record err = %v", err)
	}
	if err := store.Save(ctx, "acct", []byte(Prefix+"{}")); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("manifest-looking payload err = %v", err)
	}
}

func TestMissingRecordReturnsVaultNotFound(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore()
	if _, err := store.Load(ctx, "absent"); !errors.Is(err, errMissing) {
		t.Fatalf("load err = %v", err)
	}
	if err := store.Delete(ctx, "absent"); !errors.Is(err, errMissing) {
		t.Fatalf("delete err = %v", err)
	}
}
