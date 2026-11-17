package oauthsession

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/registrycredentials"
)

type testVault struct {
	values map[string]string
	fail   bool
}

func (v *testVault) Set(_ context.Context, service, account, value string) error {
	if v.fail {
		return errors.New("synthetic-access")
	}
	v.values[service+":"+account] = value
	return nil
}
func (v *testVault) Get(_ context.Context, service, account string) (string, error) {
	value, ok := v.values[service+":"+account]
	if !ok {
		return "", registrycredentials.ErrNotFound
	}
	if v.fail {
		return "", errors.New("synthetic-access")
	}
	return value, nil
}
func (v *testVault) Delete(_ context.Context, service, account string) error {
	if v.fail {
		return errors.New("synthetic-access")
	}
	delete(v.values, service+":"+account)
	return nil
}

func TestVaultSinkIsolationAndRedaction(t *testing.T) {
	vault := &testVault{values: make(map[string]string)}
	a, err := NewVaultSink(vault, "provider-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewVaultSink(vault, "provider-b")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tokens := Tokens{AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh", TokenType: "Bearer", ExpiresIn: 60}
	if err := a.Save(ctx, tokens); err != nil {
		t.Fatal(err)
	}
	got, expiry, err := a.Load(ctx)
	if err != nil || got.AccessToken != tokens.AccessToken || expiry.Before(time.Now()) {
		t.Fatal("stored token unavailable or expired")
	}
	if _, _, err := b.Load(ctx); err == nil {
		t.Fatal("other provider could read token")
	}
	if err := b.Save(ctx, Tokens{AccessToken: "another", TokenType: "Bearer"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Load(ctx); err != nil {
		t.Fatal("other provider was deleted")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", tokens, tokens), "synthetic") {
		t.Fatal("tokens leaked through formatting")
	}
	vault.fail = true
	if err := a.Save(ctx, tokens); err == nil || strings.Contains(err.Error(), "synthetic") {
		t.Fatal("vault error was not redacted")
	}
}

func TestVaultSinkLargeRecordLifecycle(t *testing.T) {
	ctx := context.Background()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "large-provider")
	if err != nil {
		t.Fatal(err)
	}
	first := Tokens{AccessToken: strings.Repeat("a", 9000), RefreshToken: strings.Repeat("r", 3000), TokenType: "Bearer"}
	if err := sink.Save(ctx, first); err != nil {
		t.Fatal(err)
	}
	manifest, ok := parseVaultManifest(vault.values[oauthVaultService+":large-provider"])
	if !ok || manifest.Count < 2 {
		t.Fatal("large record was not split")
	}
	for _, value := range vault.values {
		if len(value) > vaultChunkSize {
			t.Fatal("vault item exceeds supported size")
		}
	}
	got, _, err := sink.Load(ctx)
	if err != nil || got.AccessToken != first.AccessToken {
		t.Fatal("large record did not round trip")
	}
	if has, err := sink.HasRefreshToken(ctx); err != nil || !has {
		t.Fatal("refresh token was not found")
	}
	if err := sink.Save(ctx, Tokens{AccessToken: "short", TokenType: "Bearer"}); err != nil {
		t.Fatal(err)
	}
	if len(vault.values) != 1 {
		t.Fatal("old chunks remain after refresh")
	}
	if err := sink.Delete(ctx); err != nil || len(vault.values) != 0 {
		t.Fatal("provider records remain after delete")
	}
}

func TestVaultSinkMissingChunkFailsClosed(t *testing.T) {
	ctx := context.Background()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "missing-chunk")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Save(ctx, Tokens{AccessToken: strings.Repeat("a", 5000), TokenType: "Bearer"}); err != nil {
		t.Fatal(err)
	}
	m, _ := parseVaultManifest(vault.values[oauthVaultService+":missing-chunk"])
	delete(vault.values, oauthVaultService+":"+sink.chunkAccount(m, 0))
	if _, _, err := sink.Load(ctx); err == nil {
		t.Fatal("missing chunk was accepted")
	}
	if has, err := sink.HasTokens(ctx); err == nil || has {
		t.Fatal("incomplete credential was reported present")
	}
}
