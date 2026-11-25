//go:build !windows

package secretproxy

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestSubstituteDecisionEventsRedactBindings(t *testing.T) {
	logs := captureLogs(t)
	for _, tc := range []struct {
		name     string
		upstream string
		resolve  func(context.Context) ([]Substitution, error)
		want     []string
	}{
		{
			name: "substituted", upstream: "https://api.example.test",
			resolve: func(context.Context) ([]Substitution, error) {
				return []Substitution{{Placeholder: testPlaceholder, Value: []byte(testValue)}}, nil
			},
			want: []string{`"decision":"substituted"`, `"outcome":"ok"`, `"host":"api.example.test"`, `"scheme":"https"`},
		},
		{
			name: "insecure scheme", upstream: "http://127.0.0.1:9",
			resolve: func(context.Context) ([]Substitution, error) {
				return []Substitution{{Placeholder: testPlaceholder, Value: []byte(testValue)}}, nil
			},
			want: []string{`"decision":"refused"`, `"reason":"InsecureScheme"`, `"outcome":"denied"`},
		},
		{
			name: "vault locked", upstream: "https://api.example.test",
			resolve: func(context.Context) ([]Substitution, error) {
				return nil, errors.New("synthetic host keychain failure")
			},
			want: []string{`"decision":"refused"`, `"reason":"VaultLocked"`, `"outcome":"failed"`},
		},
		{
			name: "ref missing", upstream: "https://api.example.test",
			resolve: func(context.Context) ([]Substitution, error) {
				return []Substitution{{Placeholder: "", Value: []byte("one")}}, nil
			},
			want: []string{`"decision":"refused"`, `"reason":"RefMissing"`, `"outcome":"failed"`},
		},
	} {
		logs.Reset()
		fixture := startSubstituteChannel(t, tc.upstream, tc.resolve)
		fixture.send(t, map[string]string{"X-Vendor-Key": testPlaceholder})
		_ = fixture.manager.Close()
		got := logs.String()
		for _, want := range append(tc.want, `"event":"rheic.secret.substitute"`) {
			if !strings.Contains(got, want) {
				t.Fatalf("%s: missing %s in %s", tc.name, want, got)
			}
		}
		for _, canary := range []string{testPlaceholder, testValue} {
			if strings.Contains(got, canary) {
				t.Fatalf("%s: binding leaked %q: %s", tc.name, canary, got)
			}
		}
	}
}

func TestSubstituteEventsAbsentWithoutBindingDecision(t *testing.T) {
	logs := captureLogs(t)
	cases := map[string]func(context.Context) ([]Substitution, error){
		"ambiguous overlap": func(context.Context) ([]Substitution, error) {
			return []Substitution{
				{Placeholder: testPlaceholder, Value: []byte("one")},
				{Placeholder: testPlaceholder[:12], Value: []byte("two")},
			}, nil
		},
		"empty resolver result": func(context.Context) ([]Substitution, error) { return nil, nil },
		"placeholder not used": func(context.Context) ([]Substitution, error) {
			return []Substitution{{Placeholder: "rheic-placeholder-not-sent", Value: []byte("one")}}, nil
		},
	}
	for name, resolve := range cases {
		logs.Reset()
		fixture := startSubstituteChannel(t, "https://api.example.test", resolve)
		fixture.send(t, map[string]string{"X-Vendor-Key": testPlaceholder})
		_ = fixture.manager.Close()
		if strings.Contains(logs.String(), `"event":"rheic.secret.substitute"`) {
			t.Fatalf("%s: unexpected substitution event: %s", name, logs.String())
		}
	}
}

func TestSubstitutePositiveControlRefIsHashed(t *testing.T) {
	logs := captureLogs(t)
	fixture := startSubstituteChannel(t, "https://api.example.test", func(context.Context) ([]Substitution, error) {
		return []Substitution{{Placeholder: testPlaceholder, Value: []byte(testValue)}}, nil
	})
	fixture.send(t, map[string]string{"X-Vendor-Key": testPlaceholder})
	_ = fixture.manager.Close()
	got := logs.String()
	if !strings.Contains(got, `"secret_ref_id":"`) {
		t.Fatalf("substituted event lost its hashed reference: %s", got)
	}
	// The raw placeholder must never appear as the reference value.
	if strings.Contains(got, `"secret_ref_id":"`+testPlaceholder) {
		t.Fatalf("placeholder used directly as reference: %s", got)
	}
}

func (b *lockedBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

func captureLogs(t *testing.T) *lockedBuffer {
	t.Helper()
	var logs lockedBuffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}
