//go:build !windows

package secretproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const substituteToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type substituteFixture struct {
	client   *http.Client
	mu       sync.Mutex
	seen     http.Header
	reached  atomic.Int32
	resolves atomic.Int32
	manager  *Manager
}

func (f *substituteFixture) header(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen.Get(name)
}

// startSubstituteChannel runs one proxy route whose handler records the headers
// that survive substitution. The upstream is never dialed, so the https gate is
// exercised without a TLS fixture.
func startSubstituteChannel(t *testing.T, upstream string, resolve func(context.Context) ([]Substitution, error)) *substituteFixture {
	t.Helper()
	fixture := &substituteFixture{}
	dir, err := os.MkdirTemp("/tmp", "kqsub")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "p.sock")
	fixture.manager = New()
	t.Cleanup(func() { _ = fixture.manager.Close() })
	counted := func(ctx context.Context) ([]Substitution, error) {
		fixture.resolves.Add(1)
		return resolve(ctx)
	}
	route := RouteConfig{
		Service: Service{Upstream: upstream},
		Token:   substituteToken,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fixture.mu.Lock()
			fixture.seen = r.Header.Clone()
			fixture.mu.Unlock()
			fixture.reached.Add(1)
			_, _ = io.WriteString(w, "ok")
		}),
		Substitutions: counted,
	}
	if _, err := fixture.manager.StartUnixRoutes(context.Background(), "dev", map[string]RouteConfig{"vendor": route}, socket); err != nil {
		t.Fatal(err)
	}
	fixture.client = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}}
	return fixture
}

func (f *substituteFixture) send(t *testing.T, headers map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://upstream.test/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(TokenHeader, substituteToken)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

const (
	testPlaceholder = "gyrel-placeholder-4f2a9c1e"
	testValue       = "synthetic-secret-value-do-not-print"
)

func TestSubstitutionReplacesPlaceholderOnlyOnHttpsRoute(t *testing.T) {
	fixture := startSubstituteChannel(t, "https://api.example.test", func(context.Context) ([]Substitution, error) {
		return []Substitution{{Placeholder: testPlaceholder, Value: []byte(testValue)}}, nil
	})
	status := fixture.send(t, map[string]string{"X-Vendor-Key": testPlaceholder, "X-Multi": "pre-" + testPlaceholder + "-post"})
	if status != http.StatusOK || fixture.reached.Load() != 1 {
		t.Fatalf("status=%d reached=%d", status, fixture.reached.Load())
	}
	if got := fixture.header("X-Vendor-Key"); got != testValue {
		t.Fatalf("substituted header = %q", got)
	}
	if got := fixture.header("X-Multi"); got != "pre-"+testValue+"-post" {
		t.Fatalf("in-place substitution = %q", got)
	}
}

func TestSubstitutionNegativeControlsFailClosedOrSkip(t *testing.T) {
	// Plaintext loopback upstream: the resolver must not even run, and the
	// placeholder must reach the handler unchanged.
	plain := startSubstituteChannel(t, "http://127.0.0.1:9", func(context.Context) ([]Substitution, error) {
		return []Substitution{{Placeholder: testPlaceholder, Value: []byte(testValue)}}, nil
	})
	if status := plain.send(t, map[string]string{"X-Vendor-Key": testPlaceholder}); status != http.StatusOK {
		t.Fatalf("plaintext status = %d", status)
	}
	if plain.resolves.Load() != 0 || plain.header("X-Vendor-Key") != testPlaceholder {
		t.Fatalf("plaintext route substituted: resolves=%d header=%q", plain.resolves.Load(), plain.header("X-Vendor-Key"))
	}

	cases := map[string]func(context.Context) ([]Substitution, error){
		"resolver error": func(context.Context) ([]Substitution, error) {
			return nil, errors.New("synthetic keychain failure")
		},
		"duplicate placeholder": func(context.Context) ([]Substitution, error) {
			return []Substitution{
				{Placeholder: testPlaceholder, Value: []byte("one")},
				{Placeholder: testPlaceholder, Value: []byte("two")},
			}, nil
		},
		"overlapping placeholder": func(context.Context) ([]Substitution, error) {
			return []Substitution{
				{Placeholder: testPlaceholder, Value: []byte("one")},
				{Placeholder: testPlaceholder[:12], Value: []byte("two")},
			}, nil
		},
		"empty placeholder": func(context.Context) ([]Substitution, error) {
			return []Substitution{{Placeholder: "", Value: []byte("one")}}, nil
		},
	}
	for name, resolve := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := startSubstituteChannel(t, "https://api.example.test", resolve)
			if status := fixture.send(t, map[string]string{"X-Vendor-Key": testPlaceholder}); status != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502", status)
			}
			if fixture.reached.Load() != 0 {
				t.Fatal("request reached the handler after substitution failed closed")
			}
		})
	}
}

func TestSubstitutionIsSinglePassAndRemovalStopsInjection(t *testing.T) {
	const innerPlaceholder = "gyrel-placeholder-inner-7d3e"
	fixture := startSubstituteChannel(t, "https://api.example.test", func(context.Context) ([]Substitution, error) {
		return []Substitution{
			{Placeholder: testPlaceholder, Value: []byte(innerPlaceholder)},
			{Placeholder: innerPlaceholder, Value: []byte("inner-value-must-not-appear")},
		}, nil
	})
	if status := fixture.send(t, map[string]string{"X-Vendor-Key": testPlaceholder}); status == http.StatusBadGateway {
		t.Fatal("non-overlapping placeholders must not fail closed")
	}
	// The second placeholder is a distinct, non-overlapping entry: a value that
	// contains it must not be rescanned after replacement.
	if got := fixture.header("X-Vendor-Key"); got != innerPlaceholder {
		t.Fatalf("single-pass result = %q, want %q", got, innerPlaceholder)
	}

	removed := startSubstituteChannel(t, "https://api.example.test", func(context.Context) ([]Substitution, error) {
		return nil, nil
	})
	if status := removed.send(t, map[string]string{"X-Vendor-Key": testPlaceholder}); status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if got := removed.header("X-Vendor-Key"); got != testPlaceholder {
		t.Fatalf("removed binding still injected a value: %q", got)
	}
	if strings.Contains(removed.header("X-Vendor-Key"), testValue) {
		t.Fatal("secret value reached the upstream after removal")
	}
}

func TestSubstitutionNeverReplacesProxyControlledHeaders(t *testing.T) {
	fixture := startSubstituteChannel(t, "https://api.example.test", func(context.Context) ([]Substitution, error) {
		return []Substitution{{Placeholder: testPlaceholder, Value: []byte(testValue)}}, nil
	})
	if status := fixture.send(t, map[string]string{"Authorization": "Bearer " + testPlaceholder, "X-Api-Key": testPlaceholder}); status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	for _, name := range []string{"Authorization", "X-Api-Key"} {
		if got := fixture.header(name); strings.Contains(got, testValue) {
			t.Fatalf("%s was substituted despite proxy-controlled deletion: %q", name, got)
		}
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestSubstitutionLogsCarryNoPlaceholderOrValue(t *testing.T) {
	var logs lockedBuffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	ok := startSubstituteChannel(t, "https://api.example.test", func(context.Context) ([]Substitution, error) {
		return []Substitution{{Placeholder: testPlaceholder, Value: []byte(testValue)}}, nil
	})
	if status := ok.send(t, map[string]string{"X-Vendor-Key": testPlaceholder}); status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	failing := startSubstituteChannel(t, "https://api.example.test", func(context.Context) ([]Substitution, error) {
		return nil, errors.New("synthetic " + testValue)
	})
	if status := failing.send(t, map[string]string{"X-Vendor-Key": testPlaceholder}); status != http.StatusBadGateway {
		t.Fatalf("status = %d", status)
	}
	output := logs.String()
	if !strings.Contains(output, "custom secret placeholder substituted") || !strings.Contains(output, "custom secret substitution failed closed") {
		t.Fatalf("positive control: substitution events missing: %s", output)
	}
	for _, needle := range []string{testValue, testPlaceholder} {
		if strings.Contains(output, needle) {
			t.Fatalf("substitution log leaked %q", needle)
		}
	}
}
