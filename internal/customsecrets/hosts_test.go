package customsecrets

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeHostGrammar(t *testing.T) {
	accept := map[string]string{
		"api.example.test":   "api.example.test",
		"API.Example.TEST":   "api.example.test",
		"a-b.example.test":   "a-b.example.test",
		"localhost":          "localhost",
		"*.example.test":     "*.example.test",
		"**.example.test":    "**.example.test",
		"*.Example.TEST":     "*.example.test",
		"192.0.2.10":         "192.0.2.10",
		"2001:DB8::1":        "2001:db8::1",
		"::1":                "::1",
		"::ffff:192.0.2.10":  "::ffff:192.0.2.10",
		"2001:db8:0:0:0::20": "2001:db8::20",
	}
	for raw, want := range accept {
		got, err := NormalizeHost(raw)
		if err != nil || got != want {
			t.Errorf("NormalizeHost(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	reject := []string{
		"", " api.example.test", "api.example.test ", "https://api.example.test",
		"user@api.example.test", "api.example.test:443", "api.example.test/path",
		"api.example.test?x=1", "api.example.test#frag", "*", "*.com", "**.com",
		"a*.example.test", "*.*.example.test", "api.*.test", "**example.test",
		"api.example.test.", "-bad.example.test", "bad-.example.test",
		"under_score.example.test", "[2001:db8::1]", "fe80::1%eth0", "1.2.3.4:80",
		"http://[::1]", "exa mple.test", "x..example.test", "*.192.0.2.10",
		"**.", "*.", strings.Repeat("a", 64) + ".example.test",
	}
	for _, raw := range reject {
		if got, err := NormalizeHost(raw); !errors.Is(err, ErrInvalidHost) {
			t.Errorf("NormalizeHost(%q) = %q, %v; want ErrInvalidHost", raw, got, err)
		}
	}
}

func TestNormalizeHostErrorsDoNotEchoInput(t *testing.T) {
	const synthetic = "synthetic-secret-value-do-not-print"
	_, err := NormalizeHost(synthetic + "@example.test")
	if err == nil || strings.Contains(err.Error(), synthetic) {
		t.Fatalf("error echoed input: %v", err)
	}
}

func TestNormalizeHostsRejectsDuplicatesAndBounds(t *testing.T) {
	if _, err := NormalizeHosts([]string{"a.example.test", "A.example.test"}); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("duplicate after normalization accepted: %v", err)
	}
	if _, err := NormalizeHosts(nil); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("empty host list accepted: %v", err)
	}
	many := make([]string, MaxHosts+1)
	for i := range many {
		many[i] = "h" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example.test"
	}
	if _, err := NormalizeHosts(many); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("too many hosts accepted: %v", err)
	}
	got, err := NormalizeHosts([]string{"*.example.test", "api.example.test"})
	if err != nil || len(got) != 2 || got[0] != "*.example.test" || got[1] != "api.example.test" {
		t.Fatalf("ordered hosts = %v, %v", got, err)
	}
}

func TestMatchHostPositiveAndNearMissControls(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"api.example.test", "api.example.test", true},
		{"api.example.test", "API.example.test.", true},
		{"api.example.test", "cli.example.test", false},
		{"api.example.test", "api.example.test.evil.test", false},
		{"*.example.test", "cli.example.test", true},
		{"*.example.test", "CLI.Example.Test.", true},
		{"*.example.test", "a.b.example.test", false},
		{"*.example.test", "example.test", false},
		{"*.example.test", "evilexample.test", false},
		{"*.example.test", "cli.example.test.evil.test", false},
		{"*.example.test", ".example.test", false},
		{"*.example.test", "", false},
		{"**.example.test", "a.example.test", true},
		{"**.example.test", "a.b.c.example.test", true},
		{"**.example.test", "example.test", false},
		{"**.example.test", "x.evil-example.test", false},
		{"**.example.test", "example.test.evil.test", false},
		{"**.example.test", "a..example.test", false},
		{"192.0.2.10", "192.0.2.10", true},
		{"192.0.2.10", "192.0.2.11", false},
		{"192.0.2.10", "192.0.2.10.example.test", false},
		{"2001:db8::1", "2001:DB8::1", true},
		{"2001:db8::1", "2001:db8::2", false},
		{"2001:db8::1", "2001:db8::1.example.test", false},
	}
	for _, tc := range cases {
		if got := MatchHost(tc.pattern, tc.host); got != tc.want {
			t.Errorf("MatchHost(%q, %q) = %t, want %t", tc.pattern, tc.host, got, tc.want)
		}
	}
}
