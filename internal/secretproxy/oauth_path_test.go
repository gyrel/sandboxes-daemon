package secretproxy

import (
	"net/url"
	"testing"
)

func TestOAuthPathRestriction(t *testing.T) {
	for _, tc := range []struct {
		path    string
		allowed bool
	}{
		{"/backend-api/codex/responses", true},
		{"/backend-api/codex/models?client_version=1", true},
		{"/backend-api/codex", false},
		{"/backend-api/codexevil/responses", false},
		{"/backend-api/codex/../accounts", false},
		{"/backend-api/codex/%2e%2e/accounts", false},
		{"/other", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			u, err := url.Parse(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if got := allowedServicePath(u, "/backend-api/codex/"); got != tc.allowed {
				t.Fatalf("allowed=%v, want %v", got, tc.allowed)
			}
		})
	}
}
