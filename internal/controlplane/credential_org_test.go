//go:build !windows

package controlplane

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestStaticCredentialsRequireExplicitInstallationWideOptIn(t *testing.T) {
	credentials, err := NewCredentialSet([]Credential{{Name: "unscoped", Role: RoleReader, Token: string(testReaderToken)}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{DBPath: filepath.Join(t.TempDir(), "controlplane.db"), Credentials: credentials, PolicyKey: make(ed25519.PublicKey, ed25519.PublicKeySize)}
	if server, err := New(cfg); err == nil {
		_ = server.Close()
		t.Fatal("unscoped credentials accepted without opt-in")
	}
	cfg.AllowInstallationWideCredentials = true
	server, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
}

func TestStaticCredentialOrganizationIsolation(t *testing.T) {
	credentials, err := NewCredentialSet([]Credential{
		{Name: "reader", Role: RoleReader, Org: "org-a", Token: string(testReaderToken)},
		{Name: "admin", Role: RoleAdmin, Org: "org-a", Token: string(testAdminToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{DBPath: filepath.Join(t.TempDir(), "controlplane.db"), Credentials: credentials, PolicyKey: make(ed25519.PublicKey, ed25519.PublicKeySize)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, tc := range []struct {
		method, path string
		token        []byte
		want         int
	}{
		{"GET", "/v1/orgs/org-a/audit", testReaderToken, http.StatusOK},
		{"GET", "/v1/orgs/org-b/audit", testReaderToken, http.StatusForbidden},
		{"GET", "/v1/orgs/org-a/policy", testReaderToken, http.StatusNotFound},
		{"GET", "/v1/orgs/org-b/policy", testReaderToken, http.StatusForbidden},
		{"PUT", "/v1/orgs/org-b/policy", testAdminToken, http.StatusForbidden},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+string(tc.token))
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, req)
		if response.Code != tc.want {
			t.Errorf("%s %s: status=%d want=%d", tc.method, tc.path, response.Code, tc.want)
		}
	}
	if _, err := NewCredentialSet([]Credential{{Name: "invalid", Role: RoleReader, Org: "../other", Token: string(testReaderToken)}}); err == nil {
		t.Fatal("invalid organization accepted")
	}
}
