package registrycredentials

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gyrel/sandboxes-gateway/registryauth"
)

func TestProbeRegistryRealmUsesCustomPortRealm(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/team/image/manifests/latest" {
			t.Errorf("unexpected realm probe request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="https://%s/token",service="fixture"`, server.Listener.Addr().String()))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	endpoint, err := url.Parse(server.URL + "/v2/team/image/manifests/latest")
	if err != nil {
		t.Fatal(err)
	}
	realmHost := server.Listener.Addr().String()
	proxy := &PullProxy{
		authority: endpoint.Host, registryTransport: server.Client().Transport,
		service: "fixture", realms: []registryauth.Realm{{Host: realmHost, Path: "/token"}},
	}
	incoming := httptest.NewRequest(http.MethodGet, endpoint.String(), http.NoBody)
	realm, requiresAuth, err := proxy.probeRegistryRealm(context.Background(), incoming, endpoint)
	if err != nil {
		t.Fatalf("probe custom-port realm: %v", err)
	}
	if !requiresAuth || realm.Host != realmHost || realm.Path != "/token" {
		t.Fatalf("realm = %#v requiresAuth=%t, want host %q", realm, requiresAuth, realmHost)
	}
}

func TestForwardRegistryTransportDialsCustomPortIPLiteral(t *testing.T) {
	const path = "/v2/team/image/manifests/latest"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path || r.Host == "" {
			t.Errorf("unexpected registry request: host=%q path=%q", r.Host, r.URL.Path)
		}
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	authority := strings.TrimPrefix(server.URL, "https://")
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport, err := NewForwardRegistryTransport(authority, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, roots)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://"+authority+path, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		t.Fatalf("custom-port IP registry request: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("custom-port IP registry status = %d", response.StatusCode)
	}
}

func TestTLSServerNameMatchesIPLiteralWithoutInventedSNI(t *testing.T) {
	tests := []struct {
		serverName string
		host       string
		want       bool
	}{
		{serverName: "", host: "192.0.2.10", want: true},
		{serverName: "192.0.2.10", host: "192.0.2.10", want: true},
		{serverName: "192.0.2.11", host: "192.0.2.10", want: false},
		{serverName: "", host: "registry.example.test", want: false},
		{serverName: "REGISTRY.example.test.", host: "registry.example.test", want: true},
	}
	for _, test := range tests {
		if got := tlsServerNameMatches(test.serverName, test.host); got != test.want {
			t.Errorf("tlsServerNameMatches(%q, %q) = %t, want %t", test.serverName, test.host, got, test.want)
		}
	}
}

func TestProxyAuthorityBindsIPLiteralThroughIPSAN(t *testing.T) {
	authority, err := generateProxyAuthority()
	if err != nil {
		t.Fatal(err)
	}
	authority.AllowHosts("192.0.2.10:5000")
	certificate, err := authority.Leaf("192.0.2.10", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal([]byte{192, 0, 2, 10}) {
		t.Fatalf("IP certificate SANs = DNS %v IP %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if err := leaf.VerifyHostname("192.0.2.10"); err != nil {
		t.Fatalf("IP SAN did not verify: %v", err)
	}
	if err := leaf.VerifyHostname("192.0.2.11"); err == nil {
		t.Fatal("certificate verified the wrong IP literal")
	}
}

func TestPullRedirectCustomPortRejectsNonAllowlistedAuthority(t *testing.T) {
	proxy := &PullProxy{
		authority:     "registry.example.test:5000",
		redirectHosts: redirectHostSet([]string{"cdn.example.test:5000"}),
	}
	current, err := url.Parse("https://registry.example.test:5000/v2/team/image/blobs/sha256:abcd")
	if err != nil {
		t.Fatal(err)
	}
	for _, allowed := range []string{
		"https://registry.example.test:5000/blob",
		"https://cdn.example.test:5000/blob",
	} {
		if _, err := proxy.validatePullRedirect(current, allowed); err != nil {
			t.Errorf("allowlisted redirect %q was rejected: %v", allowed, err)
		}
	}
	for _, denied := range []string{
		"https://cdn.example.test:5001/blob",
		"https://cdn.example.test/blob",
		"https://attacker.example:5000/blob",
		"https://attacker.example/blob",
		"http://cdn.example.test:5000/blob",
		"https://user@cdn.example.test:5000/blob",
	} {
		if _, err := proxy.validatePullRedirect(current, denied); err == nil {
			t.Errorf("non-allowlisted redirect %q was accepted", denied)
		}
	}
}
