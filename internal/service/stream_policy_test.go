//go:build !windows

package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rheic/sandboxes-core/sandbox"

	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

func TestPolicyMutationRevokesActiveOAuthUpgrade(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "stream-policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakePolicyRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "stream-policy"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/upgrade" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Header.Get("Authorization") != "Bearer synthetic-host-token" {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_, _ = io.Copy(io.Discard, conn)
	}))
	defer upstream.Close()

	manager := secretproxy.New()
	defer func() { _ = manager.Close() }()
	svc.SetSecretProxyManager(manager)
	dir, err := os.MkdirTemp("/tmp", "rheic-service-upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	token := strings.Repeat("b", 64)
	if _, err := manager.StartUnixRoutes(ctx, sb.Name, map[string]secretproxy.RouteConfig{"openai-oauth": {
		Service: secretproxy.Service{Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer "},
		Secret:  []byte("synthetic-host-token"), Token: token,
	}}, socket); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET /upgrade HTTP/1.1\r\nHost: upstream.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n%s: %s\r\n%s: openai-oauth\r\n\r\n",
		secretproxy.TokenHeader, token, secretproxy.ServiceHeader); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status=%v err=%v", response, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for manager.ActiveUpgrades(sb.Name, "openai-oauth") != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := manager.ActiveUpgrades(sb.Name, "openai-oauth"); got != 1 {
		t.Fatalf("active upgrades before policy mutation = %d", got)
	}

	if _, err := svc.UpdatePolicy(ctx, op.SandboxID, []sandbox.NetworkRule{{Protocol: "tcp", CIDR: "0.0.0.0/0", Port: 443}}, nil); err != nil {
		t.Fatal(err)
	}
	if backend.revision <= 1 {
		t.Fatalf("policy revision was not applied: %d", backend.revision)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var buffer [1]byte
	if n, err := conn.Read(buffer[:]); n != 0 || err == nil {
		t.Fatalf("policy mutation left the upgraded stream open: n=%d err=%v", n, err)
	}
	if got := manager.ActiveUpgrades(sb.Name, "openai-oauth"); got != 0 {
		t.Fatalf("active upgrades after policy mutation = %d", got)
	}

	// Positive control: the policy revision must not disable ordinary traffic
	// on the same route.
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}}
	defer client.CloseIdleConnections()
	request, err := http.NewRequest(http.MethodGet, "http://upstream.test/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(secretproxy.TokenHeader, token)
	request.Header.Set(secretproxy.ServiceHeader, "openai-oauth")
	plain, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Body.Close() }()
	if plain.StatusCode != http.StatusNoContent {
		t.Fatalf("normal HTTP response status = %d", plain.StatusCode)
	}
}
