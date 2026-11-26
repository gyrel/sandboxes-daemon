//go:build !windows

package secretproxy

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
)

// upgradeFixture is a controlled upstream that accepts one WebSocket-style
// upgrade per test and records whether the tunneled connection was closed.
type upgradeFixture struct {
	server   *httptest.Server
	accepted chan string
	closed   chan string
}

func newUpgradeFixture(t *testing.T) *upgradeFixture {
	t.Helper()
	fixture := &upgradeFixture{accepted: make(chan string, 8), closed: make(chan string, 8)}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/upgrade" {
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
		if _, err := fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
			return
		}
		fixture.accepted <- r.URL.Query().Get("mark")
		// Echo tunneled bytes so a test can prove the stream is still alive.
		_, _ = io.Copy(conn, conn)
		fixture.closed <- r.URL.Query().Get("mark")
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func startUpgradeProxy(t *testing.T, sandbox, socket string, fixture *upgradeFixture) *Manager {
	t.Helper()
	manager := New()
	t.Cleanup(func() { _ = manager.Close() })
	service := Service{Upstream: fixture.server.URL, Header: "Authorization", Prefix: "Bearer "}
	if _, err := manager.StartUnixRoutes(context.Background(), sandbox, map[string]RouteConfig{"openai-oauth": {
		Service: service, Secret: []byte("synthetic-host-token"), Token: strings.Repeat("a", 64),
	}}, socket); err != nil {
		t.Fatal(err)
	}
	return manager
}

func dialUpgrade(t *testing.T, socket, mark string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET /upgrade?mark=%s HTTP/1.1\r\nHost: upstream.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n%s: %s\r\n%s: openai-oauth\r\n\r\n",
		mark, TokenHeader, strings.Repeat("a", 64), ServiceHeader); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d", response.StatusCode)
	}
	return conn, reader
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(message)
}

func assertClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var buffer [1]byte
	n, err := conn.Read(buffer[:])
	if n != 0 || err == nil {
		t.Fatalf("stream stayed open: n=%d err=%v", n, err)
	}
}

func proxyHTTPStatus(t *testing.T, socket, path string) int {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}}
	defer client.CloseIdleConnections()
	request, err := http.NewRequest(http.MethodGet, "http://upstream.test"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(TokenHeader, strings.Repeat("a", 64))
	request.Header.Set(ServiceHeader, "openai-oauth")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

func TestPolicyRevisionClosesActiveUpgradeAndKeepsHTTPWorking(t *testing.T) {
	fixture := newUpgradeFixture(t)
	dir, err := os.MkdirTemp("/tmp", "gyrel-upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	manager := startUpgradeProxy(t, "revocation-sandbox", socket, fixture)

	conn, _ := dialUpgrade(t, socket, "policy")
	if mark := <-fixture.accepted; mark != "policy" {
		t.Fatalf("accepted mark = %q", mark)
	}
	waitForCondition(t, 3*time.Second, func() bool { return manager.ActiveUpgrades("revocation-sandbox", "openai-oauth") == 1 },
		"upgrade was not tracked")

	// Positive control: normal HTTP responses are not tracked and keep working.
	if status := proxyHTTPStatus(t, socket, "/plain"); status != http.StatusNoContent {
		t.Fatalf("normal response status = %d", status)
	}
	if got := manager.ActiveUpgrades("revocation-sandbox", "openai-oauth"); got != 1 {
		t.Fatalf("normal HTTP request changed upgrade count to %d", got)
	}

	// A policy revision closes the established stream but leaves the route
	// available for the next authorized request.
	if closed := manager.RevokeSandboxStreams("revocation-sandbox"); closed != 1 {
		t.Fatalf("policy revocation closed %d streams, want 1", closed)
	}
	assertClosed(t, conn)
	waitForCondition(t, 3*time.Second, func() bool { return manager.ActiveUpgrades("revocation-sandbox", "openai-oauth") == 0 },
		"revoked upgrade remained tracked")
	if status := proxyHTTPStatus(t, socket, "/plain"); status != http.StatusNoContent {
		t.Fatalf("normal response after revocation status = %d", status)
	}
}

func TestStreamRevocationIsSandboxScoped(t *testing.T) {
	fixture := newUpgradeFixture(t)
	dir, err := os.MkdirTemp("/tmp", "gyrel-upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketA := filepath.Join(dir, "a.sock")
	socketB := filepath.Join(dir, "b.sock")
	manager := New()
	t.Cleanup(func() { _ = manager.Close() })
	service := Service{Upstream: fixture.server.URL, Header: "Authorization", Prefix: "Bearer "}
	for _, item := range []struct{ sandbox, socket string }{{"sandbox-a", socketA}, {"sandbox-b", socketB}} {
		if _, err := manager.StartUnixRoutes(context.Background(), item.sandbox, map[string]RouteConfig{"openai-oauth": {
			Service: service, Secret: []byte("synthetic-host-token"), Token: strings.Repeat("a", 64),
		}}, item.socket); err != nil {
			t.Fatal(err)
		}
	}
	connA, _ := dialUpgrade(t, socketA, "a")
	connB, readerB := dialUpgrade(t, socketB, "b")
	for _, mark := range []string{"a", "b"} {
		if accepted := <-fixture.accepted; accepted != mark {
			t.Fatalf("accepted mark = %q, want %q", accepted, mark)
		}
	}
	waitForCondition(t, 3*time.Second, func() bool {
		return manager.ActiveUpgrades("sandbox-a", "openai-oauth") == 1 && manager.ActiveUpgrades("sandbox-b", "openai-oauth") == 1
	}, "upgrades were not tracked per sandbox")

	if closed := manager.RevokeSandboxStreams("sandbox-a"); closed != 1 {
		t.Fatalf("revocation closed %d streams, want 1", closed)
	}
	assertClosed(t, connA)
	if got := manager.ActiveUpgrades("sandbox-b", "openai-oauth"); got != 1 {
		t.Fatalf("other sandbox upgrade count = %d", got)
	}
	if _, err := connB.Write([]byte("ping")); err != nil {
		t.Fatalf("other sandbox stream was closed: %v", err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(readerB, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("other sandbox stream is not alive: %q err=%v", echo, err)
	}
}

func TestUpgradeTrackingCleansUpWhenPeerCloses(t *testing.T) {
	fixture := newUpgradeFixture(t)
	dir, err := os.MkdirTemp("/tmp", "gyrel-upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	manager := startUpgradeProxy(t, "cleanup-sandbox", socket, fixture)
	conn, _ := dialUpgrade(t, socket, "cleanup")
	<-fixture.accepted
	waitForCondition(t, 3*time.Second, func() bool { return manager.ActiveUpgrades("cleanup-sandbox", "openai-oauth") == 1 },
		"upgrade was not tracked")

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, 3*time.Second, func() bool { return manager.ActiveUpgrades("cleanup-sandbox", "openai-oauth") == 0 },
		"closed peer left a tracked upgrade")

	if err := manager.StopSandbox("cleanup-sandbox"); err != nil {
		t.Fatal(err)
	}
	if got := manager.ActiveUpgrades("cleanup-sandbox", "openai-oauth"); got != 0 {
		t.Fatalf("teardown left %d tracked upgrades", got)
	}
}

func TestStaleUpgradeGenerationFailsClosed(t *testing.T) {
	tracker := newUpgradeTracker()
	generation := tracker.currentGeneration()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	// Simulate a policy revision landing while the request is authorized but
	// before its hijack completes.
	if closed := tracker.closeActive(); closed != 0 {
		t.Fatalf("closeActive closed %d streams, want 0", closed)
	}
	tracked := tracker.track(client, generation)
	_ = tracked.SetReadDeadline(time.Now().Add(time.Second))
	var buffer [1]byte
	if n, err := tracked.Read(buffer[:]); n != 0 || err == nil {
		t.Fatalf("stale hijack stayed open: n=%d err=%v", n, err)
	}
	if got := tracker.count(); got != 0 {
		t.Fatalf("stale hijack was tracked: %d", got)
	}
}

func TestShutdownRejectsConcurrentHijack(t *testing.T) {
	tracker := newUpgradeTracker()
	generation := tracker.currentGeneration()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	tracker.shutdown()
	tracked := tracker.track(client, generation)
	_ = tracked.SetReadDeadline(time.Now().Add(time.Second))
	var buffer [1]byte
	if n, err := tracked.Read(buffer[:]); n != 0 || err == nil {
		t.Fatalf("hijack after shutdown stayed open: n=%d err=%v", n, err)
	}
	if got := tracker.count(); got != 0 {
		t.Fatalf("hijack after shutdown was tracked: %d", got)
	}
}

func TestCredentialRevocationClosesActiveUpgrade(t *testing.T) {
	fixture := newUpgradeFixture(t)
	dir, err := os.MkdirTemp("/tmp", "gyrel-upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	manager := New()
	t.Cleanup(func() { _ = manager.Close() })
	service := Service{Upstream: fixture.server.URL, Header: "Authorization", Prefix: "Bearer ", CredentialScope: "global-oauth"}
	if _, err := manager.StartUnixRoutes(context.Background(), "credential-sandbox", map[string]RouteConfig{"openai-oauth": {
		Service: service, Secret: []byte("synthetic-host-token"), Token: strings.Repeat("a", 64),
	}}, socket); err != nil {
		t.Fatal(err)
	}
	conn, _ := dialUpgrade(t, socket, "credential")
	<-fixture.accepted
	waitForCondition(t, 3*time.Second, func() bool { return manager.ActiveUpgrades("credential-sandbox", "openai-oauth") == 1 },
		"upgrade was not tracked")

	if err := manager.RevokeSecret("openai-oauth", "credential-sandbox", "global-oauth"); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, conn)
	waitForCondition(t, 3*time.Second, func() bool { return manager.ActiveUpgrades("credential-sandbox", "openai-oauth") == 0 },
		"credential revocation left a tracked upgrade")
}
