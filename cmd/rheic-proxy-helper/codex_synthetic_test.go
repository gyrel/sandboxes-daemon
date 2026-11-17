//go:build linux

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
)

func TestSyntheticCodexThroughHelperAndBroker(t *testing.T) {
	if os.Getenv("RHEIC_SYNTHETIC_CODEX") != "1" {
		t.Skip("requires an isolated container with Codex 0.165.0")
	}
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backend-api/codex/responses" || r.Header.Get("Authorization") != "Bearer synthetic-host-token" {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			http.Error(w, "websocket unavailable", http.StatusUpgradeRequired)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "denied", http.StatusMethodNotAllowed)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"type\":\"response.output_item.done\",\"item\":{\"id\":\"msg_fixture\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"RHEIC_SYNTHETIC_OK\"}]}}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_fixture\",\"end_turn\":true}}\n\n")
	}))
	defer upstream.Close()
	dir, err := os.MkdirTemp("/tmp", "rheic-codex-synthetic-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	manager := secretproxy.New()
	defer func() { _ = manager.Close() }()
	route := secretproxy.Service{Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer ", AllowedPathPrefix: "/backend-api/codex/"}
	if _, err = manager.StartUnixRoutes(context.Background(), "codex-synthetic", map[string]secretproxy.RouteConfig{"openai-oauth": {Service: route, Secret: []byte("synthetic-host-token"), Token: strings.Repeat("a", 64)}}, socket); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	listener, err := net.Listen("tcp", "127.0.0.1:3128")
	if err != nil {
		t.Fatal(err)
	}
	helper := httptest.NewUnstartedServer(newRouteHandler("openai-oauth", "chatgpt.com", transport))
	_ = helper.Listener.Close()
	helper.Listener = listener
	helper.Start()
	defer helper.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "codex", "-c", "openai_base_url=http://127.0.0.1:3128/backend-api/codex", "exec", "--skip-git-repo-check", "--ephemeral", "Reply RHEIC_SYNTHETIC_OK")
	if err := os.Mkdir(filepath.Join(dir, "codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "CODEX_HOME=" + filepath.Join(dir, "codex"), "CODEX_API_KEY=rheic-proxy-placeholder", "NO_COLOR=1", "TERM=dumb"}
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("codex: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "RHEIC_SYNTHETIC_OK") || calls.Load() != 1 {
		t.Fatalf("fixture calls=%d output=%s", calls.Load(), output)
	}
}
