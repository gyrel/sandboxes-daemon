//go:build linux

package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
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
	var calls, websocketCalls, upgradeAttempts atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backend-api/codex/responses" || r.Header.Get("Authorization") != "Bearer synthetic-host-token" {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			upgradeAttempts.Add(1)
			if os.Getenv("RHEIC_SYNTHETIC_WS") == "1" {
				if err := serveSyntheticCodexWebSocket(w, r); err != nil {
					t.Errorf("synthetic websocket: %v", err)
					return
				}
				websocketCalls.Add(1)
				return
			}
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
	if !strings.Contains(string(output), "RHEIC_SYNTHETIC_OK") {
		t.Fatalf("output=%s", output)
	}
	mode := "http"
	if os.Getenv("RHEIC_SYNTHETIC_WS") == "1" {
		mode = "websocket"
		if websocketCalls.Load() < 1 || calls.Load() != 0 {
			t.Fatalf("websocket=%d HTTP=%d output=%s", websocketCalls.Load(), calls.Load(), output)
		}
	} else if websocketCalls.Load() != 0 || calls.Load() != 1 {
		t.Fatalf("websocket=%d HTTP=%d output=%s", websocketCalls.Load(), calls.Load(), output)
	}
	recordCodexTransportEvidence(t, mode, int(websocketCalls.Load()), int(calls.Load()), int(upgradeAttempts.Load()))
}

// recordCodexTransportEvidence emits a deterministic, machine-readable record
// of the transport the actual Codex client used. It runs only in tests and
// contains counters only: no request bodies, headers, or credentials.
func recordCodexTransportEvidence(t *testing.T, mode string, upgraded, httpResponses, upgradeAttempts int) {
	t.Helper()
	line := fmt.Sprintf("CODEX_TRANSPORT_EVIDENCE transport=%s upgraded_streams=%d http_responses=%d upgrade_attempts=%d\n",
		mode, upgraded, httpResponses, upgradeAttempts)
	t.Logf("%s", strings.TrimSpace(line))
	if path := os.Getenv("RHEIC_CODEX_TRANSPORT_EVIDENCE"); path != "" {
		if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
			t.Fatalf("write transport evidence: %v", err)
		}
	}
}

func serveSyntheticCodexWebSocket(w http.ResponseWriter, r *http.Request) error {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if _, err = fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
		return err
	}
	header := make([]byte, 2)
	if _, err = io.ReadFull(conn, header); err != nil {
		return err
	}
	size := uint64(header[1] & 127)
	switch size {
	case 126:
		var n uint16
		if err = binary.Read(conn, binary.BigEndian, &n); err != nil {
			return err
		}
		size = uint64(n)
	case 127:
		if err = binary.Read(conn, binary.BigEndian, &size); err != nil {
			return err
		}
	}
	if header[1]&128 == 0 || size > 8<<20 {
		return fmt.Errorf("invalid fixture frame")
	}
	mask := make([]byte, 4)
	if _, err = io.ReadFull(conn, mask); err != nil {
		return err
	}
	payload := make([]byte, int(size))
	if _, err = io.ReadFull(conn, payload); err != nil {
		return err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	if !strings.Contains(string(payload), "response.create") {
		return fmt.Errorf("unexpected fixture frame")
	}
	for _, event := range []string{`{"type":"response.output_item.done","item":{"id":"msg_fixture","type":"message","role":"assistant","content":[{"type":"output_text","text":"RHEIC_SYNTHETIC_OK"}]}}`, `{"type":"response.completed","response":{"id":"resp_fixture","end_turn":true}}`} {
		frame := []byte(event)
		head := []byte{0x81}
		if len(frame) < 126 {
			head = append(head, byte(len(frame)))
		} else {
			head = append(head, 126, byte(len(frame)>>8), byte(len(frame)))
		}
		if _, err = conn.Write(append(head, frame...)); err != nil {
			return err
		}
	}
	_, _ = io.Copy(io.Discard, conn)
	return nil
}
