//go:build linux

package main

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

	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
)

func TestRelayUpgradeBidirectional(t *testing.T) {
	upstream, peer := net.Pipe()
	defer peer.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		relayUpgrade(w, &http.Response{StatusCode: 101, Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}, Body: upstream})
	}))
	defer server.Close()
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		t.Fatalf("status %d", response.StatusCode)
	}
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4)
		_, err := io.ReadFull(peer, buf)
		if err == nil && string(buf) != "ping" {
			err = fmt.Errorf("got %q", buf)
		}
		if err == nil {
			_, err = peer.Write([]byte("pong"))
		}
		done <- err
	}()
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err = io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong" {
		t.Fatalf("got %q", got)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRouteUpgradeRejectsOtherServicesAndProtocols(t *testing.T) {
	for _, tc := range []struct{ service, protocol string }{{"openai", "websocket"}, {"openai-oauth", "other"}} {
		recorder := httptest.NewRecorder()
		resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{"Upgrade": {tc.protocol}}}
		if !handleRouteUpgrade(recorder, resp, tc.service) || recorder.Code != http.StatusBadGateway {
			t.Fatalf("service=%q protocol=%q status=%d", tc.service, tc.protocol, recorder.Code)
		}
	}
	recorder := httptest.NewRecorder()
	if handleRouteUpgrade(recorder, &http.Response{StatusCode: http.StatusOK}, "openai-oauth") {
		t.Fatal("normal response treated as upgrade")
	}
}

func TestOAuthWebSocketThroughHelperAndBroker(t *testing.T) {
	upstreamResult := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backend-api/codex/responses" || r.Header.Get("Authorization") != "Bearer synthetic-host-token" {
			upstreamResult <- fmt.Errorf("unexpected upstream request")
			http.Error(w, "bad request", 400)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			upstreamResult <- fmt.Errorf("upstream cannot hijack")
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			upstreamResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
			upstreamResult <- err
			return
		}
		buf := make([]byte, 4)
		if _, err = io.ReadFull(conn, buf); err != nil {
			upstreamResult <- err
			return
		}
		if string(buf) != "ping" {
			upstreamResult <- fmt.Errorf("unexpected request bytes")
			return
		}
		_, err = conn.Write([]byte("pong"))
		upstreamResult <- err
	}))
	defer upstream.Close()
	dir, err := os.MkdirTemp("/tmp", "rheic-upgrade-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	manager := secretproxy.New()
	defer func() { _ = manager.Close() }()
	token := strings.Repeat("a", 64)
	route := secretproxy.Service{Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer ", AllowedPathPrefix: "/backend-api/codex/"}
	if _, err = manager.StartUnixRoutes(context.Background(), "upgrade-test", map[string]secretproxy.RouteConfig{"openai-oauth": {Service: route, Secret: []byte("synthetic-host-token"), Token: token}}, socket); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	helper := httptest.NewServer(newRouteHandler("openai-oauth", "chatgpt.com", transport))
	defer helper.Close()
	conn, err := net.Dial("tcp", helper.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err = fmt.Fprint(conn, "GET /backend-api/codex/responses HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer rheic-proxy-placeholder\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err = io.ReadFull(reader, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong" {
		t.Fatalf("reply=%q", buf)
	}
	if err = <-upstreamResult; err != nil {
		t.Fatal(err)
	}
}
