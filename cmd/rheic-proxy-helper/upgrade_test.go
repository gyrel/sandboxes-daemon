//go:build linux

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
