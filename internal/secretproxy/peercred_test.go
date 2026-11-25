//go:build !windows

package secretproxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mustTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "kqpeercred")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestPeerCheckingListenerRejectsForeignOwner(t *testing.T) {
	var out bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&out, nil)))
	defer slog.SetDefault(old)
	inner, err := net.Listen("unix", filepath.Join(mustTempDir(t), "canary-token.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var rejected atomic.Int64
	droppedUID := uint64(987654321)
	listener := peerCheckingListener{
		Listener: inner,
		rejected: &rejected,
		peerUID: func(net.Conn) (uint64, bool) {
			return droppedUID, true
		},
	}
	defer func() { _ = listener.Close() }()

	conn, err := net.Dial("unix", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- peer
	}()
	select {
	case peer := <-accepted:
		_ = peer.Close()
		t.Fatal("foreign-owner connection was accepted")
	case err := <-acceptErr:
		t.Fatalf("accept returned error instead of skipping peer: %v", err)
	case <-time.After(2 * time.Second):
	}
	_ = listener.Close()
	<-acceptErr
	if !strings.Contains(out.String(), "rheic.peercred.reject") || strings.Contains(out.String(), inner.Addr().String()) {
		t.Fatalf("unexpected event: %s", out.String())
	}
	var record map[string]json.RawMessage
	line := strings.TrimSpace(out.String())
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("expected one JSON event: %v", err)
	}
	uid := strconv.FormatUint(droppedUID, 10)
	if string(record["peer_uid"]) != uid {
		t.Errorf("peer_uid = %s, want numeric %s", record["peer_uid"], uid)
	}
	delete(record, "peer_uid")
	rest, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rest), uid) || strings.Contains(line, "canary-token") || strings.Contains(line, inner.Addr().String()) {
		t.Errorf("UID or socket path leaked outside peer_uid: %s", line)
	}
	if rejected.Load() != 1 {
		t.Fatalf("rejected=%d want 1", rejected.Load())
	}
}

func TestPeerCheckingListenerAcceptsSameOwner(t *testing.T) {
	inner, err := net.Listen("unix", filepath.Join(mustTempDir(t), "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var rejected atomic.Int64
	listener := peerCheckingListener{
		Listener: inner,
		rejected: &rejected,
		peerUID: func(net.Conn) (uint64, bool) {
			return currentUID(), true
		},
	}
	defer func() { _ = listener.Close() }()

	conn, err := net.Dial("unix", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- peer
	}()
	select {
	case peer := <-accepted:
		_ = peer.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("same-owner connection was not accepted")
	}
	if rejected.Load() != 0 {
		t.Fatalf("rejected=%d want 0", rejected.Load())
	}
}

func TestPeerCheckingListenerRejectsUnverifiablePeer(t *testing.T) {
	inner, err := net.Listen("unix", filepath.Join(mustTempDir(t), "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var rejected atomic.Int64
	listener := peerCheckingListener{
		Listener: inner,
		rejected: &rejected,
		peerUID: func(net.Conn) (uint64, bool) {
			return 0, false
		},
	}
	defer func() { _ = listener.Close() }()

	conn, err := net.Dial("unix", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		peer, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- peer
		}
	}()
	select {
	case peer := <-accepted:
		_ = peer.Close()
		t.Fatal("unverifiable peer was accepted")
	case <-time.After(2 * time.Second):
	}
	if rejected.Load() != 1 {
		t.Fatalf("rejected=%d want 1", rejected.Load())
	}
}

func TestPeerCheckingListenerPropagatesAcceptError(t *testing.T) {
	inner, err := net.Listen("unix", filepath.Join(mustTempDir(t), "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var rejected atomic.Int64
	listener := peerCheckingListener{Listener: inner, rejected: &rejected, peerUID: peerOwnerUID}
	if err := inner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); err == nil {
		t.Fatal("accept error = nil, want non-nil")
	}
}
