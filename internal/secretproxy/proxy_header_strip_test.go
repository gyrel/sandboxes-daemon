//go:build !windows

package secretproxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type capturedUpstreamRequest struct {
	raw    string
	header http.Header
}

// newCapturingUpstream records the raw request header block before the Go HTTP
// server parses it, so tests can scan exactly what reaches the upstream wire.
func newCapturingUpstream(t *testing.T) (string, <-chan capturedUpstreamRequest) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	captures := make(chan capturedUpstreamRequest, 1)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go captureUpstreamRequest(conn, captures)
		}
	}()
	return listener.Addr().String(), captures
}

func captureUpstreamRequest(conn net.Conn, captures chan<- capturedUpstreamRequest) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	raw, err := readRawHeaderBlock(conn)
	if err != nil {
		return
	}
	request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return
	}
	captures <- capturedUpstreamRequest{raw: raw, header: request.Header}
	_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))
}

func readRawHeaderBlock(conn net.Conn) (string, error) {
	var block strings.Builder
	var buffer [1]byte
	for {
		n, err := conn.Read(buffer[:])
		if n > 0 {
			block.WriteByte(buffer[0])
			if strings.HasSuffix(block.String(), "\r\n\r\n") {
				return block.String(), nil
			}
		}
		if err != nil {
			return block.String(), err
		}
	}
}

func startHeaderStripProxy(t *testing.T, upstreamAddr, token string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gyrel-header-strip")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	manager := New()
	t.Cleanup(func() { _ = manager.Close() })
	route := RouteConfig{
		Service: Service{Upstream: "http://" + upstreamAddr, Header: "Authorization", Prefix: "Bearer "},
		Secret:  []byte("synthetic-host-credential"),
		Token:   token,
	}
	if _, err := manager.StartUnixRoutes(context.Background(), "header-strip", map[string]RouteConfig{"synthetic-service": route}, socket); err != nil {
		t.Fatal(err)
	}
	return socket
}

func TestProxyStripsGuestProductHeadersBeforeUpstream(t *testing.T) {
	token := strings.Repeat("a", 64)
	upstreamAddr, captures := newCapturingUpstream(t)
	socket := startHeaderStripProxy(t, upstreamAddr, token)
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}}
	request, err := http.NewRequest(http.MethodGet, "http://broker/v1/models", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(ServiceHeader, "synthetic-service")
	request.Header.Set(TokenHeader, token)
	request.Header.Set("X-Gyrel-Foo", "leak")
	request.Header.Set("x-rheic-bar", "leak")
	request.Header.Set("X-Gyrel-Secret-Proxy", "sneaky")
	request.Header.Set("X-Rheic-Trace", "leak")
	request.Header.Set("X-Custom", "keep")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("proxy status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}

	var captured capturedUpstreamRequest
	select {
	case captured = <-captures:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream captured no request")
	}

	t.Run("guest product headers are dropped", func(t *testing.T) {
		for _, name := range []string{"X-Gyrel-Foo", "X-Rheic-Bar", "X-Gyrel-Secret-Proxy", "X-Rheic-Trace"} {
			if value := captured.header.Get(name); value != "" {
				t.Errorf("upstream saw %s = %q", name, value)
			}
		}
	})
	t.Run("unrelated header survives", func(t *testing.T) {
		if got := captured.header.Get("X-Custom"); got != "keep" {
			t.Errorf("upstream X-Custom = %q, want %q", got, "keep")
		}
	})
	t.Run("credential injection is unchanged", func(t *testing.T) {
		if got := captured.header.Get("Authorization"); got != "Bearer synthetic-host-credential" {
			t.Errorf("upstream Authorization = %q, want %q", got, "Bearer synthetic-host-credential")
		}
	})
	t.Run("wire header block is product-free", func(t *testing.T) {
		lower := strings.ToLower(captured.raw)
		if strings.Contains(lower, "x-gyrel-") {
			t.Errorf("raw upstream header block contains product namespace: %q", captured.raw)
		}
		if strings.Contains(lower, "x-rheic-") {
			t.Errorf("raw upstream header block contains product namespace: %q", captured.raw)
		}
	})
}

func TestDropGuestCredentialHeadersRemovesProductNamespaces(t *testing.T) {
	request := &http.Request{Header: http.Header{
		"X-Gyrel-Foo":   {"leak"},
		"x-rheic-bar":   {"leak"},
		"Authorization": {"Bearer guest-controlled"},
		"X-Custom":      {"keep"},
	}}
	dropGuestCredentialHeaders(request)
	if got := request.Header.Get("X-Gyrel-Foo"); got != "" {
		t.Errorf("X-Gyrel-Foo survived as %q", got)
	}
	if got := request.Header.Get("X-Rheic-Bar"); got != "" {
		t.Errorf("x-rheic-bar survived as %q", got)
	}
	if got := request.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization survived as %q", got)
	}
	if got := request.Header.Get("X-Custom"); got != "keep" {
		t.Errorf("X-Custom = %q, want %q", got, "keep")
	}
}
