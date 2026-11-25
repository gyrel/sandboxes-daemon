package secretproxy

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestEnforceResponseLimitAllowsResponseAtLimit(t *testing.T) {
	response := &http.Response{ContentLength: maxResponseBody, Body: io.NopCloser(strings.NewReader("ok"))}

	if err := enforceResponseLimit(response); err != nil {
		t.Fatalf("enforce response limit: %v", err)
	}
	got, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read bounded response: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("response = %q, want %q", got, "ok")
	}
}

func TestEnforceResponseLimitRejectsOversizedContentLength(t *testing.T) {
	response := &http.Response{ContentLength: maxResponseBody + 1, Body: io.NopCloser(strings.NewReader("unused"))}

	if err := enforceResponseLimit(response); !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("enforce response limit error = %v, want %v", err, errResponseTooLarge)
	}
}

func TestBoundedResponseBodyAllowsPayloadAtLimit(t *testing.T) {
	body := &boundedResponseBody{body: io.NopCloser(strings.NewReader("abc")), remaining: 3}

	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read response at limit: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("response = %q, want %q", got, "abc")
	}
}

func TestBoundedResponseBodyRejectsPayloadOverLimit(t *testing.T) {
	body := &boundedResponseBody{body: io.NopCloser(strings.NewReader("abcd")), remaining: 3}

	got, err := io.ReadAll(body)
	if !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("read error = %v, want %v", err, errResponseTooLarge)
	}
	if string(got) != "abc" {
		t.Fatalf("response bytes before rejection = %q, want %q", got, "abc")
	}
}

func TestEnforceResponseLimitPreservesUpgradeStream(t *testing.T) {
	local, peer := net.Pipe()
	defer func() { _ = local.Close(); _ = peer.Close() }()
	response := &http.Response{StatusCode: http.StatusSwitchingProtocols, Body: local, Header: http.Header{"Upgrade": {"websocket"}}, Request: &http.Request{Header: http.Header{"X-Gyrel-Secret-Proxy": {"openai-oauth"}}}}
	if err := enforceResponseLimit(response); err != nil {
		t.Fatal(err)
	}
	if _, ok := response.Body.(io.ReadWriteCloser); !ok {
		t.Fatal("upgrade lost write capability")
	}
	other := &http.Response{StatusCode: http.StatusSwitchingProtocols, Body: local, Header: response.Header, Request: &http.Request{Header: http.Header{"X-Gyrel-Secret-Proxy": {"openai"}}}}
	if err := enforceResponseLimit(other); err == nil {
		t.Fatal("accepted upgrade for another route")
	}
	nonWebSocket := &http.Response{StatusCode: http.StatusSwitchingProtocols, Body: local, Header: http.Header{"Upgrade": {"other"}}, Request: response.Request}
	if err := enforceResponseLimit(nonWebSocket); err == nil {
		t.Fatal("accepted non-WebSocket upgrade")
	}
	invalid := &http.Response{StatusCode: http.StatusSwitchingProtocols, Body: io.NopCloser(strings.NewReader("")), Header: response.Header, Request: response.Request}
	if err := enforceResponseLimit(invalid); err == nil {
		t.Fatal("accepted non-writable upgrade")
	}
}
