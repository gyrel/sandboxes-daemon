package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/gyrel/sandboxes-core"
	"github.com/gyrel/sandboxes-core/ids"
	"github.com/gyrel/sandboxes-core/sandbox"

	"github.com/gyrel/sandboxes-daemon/internal/machinecode"
	"github.com/gyrel/sandboxes-daemon/internal/store"
)

func TestPortPublishAllowlistDecisionMatrix(t *testing.T) {
	svc := newPublishTestService(t)
	for _, tc := range []struct {
		name     string
		allow    []string
		port     sandbox.Port
		wantCode machinecode.Code
		wantIP   string
		wantCIDR string
	}{
		{name: "loopback default", port: sandbox.Port{Host: 8080, Guest: 80}, wantIP: "127.0.0.1"},
		{name: "loopback 127/8", port: sandbox.Port{Host: 8080, Guest: 80, HostIP: "127.0.0.2"}, wantIP: "127.0.0.2"},
		{name: "ipv6 loopback", port: sandbox.Port{Host: 8080, Guest: 80, Protocol: "tcp6"}, wantIP: "::1"},
		{name: "non-loopback absent", port: sandbox.Port{Host: 8080, Guest: 80, HostIP: "192.0.2.10"}, wantCode: machinecode.BindForbidden},
		{name: "non-loopback empty allowlist", allow: []string{}, port: sandbox.Port{Host: 8080, Guest: 80, HostIP: "192.0.2.10"}, wantCode: machinecode.BindForbidden},
		{name: "non-loopback malformed allowlist", allow: []string{"garbage"}, port: sandbox.Port{Host: 8080, Guest: 80, HostIP: "192.0.2.10"}, wantCode: machinecode.BindForbidden},
		{
			name: "non-loopback inside v4 CIDR", allow: []string{"192.0.2.0/24"},
			port:   sandbox.Port{Host: 8080, Guest: 80, HostIP: "192.0.2.10"},
			wantIP: "192.0.2.10", wantCIDR: "192.0.2.0/24",
		},
		{
			name: "non-loopback outside v4 CIDR", allow: []string{"198.51.100.0/24"},
			port:     sandbox.Port{Host: 8080, Guest: 80, HostIP: "192.0.2.10"},
			wantCode: machinecode.BindForbidden,
		},
		{
			name: "non-loopback inside v6 CIDR", allow: []string{"2001:db8::/32"},
			port:   sandbox.Port{Host: 8080, Guest: 80, Protocol: "tcp6", HostIP: "2001:db8::5"},
			wantIP: "2001:db8::5", wantCIDR: "2001:db8::/32",
		},
		{
			name: "wildcard v4 bind refused with allow-all allow", allow: []string{"0.0.0.0/0"},
			port: sandbox.Port{Host: 8080, Guest: 80, HostIP: "0.0.0.0"}, wantCode: machinecode.BindForbidden,
		},
		{
			name: "wildcard v6 bind refused with allow-all allow", allow: []string{"::/0"},
			port: sandbox.Port{Host: 8080, Guest: 80, Protocol: "tcp6", HostIP: "::"}, wantCode: machinecode.BindForbidden,
		},
		{
			name: "concrete v4 inside wildcard allow", allow: []string{"0.0.0.0/0"},
			port:   sandbox.Port{Host: 8080, Guest: 80, HostIP: "203.0.113.9"},
			wantIP: "203.0.113.9", wantCIDR: "0.0.0.0/0",
		},
		{
			name: "explicit family mismatch", allow: []string{"192.0.2.0/24"},
			port:     sandbox.Port{Host: 8080, Guest: 80, Protocol: "tcp6", HostIP: "192.0.2.10"},
			wantCode: machinecode.SpecInvalid,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc.PublishAllowedCIDRs = tc.allow
			ports, grants, err := svc.normalizePortsForPublish(context.Background(), "sb-matrix", []sandbox.Port{tc.port})
			if tc.wantCode != "" {
				if code, ok := machinecode.Of(err); !ok || code != tc.wantCode {
					t.Fatalf("error = %v, reason = %q, want %q", err, code, tc.wantCode)
				}
				if len(ports) != 0 || len(grants) != 0 {
					t.Fatalf("refusal produced ports=%+v grants=%+v", ports, grants)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(ports) != 1 || ports[0].HostIP != tc.wantIP {
				t.Fatalf("ports = %+v, want host IP %s", ports, tc.wantIP)
			}
			if tc.wantCIDR == "" {
				if len(grants) != 0 {
					t.Fatalf("loopback produced grants %+v", grants)
				}
				return
			}
			if len(grants) != 1 || grants[0].CIDR != tc.wantCIDR || grants[0].BindIP != tc.wantIP {
				t.Fatalf("grants = %+v, want CIDR %s IP %s", grants, tc.wantCIDR, tc.wantIP)
			}
			if grants[0].GuestPort != tc.port.Guest || grants[0].HostPort != tc.port.Host {
				t.Fatalf("grant ports = %+v", grants[0])
			}
		})
	}
}

func TestPublishGrantedEventFields(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)

	svc := newPublishTestService(t)
	svc.PublishAllowedCIDRs = []string{"192.0.2.0/24"}
	ctx := ids.WithReqID(ids.WithOpID(context.Background(), ids.NewOpID()), ids.NewReqID())
	ports, grants, err := svc.normalizePortsForPublish(ctx, "sb-audit", []sandbox.Port{{Host: 18080, Guest: 8080, HostIP: "192.0.2.10"}})
	if err != nil || len(ports) != 1 || len(grants) != 1 {
		t.Fatalf("decision ports=%+v grants=%+v err=%v", ports, grants, err)
	}
	svc.emitPublishGrants(ctx, "sb-audit", grants)

	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("granted event was not emitted")
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("event is not JSON: %v (%s)", err, line)
	}
	want := map[string]any{
		"schema_version":  float64(1),
		"event":           "gyrel.port.publish-granted",
		"component":       "daemon",
		"outcome":         "ok",
		"sandbox_id":      "sb-audit",
		"guest_port":      float64(8080),
		"host_port":       float64(18080),
		"protocol":        "tcp",
		"bind_cidr_label": "192.0.2.0/24",
		"bind_ip":         "192.0.2.10",
	}
	for key, value := range want {
		if record[key] != value {
			t.Errorf("%s = %v, want %v", key, record[key], value)
		}
	}
	if record["op_id"] == nil || record["req_id"] == nil {
		t.Fatalf("correlation fields missing: %v", record)
	}
}

func TestCreateNonLoopbackWithoutAllowlistLeavesNoLease(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "publish-refusal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)

	_, err = svc.Create(ctx, CreateRequest{
		Name:  "denied-bind",
		Ports: []sandbox.Port{{Host: 28080, Guest: 80, HostIP: "192.0.2.10"}},
	})
	if code, ok := machinecode.Of(err); !ok || code != machinecode.BindForbidden {
		t.Fatalf("error = %v, reason = %q, want BIND_FORBIDDEN", err, code)
	}
	if backend.created != 0 {
		t.Fatalf("runtime created %d sandboxes after refusal", backend.created)
	}
	list, _, err := svc.List(ctx, sandbox.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("refusal persisted %d lease rows: %+v", len(list), list)
	}
	if _, err := svc.GetByName(ctx, "denied-bind"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("lookup after refusal = %v", err)
	}
}

func TestUpdatePortsRefusalKeepsStoredPorts(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "publish-update.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	op, err := svc.Create(ctx, CreateRequest{Name: "kept"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdatePorts(ctx, op.SandboxID, []sandbox.Port{{Host: 28081, Guest: 80, HostIP: "192.0.2.10"}}); err == nil {
		t.Fatal("non-loopback update without an allowlist was accepted")
	} else if code, ok := machinecode.Of(err); !ok || code != machinecode.BindForbidden {
		t.Fatalf("error = %v, reason = %q", err, code)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sb.Ports) != 0 {
		t.Fatalf("refused update persisted ports %+v", sb.Ports)
	}
}

func TestCreateAllowedNonLoopbackPublishesAuditEvent(t *testing.T) {
	ip := localNonLoopbackIPv4(t)
	port := freeTCPPortOn(t, ip)

	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)

	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "publish-granted.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	svc.PublishAllowedCIDRs = []string{ip.String() + "/32"}

	op, err := svc.Create(ctx, CreateRequest{
		Name:  "granted-bind",
		Ports: []sandbox.Port{{Host: port, Guest: 8080, HostIP: ip.String()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sb.Ports) != 1 || sb.Ports[0].HostIP != ip.String() {
		t.Fatalf("stored ports = %+v", sb.Ports)
	}

	var event map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil {
			continue
		}
		if record["event"] == "gyrel.port.publish-granted" {
			event = record
			break
		}
	}
	if event == nil {
		t.Fatal("create did not emit a publish-granted event")
	}
	if event["sandbox_id"] != op.SandboxID || event["bind_ip"] != ip.String() ||
		event["bind_cidr_label"] != ip.String()+"/32" || event["host_port"] != float64(port) {
		t.Fatalf("granted event = %+v", event)
	}
}

func TestStartRevokedNonLoopbackGrantFailsClosed(t *testing.T) {
	ip := localNonLoopbackIPv4(t)
	port := freeTCPPortOn(t, ip)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "publish-start.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	creator := New(st, nil)
	creator.PublishAllowedCIDRs = []string{ip.String() + "/32"}
	op, err := creator.Create(ctx, CreateRequest{
		Name:  "revoked-bind",
		Ports: []sandbox.Port{{Host: port, Guest: 8080, HostIP: ip.String()}},
	})
	if err != nil {
		t.Fatal(err)
	}

	backend := &fakeRuntime{}
	runner := New(st, backend)
	if _, err := runner.Start(ctx, op.SandboxID); err == nil {
		t.Fatal("start honored a non-loopback port after the grant was revoked")
	} else if code, ok := machinecode.Of(err); !ok || code != machinecode.BindForbidden {
		t.Fatalf("error = %v, reason = %q", err, code)
	}
	if backend.started != 0 {
		t.Fatalf("runtime started %d times after refusal", backend.started)
	}
	sb, err := runner.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.State != sandbox.Stopped {
		t.Fatalf("refused start changed state to %s", sb.State)
	}
}

func newPublishTestService(t *testing.T) *Service {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "publish-service.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, nil)
}

func localNonLoopbackIPv4(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range addrs {
		ipNet, ok := candidate.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() && addr.IsGlobalUnicast() && !addr.IsLoopback() {
			return addr
		}
	}
	t.Skip("no non-loopback IPv4 interface available")
	return netip.Addr{}
}

func freeTCPPortOn(t *testing.T, ip netip.Addr) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Skipf("cannot bind a probe socket on %s: %v", ip, err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
