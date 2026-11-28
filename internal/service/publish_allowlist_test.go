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
	"github.com/gyrel/slogx/events"

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
	capture := &captureHandler{}
	previous := slog.Default()
	slog.SetDefault(slog.New(capture))
	defer slog.SetDefault(previous)

	svc := newPublishTestService(t)
	svc.PublishAllowedCIDRs = []string{"192.0.2.0/24"}
	ctx := ids.WithReqID(ids.WithOpID(context.Background(), ids.NewOpID()), ids.NewReqID())
	ports, grants, err := svc.normalizePortsForPublish(ctx, "sb-audit", []sandbox.Port{{Host: 18080, Guest: 8080, HostIP: "192.0.2.10"}})
	if err != nil || len(ports) != 1 || len(grants) != 1 {
		t.Fatalf("decision ports=%+v grants=%+v err=%v", ports, grants, err)
	}
	svc.emitPublishGrants(ctx, "sb-audit", grants)

	record, ok := capture.find("gyrel.port.publish-granted")
	if !ok {
		t.Fatal("granted event was not emitted")
	}

	op, req := ids.FromContext(ctx)
	opID, reqID := events.ID(op), events.ID(req)
	wantEvent, err := events.PortPublishGranted(events.OutcomeOK, events.PortPublishGrantedParams{
		SandboxID:     "sb-audit",
		GuestPort:     8080,
		HostPort:      18080,
		Protocol:      "tcp",
		BindCIDRLabel: "192.0.2.0/24",
		BindIP:        "192.0.2.10",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Field set, deterministic ordering and value kinds must match the catalog
	// constructor exactly: the raw slog.Int emission used Int64 for the ports,
	// while the catalog emits Uint64.
	want := wantEvent.Attrs(events.Standard{OpID: &opID, ReqID: &reqID})
	if len(record.attrs) != len(want) {
		t.Fatalf("granted event attrs = %v, want %v", attrKeys(record.attrs), attrKeys(want))
	}
	for i := range want {
		got := record.attrs[i]
		if got.Key != want[i].Key || !got.Value.Equal(want[i].Value) {
			t.Fatalf("granted attr[%d] = %s(%v), want %s(%v)", i, got.Key, got.Value, want[i].Key, want[i].Value)
		}
	}
}

func TestPublishRefusedEventFields(t *testing.T) {
	for _, tc := range []struct {
		name       string
		allow      []string
		hostIP     string
		wantReason events.PortPublishRefusedReason
	}{
		{name: "allowlist absent", hostIP: "192.0.2.10", wantReason: events.PortPublishRefusedReasonBindForbidden},
		{name: "outside allowlist", allow: []string{"198.51.100.0/24"}, hostIP: "192.0.2.10", wantReason: events.PortPublishRefusedReasonBindForbidden},
		{name: "wildcard bind", allow: []string{"0.0.0.0/0"}, hostIP: "0.0.0.0", wantReason: events.PortPublishRefusedReasonBindForbidden},
		{name: "malformed allowlist", allow: []string{"garbage"}, hostIP: "192.0.2.10", wantReason: events.PortPublishRefusedReasonAllowlistInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := &captureHandler{}
			previous := slog.Default()
			slog.SetDefault(slog.New(capture))
			defer slog.SetDefault(previous)

			svc := newPublishTestService(t)
			svc.PublishAllowedCIDRs = tc.allow
			ctx := ids.WithReqID(ids.WithOpID(context.Background(), ids.NewOpID()), ids.NewReqID())
			_, _, err := svc.normalizePortsForPublish(ctx, "sb-refused", []sandbox.Port{{Host: 18081, Guest: 8080, HostIP: tc.hostIP}})
			if code, ok := machinecode.Of(err); !ok || code != machinecode.BindForbidden {
				t.Fatalf("error = %v, reason = %q, want BIND_FORBIDDEN", err, code)
			}

			record, ok := capture.find("gyrel.port.publish-refused")
			if !ok {
				t.Fatal("refused event was not emitted")
			}
			op, req := ids.FromContext(ctx)
			opID, reqID := events.ID(op), events.ID(req)
			wantEvent, err := events.PortPublishRefused(events.OutcomeDenied, events.PortPublishRefusedParams{
				SandboxID:   "sb-refused",
				RequestedIP: tc.hostIP,
				Reason:      tc.wantReason,
			})
			if err != nil {
				t.Fatal(err)
			}
			want := wantEvent.Attrs(events.Standard{OpID: &opID, ReqID: &reqID})
			if len(record.attrs) != len(want) {
				t.Fatalf("refused event attrs = %v, want %v", attrKeys(record.attrs), attrKeys(want))
			}
			for i := range want {
				got := record.attrs[i]
				if got.Key != want[i].Key || !got.Value.Equal(want[i].Value) {
					t.Fatalf("refused attr[%d] = %s(%v), want %s(%v)", i, got.Key, got.Value, want[i].Key, want[i].Value)
				}
			}

			// The structured warning is additive; the refusal event must not
			// replace it.
			warning, ok := capture.find("port publish refused")
			if !ok {
				t.Fatal("structured refusal warning was not emitted")
			}
			if reason := warning.attrString("reason"); reason != string(tc.wantReason) {
				t.Fatalf("warning reason = %q, want %q", reason, tc.wantReason)
			}
		})
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

// captureHandler records raw slog attributes so catalog emissions can be
// compared field-for-field with their constructor's Attrs output.
type captureHandler struct {
	records []captureRecord
}

type captureRecord struct {
	message string
	attrs   []slog.Attr
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := make([]slog.Attr, 0, record.NumAttrs())
	record.Attrs(func(attr slog.Attr) bool {
		attrs = append(attrs, attr)
		return true
	})
	h.records = append(h.records, captureRecord{message: record.Message, attrs: attrs})
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) find(message string) (captureRecord, bool) {
	for _, record := range h.records {
		if record.message == message {
			return record, true
		}
	}
	return captureRecord{}, false
}

func (r captureRecord) attrString(key string) string {
	for _, attr := range r.attrs {
		if attr.Key == key && attr.Value.Kind() == slog.KindString {
			return attr.Value.String()
		}
	}
	return ""
}

func attrKeys(attrs []slog.Attr) []string {
	keys := make([]string, len(attrs))
	for i := range attrs {
		keys[i] = attrs[i].Key
	}
	return keys
}
