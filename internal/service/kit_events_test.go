package service

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"github.com/gyrel/sandboxes-core/ids"
	"github.com/gyrel/slogx/events"
)

func TestKitCheckEventsRedactInputs(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx := ids.WithReqID(ids.WithOpID(context.Background(), ids.NewOpID()), ids.NewReqID())
	for _, tc := range []struct {
		reason localv1.CheckKitReason
		want   string
	}{
		{localv1.CheckKitReason_CHECK_KIT_REASON_OK, `"outcome":"ok"`},
		{localv1.CheckKitReason_CHECK_KIT_REASON_SOURCE_NOT_ALLOWED, `"reason":"SourceNotAllowed"`},
		{localv1.CheckKitReason_CHECK_KIT_REASON_LOCAL_DISABLED, `"reason":"LocalKitDisabled"`},
		{localv1.CheckKitReason_CHECK_KIT_REASON_SIGNATURE_REQUIRED, `"reason":"SignatureRequired"`},
		{localv1.CheckKitReason_CHECK_KIT_REASON_INVALID_REFERENCE, `"reason":"InvalidReference"`},
		{localv1.CheckKitReason_CHECK_KIT_REASON_POLICY_UNAVAILABLE, `"reason":"PolicyUnavailable"`},
	} {
		output.Reset()
		emitKitCheck(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_GIT, "synthetic-secret-canary", []string{"git"}, false, false, tc.reason)
		got := output.String()
		if !strings.Contains(got, tc.want) || strings.Contains(got, "synthetic-secret-canary") {
			t.Fatalf("unexpected event: %s", got)
		}
		op, req := ids.FromContext(ctx)
		if !strings.Contains(got, op) || !strings.Contains(got, req) {
			t.Fatal("missing correlation IDs")
		}
	}
}

func TestPlatformUnsupportedEventsRedactInputs(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx := ids.WithReqID(ids.WithOpID(context.Background(), ids.NewOpID()), ids.NewReqID())
	emitPlatformUnsupported(ctx, events.PlatformUnsupportedCapabilityApprovalprovidermissing)
	got := output.String()
	if !strings.Contains(got, `"capability":"ApprovalProviderMissing"`) || !strings.Contains(got, `"outcome":"unsupported"`) {
		t.Fatalf("unexpected event: %s", got)
	}
}
