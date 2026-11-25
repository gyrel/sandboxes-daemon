package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"github.com/rheic/sandboxes-core/ids"
	"github.com/rheic/slogx/events"
)

func emitKitCheck(ctx context.Context, kind localv1.KitSourceKind, ref string, sources []string, local, signature bool, reason localv1.CheckKitReason) {
	p := events.KitCheckParams{Source: events.ID(kitSourceKindName(kind)), AllowLocal: local, RequireSignature: signature, Mode: events.KitCheckModeDaemonChecked}
	// References may contain credentials, so only a digest is emitted.
	refHash := sha256.Sum256([]byte(ref))
	p.KitRef = events.ID(hex.EncodeToString(refHash[:]))
	sourcesHash := sha256.Sum256([]byte(strings.Join(sources, ",")))
	p.AllowedSourcesHash = events.Hash(hex.EncodeToString(sourcesHash[:]))
	outcome := events.OutcomeDenied
	p.Decision = events.KitCheckDecisionDeny
	switch reason {
	case localv1.CheckKitReason_CHECK_KIT_REASON_OK:
		outcome = events.OutcomeOK
		p.Decision = events.KitCheckDecisionAllow
	case localv1.CheckKitReason_CHECK_KIT_REASON_SOURCE_NOT_ALLOWED:
		p.Reason = events.KitCheckReasonSourcenotallowed
	case localv1.CheckKitReason_CHECK_KIT_REASON_LOCAL_DISABLED:
		p.Reason = events.KitCheckReasonLocalkitdisabled
	case localv1.CheckKitReason_CHECK_KIT_REASON_SIGNATURE_REQUIRED:
		p.Reason = events.KitCheckReasonSignaturerequired
	case localv1.CheckKitReason_CHECK_KIT_REASON_INVALID_REFERENCE:
		p.Reason = events.KitCheckReasonInvalidreference
	case localv1.CheckKitReason_CHECK_KIT_REASON_POLICY_UNAVAILABLE:
		p.Reason = events.KitCheckReasonPolicyunavailable
	default:
		return
	}
	event, err := events.KitCheck(outcome, p)
	if err != nil {
		return
	}
	op, req := ids.FromContext(ctx)
	standard := events.Standard{}
	if ids.Validate(op) == nil {
		id := events.ID(op)
		standard.OpID = &id
	}
	if ids.Validate(req) == nil {
		id := events.ID(req)
		standard.ReqID = &id
	}
	event.Emit(ctx, slog.Default(), standard)
}

func emitPlatformUnsupported(ctx context.Context, capability events.PlatformUnsupportedCapability) {
	event, err := events.PlatformUnsupported(events.OutcomeUnsupported, events.PlatformUnsupportedParams{Capability: capability})
	if err != nil {
		return
	}
	op, req := ids.FromContext(ctx)
	standard := events.Standard{}
	if ids.Validate(op) == nil {
		id := events.ID(op)
		standard.OpID = &id
	}
	if ids.Validate(req) == nil {
		id := events.ID(req)
		standard.ReqID = &id
	}
	event.Emit(ctx, slog.Default(), standard)
}
