package service

import (
	"context"
	"log/slog"

	"github.com/gyrel/sandboxes-core/ids"
	"github.com/gyrel/slogx/events"
)

func (s *Service) emitPublishGrants(ctx context.Context, sandboxID string, grants []portPublishGrant) {
	for _, grant := range grants {
		emitPortPublishGranted(ctx, sandboxID, grant)
	}
}

// emitPortPublishGranted records one authorized non-loopback bind from the
// catalog constructor. Correlation ids travel in events.Standard, the same
// way every other catalog emitter in the daemon attaches them.
func emitPortPublishGranted(ctx context.Context, sandboxID string, grant portPublishGrant) {
	event, err := events.PortPublishGranted(events.OutcomeOK, events.PortPublishGrantedParams{
		SandboxID:     sandboxID,
		GuestPort:     grant.GuestPort,
		HostPort:      grant.HostPort,
		Protocol:      grant.Protocol,
		BindCIDRLabel: grant.CIDR,
		BindIP:        grant.BindIP,
	})
	if err != nil {
		// A granted publish must never lose its audit trail silently.
		slog.Warn("port publish granted event construction failed", "sandbox_id", sandboxID, "host_port", int(grant.HostPort), "error", err)
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

// emitPortPublishRefused records one denied non-loopback bind from the catalog
// constructor. The structured warning at the policy boundary remains in place;
// this event is additive audit.
func emitPortPublishRefused(ctx context.Context, sandboxID, requestedIP string, reason events.PortPublishRefusedReason) {
	event, err := events.PortPublishRefused(events.OutcomeDenied, events.PortPublishRefusedParams{
		SandboxID:   sandboxID,
		RequestedIP: requestedIP,
		Reason:      reason,
	})
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
