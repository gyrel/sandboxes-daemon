package service

import (
	"context"
	"log/slog"

	"github.com/gyrel/sandboxes-core/ids"
	"github.com/gyrel/slogx/events"
)

// portPublishGrantedEvent is the catalog name for an authorized non-loopback
// host port publish. slogx v0.3.0 has no constructor for this name and the
// dependency is pinned, so the daemon emits the catalog shape directly:
// schema_version, event, component, outcome, typed fields, then correlation.
const portPublishGrantedEvent = "gyrel.port.publish-granted"

func (s *Service) emitPublishGrants(ctx context.Context, sandboxID string, grants []portPublishGrant) {
	for _, grant := range grants {
		emitPortPublishGranted(ctx, sandboxID, grant)
	}
}

func emitPortPublishGranted(ctx context.Context, sandboxID string, grant portPublishGrant) {
	attrs := []slog.Attr{
		slog.Int("schema_version", 1),
		slog.String("event", portPublishGrantedEvent),
		slog.String("component", "daemon"),
		slog.String("outcome", string(events.OutcomeOK)),
		slog.String("sandbox_id", sandboxID),
		slog.Int("guest_port", int(grant.GuestPort)),
		slog.Int("host_port", int(grant.HostPort)),
		slog.String("protocol", grant.Protocol),
		slog.String("bind_cidr_label", grant.CIDR),
		slog.String("bind_ip", grant.BindIP),
	}
	op, req := ids.FromContext(ctx)
	if ids.Validate(op) == nil {
		attrs = append(attrs, slog.String("op_id", op))
	}
	if ids.Validate(req) == nil {
		attrs = append(attrs, slog.String("req_id", req))
	}
	slog.LogAttrs(ctx, slog.LevelInfo, portPublishGrantedEvent, attrs...)
}
