package mcpmanager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"

	"github.com/gyrel/sandboxes-core/ids"
	"github.com/gyrel/slogx/events"
)

func emitRegistration(ctx context.Context, name string, challenge, stored bool) {
	sum := sha256.Sum256([]byte(name))
	event, err := events.MCPRegister(events.OutcomeOK, events.MCPRegisterParams{
		ServerIDHash: events.Hash(hex.EncodeToString(sum[:12])), ChallengeIssued: challenge, Stored: stored,
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

// emitLoad records attachment without exposing the server name or sandbox data.
func emitLoad(ctx context.Context, name string) {
	sum := sha256.Sum256([]byte(name))
	event, err := events.MCPLoad(events.OutcomeOK, events.MCPLoadParams{
		ServerIDHash: events.Hash(hex.EncodeToString(sum[:12])),
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
