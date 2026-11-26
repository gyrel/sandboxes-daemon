package secretproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"

	"github.com/gyrel/sandboxes-core/ids"
	"github.com/gyrel/slogx/events"
)

// emitSecretSubstitute records one substitution decision. Placeholder values
// and header bodies never enter the catalog: a bound reference is reduced to
// a SHA-256 digest of its placeholder, and refusals without a single bound
// reference (scheme or vault failures) emit an empty secret_ref_id.
func emitSecretSubstitute(ctx context.Context, host, placeholder string,
	decision events.SecretSubstituteDecision, reason events.SecretSubstituteReason, outcome events.Outcome) {
	p := events.SecretSubstituteParams{
		Host: events.Host(host), Scheme: events.SecretSubstituteSchemeHTTPS, Decision: decision, Reason: reason,
	}
	if placeholder != "" {
		sum := sha256.Sum256([]byte(placeholder))
		p.SecretRefID = events.ID(hex.EncodeToString(sum[:]))
	}
	event, err := events.SecretSubstitute(outcome, p)
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
