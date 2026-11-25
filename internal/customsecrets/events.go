package customsecrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"runtime"

	"github.com/rheic/sandboxes-core/ids"
	"github.com/rheic/slogx/events"
)

// emitSecretWrite records one host-vault write attempt. The vault account key
// is reduced to a SHA-256 digest; the placeholder is only ever echoed once by
// the write path that returns it, so the event reports issuance without
// carrying the placeholder itself.
func emitSecretWrite(ctx context.Context, account string, placeholderIssued bool, outcome events.Outcome) {
	sum := sha256.Sum256([]byte(account))
	event, err := events.SecretWrite(outcome, events.SecretWriteParams{
		SecretRefID:       events.ID(hex.EncodeToString(sum[:])),
		VaultBackend:      vaultBackend(),
		PlaceholderIssued: placeholderIssued,
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

// vaultBackend maps the platform credential vault the chunked store drives.
func vaultBackend() events.SecretWriteVaultBackend {
	switch runtime.GOOS {
	case "darwin":
		return events.SecretWriteVaultBackendKeychain
	case "windows":
		return events.SecretWriteVaultBackendCredman
	default:
		return events.SecretWriteVaultBackendSecretservice
	}
}
