package servicesecrets

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
// is reduced to a SHA-256 digest so service identities, scopes and secret
// material never enter the catalog; the backend names the OS vault in use.
func emitSecretWrite(ctx context.Context, account string, outcome events.Outcome) {
	sum := sha256.Sum256([]byte(account))
	event, err := events.SecretWrite(outcome, events.SecretWriteParams{
		SecretRefID:  events.ID(hex.EncodeToString(sum[:])),
		VaultBackend: vaultBackend(),
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

// vaultBackend maps the platform credential vault go-keyring drives.
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
