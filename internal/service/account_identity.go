package service

import (
	"context"

	"github.com/rheic/sandboxes-daemon/internal/registrycredentials"
)

// AccountUsername returns the stored display label for a signed-in account.
// The Docker account keeps its Hub username in the registry credential index
// at login (device OAuth and PAT paths); other providers have no stored label
// yet. This is identity display data, consistent with `rsbx secret ls`:
// token material is never read here.
func (s *Service) AccountUsername(ctx context.Context, provider string) (string, error) {
	if provider != dockerAccountProvider {
		return "", nil
	}
	entries, err := s.store.ListRegistryCredentialIndex(ctx)
	if err != nil {
		return "", err
	}
	for index := range entries {
		entry := &entries[index]
		if entry.Registry != dockerHubRegistry || entry.Username == "" {
			continue
		}
		switch registrycredentials.Scope(entry.Scope) {
		case registrycredentials.ScopeHostOnly, registrycredentials.ScopeAllSandboxes:
			return entry.Username, nil
		}
	}
	return "", nil
}
