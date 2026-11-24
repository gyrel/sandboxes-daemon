package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	core "github.com/rheic/sandboxes-core"

	"github.com/rheic/sandboxes-daemon/internal/customsecrets"
	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

// ErrCustomSecretApprovalUnavailable reports that a reference or command source
// needs a trusted OS-backed approval provider, which this daemon does not have
// yet. Such sources are refused before anything is stored.
var ErrCustomSecretApprovalUnavailable = fmt.Errorf("%w: custom secret reference and command sources require trusted host approval, which is not available", core.ErrConflict)

// CustomSecretSetRequest is one set-custom request after RPC decoding. Value is
// write-only; the caller clears it.
type CustomSecretSetRequest struct {
	Service     string
	Scope       servicesecrets.Scope
	SandboxName string
	Value       []byte
	Source      *servicesecrets.Source
	Env         string
	Placeholder string
	Hosts       []string
}

// SetCustomSecretStore configures host-keychain storage for custom secrets.
func (s *Service) SetCustomSecretStore(secretStore *customsecrets.Store) {
	s.customSecrets = secretStore
}

// SetCustomSecret stores or replaces one custom secret. It returns the
// non-secret summary and the full placeholder, which the write path echoes once.
// The placeholder is written to the keychain together with the value, and only
// its mask reaches SQLite.
func (s *Service) SetCustomSecret(ctx context.Context, req CustomSecretSetRequest) (customsecrets.Summary, string, error) {
	defer clear(req.Value)
	if s.customSecrets == nil || s.store == nil {
		return customsecrets.Summary{}, "", errors.New("custom secret store is unavailable")
	}
	if req.Source != nil && (req.Source.Reference != "" || req.Source.Command != "") {
		slog.Info("custom secret refused", "decision", "approval_unavailable", "service", req.Service)
		return customsecrets.Summary{}, "", ErrCustomSecretApprovalUnavailable
	}
	scope, sandboxName, err := customsecrets.ValidateScope(req.Scope, req.SandboxName)
	if err != nil {
		return customsecrets.Summary{}, "", err
	}
	if err := customsecrets.ValidateValue(req.Value); err != nil {
		return customsecrets.Summary{}, "", err
	}
	hosts, err := customsecrets.NormalizeHosts(req.Hosts)
	if err != nil {
		return customsecrets.Summary{}, "", err
	}
	name, err := customServiceName(req.Service, hosts)
	if err != nil {
		return customsecrets.Summary{}, "", err
	}
	if err := customsecrets.ValidateEnvName(req.Env); err != nil {
		return customsecrets.Summary{}, "", err
	}
	release, err := s.acquireCredentialGate(ctx, customSecretGateKey(name, scope, sandboxName))
	if err != nil {
		return customsecrets.Summary{}, "", err
	}
	defer release()
	return s.storeCustomSecret(ctx, customSecretWrite{
		name: name, scope: scope, sandboxName: sandboxName, hosts: hosts,
		env: req.Env, placeholderRequest: req.Placeholder, value: string(req.Value),
	})
}

type customSecretWrite struct {
	name, sandboxName, env, placeholderRequest, placeholder, value string
	scope                                                          servicesecrets.Scope
	hosts                                                          []string
}

func (s *Service) storeCustomSecret(ctx context.Context, write customSecretWrite) (customsecrets.Summary, string, error) {
	previous, previousErr := s.customSecrets.Load(ctx, write.name, write.scope, write.sandboxName)
	hadPrevious := previousErr == nil
	if previousErr != nil && !customsecrets.IsNotFound(previousErr) {
		return customsecrets.Summary{}, "", fmt.Errorf("check existing custom secret: %w", previousErr)
	}
	placeholder, err := choosePlaceholder(write.placeholderRequest, previous, hadPrevious, []byte(write.value))
	if err != nil {
		return customsecrets.Summary{}, "", err
	}
	write.placeholder = placeholder
	previousIndex, indexErr := s.store.GetCustomSecretIndex(ctx, write.name, string(write.scope), write.sandboxName)
	if indexErr != nil && !errors.Is(indexErr, core.ErrNotFound) {
		return customsecrets.Summary{}, "", fmt.Errorf("check existing custom secret index: %w", indexErr)
	}
	now := s.now().UTC()
	createdAt := now
	if indexErr == nil {
		createdAt = previousIndex.CreatedAt
	}
	record := customsecrets.Record{Placeholder: write.placeholder, Value: write.value}
	if err := s.customSecrets.Save(ctx, write.name, write.scope, write.sandboxName, record); err != nil {
		return customsecrets.Summary{}, "", err
	}
	entry := store.CustomSecretIndex{
		Service: write.name, Scope: string(write.scope), SandboxName: write.sandboxName, EnvName: write.env,
		Hosts: write.hosts, PlaceholderMasked: customsecrets.MaskPlaceholder(write.placeholder),
		Origin: servicesecrets.OriginLocal, CreatedAt: createdAt, UpdatedAt: now,
	}
	if err := s.store.UpsertCustomSecretIndex(ctx, entry); err != nil {
		return customsecrets.Summary{}, "", errors.Join(err, s.rollbackCustomSecret(ctx, write, previous, hadPrevious))
	}
	slog.Info("custom secret stored", "decision", "stored", "service", write.name, "scope", string(write.scope),
		"sandbox", write.sandboxName, "hosts", write.hosts, "env", write.env, "replaced", hadPrevious)
	return customSummary(entry), write.placeholder, nil
}

// choosePlaceholder keeps the placeholder that the sandbox environment already
// holds when an update does not name a new one. A rotated value must not orphan
// running sandboxes whose environment carries the old placeholder.
func choosePlaceholder(request string, previous customsecrets.Record, hadPrevious bool, value []byte) (string, error) {
	if request == "" && hadPrevious && customsecrets.ValidatePlaceholder(previous.Placeholder, value) == nil {
		return previous.Placeholder, nil
	}
	return customsecrets.ResolvePlaceholder(request, value, rand.Reader)
}

// rollbackCustomSecret restores the previous keychain record, or removes the new
// one, when the metadata write fails. A failed rollback is reported, not hidden.
func (s *Service) rollbackCustomSecret(ctx context.Context, write customSecretWrite, previous customsecrets.Record, hadPrevious bool) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var err error
	if hadPrevious {
		err = s.customSecrets.Save(rollbackCtx, write.name, write.scope, write.sandboxName, previous)
	} else {
		err = s.customSecrets.Delete(rollbackCtx, write.name, write.scope, write.sandboxName)
		if customsecrets.IsNotFound(err) {
			err = nil
		}
	}
	if err != nil {
		return fmt.Errorf("roll back custom secret after index failure: %w", err)
	}
	return nil
}

// ListCustomSecrets returns non-secret custom secret summaries.
func (s *Service) ListCustomSecrets(ctx context.Context) ([]customsecrets.Summary, error) {
	if s.store == nil {
		return nil, errors.New("custom secret index is unavailable")
	}
	entries, err := s.store.ListCustomSecretIndex(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]customsecrets.Summary, 0, len(entries))
	for index := range entries {
		out = append(out, customSummary(entries[index]))
	}
	return out, nil
}

// RemoveCustomSecret deletes one custom secret. It reports false when no custom
// secret matches, so callers can fall back to service secrets. Upgraded streams
// authorized under the secret are closed first, then the keychain record, then
// the index row. A failure after the keychain delete leaves the row behind, and
// a retry converges because a missing keychain record is not an error.
func (s *Service) RemoveCustomSecret(ctx context.Context, service string, scope servicesecrets.Scope, sandboxName string) (bool, error) {
	service = strings.ToLower(strings.TrimSpace(service))
	scope, sandboxName, err := customsecrets.ValidateScope(scope, sandboxName)
	if err != nil || s.customSecrets == nil || s.store == nil {
		// An invalid key cannot name a custom secret. The service-secret path
		// validates the same key and reports the error for its own namespace.
		return false, nil
	}
	release, err := s.acquireCredentialGate(ctx, customSecretGateKey(service, scope, sandboxName))
	if err != nil {
		return false, err
	}
	defer release()
	if _, err := s.store.GetCustomSecretIndex(ctx, service, string(scope), sandboxName); errors.Is(err, core.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := s.revokeCustomSecretStreams(ctx, scope, sandboxName); err != nil {
		return false, err
	}
	if err := s.customSecrets.Delete(ctx, service, scope, sandboxName); err != nil && !customsecrets.IsNotFound(err) {
		return false, err
	}
	if err := s.store.DeleteCustomSecretIndex(ctx, service, string(scope), sandboxName); err != nil {
		return false, err
	}
	slog.Info("custom secret removed", "decision", "removed", "service", service, "scope", string(scope), "sandbox", sandboxName)
	return true, nil
}

// revokeCustomSecretStreams closes hijacked streams that were authorized while
// the custom secret could be substituted. Global secrets reach every sandbox, so
// every sandbox's channel is revoked.
func (s *Service) revokeCustomSecretStreams(ctx context.Context, scope servicesecrets.Scope, sandboxName string) error {
	if scope == servicesecrets.ScopeSandbox {
		s.revokeSandboxStreams(sandboxName)
		return nil
	}
	sandboxes, err := s.listAll(ctx)
	if err != nil {
		return fmt.Errorf("list sandboxes for custom secret revocation: %w", err)
	}
	for index := range sandboxes {
		s.revokeSandboxStreams(sandboxes[index].Name)
	}
	return nil
}

// cleanupSandboxCustomSecrets removes sandbox-scoped custom secrets with their
// sandbox, mirroring service secret cleanup.
func (s *Service) cleanupSandboxCustomSecrets(ctx context.Context, sandboxName string) error {
	if s.customSecrets == nil || s.store == nil {
		return nil
	}
	entries, err := s.store.ListCustomSecretIndexForSandbox(ctx, sandboxName)
	if err != nil {
		return err
	}
	var failures []error
	for index := range entries {
		entry := &entries[index]
		if entry.Scope != string(servicesecrets.ScopeSandbox) || entry.SandboxName != sandboxName {
			continue
		}
		if err := s.customSecrets.Delete(ctx, entry.Service, servicesecrets.ScopeSandbox, sandboxName); err != nil && !customsecrets.IsNotFound(err) {
			failures = append(failures, fmt.Errorf("remove custom secret: %w", err))
			continue
		}
		if err := s.store.DeleteCustomSecretIndex(ctx, entry.Service, entry.Scope, entry.SandboxName); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// customCreateEnv appends one placeholder per custom secret that names an
// environment variable and applies to this sandbox. Only placeholders are
// injected, never values. A name collision with user environment fails the
// create instead of silently overriding either entry.
func (s *Service) customCreateEnv(ctx context.Context, sandboxName string, env []string) ([]string, error) {
	if s.customSecrets == nil || s.store == nil {
		return env, nil
	}
	entries, err := s.store.ListCustomSecretIndexForSandbox(ctx, sandboxName)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]struct{}, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		keys[key] = struct{}{}
	}
	out := slices.Clone(env)
	for index := range entries {
		entry := &entries[index]
		if entry.EnvName == "" {
			continue
		}
		if _, exists := keys[entry.EnvName]; exists {
			return nil, fmt.Errorf("%w: custom secret environment name %s collides with another environment entry", core.ErrConflict, entry.EnvName)
		}
		record, err := s.customSecrets.Load(ctx, entry.Service, servicesecrets.Scope(entry.Scope), secretScopeSandboxName(servicesecrets.Scope(entry.Scope), sandboxName))
		if customsecrets.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		keys[entry.EnvName] = struct{}{}
		out = append(out, entry.EnvName+"="+record.Placeholder)
	}
	return out, nil
}

// customSubstitutions returns the per-request resolver for a sandbox route whose
// upstream is upstreamHost. Bindings are read on every request, so set and
// remove take effect without restarting the channel.
func (s *Service) customSubstitutions(sandboxName, upstreamHost string) secretproxy.SubstitutionResolver {
	if s.customSecrets == nil || s.store == nil {
		return nil
	}
	return func(ctx context.Context) ([]secretproxy.Substitution, error) {
		return s.resolveCustomSubstitutions(ctx, sandboxName, upstreamHost)
	}
}

func (s *Service) resolveCustomSubstitutions(ctx context.Context, sandboxName, upstreamHost string) ([]secretproxy.Substitution, error) {
	entries, err := s.store.ListCustomSecretIndexForSandbox(ctx, sandboxName)
	if err != nil {
		return nil, err
	}
	var out []secretproxy.Substitution
	for index := range entries {
		entry := &entries[index]
		if !anyHostMatches(entry.Hosts, upstreamHost) {
			continue
		}
		scope := servicesecrets.Scope(entry.Scope)
		record, err := s.customSecrets.Load(ctx, entry.Service, scope, secretScopeSandboxName(scope, sandboxName))
		if customsecrets.IsNotFound(err) {
			continue
		}
		if err != nil {
			clearSubstitutions(out)
			return nil, err
		}
		out = append(out, secretproxy.Substitution{Placeholder: record.Placeholder, Value: []byte(record.Value)})
	}
	return out, nil
}

func clearSubstitutions(subs []secretproxy.Substitution) {
	for i := range subs {
		clear(subs[i].Value)
	}
}

func anyHostMatches(patterns []string, host string) bool {
	for _, pattern := range patterns {
		if customsecrets.MatchHost(pattern, host) {
			return true
		}
	}
	return false
}

// customServiceName derives or validates the custom service identity. The
// derived name is the first normalized host pattern. Built-in service names are
// reserved so a custom entry can never shadow a provider secret.
func customServiceName(explicit string, hosts []string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(explicit))
	if name == "" {
		name = hosts[0]
	}
	if err := customsecrets.ValidateServiceName(name); err != nil {
		return "", err
	}
	if slices.Contains(servicesecrets.Services, name) {
		return "", fmt.Errorf("%w: service name is reserved for a built-in service", customsecrets.ErrInvalidInput)
	}
	return name, nil
}

func customSecretGateKey(service string, scope servicesecrets.Scope, sandboxName string) string {
	return "custom-secret/" + service + "/" + string(scope) + "/" + sandboxName
}

func customSummary(entry store.CustomSecretIndex) customsecrets.Summary {
	return customsecrets.Summary{
		Service: entry.Service, Scope: servicesecrets.Scope(entry.Scope), SandboxName: entry.SandboxName,
		EnvName: entry.EnvName, Hosts: slices.Clone(entry.Hosts), PlaceholderMasked: entry.PlaceholderMasked,
		Origin: entry.Origin, CreatedAt: entry.CreatedAt, UpdatedAt: entry.UpdatedAt,
	}
}
