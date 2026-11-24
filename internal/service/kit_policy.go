package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"

	core "github.com/rheic/sandboxes-core"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"

	"github.com/rheic/sandboxes-daemon/internal/orgpolicy"
)

// KitPolicyConfig is the effective kit policy for display. Managed reports
// whether an organization policy overrides local settings.
type KitPolicyConfig struct {
	AllowedSources   []string
	AllowLocalKits   bool
	RequireSignature bool
	Managed          bool
}

const (
	kitAllowedSourcesSetting   = "kit.allowedSources"
	kitAllowLocalKitsSetting   = "kit.allowLocalKits"
	kitRequireSignatureSetting = "kit.requireSignature"
)

const (
	kitSourceDirectory = "directory"
	kitSourceZip       = "zip"
	kitSourceGit       = "git"
	kitSourceOci       = "oci"
)

func (s *Service) CheckKitSource(ctx context.Context, kind localv1.KitSourceKind, ref string, sandboxID string, signed bool) (localv1.CheckKitReason, bool, error) {
	if kind == localv1.KitSourceKind_KIT_SOURCE_KIND_UNSPECIFIED {
		return localv1.CheckKitReason_CHECK_KIT_REASON_UNSPECIFIED, false, fmt.Errorf("%w: kit source kind is required", core.ErrConflict)
	}
	_ = sandboxID

	// Managed organization policy: a missing or invalid bundle fails closed and
	// a local allow can never relax it.
	managed := false
	if s.OrgPolicyEnforce && strings.TrimSpace(s.OrgPolicyOrg) != "" {
		if _, err := orgpolicy.Load(ctx, s.store, s.OrgPolicyOrg, s.now().UTC()); err != nil {
			slog.Info("kit policy check", "reason", "policy_unavailable", "allowed", false, "managed", true)
			return localv1.CheckKitReason_CHECK_KIT_REASON_POLICY_UNAVAILABLE, false, nil //nolint:nilerr // fail-closed outcome is reported via reason, not an RPC error
		}
		managed = true
	}

	if invalidKitReference(ref) {
		slog.Info("kit policy check", "reason", "invalid_reference", "allowed", false, "managed", managed)
		return localv1.CheckKitReason_CHECK_KIT_REASON_INVALID_REFERENCE, false, nil
	}

	allowedSources, allowLocal, requireSig := s.effectiveKitSettings(ctx)
	sourceName := kitSourceKindName(kind)

	allowed := false
	for _, source := range allowedSources {
		if strings.EqualFold(strings.TrimSpace(source), sourceName) {
			allowed = true
			break
		}
	}
	if !allowed {
		slog.Info("kit policy check", "reason", "source_not_allowed", "allowed", false, "managed", managed, "checked_settings", []string{kitAllowedSourcesSetting})
		return localv1.CheckKitReason_CHECK_KIT_REASON_SOURCE_NOT_ALLOWED, false, nil
	}

	if (kind == localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY || kind == localv1.KitSourceKind_KIT_SOURCE_KIND_ZIP) && !allowLocal {
		slog.Info("kit policy check", "reason", "local_disabled", "allowed", false, "managed", managed, "checked_settings", []string{kitAllowLocalKitsSetting})
		return localv1.CheckKitReason_CHECK_KIT_REASON_LOCAL_DISABLED, false, nil
	}

	if requireSig && !signed {
		slog.Info("kit policy check", "reason", "signature_required", "allowed", false, "managed", managed, "checked_settings", []string{kitRequireSignatureSetting})
		return localv1.CheckKitReason_CHECK_KIT_REASON_SIGNATURE_REQUIRED, false, nil
	}

	slog.Info("kit policy check", "reason", "ok", "allowed", true, "managed", managed)
	return localv1.CheckKitReason_CHECK_KIT_REASON_OK, true, nil
}

func (s *Service) GetKitPolicyConfig(ctx context.Context) (KitPolicyConfig, error) {
	allowedSources, allowLocal, requireSig := s.effectiveKitSettings(ctx)

	// A configured managed organization is reported as managed even while its
	// bundle is missing or invalid: checks fail closed in that state (see
	// CheckKitSource), and the display must not suggest local autonomy.
	managed := s.OrgPolicyEnforce && strings.TrimSpace(s.OrgPolicyOrg) != ""

	if len(allowedSources) == 0 {
		allowedSources = []string{kitSourceDirectory, kitSourceZip}
	}
	return KitPolicyConfig{
		AllowedSources:   append([]string(nil), allowedSources...),
		AllowLocalKits:   allowLocal,
		RequireSignature: requireSig,
		Managed:          managed,
	}, nil
}

// effectiveKitSettings resolves the effective kit settings, applying store
// overrides and defaults. A present but invalid store value fails closed by
// falling back to the most restrictive safe defaults.
func (s *Service) effectiveKitSettings(ctx context.Context) ([]string, bool, bool) {
	allowedSources := append([]string(nil), s.KitAllowedSources...)
	allowLocal := s.KitAllowLocalKits
	requireSig := s.KitRequireSignature

	if len(allowedSources) == 0 && len(s.KitAllowedSources) == 0 {
		allowedSources = []string{kitSourceDirectory, kitSourceZip}
	}
	if s.store == nil {
		return allowedSources, allowLocal, requireSig
	}
	allowedSources, allowLocal, requireSig = s.applyStoreKitSettings(ctx, allowedSources, allowLocal, requireSig)
	return allowedSources, allowLocal, requireSig
}

func (s *Service) applyStoreKitSettings(ctx context.Context, allowedSources []string, allowLocal, requireSig bool) ([]string, bool, bool) {
	storeAllowedPresent := false
	if raw, err := s.store.GetSetting(ctx, kitAllowedSourcesSetting); err == nil {
		storeAllowedPresent = true
		parsed, perr := parseKitSourcesSetting(raw)
		if perr != nil {
			allowedSources = []string{}
		} else {
			allowedSources = parsed
		}
	} else if !errors.Is(err, core.ErrNotFound) {
		allowedSources = []string{}
		storeAllowedPresent = true
	}
	if raw, err := s.store.GetSetting(ctx, kitAllowLocalKitsSetting); err == nil {
		b, perr := strconv.ParseBool(strings.TrimSpace(raw))
		if perr != nil {
			allowLocal = false
		} else {
			allowLocal = b
		}
	} else if !errors.Is(err, core.ErrNotFound) {
		allowLocal = false
	}
	if raw, err := s.store.GetSetting(ctx, kitRequireSignatureSetting); err == nil {
		b, perr := strconv.ParseBool(strings.TrimSpace(raw))
		if perr != nil {
			requireSig = true
		} else {
			requireSig = b
		}
	} else if !errors.Is(err, core.ErrNotFound) {
		requireSig = true
	}
	if !storeAllowedPresent && len(allowedSources) == 0 {
		allowedSources = []string{kitSourceDirectory, kitSourceZip}
	}
	return allowedSources, allowLocal, requireSig
}

func parseKitSourcesSetting(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty kit allowed sources")
	}
	var arr []string
	if err := json.Unmarshal([]byte(raw), &arr); err == nil {
		out := make([]string, 0, len(arr))
		seen := make(map[string]struct{})
		for _, v := range arr {
			kind := strings.ToLower(strings.TrimSpace(v))
			switch kind {
			case kitSourceDirectory, kitSourceZip, kitSourceGit, kitSourceOci:
			default:
				return nil, fmt.Errorf("unknown source kind %q", v)
			}
			if _, ok := seen[kind]; ok {
				continue
			}
			seen[kind] = struct{}{}
			out = append(out, kind)
		}
		if len(out) == 0 {
			return nil, errors.New("empty kit allowed sources")
		}
		return out, nil
	}
	return parseKitAllowedSources(raw)
}

func parseKitAllowedSources(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("kit.allowedSources must be a non-empty comma-separated list")
	}
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, part := range strings.Split(value, ",") {
		kind := strings.ToLower(strings.TrimSpace(part))
		switch kind {
		case kitSourceDirectory, kitSourceZip, kitSourceGit, kitSourceOci:
		default:
			return nil, fmt.Errorf("kit.allowedSources contains unknown source kind %q", part)
		}
		if _, exists := seen[kind]; exists {
			return nil, fmt.Errorf("kit.allowedSources contains duplicate source kind %q", kind)
		}
		seen[kind] = struct{}{}
		out = append(out, kind)
	}
	if len(out) == 0 {
		return nil, errors.New("kit.allowedSources must not be empty")
	}
	return out, nil
}

// invalidKitReference rejects references that could carry credentials or
// query material, and empty references (a check without an identifier cannot
// be granted).
func invalidKitReference(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return true
	}
	u, err := url.Parse(ref)
	if err != nil || u == nil {
		return true
	}
	if u.User != nil {
		return true
	}
	if u.RawQuery != "" {
		return true
	}
	return false
}

func kitSourceKindName(kind localv1.KitSourceKind) string {
	switch kind {
	case localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY:
		return "directory"
	case localv1.KitSourceKind_KIT_SOURCE_KIND_ZIP:
		return "zip"
	case localv1.KitSourceKind_KIT_SOURCE_KIND_GIT:
		return "git"
	case localv1.KitSourceKind_KIT_SOURCE_KIND_OCI:
		return "oci"
	default:
		return ""
	}
}
