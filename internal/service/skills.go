package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"

	runtimeapi "github.com/rheic/sandboxes-runtime"
)

const (
	skillsSettingPrefix = "sandbox.skills."

	skillsModeOff       = "off"
	skillsModeReadOnly  = "readonly"
	skillsModeReadWrite = "readwrite"

	skillsHelperNamePrefix = "sandboxes-guest-linux-"
)

// SkillsOptions selects shared skills delivery for a new sandbox.
type SkillsOptions struct {
	Mode      string
	StorePath string
}

var skillsAgents = map[string]bool{
	"codex": true, "devin": true, "kimi": true, "dsh": true, "claude": true,
	"opencode": true, "copilot": true, "cursor": true, "droid": true,
}

// resolveSkillsMount validates the requested mode and resolves the fixed host
// store plus the trusted guest helper. Read-write mode remains unsupported
// because a per-agent bind target cannot be established safely yet.
func (s *Service) resolveSkillsMount(req CreateRequest) (*runtimeapi.SkillsMount, error) {
	if req.Skills == nil {
		return nil, nil //nolint:nilnil // Absent options mean shared skills are disabled.
	}
	if err := s.validateSkillsRequest(req); err != nil {
		return nil, err
	}
	if req.Skills.Mode == skillsModeOff {
		return nil, nil //nolint:nilnil // Explicit off mode has no runtime mount.
	}
	// sbx parity: an agent without a guest skills directory (e.g. shell)
	// treats a shared-skills request as a no-op, for both the settings
	// default and an explicit flag, matching live `sbx run shell` behavior.
	// No mount means nothing is exposed, so this stays fail-closed; readwrite
	// is rejected above regardless of agent.
	if !skillsAgents[req.Agent] {
		return nil, nil //nolint:nilnil // No skills target exists in this guest; skip the mount.
	}
	if s.backend == nil {
		return nil, fmt.Errorf("%w: shared skills require a VM runtime", core.ErrConflict)
	}
	return s.resolveReadOnlySkillsMount(req)
}

func (s *Service) validateSkillsRequest(req CreateRequest) error {
	if req.Skills.Mode == "" {
		return fmt.Errorf("%w: shared skills mode is invalid", core.ErrConflict)
	}
	if req.Skills.Mode == skillsModeOff {
		if req.Skills.StorePath != "" {
			return fmt.Errorf("%w: shared skills off mode requires an empty store path", core.ErrConflict)
		}
		return nil
	}
	if req.Skills.Mode != skillsModeReadOnly {
		return fmt.Errorf("%w: shared skills mode %q is not supported", core.ErrConflict, req.Skills.Mode)
	}
	return nil
}

func (s *Service) resolveReadOnlySkillsMount(req CreateRequest) (*runtimeapi.SkillsMount, error) {
	store, err := s.skillsStorePath()
	if err != nil {
		return nil, err
	}
	if req.Skills.StorePath != "" {
		requested := filepath.Clean(req.Skills.StorePath)
		if requested != req.Skills.StorePath || requested != store {
			return nil, fmt.Errorf("%w: shared skills store must equal the daemon store %q", core.ErrConflict, store)
		}
	}
	info, err := os.Lstat(store)
	if err != nil {
		return nil, fmt.Errorf("%w: shared skills store is unavailable; import skills first", core.ErrConflict)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: shared skills store must be a real directory", core.ErrConflict)
	}
	helper, err := resolveSkillsHelperPath(s.skillsHelperPath, "")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", core.ErrConflict, err)
	}
	return &runtimeapi.SkillsMount{StorePath: store, HelperPath: helper, ReadOnly: true}, nil
}

func (s *Service) skillsStorePath() (string, error) {
	if s.skillsStoreOverride != "" {
		if !filepath.IsAbs(s.skillsStoreOverride) || filepath.Clean(s.skillsStoreOverride) != s.skillsStoreOverride {
			return "", fmt.Errorf("%w: shared skills store path must be a clean absolute path", core.ErrConflict)
		}
		return s.skillsStoreOverride, nil
	}
	if configured := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); configured != "" {
		if !filepath.IsAbs(configured) {
			return "", fmt.Errorf("%w: XDG_CONFIG_HOME must be absolute", core.ErrConflict)
		}
		return filepath.Join(configured, "rheic", "skills"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		return "", fmt.Errorf("%w: home directory is unavailable", core.ErrConflict)
	}
	return filepath.Join(home, ".config", "rheic", "skills"), nil
}

// installSharedSkills links store entries into the agent's skills directory.
// The helper runs as the container's default user, so it resolves that user's
// home inside the guest instead of trusting a host-provided path.
func (s *Service) installSharedSkills(ctx context.Context, handle runtimeapi.Handle, agent string) error {
	native, ok := s.backend.(runtimeapi.NativeExecutor)
	if !ok {
		return errors.New("shared skills require a runtime with native exec support")
	}
	var stdout, stderr bytes.Buffer
	code, err := native.ExecNative(ctx, handle, runtimeapi.ExecRequest{
		Argv: []string{
			runtimeapi.SkillsHelperGuestPath, "link-skills",
			"--agent", agent,
			"--store", runtimeapi.SkillsStoreGuestPath,
		},
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		return fmt.Errorf("link shared skills: %w", err)
	}
	if code != 0 {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if len(detail) > 2048 {
			detail = detail[:2048]
		}
		return fmt.Errorf("link shared skills: helper exited with status %d: %s", code, detail)
	}
	return nil
}

// resolveSkillsHelperPath mirrors proxy-helper discovery: an explicit path
// wins, otherwise only deterministic locations next to the daemon are
// considered. PATH is never consulted.
func resolveSkillsHelperPath(explicitPath, executablePath string) (string, error) {
	return resolveGuestHelperPath(explicitPath, executablePath, skillsHelperNamePrefix, "skills helper", "--skills-helper", "guest binary", validateStaticLinuxExecutable)
}

// SetSkillsRuntime configures the trusted guest helper and optional store
// override. The store default is resolved from XDG_CONFIG_HOME or HOME.
func (s *Service) SetSkillsRuntime(helperPath, storePath string) {
	s.skillsHelperPath = helperPath
	s.skillsStoreOverride = storePath
}

func (s *Service) installSharedSkillsIfNeeded(ctx context.Context, handle runtimeapi.Handle, mount *runtimeapi.SkillsMount, agent string) error {
	if mount == nil {
		return nil
	}
	return s.installSharedSkills(ctx, handle, agent)
}

func skillsSettingKey(id string) string { return skillsSettingPrefix + id }

func (s *Service) recordSkillsMode(ctx context.Context, id, mode string) error {
	return s.store.SetSetting(ctx, skillsSettingKey(id), mode)
}

// replaySharedSkills reruns the linker at start so links added to the store
// since creation appear. On Linux the fd-pinned mount exposes new entries; the
// macOS snapshot keeps its creation-time view until the sandbox is recreated.
func (s *Service) replaySharedSkills(ctx context.Context, sb sandbox.Sandbox) error {
	mode, err := s.store.GetSetting(ctx, skillsSettingKey(sb.ID))
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if mode != skillsModeReadOnly {
		return nil
	}
	return s.installSharedSkills(ctx, s.backend.Handle(sb.Name), sandboxAgent(sb))
}
