package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	posixpath "path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"
	runtime "github.com/rheic/sandboxes-runtime"
)

const (
	cloneSourceGuestPath = "/run/sandbox/source"
	cloneExportGuestDir  = "/run/sandbox/export"
	cloneGitGuestIP      = "192.168.127.3"
	cloneGitGuestPort    = 9418
	cloneGitHostIP       = "127.0.0.1"
	cloneCommandTimeout  = 2 * time.Minute
	cloneGitReadyTimeout = 10 * time.Second
	cloneOutputLimit     = 4096
	cloneGitCommand      = "git"
	cloneGitConfig       = "config"
	cloneGitLocalFlag    = "--local"
	cloneGitTrustConfig  = "/tmp/.rheic-clone-gitconfig"
	cloneShellCommand    = "/bin/sh"
)

var cloneRepositorySlug = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// errCloneForwardUnavailable reports that a persisted clone Git endpoint could
// not be verified or republished. Callers must treat the clone as unusable
// until the sandbox is restarted rather than trusting a stale host port.
var errCloneForwardUnavailable = errors.New("clone Git forward is unavailable")

// normalizeCloneOptions validates a non-nil clone request. Callers must skip
// this function when no clone options were supplied.
func normalizeCloneOptions(clone *sandbox.CloneOptions, workspaces []sandbox.Workspace) (*sandbox.CloneOptions, error) {
	if len(workspaces) != 1 {
		return nil, fmt.Errorf("%w: clone mode requires exactly one workspace", core.ErrConflict)
	}
	source, match, err := findCloneSourceWorkspace(clone.SourceWorkspacePath, workspaces)
	if err != nil {
		return nil, err
	}
	if err := validateCloneGuestWorkdir(clone.GuestWorkdir); err != nil {
		return nil, err
	}
	workspaces[match].ReadOnly = true
	workspaces[match].GuestPath = cloneSourceGuestPath
	if err := validateCloneWorkspaceOverlaps(workspaces, match); err != nil {
		return nil, err
	}
	if _, err := normalizeWorkspaces(CreateRequest{Workspaces: workspaces}); err != nil {
		return nil, err
	}
	return newCloneOptions(source, clone.GuestWorkdir), nil
}

func findCloneSourceWorkspace(source string, workspaces []sandbox.Workspace) (string, int, error) {
	if source == "" || !filepath.IsAbs(source) || strings.ContainsRune(source, '\x00') {
		return "", 0, fmt.Errorf("%w: clone source must identify one absolute workspace path", core.ErrConflict)
	}
	source = filepath.Clean(source)
	match := -1
	for i := range workspaces {
		if workspaces[i].Path != source {
			continue
		}
		if match >= 0 {
			return "", 0, fmt.Errorf("%w: clone source matches multiple workspaces", core.ErrConflict)
		}
		match = i
	}
	if match < 0 {
		return "", 0, fmt.Errorf("%w: clone source must match exactly one workspace", core.ErrConflict)
	}
	if err := validateCloneSourceRepository(source); err != nil {
		return "", 0, err
	}
	return source, match, nil
}

func validateCloneGuestWorkdir(guestWorkdir *string) error {
	if guestWorkdir == nil {
		return nil
	}
	if !validCloneGuestPath(*guestWorkdir) || !validCloneRepositorySlug(posixpath.Base(*guestWorkdir)) {
		return fmt.Errorf("%w: clone guest workdir must be a clean absolute POSIX path with a safe repository name", core.ErrConflict)
	}
	return nil
}

func validateCloneWorkspaceOverlaps(workspaces []sandbox.Workspace, sourceIndex int) error {
	for i := range workspaces {
		if i == sourceIndex {
			continue
		}
		destination := workspaces[i].GuestPath
		if destination == "" {
			destination = workspaces[i].Path
		}
		if posixPathsOverlap(destination, cloneSourceGuestPath) {
			return fmt.Errorf("%w: another workspace overlaps the clone source mount", core.ErrConflict)
		}
	}
	return nil
}

func newCloneOptions(source string, guestWorkdir *string) *sandbox.CloneOptions {
	result := &sandbox.CloneOptions{SourceWorkspacePath: source}
	if guestWorkdir != nil {
		workdir := *guestWorkdir
		result.GuestWorkdir = &workdir
	}
	return result
}

func validCloneGuestPath(value string) bool {
	return value != "" && posixpath.IsAbs(value) && posixpath.Clean(value) == value && !strings.ContainsAny(value, ",=\x00\r\n")
}

func validCloneRepositorySlug(value string) bool {
	return value != "." && value != ".." && cloneRepositorySlug.MatchString(value)
}

func posixPathsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func validateCloneSourceRepository(source string) error {
	before, err := os.Lstat(source)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: clone source must be a real directory", core.ErrConflict)
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		return fmt.Errorf("%w: clone source cannot be safely opened", core.ErrConflict)
	}
	defer func() { _ = root.Close() }()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) || !opened.IsDir() {
		return fmt.Errorf("%w: clone source changed while opening", core.ErrConflict)
	}
	gitInfo, err := root.Lstat(".git")
	if err != nil || !gitInfo.IsDir() || gitInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: clone source must contain a .git directory; worktree files are unsupported", core.ErrConflict)
	}
	configInfo, err := root.Lstat(".git/config")
	if err != nil || !configInfo.Mode().IsRegular() {
		return fmt.Errorf("%w: clone source Git config must be a regular file", core.ErrConflict)
	}
	return nil
}

func (s *Service) requireCloneCapabilities(ctx context.Context) error {
	if s.backend == nil {
		return fmt.Errorf("%w: clone mode requires a VM runtime", core.ErrConflict)
	}
	if _, ok := s.backend.(runtime.NativeExecutor); !ok {
		return fmt.Errorf("%w: runtime does not support bounded clone initialization", core.ErrConflict)
	}
	if _, ok := s.backend.(runtime.GitDaemonForwarder); !ok {
		return fmt.Errorf("%w: runtime network does not support managed Git forwarding", core.ErrConflict)
	}
	capabilities, err := s.backend.Capabilities(ctx)
	if err != nil {
		return fmt.Errorf("inspect clone runtime capabilities: %w", err)
	}
	if !capabilities.Workspace || !capabilities.Network {
		return fmt.Errorf("%w: clone mode requires workspace mounts and managed networking", core.ErrConflict)
	}
	return nil
}

func (s *Service) bootstrapClone(ctx context.Context, handle runtime.Handle, name string, clone *sandbox.CloneOptions, sb *sandbox.Sandbox) error {
	if err := s.requireCloneTooling(ctx, handle); err != nil {
		return err
	}
	workdir, err := resolveCloneWorkdir(clone)
	if err != nil {
		return err
	}
	if err := s.prepareCloneWorkdir(ctx, handle, workdir, sb.Workspaces); err != nil {
		return err
	}
	if err := s.initializeGuestClone(ctx, handle, workdir); err != nil {
		return err
	}
	state := &sandbox.CloneState{Options: *clone, Info: &sandbox.CloneInfo{GuestWorkdir: workdir, RemoteName: "sandbox-" + name}}
	sb.Meta.Clone = state
	port, err := s.startCloneGitDaemon(ctx, handle, name, state.Info)
	if err != nil {
		return err
	}
	state.Info.GitEndpoint = &sandbox.GitEndpoint{HostIP: cloneGitHostIP, Port: port, Repository: posixpath.Base(workdir)}
	return nil
}

func (s *Service) requireCloneTooling(ctx context.Context, handle runtime.Handle) error {
	if err := s.requireClonePathResolution(ctx, handle, "/", "-e"); err != nil {
		return fmt.Errorf("%w: clone image must include a working realpath command: %w", core.ErrConflict, err)
	}
	gitVersion, err := s.runCloneCommand(ctx, handle, []string{cloneGitCommand, "--version"}, cloneGitEnvironment())
	if err != nil {
		return fmt.Errorf("%w: clone image must include a working Git client and daemon: %w", core.ErrConflict, err)
	}
	if !strings.HasPrefix(strings.TrimSpace(gitVersion), "git version ") {
		return fmt.Errorf("%w: clone image must include a working Git client and daemon", core.ErrConflict)
	}
	return nil
}

// resolveCloneWorkdir mirrors sbx: the private clone lands at the host
// workspace path itself inside the guest, unless the caller chose an explicit
// guest workdir.
func resolveCloneWorkdir(clone *sandbox.CloneOptions) (string, error) {
	if clone.GuestWorkdir != nil {
		return *clone.GuestWorkdir, nil
	}
	workdir := filepath.ToSlash(clone.SourceWorkspacePath)
	if !validCloneGuestPath(workdir) || !validCloneRepositorySlug(posixpath.Base(workdir)) {
		return "", fmt.Errorf("%w: clone source path cannot be used as a guest working directory", core.ErrConflict)
	}
	return workdir, nil
}

func (s *Service) prepareCloneWorkdir(ctx context.Context, handle runtime.Handle, workdir string, workspaces []sandbox.Workspace) error {
	if !validCloneGuestPath(workdir) {
		return fmt.Errorf("%w: clone guest workdir must be a clean absolute POSIX path", core.ErrConflict)
	}
	if !validCloneRepositorySlug(posixpath.Base(workdir)) {
		return errors.New("clone working directory has an unsafe repository name")
	}
	if err := validateCloneWorkdirAgainstWorkspaces(workdir, workspaces); err != nil {
		return err
	}
	parent := posixpath.Dir(workdir)
	if err := s.requireClonePathResolution(ctx, handle, parent, "-m"); err != nil {
		return fmt.Errorf("validate clone destination parent: %w", err)
	}
	if err := s.requireClonePathResolution(ctx, handle, workdir, "-m"); err != nil {
		return fmt.Errorf("validate clone destination: %w", err)
	}
	if parent != "/" {
		if _, err := s.runCloneCommand(ctx, handle, []string{"mkdir", "-p", "--", parent}, nil); err != nil {
			return fmt.Errorf("prepare clone parent directory: %w", err)
		}
	}
	if err := s.requireClonePathResolution(ctx, handle, parent, "-e"); err != nil {
		return fmt.Errorf("revalidate clone destination parent: %w", err)
	}
	if err := s.requireClonePathResolution(ctx, handle, workdir, "-m"); err != nil {
		return fmt.Errorf("revalidate clone destination: %w", err)
	}
	return s.requireEmptyCloneDestination(ctx, handle, workdir)
}

// requireEmptyCloneDestination rejects an existing clone destination that
// already holds content, so a private clone never overwrites guest files.
func (s *Service) requireEmptyCloneDestination(ctx context.Context, handle runtime.Handle, workdir string) error {
	probe := `if [ -e "$1" ]; then [ -d "$1" ] && [ -z "$(ls -A -- "$1")" ]; fi`
	if _, err := s.runCloneCommand(ctx, handle, []string{cloneShellCommand, "-c", probe, "clone-destination", workdir}, nil); err != nil {
		return fmt.Errorf("%w: clone guest workdir must be absent or empty: %w", core.ErrConflict, err)
	}
	return nil
}

func (s *Service) initializeGuestClone(ctx context.Context, handle runtime.Handle, workdir string) error {
	cloneEnv := cloneGitEnvironment()
	// The read-only source stays owned by the host user, while the guest user
	// differs, so Git rejects it as a dubious-ownership repository. Only the
	// protected (system/global) scope is honored for safe.directory, so a
	// throwaway global config grants trust for this clone and is removed again.
	if err := s.writeCloneTrustConfig(ctx, handle); err != nil {
		return err
	}
	defer func() { _ = s.removeCloneTrustConfig(ctx, handle) }()
	trustEnv := withCloneGlobalConfig(cloneEnv, cloneGitTrustConfig)
	if _, err := s.runCloneCommand(ctx, handle, []string{cloneGitCommand, "clone", "--no-local", "--no-hardlinks", "--no-recurse-submodules", "--", cloneSourceGuestPath, workdir}, trustEnv); err != nil {
		return fmt.Errorf("create private guest clone: %w", err)
	}
	if _, err := s.runCloneCommand(ctx, handle, []string{cloneGitCommand, "-C", workdir, "remote", "set-url", "origin", cloneSourceGuestPath}, cloneEnv); err != nil {
		return fmt.Errorf("keep read-only source as guest clone origin: %w", err)
	}
	if _, err := s.runCloneCommand(ctx, handle, []string{cloneGitCommand, "-C", workdir, cloneGitConfig, cloneGitLocalFlag, "core.hooksPath", "/dev/null"}, cloneEnv); err != nil {
		return fmt.Errorf("disable clone hooks: %w", err)
	}
	if _, err := s.runCloneCommand(ctx, handle, []string{cloneGitCommand, "-C", workdir, cloneGitConfig, cloneGitLocalFlag, "credential.helper", ""}, cloneEnv); err != nil {
		return fmt.Errorf("disable clone credential helpers: %w", err)
	}
	return nil
}

func (s *Service) requireClonePathResolution(ctx context.Context, handle runtime.Handle, guestPath, mode string) error {
	resolved, err := s.runCloneCommand(ctx, handle, []string{"realpath", mode, "--", guestPath}, nil)
	if err != nil {
		return err
	}
	if strings.TrimSuffix(resolved, "\n") != guestPath || strings.Count(resolved, "\n") != 1 {
		return fmt.Errorf("guest path %q resolves to a different or ambiguous destination", guestPath)
	}
	return nil
}

func validateCloneWorkdirAgainstWorkspaces(workdir string, workspaces []sandbox.Workspace) error {
	for i := range workspaces {
		destination := workspaces[i].GuestPath
		if destination == "" {
			destination = workspaces[i].Path
		}
		if posixPathsOverlap(workdir, destination) {
			return fmt.Errorf("%w: clone guest workdir overlaps a workspace mount", core.ErrConflict)
		}
	}
	return nil
}

func (s *Service) startCloneGitDaemon(ctx context.Context, handle runtime.Handle, name string, info *sandbox.CloneInfo) (uint16, error) {
	workdir := info.GuestWorkdir
	repository := posixpath.Base(workdir)
	// A Git working tree is not itself a Git directory, so export exactly one
	// entry whose .git file carries the gitdir indirection. The daemon serves
	// it at /<repository>, matching sbx instead of exposing /<repository>/.git.
	entry, err := s.prepareCloneExport(ctx, handle, workdir, repository)
	if err != nil {
		return 0, err
	}
	args := []string{cloneGitCommand, "daemon", "--detach", "--reuseaddr", "--listen=" + cloneGitGuestIP,
		"--port=" + strconv.Itoa(cloneGitGuestPort), "--base-path=" + cloneExportGuestDir, "--export-all",
		"--enable=upload-pack", "--disable=receive-pack", entry}
	if _, err := s.runCloneCommand(ctx, handle, args, daemonGitEnvironment()); err != nil {
		return 0, fmt.Errorf("start guest Git daemon: %w", err)
	}
	if err := s.waitCloneGitDaemon(ctx, handle, repository); err != nil {
		return 0, err
	}
	forwarder := s.backend.(runtime.GitDaemonForwarder)
	port, err := forwarder.SetGitDaemon(ctx, name, true)
	if err != nil {
		return 0, errors.Join(fmt.Errorf("publish guest Git daemon: %w", err), s.withdrawCloneGitForward(ctx, name))
	}
	if port == 0 {
		return 0, errors.Join(errors.New("gateway returned an empty Git daemon port"), s.withdrawCloneGitForward(ctx, name))
	}
	return port, nil
}

// prepareCloneExport recreates the single-entry export directory that makes
// the clone's Git directory reachable as /<repository> through git daemon.
func (s *Service) prepareCloneExport(ctx context.Context, handle runtime.Handle, workdir, repository string) (string, error) {
	script := `set -eu; umask 077; rm -rf -- "$1"; mkdir -p -- "$1/$2"; printf 'gitdir: %s/.git\n' "$3" > "$1/$2/.git"`
	if _, err := s.runCloneCommand(ctx, handle, []string{cloneShellCommand, "-c", script, "clone-export", cloneExportGuestDir, repository, workdir}, nil); err != nil {
		return "", fmt.Errorf("prepare guest Git export: %w", err)
	}
	return posixpath.Join(cloneExportGuestDir, repository), nil
}

func (s *Service) removeCloneExport(ctx context.Context, handle runtime.Handle) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if _, err := s.runCloneCommand(cleanupCtx, handle, []string{"rm", "-rf", "--", cloneExportGuestDir}, nil); err != nil {
		return fmt.Errorf("remove guest Git export: %w", err)
	}
	return nil
}

// waitCloneGitDaemon confirms the guest Git daemon really serves the clone
// before its forward is published: --detach hides bind and startup failures.
func (s *Service) waitCloneGitDaemon(ctx context.Context, handle runtime.Handle, repository string) error {
	url := "git://" + net.JoinHostPort(cloneGitGuestIP, strconv.Itoa(cloneGitGuestPort)) + "/" + repository
	deadline := time.Now().Add(cloneGitReadyTimeout)
	var lastErr error
	for {
		_, lastErr = s.runCloneCommand(ctx, handle, []string{cloneGitCommand, "ls-remote", "--quiet", url, "HEAD"}, cloneGitProbeEnvironment())
		if lastErr == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("guest Git daemon did not serve %q: %w", repository, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (s *Service) withdrawCloneGitForward(ctx context.Context, name string) error {
	forwarder, ok := s.backend.(runtime.GitDaemonForwarder)
	if !ok {
		return errors.New("runtime does not support Git daemon forward withdrawal")
	}
	if _, err := forwarder.SetGitDaemon(ctx, name, false); err != nil {
		return fmt.Errorf("withdraw guest Git daemon forward: %w", err)
	}
	return nil
}

// ensureCloneForward repairs a Running clone's persisted host endpoint when the
// gateway forward no longer reaches the guest Git daemon. It never invents an
// endpoint: if the stale forward cannot be withdrawn or the replacement cannot
// be verified, the endpoint is cleared and a typed error is returned.
func (s *Service) ensureCloneForward(ctx context.Context, sb *sandbox.Sandbox) error {
	if sb == nil || sb.State != sandbox.Running || sb.Meta == nil || sb.Meta.Clone == nil ||
		sb.Meta.Clone.Info == nil || sb.Meta.Clone.Info.GitEndpoint == nil {
		return nil
	}
	if s.backend == nil {
		return s.clearCloneEndpoint(ctx, sb, fmt.Errorf("%w: clone runtime is unavailable", errCloneForwardUnavailable))
	}
	info := sb.Meta.Clone.Info
	repository, err := cloneForwardRepository(info)
	if err != nil {
		return s.clearCloneEndpoint(ctx, sb, fmt.Errorf("%w: %w", errCloneForwardUnavailable, err))
	}
	port, err := s.verifyCloneForward(ctx, sb.Name, repository)
	if err == nil {
		if port == info.GitEndpoint.Port && info.GitEndpoint.HostIP == cloneGitHostIP && info.GitEndpoint.Repository == repository {
			return nil
		}
		// The gateway verified ownership by replacing the stale forward with a
		// new one. Persist that verified endpoint instead of publishing again.
		return s.persistCloneEndpoint(ctx, sb, &sandbox.GitEndpoint{HostIP: cloneGitHostIP, Port: port, Repository: repository})
	}
	if err := s.withdrawCloneGitForward(ctx, sb.Name); err != nil {
		return s.clearCloneEndpoint(ctx, sb, fmt.Errorf("%w: withdraw stale clone forward: %w", errCloneForwardUnavailable, err))
	}
	port, err = s.publishCloneForward(ctx, sb.Name, repository)
	if err != nil {
		return s.clearCloneEndpoint(ctx, sb, err)
	}
	endpoint := &sandbox.GitEndpoint{HostIP: cloneGitHostIP, Port: port, Repository: repository}
	return s.persistCloneEndpoint(ctx, sb, endpoint)
}

func cloneForwardRepository(info *sandbox.CloneInfo) (string, error) {
	if !validCloneGuestPath(info.GuestWorkdir) || !validCloneRepositorySlug(posixpath.Base(info.GuestWorkdir)) {
		return "", errors.New("stored clone metadata is invalid")
	}
	return posixpath.Base(info.GuestWorkdir), nil
}

// verifyCloneForward asks the gateway to verify its owned forward, then
// confirms the guest daemon still serves it. A changed port means the gateway
// replaced a stale forward while reasserting ownership.
func (s *Service) verifyCloneForward(ctx context.Context, name, repository string) (uint16, error) {
	forwarder, ok := s.backend.(runtime.GitDaemonForwarder)
	if !ok {
		return 0, errors.New("runtime does not support managed Git daemon forwarding")
	}
	port, err := forwarder.SetGitDaemon(ctx, name, true)
	if err != nil {
		return 0, err
	}
	if port == 0 {
		return 0, errors.New("gateway returned an empty clone Git port")
	}
	if err := s.waitCloneGitDaemon(ctx, s.backend.Handle(name), repository); err != nil {
		return 0, fmt.Errorf("guest clone Git daemon is unreachable: %w", err)
	}
	return port, nil
}

func (s *Service) publishCloneForward(ctx context.Context, name, repository string) (uint16, error) {
	forwarder, ok := s.backend.(runtime.GitDaemonForwarder)
	if !ok {
		return 0, fmt.Errorf("%w: runtime does not support managed Git daemon forwarding", errCloneForwardUnavailable)
	}
	port, err := forwarder.SetGitDaemon(ctx, name, true)
	if err != nil {
		return 0, fmt.Errorf("%w: publish clone forward: %w", errCloneForwardUnavailable, err)
	}
	if port == 0 {
		return 0, fmt.Errorf("%w: gateway returned an empty clone Git port", errCloneForwardUnavailable)
	}
	if err := s.waitCloneGitDaemon(ctx, s.backend.Handle(name), repository); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if withdrawErr := s.withdrawCloneGitForward(cleanupCtx, name); withdrawErr != nil {
			return 0, fmt.Errorf("%w: verify republished clone forward: %w", errCloneForwardUnavailable, errors.Join(err, withdrawErr))
		}
		return 0, fmt.Errorf("%w: verify republished clone forward: %w", errCloneForwardUnavailable, err)
	}
	return port, nil
}

func (s *Service) persistCloneEndpoint(ctx context.Context, sb *sandbox.Sandbox, endpoint *sandbox.GitEndpoint) error {
	sb.Meta.Clone.Info.GitEndpoint = endpoint
	sb.UpdatedAt = s.now().UTC()
	if err := s.store.Update(ctx, *sb); err != nil {
		// Keep the in-memory record fail-closed so the caller does not persist
		// an endpoint that failed to commit.
		sb.Meta.Clone.Info.GitEndpoint = nil
		return fmt.Errorf("%w: persist repaired clone endpoint: %w", errCloneForwardUnavailable, err)
	}
	return nil
}

func (s *Service) clearCloneEndpoint(ctx context.Context, sb *sandbox.Sandbox, cause error) error {
	sb.Meta.Clone.Info.GitEndpoint = nil
	sb.UpdatedAt = s.now().UTC()
	if err := s.store.Update(ctx, *sb); err != nil {
		return errors.Join(cause, fmt.Errorf("clear stale clone endpoint: %w", err))
	}
	return cause
}

func (s *Service) startStoredClone(ctx context.Context, sb *sandbox.Sandbox) error {
	if sb.Meta.Clone == nil {
		return nil
	}
	if sb.Meta.Clone.Info == nil || !validCloneGuestPath(sb.Meta.Clone.Info.GuestWorkdir) || !validCloneRepositorySlug(posixpath.Base(sb.Meta.Clone.Info.GuestWorkdir)) {
		return errors.New("stored clone metadata is invalid")
	}
	if _, err := s.runCloneCommand(ctx, s.backend.Handle(sb.Name), []string{cloneGitCommand, "-C", sb.Meta.Clone.Info.GuestWorkdir, cloneGitConfig, cloneGitLocalFlag, "core.hooksPath", "/dev/null"}, cloneGitEnvironment()); err != nil {
		return fmt.Errorf("restore clone hook policy: %w", err)
	}
	port, err := s.startCloneGitDaemon(ctx, s.backend.Handle(sb.Name), sb.Name, sb.Meta.Clone.Info)
	if err != nil {
		return err
	}
	sb.Meta.Clone.Info.GitEndpoint = &sandbox.GitEndpoint{HostIP: cloneGitHostIP, Port: port, Repository: posixpath.Base(sb.Meta.Clone.Info.GuestWorkdir)}
	return nil
}

func (s *Service) stopStoredClone(ctx context.Context, sb *sandbox.Sandbox) error {
	if sb.Meta.Clone == nil {
		return nil
	}
	if (sb.Meta.Clone.Info == nil || sb.Meta.Clone.Info.GitEndpoint == nil) && sb.State != sandbox.Running && sb.State != sandbox.Unknown {
		return nil
	}
	if err := s.withdrawCloneGitForward(ctx, sb.Name); err != nil {
		return err
	}
	if err := s.removeCloneExport(ctx, s.backend.Handle(sb.Name)); err != nil {
		return err
	}
	if sb.Meta.Clone.Info != nil {
		sb.Meta.Clone.Info.GitEndpoint = nil
	}
	return nil
}

func (s *Service) runCloneCommand(ctx context.Context, handle runtime.Handle, argv, extraEnv []string) (string, error) {
	executor, ok := s.backend.(runtime.NativeExecutor)
	if !ok {
		return "", fmt.Errorf("%w: runtime does not support bounded clone initialization", core.ErrConflict)
	}
	commandCtx, cancel := context.WithTimeout(ctx, cloneCommandTimeout)
	defer cancel()
	var stdout, stderr limitedCloneBuffer
	stdout.limit = cloneOutputLimit
	stderr.limit = cloneOutputLimit
	env := append([]string(nil), extraEnv...)
	args := make([]string, 0, len(argv)+len(env)+3)
	args = append(args, "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin")
	args = append(args, env...)
	args = append(args, argv...)
	code, err := executor.ExecNative(commandCtx, handle, runtime.ExecRequest{
		Argv: args, Workdir: "", Stdout: &stdout, Stderr: &stderr,
	})
	if err != nil || code != 0 {
		return "", errors.Join(fmt.Errorf("guest command failed with exit code %d", code), err, stdout.err, stderr.err, guestCommandFailure(stderr.String()))
	}
	return stdout.String(), nil
}

// guestCommandFailure surfaces the bounded guest stderr so a failed clone
// reports the underlying Git error instead of only an exit code.
func guestCommandFailure(stderr string) error {
	message := strings.TrimSpace(stderr)
	if message == "" {
		return nil
	}
	return fmt.Errorf("guest stderr: %s", message)
}

type limitedCloneBuffer struct {
	bytes.Buffer
	limit int
	err   error
}

func (b *limitedCloneBuffer) Write(p []byte) (int, error) {
	if b.limit < 0 || len(p) > b.limit-b.Len() {
		b.err = errors.New("guest command output exceeded the limit")
		return 0, b.err
	}
	return b.Buffer.Write(p)
}

func cloneGitEnvironment() []string {
	return []string{
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false", "GIT_ALLOW_PROTOCOL=file",
		"GIT_CONFIG_COUNT=3", "GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/dev/null",
		"GIT_CONFIG_KEY_1=credential.helper", "GIT_CONFIG_VALUE_1=",
		"GIT_CONFIG_KEY_2=init.templateDir", "GIT_CONFIG_VALUE_2=/dev/null",
	}
}

// writeCloneTrustConfig writes the one throwaway global Git config that makes
// the read-only host-owned source usable inside the guest.
func (s *Service) writeCloneTrustConfig(ctx context.Context, handle runtime.Handle) error {
	script := `umask 077; printf '[safe]\n\tdirectory = *\n' > "$1"`
	if _, err := s.runCloneCommand(ctx, handle, []string{cloneShellCommand, "-c", script, "clone-trust-config", cloneGitTrustConfig}, nil); err != nil {
		return fmt.Errorf("prepare clone Git trust config: %w", err)
	}
	return nil
}

func (s *Service) removeCloneTrustConfig(ctx context.Context, handle runtime.Handle) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if _, err := s.runCloneCommand(cleanupCtx, handle, []string{"rm", "-f", "--", cloneGitTrustConfig}, nil); err != nil {
		return fmt.Errorf("remove clone Git trust config: %w", err)
	}
	return nil
}

// withCloneGlobalConfig replaces GIT_CONFIG_GLOBAL in a prepared Git
// environment so exactly one extra global config file is honored.
func withCloneGlobalConfig(env []string, path string) []string {
	result := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if strings.HasPrefix(entry, "GIT_CONFIG_GLOBAL=") {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "GIT_CONFIG_GLOBAL="+path)
}

// cloneGitProbeEnvironment allows only the Git protocol for the in-guest
// readiness probe; every other Git command stays confined to local files.
func cloneGitProbeEnvironment() []string {
	env := make([]string, 0, len(cloneGitEnvironment())+1)
	for _, entry := range cloneGitEnvironment() {
		if strings.HasPrefix(entry, "GIT_ALLOW_PROTOCOL=") {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "GIT_ALLOW_PROTOCOL=git")
}

func daemonGitEnvironment() []string {
	return []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "HOME=/nonexistent"}
}
