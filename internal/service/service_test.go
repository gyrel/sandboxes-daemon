package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	posixpath "path"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/operation"
	"github.com/rheic/sandboxes-core/sandbox"
	runtime "github.com/rheic/sandboxes-runtime"

	"github.com/rheic/sandboxes-daemon/internal/registrycredentials"
	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)

	op, err := svc.Create(ctx, CreateRequest{Name: "dev", Image: "scratch"})
	if err != nil {
		t.Fatal(err)
	}
	if op.State != operation.Done {
		t.Fatalf("create state = %s", op.State)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.State != sandbox.Stopped {
		t.Fatalf("state = %s", sb.State)
	}

	if _, err := svc.Start(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, sb.ID)
	if err != nil || sb.State != sandbox.Running {
		t.Fatalf("start: %+v, %v", sb, err)
	}

	if _, err := svc.Stop(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, sb.ID)
	if err != nil || sb.State != sandbox.Stopped {
		t.Fatalf("stop: %+v, %v", sb, err)
	}

	if _, err := svc.Delete(ctx, sb.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, sb.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestDuplicateName(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)

	if _, err := svc.Create(ctx, CreateRequest{Name: "dev"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, CreateRequest{Name: "dev"}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestRemoteMCPUsesExplicitHostAllowlist(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "mcp-allowlist.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	defer func() { _ = svc.Close() }()
	svc.SetMCPRemoteAllowlist([]string{"mcp.example.test"})
	if _, err := svc.RegisterRemoteMCPServer(ctx, "allowed", "https://mcp.example.test/mcp", nil, nil); err != nil {
		t.Fatalf("allowed remote host rejected: %v", err)
	}
	if _, err := svc.RegisterRemoteMCPServer(ctx, "blocked", "https://other.example.test/mcp", nil, nil); err == nil {
		t.Fatal("host outside the administrator allowlist was accepted")
	}
	svc.SetMCPRemoteAllowlist(nil)
	if _, err := svc.RegisterRemoteMCPServer(ctx, "revoked", "https://mcp.example.test/mcp", nil, nil); err == nil {
		t.Fatal("empty/revoked host policy still allowed registration")
	}
}

func TestCreateBakesValidatedEnv(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	if _, err := svc.Create(ctx, CreateRequest{Name: "env-ok", Env: map[string]string{"B": "2", "A": "1"}}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(backend.lastConfig.Env, ","); got != "A=1,B=2" {
		t.Fatalf("env = %q", got)
	}
	created := backend.created
	for i, env := range []map[string]string{
		{"BAD-NAME": "x"},
		{"A": "x\x00y"},
		{strings.Repeat("K", 256): "x"},
		{"OPENAI_API_KEY": "${secret:openai}"},
	} {
		if _, err := svc.Create(ctx, CreateRequest{Name: fmt.Sprintf("env-bad-%d", i), Env: env}); err == nil {
			t.Fatalf("invalid env accepted: %v", env)
		}
	}
	if backend.created != created {
		t.Fatalf("invalid env reached runtime: created=%d want %d", backend.created, created)
	}
}

func TestCreateRejectsUnsafeNamesBeforeRuntime(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	for _, name := range []string{"", ".", "..", "../outside", "a/b", `a\b`, "a\x00b", strings.Repeat("x", 64)} {
		if _, err := svc.Create(ctx, CreateRequest{Name: name}); !errors.Is(err, core.ErrConflict) {
			t.Fatalf("unsafe name %q: %v", name, err)
		}
	}
	if backend.created != 0 {
		t.Fatal("unsafe name reached runtime")
	}
	if _, err := svc.Create(ctx, CreateRequest{Name: "fixture-1"}); err != nil || backend.created != 1 {
		t.Fatalf("valid name rejected: %v", err)
	}
}

func TestDeleteRunningRequiresForce(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)

	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, false); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, true); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileInterruptedState(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Unix(100, 0).UTC()
	sb := sandbox.Sandbox{
		ID: "sb-1", Name: "dev", State: sandbox.Running, Generation: 2,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	op := operation.Operation{
		ID: "op-1", SandboxID: "sb-1", Kind: operation.KindStart,
		State: operation.Pending, Generation: 2, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Operations().Create(ctx, op); err != nil {
		t.Fatal(err)
	}

	svc := New(st, nil)
	changed, err := svc.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 2 {
		t.Fatalf("changed = %d", changed)
	}
	got, err := st.Get(ctx, "sb-1")
	if err != nil || got.State != sandbox.Unknown {
		t.Fatalf("sandbox: %+v, %v", got, err)
	}
	if _, err := svc.Delete(ctx, got.ID, false); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("unknown runtime state was deleted without force: %v", err)
	}
	gotOp, err := st.Operations().Get(ctx, "op-1")
	if err != nil || gotOp.State != operation.Failed {
		t.Fatalf("operation: %+v, %v", gotOp, err)
	}
}

func TestReconcileRemovesInterruptedCreateRuntime(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "interrupted-create.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Unix(200, 0).UTC()
	sb := sandbox.Sandbox{
		ID: "sb-interrupted", Name: "interrupted", State: sandbox.Creating, Generation: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	settings := []string{
		proxyServiceSettingKey(sb.ID),
		registryProxySettingKey(sb.ID),
		privateRegistrySettingKey(sb.ID),
		dockerSettingKey(sb.ID),
	}
	for _, key := range settings {
		if err := st.SetSetting(ctx, key, "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	backend := &fakeRuntime{}
	svc := New(st, backend)

	changed, err := svc.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 1 {
		t.Fatalf("reconcile changed = %d, want 1", changed)
	}
	if _, err := st.Get(ctx, sb.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("interrupted create row survived reconcile: %v", err)
	}
	if backend.deleted != 1 {
		t.Fatalf("runtime deletes = %d, want 1", backend.deleted)
	}
	for _, key := range settings {
		if _, err := st.GetSetting(ctx, key); !errors.Is(err, core.ErrNotFound) {
			t.Fatalf("setting %q survived reconcile: %v", key, err)
		}
	}
}

func TestReconcileCleansTrackedButUnstartedCreate(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "unstarted-create.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Unix(300, 0).UTC()
	sb := sandbox.Sandbox{
		ID: "sb-unstarted", Name: "unstarted", State: sandbox.Creating, Generation: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, proxyServiceSettingKey(sb.ID), "openai"); err != nil {
		t.Fatal(err)
	}
	backend := &fakeRuntime{}
	svc := New(st, backend)

	if _, err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, sb.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("tracked-but-unstarted create survived reconcile: %v", err)
	}
	if _, err := st.GetSetting(ctx, proxyServiceSettingKey(sb.ID)); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("unstarted create setting survived reconcile: %v", err)
	}
}

func TestCreatePersistsIntentBeforeRuntime(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "create-intent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	observed := false
	backend.afterCreate = func() {
		got, err := st.GetByName(ctx, "persist-intent")
		if err != nil {
			t.Errorf("intent row is missing during runtime create: %v", err)
			return
		}
		if got.State != sandbox.Creating {
			t.Errorf("intent state during runtime create = %s, want creating", got.State)
		}
		observed = true
	}
	svc := New(st, backend)
	if _, err := svc.Create(ctx, CreateRequest{Name: "persist-intent"}); err != nil {
		t.Fatal(err)
	}
	if !observed {
		t.Fatal("runtime create hook was not called")
	}
}

type fakeRuntime struct {
	created          int
	lastConfig       runtime.Config
	proxyHelperPath  string
	proxyGuestPort   uint16
	proxyServiceHost string
	proxyRouteArgs   []string
	lastHandle       runtime.Handle
	lastExec         runtime.ExecRequest
	started          int
	stopped          int
	deleted          int
	deleteErr        error
	afterCreate      func()
	deleteCtxErr     error
	stopGrace        time.Duration
}

type fakeCloneRuntime struct {
	fakeRuntime
	execRequests   []runtime.ExecRequest
	execFailMatch  string
	execFailure    error
	execFailEcho   bool
	forwardCalls   []bool
	forwardPorts   []uint16
	forwardError   error
	withdrawError  error
	guestRealpaths map[string]string
	gitUnavailable bool
}

func (f *fakeCloneRuntime) Capabilities(context.Context) (runtime.Capabilities, error) {
	return runtime.Capabilities{Workspace: true, Network: true}, nil
}

func (f *fakeCloneRuntime) ExecNative(_ context.Context, _ runtime.Handle, req runtime.ExecRequest) (int, error) {
	copyReq := req
	copyReq.Argv = append([]string(nil), req.Argv...)
	copyReq.Env = append([]string(nil), req.Env...)
	f.execRequests = append(f.execRequests, copyReq)
	command := cloneGuestCommand(req.Argv)
	if f.execFailMatch != "" && strings.Contains(strings.Join(command, " "), f.execFailMatch) {
		if f.execFailEcho && req.Stderr != nil {
			_, _ = io.WriteString(req.Stderr, strings.Join(req.Argv, " "))
		}
		return 1, f.execFailure
	}
	if f.gitUnavailable && len(command) > 0 && command[0] == "git" {
		return 127, errors.New("git not found")
	}
	if len(command) == 2 && command[0] == "git" && command[1] == "--version" && req.Stdout != nil {
		if _, err := io.WriteString(req.Stdout, "git version 2.50.1\n"); err != nil {
			return 1, err
		}
	}
	if len(command) == 4 && command[0] == "realpath" && req.Stdout != nil {
		resolved := command[3]
		if configured, ok := f.guestRealpaths[resolved]; ok {
			resolved = configured
		}
		if _, err := io.WriteString(req.Stdout, resolved+"\n"); err != nil {
			return 1, err
		}
	}
	return 0, nil
}

func (f *fakeCloneRuntime) SetGitDaemon(_ context.Context, _ string, enabled bool) (uint16, error) {
	f.forwardCalls = append(f.forwardCalls, enabled)
	if enabled && f.forwardError != nil {
		return 0, f.forwardError
	}
	if !enabled {
		return 0, f.withdrawError
	}
	index := 0
	for _, call := range f.forwardCalls[:len(f.forwardCalls)-1] {
		if call {
			index++
		}
	}
	if index >= len(f.forwardPorts) {
		return 49152, nil
	}
	return f.forwardPorts[index], nil
}

func cloneGuestCommand(argv []string) []string {
	for i, arg := range argv {
		if arg == "git" || arg == "mkdir" || arg == "rm" || arg == "realpath" || arg == "/bin/sh" {
			return argv[i:]
		}
	}
	return nil
}

// cloneExportPrepared reports whether the guest command created the single
// export entry that git daemon serves.
func cloneExportPrepared(request runtime.ExecRequest) bool {
	command := cloneGuestCommand(request.Argv)
	return len(command) == 8 && command[0] == cloneShellCommand && command[3] == "clone-export" &&
		command[4] == cloneExportGuestDir && validCloneEndpointPath(cloneEndpointPath(command[5], command[6])) && command[7] != ""
}

// cloneAuthPrepared reports whether the guest command installed the token,
// repository name and access hook used by every Git daemon connection.
func cloneAuthPrepared(request runtime.ExecRequest) bool {
	command := cloneGuestCommand(request.Argv)
	return len(command) == 7 && command[0] == cloneShellCommand && command[3] == "clone-auth" &&
		command[4] == cloneAuthGuestDir && validCloneEndpointPath(cloneEndpointPath(command[5], command[6]))
}

// cloneAuthRemoved reports whether the guest command deleted the token and
// access hook on clone teardown.
func cloneAuthRemoved(request runtime.ExecRequest) bool {
	command := cloneGuestCommand(request.Argv)
	return len(command) == 4 && command[0] == "rm" && command[1] == "-rf" && command[2] == "--" && command[3] == cloneAuthGuestDir
}

// cloneEndpointToken returns the per-sandbox token from a published endpoint.
func cloneEndpointToken(t *testing.T, endpoint *sandbox.GitEndpoint) string {
	t.Helper()
	if endpoint == nil {
		t.Fatal("clone has no Git endpoint")
	}
	token, _, ok := splitCloneEndpointPath(endpoint.Repository)
	if !ok {
		t.Fatalf("clone endpoint path %q is not token/repository", endpoint.Repository)
	}
	return token
}

// cloneExportRemoved reports whether the guest command removed the export
// directory on clone teardown.
func cloneExportRemoved(request runtime.ExecRequest) bool {
	command := cloneGuestCommand(request.Argv)
	return len(command) == 4 && command[0] == "rm" && command[1] == "-rf" && command[2] == "--" && command[3] == cloneExportGuestDir
}

type blockingStopRuntime struct {
	fakeRuntime
	stopEntered  chan struct{}
	stopRelease  chan struct{}
	deleteCalled chan struct{}
}

func (b *blockingStopRuntime) Stop(ctx context.Context, _ runtime.Handle, _ time.Duration) error {
	close(b.stopEntered)
	select {
	case <-b.stopRelease:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *blockingStopRuntime) Delete(context.Context, runtime.Handle) error {
	close(b.deleteCalled)
	return nil
}

func (f *fakeRuntime) Capabilities(context.Context) (runtime.Capabilities, error) {
	return runtime.Capabilities{Workspace: true}, nil
}
func (f *fakeRuntime) Create(_ context.Context, cfg runtime.Config) (runtime.Handle, error) {
	f.created++
	f.lastConfig = cfg
	if f.afterCreate != nil {
		f.afterCreate()
	}
	return runtime.Handle{ID: "rheic-" + cfg.Name}, nil
}
func (f *fakeRuntime) CreateWithProxy(ctx context.Context, cfg *runtime.Config, helperPath string, guestPort uint16, serviceHost string) (runtime.Handle, error) {
	f.proxyHelperPath = helperPath
	f.proxyGuestPort = guestPort
	f.proxyServiceHost = serviceHost
	return f.Create(ctx, *cfg)
}
func (f *fakeRuntime) CreateWithProxyRouteArgs(ctx context.Context, cfg *runtime.Config, helperPath string, routes []string) (runtime.Handle, error) {
	f.proxyHelperPath = helperPath
	f.proxyRouteArgs = append([]string(nil), routes...)
	return f.Create(ctx, *cfg)
}
func (f *fakeRuntime) Exec(_ context.Context, _ runtime.Handle, req runtime.ExecRequest) (int, error) {
	f.lastExec = req
	return 0, nil
}

func (f *fakeRuntime) ExecNative(_ context.Context, _ runtime.Handle, req runtime.ExecRequest) (int, error) {
	f.lastExec = req
	return 0, nil
}

func (f *fakeRuntime) Start(_ context.Context, h runtime.Handle) error {
	f.started++
	f.lastHandle = h
	return nil
}
func (f *fakeRuntime) Stop(_ context.Context, _ runtime.Handle, grace time.Duration) error {
	f.stopped++
	f.stopGrace = grace
	return nil
}

func TestStopUsesRequestedGrace(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StopWithGrace(ctx, op.SandboxID, 23*time.Second); err != nil {
		t.Fatal(err)
	}
	if backend.stopGrace != 23*time.Second {
		t.Fatalf("grace = %s", backend.stopGrace)
	}
	if _, err := svc.StopWithGrace(ctx, op.SandboxID, -time.Second); err == nil {
		t.Fatal("negative grace accepted")
	}
}
func (f *fakeRuntime) Delete(ctx context.Context, _ runtime.Handle) error {
	f.deleted++
	f.deleteCtxErr = ctx.Err()
	return f.deleteErr
}
func (f *fakeRuntime) Handle(name string) runtime.Handle {
	return runtime.Handle{ID: "rheic-" + name}
}

func TestLifecycleWithRuntime(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)

	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.State != sandbox.Running {
		t.Fatalf("create: %+v, %v", sb, err)
	}
	if _, err := svc.Start(ctx, sb.ID); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("expected running conflict, got %v", err)
	}
	if _, err := svc.Stop(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Delete(ctx, sb.ID, true); err != nil {
		t.Fatal(err)
	}
	if backend.created != 1 || backend.stopped != 1 || backend.started != 1 || backend.deleted != 1 {
		t.Fatalf("backend calls: %+v", backend)
	}
}

func TestStopAndDeleteSerializePerSandbox(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &blockingStopRuntime{stopEntered: make(chan struct{}), stopRelease: make(chan struct{}), deleteCalled: make(chan struct{})}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	stopDone := make(chan error, 1)
	go func() { _, err := svc.Stop(ctx, op.SandboxID); stopDone <- err }()
	<-backend.stopEntered
	deleteDone := make(chan error, 1)
	go func() { _, err := svc.Delete(ctx, op.SandboxID, true); deleteDone <- err }()
	select {
	case <-backend.deleteCalled:
		close(backend.stopRelease)
		t.Fatal("delete reached runtime while stop was in progress")
	case <-time.After(500 * time.Millisecond):
	}
	close(backend.stopRelease)
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, op.SandboxID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("sandbox record remains after delete: %v", err)
	}
}

func TestLifecycleWaitHonorsCancellation(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &blockingStopRuntime{stopEntered: make(chan struct{}), stopRelease: make(chan struct{}), deleteCalled: make(chan struct{})}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := svc.Stop(ctx, op.SandboxID); done <- err }()
	<-backend.stopEntered
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = svc.Delete(canceled, op.SandboxID, true)
	close(backend.stopRelease)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting delete ignored cancellation: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-backend.deleteCalled:
		t.Fatal("canceled delete reached runtime")
	default:
	}
}

func TestForceDeleteKeepsRecordOnRuntimeFailure(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{deleteErr: errors.New("runtime unavailable")}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, true); !errors.Is(err, backend.deleteErr) {
		t.Fatalf("runtime failure not returned: %v", err)
	}
	if got, err := svc.Get(ctx, op.SandboxID); err != nil || got.State != sandbox.Unknown {
		t.Fatalf("sandbox state after failed delete: %+v, %v", got, err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, false); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("unknown sandbox deleted without force: %v", err)
	}
	backend.deleteErr = nil
	if _, err := svc.Delete(ctx, op.SandboxID, true); err != nil {
		t.Fatalf("retry after runtime recovery failed: %v", err)
	}
	if _, err := svc.Get(ctx, op.SandboxID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("sandbox record not removed on success: %v", err)
	}
}

func TestDeleteCleanupFailureKeepsRecordAndReconcileFinishes(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "delete-cleanup-retry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	vault := &fakeServiceSecretVault{items: make(map[string]string)}
	secretStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(st, nil)
	svc.SetServiceSecretStore(secretStore)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeSandbox, "dev", []byte("synthetic-key")); err != nil {
		t.Fatal(err)
	}
	settings := []string{
		proxyServiceSettingKey(op.SandboxID),
		registryProxySettingKey(op.SandboxID),
		privateRegistrySettingKey(op.SandboxID),
		dockerSettingKey(op.SandboxID),
	}
	for _, key := range settings {
		if err := st.SetSetting(ctx, key, "fixture"); err != nil {
			t.Fatal(err)
		}
	}

	cleanupErr := errors.New("host keychain unavailable")
	vault.deleteErr = cleanupErr
	deleteOp, err := svc.Delete(ctx, op.SandboxID, false)
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("cleanup failure was not returned: %v", err)
	}
	if deleteOp.State != operation.Failed || !strings.Contains(deleteOp.Error, cleanupErr.Error()) {
		t.Fatalf("failed delete operation was not observable: %+v", deleteOp)
	}
	got, err := svc.Get(ctx, op.SandboxID)
	if err != nil || got.State != sandbox.Deleting {
		t.Fatalf("sandbox row was dropped or left in the wrong state: %+v, %v", got, err)
	}
	for _, key := range settings {
		if value, err := st.GetSetting(ctx, key); err != nil || value != "fixture" {
			t.Fatalf("sandbox setting %q was removed before cleanup succeeded: %q, %v", key, value, err)
		}
	}

	vault.deleteErr = nil
	changed, err := svc.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 1 {
		t.Fatalf("reconcile changed = %d, want 1", changed)
	}
	if _, err := svc.Get(ctx, op.SandboxID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("reconcile did not finish the delete: %v", err)
	}
	if _, err := secretStore.Load(ctx, "openai", servicesecrets.ScopeSandbox, "dev"); !errors.Is(err, servicesecrets.ErrNotFound) {
		t.Fatalf("sandbox service secret survived reconcile: %v", err)
	}
	for _, key := range settings {
		if _, err := st.GetSetting(ctx, key); !errors.Is(err, core.ErrNotFound) {
			t.Fatalf("sandbox setting %q survived reconcile: %v", key, err)
		}
	}
}

func TestDeleteCleanupRetryIsIdempotent(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "delete-cleanup-idempotent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	vault := &fakeServiceSecretVault{items: make(map[string]string)}
	secretStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(st, nil)
	svc.SetServiceSecretStore(secretStore)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeSandbox, "dev", []byte("synthetic-key")); err != nil {
		t.Fatal(err)
	}
	vault.deleteErr = errors.New("host keychain unavailable")
	if _, err := svc.Delete(ctx, op.SandboxID, false); err == nil {
		t.Fatal("delete unexpectedly succeeded while cleanup was failing")
	}
	vault.deleteErr = nil

	if _, err := svc.Delete(ctx, op.SandboxID, false); err != nil {
		t.Fatalf("retry after cleanup recovery failed: %v", err)
	}
	if _, err := svc.Get(ctx, op.SandboxID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("sandbox row remains after successful retry: %v", err)
	}
	if _, err := secretStore.Load(ctx, "openai", servicesecrets.ScopeSandbox, "dev"); !errors.Is(err, servicesecrets.ErrNotFound) {
		t.Fatalf("sandbox service secret remains after successful retry: %v", err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, false); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("repeated delete = %v, want not found", err)
	}
	if changed, err := svc.Reconcile(ctx); err != nil || changed != 0 {
		t.Fatalf("reconcile after successful delete = %d, %v", changed, err)
	}
}

func TestCreateReportsRollbackFailure(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	if _, err := svc.Create(ctx, CreateRequest{Name: "one", IdempotencyKey: "first-key"}); err != nil {
		t.Fatal(err)
	}
	backend.deleteErr = errors.New("synthetic cleanup failure")
	backend.afterCreate = func() {
		now := time.Now()
		err := st.Operations().Create(ctx, operation.Operation{ID: "fixture-op", SandboxID: "fixture", Kind: operation.KindCreate, State: operation.Done, Generation: 1, IdempotencyKey: "other-key", CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Create(ctx, CreateRequest{Name: "two", IdempotencyKey: "other-key"}); !errors.Is(err, backend.deleteErr) {
		t.Fatalf("cleanup failure was hidden: %v", err)
	}
	if backend.deleted != 1 {
		t.Fatalf("cleanup calls = %d", backend.deleted)
	}
	if _, err := svc.GetByName(ctx, "one"); err != nil {
		t.Fatalf("existing sandbox record was affected: %v", err)
	}
}

func TestConcurrentCreateSameNameDoesNotRollbackExistingSandbox(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	errs := make(chan error, 2)
	for _, key := range []string{"first", "second"} {
		go func() {
			_, err := svc.Create(ctx, CreateRequest{Name: "dev", IdempotencyKey: key})
			errs <- err
		}()
	}
	first, second := <-errs, <-errs
	if (first != nil || !errors.Is(second, core.ErrConflict)) && (second != nil || !errors.Is(first, core.ErrConflict)) {
		t.Fatalf("unexpected create results: %v, %v", first, second)
	}
	if backend.created != 1 || backend.deleted != 0 {
		t.Fatalf("existing resource at risk: created=%d deleted=%d", backend.created, backend.deleted)
	}
}

func TestCreateIdempotencyReplayAndConflict(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	workspace := filepath.Join(t.TempDir(), "fixture")
	req := CreateRequest{Name: "dev", IdempotencyKey: "key", Workspace: workspace}
	first, err := svc.Create(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Create(ctx, req)
	if err != nil || first.ID != second.ID || backend.created != 1 {
		t.Fatalf("idempotent replay: first=%s second=%s created=%d err=%v", first.ID, second.ID, backend.created, err)
	}
	req.Workspace = filepath.Join(t.TempDir(), "different")
	if _, err := svc.Create(ctx, req); !errors.Is(err, core.ErrConflict) || backend.created != 1 {
		t.Fatalf("different request accepted or reached runtime: %v", err)
	}
	if _, err := svc.Delete(ctx, first.SandboxID, true); err != nil {
		t.Fatal(err)
	}
	req.Workspace = workspace
	if _, err := svc.Create(ctx, req); !errors.Is(err, core.ErrConflict) || backend.created != 1 {
		t.Fatalf("key reused after deletion: %v", err)
	}
}

func TestConcurrentCreateWithSameKeyRunsBackendOnce(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	type result struct {
		op  operation.Operation
		err error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			op, err := svc.Create(ctx, CreateRequest{Name: "dev", IdempotencyKey: "same-key"})
			results <- result{op: op, err: err}
		}()
	}
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.op.ID != second.op.ID || backend.created != 1 {
		t.Fatalf("concurrent replay failed: first=%+v second=%+v created=%d", first, second, backend.created)
	}
}

func TestCreateWaitingForSameKeyHonorsCancellation(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	entered, release := make(chan struct{}), make(chan struct{})
	backend := &fakeRuntime{afterCreate: func() { close(entered); <-release }}
	svc := New(st, backend)
	done := make(chan error, 1)
	go func() {
		_, err := svc.Create(ctx, CreateRequest{Name: "dev", IdempotencyKey: "key"})
		done <- err
	}()
	<-entered
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = svc.Create(canceled, CreateRequest{Name: "dev", IdempotencyKey: "key"})
	close(release)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting create ignored cancellation: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCreateRollbackContinuesAfterRequestCancellation(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := &fakeRuntime{afterCreate: cancel}
	svc := New(st, backend)
	if _, err := svc.Create(ctx, CreateRequest{Name: "dev"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled request, got %v", err)
	}
	if backend.deleted != 1 || backend.deleteCtxErr != nil {
		t.Fatalf("cleanup did not run with a live context: calls=%d err=%v", backend.deleted, backend.deleteCtxErr)
	}
}

func TestCreatePassesResourceOverridesAndDefaults(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "sized", CPUs: 4, MemoryMiB: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if backend.lastConfig.CPUs != 4 || backend.lastConfig.MemoryMiB != 4096 {
		t.Fatalf("runtime config = %+v", backend.lastConfig)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.CPUs != 4 || sb.MemoryMiB != 4096 {
		t.Fatalf("sandbox = %+v, %v", sb, err)
	}
	op, err = svc.Create(ctx, CreateRequest{Name: "defaults"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, op.SandboxID)
	if err != nil || sb.CPUs != svc.DefaultCPUs || sb.MemoryMiB != svc.DefaultMemoryMiB {
		t.Fatalf("defaults = %+v, %v (want %d CPU/%d MiB)", sb, err, svc.DefaultCPUs, svc.DefaultMemoryMiB)
	}
	for _, req := range []CreateRequest{{Name: "bad-cpu", CPUs: 65}, {Name: "bad-memory", MemoryMiB: 64}} {
		if _, err := svc.Create(ctx, req); err == nil {
			t.Fatalf("invalid request accepted: %+v", req)
		}
	}
}

func TestStopAndStartTrackStoppedAt(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "timed"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || !sb.StoppedAt.IsZero() {
		t.Fatalf("running stoppedAt=%v err=%v", sb.StoppedAt, err)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, op.SandboxID)
	if err != nil || sb.StoppedAt.IsZero() {
		t.Fatalf("stopped stoppedAt=%v err=%v", sb.StoppedAt, err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, op.SandboxID)
	if err != nil || !sb.StoppedAt.IsZero() {
		t.Fatalf("restarted stoppedAt=%v err=%v", sb.StoppedAt, err)
	}
}

func TestCreatePassesWorkspacesAndStoresThem(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	work := filepath.Join(t.TempDir(), "work")
	docs := filepath.Join(t.TempDir(), "docs")
	hostPort := availableHostTCPPort(t)
	op, err := svc.Create(ctx, CreateRequest{Name: "multi", Agent: "shell", Detached: true, Workspaces: []sandbox.Workspace{
		{Path: work}, {Path: docs, GuestPath: "/mnt/docs", ReadOnly: true},
	}, Ports: []sandbox.Port{{Host: hostPort, Guest: 3000}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(backend.lastConfig.Workspaces) != 2 || !backend.lastConfig.Workspaces[1].ReadOnly || backend.lastConfig.Workspaces[1].GuestPath != "/mnt/docs" ||
		backend.lastConfig.Workspace != work || len(backend.lastConfig.Ports) != 1 || backend.lastConfig.Ports[0].Host != hostPort {
		t.Fatalf("runtime config=%+v", backend.lastConfig)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || len(sb.Workspaces) != 2 || sb.Workspace != work || sb.Workspaces[1].GuestPath != "/mnt/docs" || !sb.Workspaces[1].ReadOnly ||
		len(sb.Ports) != 1 || sb.Ports[0].Host != hostPort || sb.Ports[0].Guest != 3000 || sb.Meta == nil || sb.Meta.Agent != "shell" || !sb.Meta.Detached {
		t.Fatalf("sandbox=%+v err=%v", sb, err)
	}
}

func TestCreateRejectsInvalidWorkspaces(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, &fakeRuntime{})
	for _, workspaces := range [][]sandbox.Workspace{
		{{Path: "relative"}},
		{{Path: "/work"}, {Path: "/work"}},
		{{Path: ""}},
	} {
		if _, err := svc.Create(ctx, CreateRequest{Name: "bad", Workspaces: workspaces}); err == nil {
			t.Fatalf("invalid workspaces accepted: %+v", workspaces)
		}
	}
}

func TestNormalizeCloneOptionsRequiresOneRealGitWorkspaceAndMountsItReadOnly(t *testing.T) {
	source := makeCloneSourceRepository(t)
	other := t.TempDir()
	guestWorkdir := "/workspace/project"
	workspaces, err := normalizeWorkspaces(CreateRequest{Workspaces: []sandbox.Workspace{{Path: source}}})
	if err != nil {
		t.Fatal(err)
	}
	clone, err := normalizeCloneOptions(&sandbox.CloneOptions{SourceWorkspacePath: source, GuestWorkdir: &guestWorkdir}, workspaces)
	if err != nil {
		t.Fatal(err)
	}
	if clone == nil || len(workspaces) != 1 || !workspaces[0].ReadOnly || workspaces[0].GuestPath != cloneSourceGuestPath {
		t.Fatalf("normalized clone=%+v workspaces=%+v", clone, workspaces)
	}

	for _, test := range []struct {
		name       string
		clone      *sandbox.CloneOptions
		workspaces []sandbox.Workspace
	}{
		{name: "source missing", clone: &sandbox.CloneOptions{SourceWorkspacePath: filepath.Join(t.TempDir(), "missing")}, workspaces: []sandbox.Workspace{{Path: source}}},
		{name: "source path not a workspace", clone: &sandbox.CloneOptions{SourceWorkspacePath: other}, workspaces: []sandbox.Workspace{{Path: source}}},
		{name: "source is not primary", clone: &sandbox.CloneOptions{SourceWorkspacePath: source}, workspaces: []sandbox.Workspace{{Path: other, ReadOnly: true}, {Path: source}}},
		{name: "unsafe repository slug", clone: &sandbox.CloneOptions{SourceWorkspacePath: source, GuestWorkdir: ptrString("/workspace/unsafe repo")}, workspaces: []sandbox.Workspace{{Path: source}}},
		{name: "extra workspace", clone: &sandbox.CloneOptions{SourceWorkspacePath: source}, workspaces: []sandbox.Workspace{{Path: source}, {Path: other, GuestPath: "/workspace/cache"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizeCloneOptions(test.clone, test.workspaces); !errors.Is(err, core.ErrConflict) {
				t.Fatalf("normalizeCloneOptions error=%v, want conflict", err)
			}
		})
	}
}

func TestCloneAdditionalReadOnlyWorkspace(t *testing.T) {
	requirePOSIXCloneHost(t)
	source := makeCloneSourceRepository(t)
	other := t.TempDir()
	for _, tc := range []struct {
		name      string
		guestPath string
		readOnly  bool
		wantError bool
	}{
		{name: "separate read-only", readOnly: true},
		{name: "writable rejected", guestPath: "/reference", wantError: true},
		{name: "clone source reserved", guestPath: "/run/sandbox/source/child", readOnly: true, wantError: true},
		{name: "clone auth reserved", guestPath: "/run/sandbox/clone-auth", readOnly: true, wantError: true},
		{name: "clone export reserved", guestPath: "/run/sandbox/export", readOnly: true, wantError: true},
		{name: "custom guest path rejected", guestPath: "/reference", readOnly: true, wantError: true},
		{name: "clone workdir overlap", guestPath: "", readOnly: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extraPath := other
			if tc.name == "clone workdir overlap" {
				extraPath = filepath.Join(source, "nested")
			}
			workspaces := []sandbox.Workspace{{Path: source}, {Path: extraPath, GuestPath: tc.guestPath, ReadOnly: tc.readOnly}}
			_, err := normalizeCloneOptions(&sandbox.CloneOptions{SourceWorkspacePath: source}, workspaces)
			if (err != nil) != tc.wantError {
				t.Fatalf("normalizeCloneOptions error=%v, wantError=%v", err, tc.wantError)
			}
			if err == nil && (!workspaces[0].ReadOnly || workspaces[0].GuestPath != cloneSourceGuestPath || !workspaces[1].ReadOnly || workspaces[1].GuestPath != tc.guestPath) {
				t.Fatalf("incorrect workspace mapping: %+v", workspaces)
			}
		})
	}
}

func TestCreateCloneAdditionalWorkspacePathValidation(t *testing.T) {
	requirePOSIXCloneHost(t)
	for _, tc := range []struct {
		name      string
		guestPath string
		wantError bool
	}{
		{name: "host path"},
		{name: "custom guest path rejected", guestPath: "/reference", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, err := store.Open(ctx, filepath.Join(t.TempDir(), "clone-extra.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			backend := &fakeCloneRuntime{forwardPorts: []uint16{49152}, guestRealpaths: map[string]string{}}
			svc := New(st, backend)
			source := makeCloneSourceRepository(t)
			_, err = svc.Create(ctx, CreateRequest{Name: "clone-extra-check", Workspaces: []sandbox.Workspace{
				{Path: source}, {Path: t.TempDir(), GuestPath: tc.guestPath, ReadOnly: true},
			}, Clone: &sandbox.CloneOptions{SourceWorkspacePath: source}})
			if (err != nil) != tc.wantError {
				t.Fatalf("Create error=%v wantError=%v", err, tc.wantError)
			}
			if tc.wantError && len(backend.forwardCalls) != 0 {
				t.Fatalf("unsafe clone setup on rejected request: forward=%v", backend.forwardCalls)
			}
		})
	}
}

func TestCloneSourceRejectsWorktreesAndSymlinks(t *testing.T) {
	worktree := t.TempDir()
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: /tmp/external"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateCloneSourceRepository(worktree); !errors.Is(err, core.ErrConflict) {
		t.Fatalf(".git file was accepted: %v", err)
	}

	gitDirectory := t.TempDir()
	if err := os.WriteFile(filepath.Join(gitDirectory, "config"), []byte("[core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkedGit := t.TempDir()
	if err := os.Symlink(gitDirectory, filepath.Join(symlinkedGit, ".git")); err != nil {
		t.Fatal(err)
	}
	if err := validateCloneSourceRepository(symlinkedGit); !errors.Is(err, core.ErrConflict) {
		t.Fatalf(".git symlink was accepted: %v", err)
	}

	sourceRepository := makeCloneSourceRepository(t)
	alias := filepath.Join(t.TempDir(), "repo-link")
	if err := os.Symlink(sourceRepository, alias); err != nil {
		t.Fatal(err)
	}
	if err := validateCloneSourceRepository(alias); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("workspace symlink was accepted: %v", err)
	}
}

func TestResolveCloneWorkdirUsesHostPathUnlessExplicit(t *testing.T) {
	requirePOSIXCloneHost(t)
	explicit := "/workspace/project"
	if got, err := resolveCloneWorkdir(&sandbox.CloneOptions{SourceWorkspacePath: "/private/tmp/lab/repo", GuestWorkdir: &explicit}); err != nil || got != explicit {
		t.Fatalf("explicit workdir = %q, err=%v, want %q", got, err, explicit)
	}
	if got, err := resolveCloneWorkdir(&sandbox.CloneOptions{SourceWorkspacePath: "/private/tmp/lab/repo"}); err != nil || got != "/private/tmp/lab/repo" {
		t.Fatalf("default workdir = %q, err=%v, want host workspace path", got, err)
	}
	if _, err := resolveCloneWorkdir(&sandbox.CloneOptions{SourceWorkspacePath: "relative/repo"}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("relative default workdir error = %v, want conflict", err)
	}
}

func TestStateOnlyCloneFailsClosedBeforePersistence(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "state-only-clone.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	source := makeCloneSourceRepository(t)
	if _, err := svc.Create(ctx, CreateRequest{Name: "clone", Workspaces: []sandbox.Workspace{{Path: source}}, Clone: &sandbox.CloneOptions{SourceWorkspacePath: source}}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("state-only clone error=%v, want conflict", err)
	}
	if _, err := svc.GetByName(ctx, "clone"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("state-only clone persisted sandbox: %v", err)
	}
}

func TestCreateCloneUsesPrivateReadOnlySourceAndUploadOnlyDaemon(t *testing.T) {
	requirePOSIXCloneHost(t)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "clone.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeCloneRuntime{forwardPorts: []uint16{49152}}
	svc := New(st, backend)
	source := makeCloneSourceRepository(t)
	repository := filepath.Base(source)
	workdir := filepath.ToSlash(source)
	op, err := svc.Create(ctx, CreateRequest{Name: "clone-demo", Workspaces: []sandbox.Workspace{{Path: source}}, Clone: &sandbox.CloneOptions{SourceWorkspacePath: source}})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	token := cloneEndpointToken(t, sb.Meta.Clone.Info.GitEndpoint)
	exportEntry := posixpath.Join(cloneExportGuestDir, token, repository)
	probeURL := fmt.Sprintf("git://%s:%d/%s/%s", cloneGitGuestIP, cloneGitGuestPort, token, repository)
	if len(token) != cloneTokenHexLength || !cloneTokenPattern.MatchString(token) {
		t.Fatalf("clone token = %q, want %d lowercase hex characters", token, cloneTokenHexLength)
	}
	if len(backend.lastConfig.Workspaces) != 1 || backend.lastConfig.Workspaces[0].Path != source ||
		!backend.lastConfig.Workspaces[0].ReadOnly || backend.lastConfig.Workspaces[0].GuestPath != cloneSourceGuestPath {
		t.Fatalf("runtime clone source mount = %+v", backend.lastConfig.Workspaces)
	}
	if sb.Meta.Clone == nil || sb.Meta.Clone.Options.SourceWorkspacePath != source || sb.Meta.Clone.Options.GuestWorkdir != nil || sb.Meta.Clone.Info == nil ||
		sb.Meta.Clone.Info.GuestWorkdir != workdir || sb.Meta.Clone.Info.RemoteName != "sandbox-clone-demo" || sb.Meta.Clone.Info.GitEndpoint == nil ||
		sb.Meta.Clone.Info.GitEndpoint.HostIP != cloneGitHostIP || sb.Meta.Clone.Info.GitEndpoint.Port != 49152 ||
		sb.Meta.Clone.Info.GitEndpoint.Repository != token+"/"+repository {
		t.Fatalf("clone state = %+v", sb.Meta.Clone)
	}

	var sawClone, sawOriginRetained, sawHooksDisabled, sawCredentialsDisabled, sawExportPrep, sawAuthPrep, sawUploadDaemon, sawProbe, sawTrustConfig bool
	for _, request := range backend.execRequests {
		command := cloneGuestCommand(request.Argv)
		joined := strings.Join(command, " ")
		switch {
		case strings.Contains(joined, " clone "):
			sawClone = strings.Contains(joined, "--no-local") && strings.Contains(joined, "--no-hardlinks") &&
				strings.Contains(joined, "--no-recurse-submodules") && strings.Contains(joined, "-- /run/sandbox/source "+workdir) &&
				strings.Contains(strings.Join(request.Argv, " "), "GIT_CONFIG_GLOBAL=/tmp/.rheic-clone-gitconfig")
		case strings.Contains(joined, "remote set-url origin"):
			sawOriginRetained = strings.HasSuffix(joined, "remote set-url origin "+cloneSourceGuestPath)
		case strings.Contains(joined, "core.hooksPath /dev/null"):
			sawHooksDisabled = true
		case strings.Contains(joined, "credential.helper "):
			sawCredentialsDisabled = true
		case strings.Contains(joined, "git daemon"):
			sawUploadDaemon = strings.Contains(joined, "--base-path="+cloneExportGuestDir) && !strings.Contains(joined, "--strict-paths") &&
				strings.Contains(joined, "--access-hook="+cloneAuthHookPath) &&
				strings.Contains(joined, "--enable=upload-pack") && strings.Contains(joined, "--disable=receive-pack") &&
				strings.HasSuffix(joined, " "+exportEntry) && !strings.Contains(joined, "sh -c")
		case len(command) > 1 && command[0] == "git" && command[1] == "ls-remote":
			sawProbe = strings.Contains(joined, " "+probeURL+" HEAD") && !strings.Contains(joined, "/.git")
		case cloneExportPrepared(request):
			sawExportPrep = strings.Contains(command[2], "rm -rf") && strings.Contains(command[2], `printf 'gitdir: %s/.git\n'`) &&
				command[4] == cloneExportGuestDir && command[5] == token && command[6] == repository && command[7] == workdir
		case cloneAuthPrepared(request):
			sawAuthPrep = strings.Contains(command[2], "CLONE_ACCESS_HOOK") && command[4] == cloneAuthGuestDir &&
				command[5] == token && command[6] == repository
		}
		if strings.Contains(joined, "clone-trust-config") {
			sawTrustConfig = true
		}
		if request.Argv[0] != "/usr/bin/env" || request.Argv[1] != "-i" {
			t.Fatalf("clone command did not clear inherited guest environment: %v", request.Argv)
		}
	}
	if !sawClone || !sawOriginRetained || !sawHooksDisabled || !sawCredentialsDisabled || !sawExportPrep || !sawAuthPrep ||
		!sawUploadDaemon || !sawProbe || !sawTrustConfig {
		t.Fatalf("clone commands missing: clone=%v trust=%v origin=%v hooks=%v credentials=%v export=%v auth=%v daemon=%v probe=%v",
			sawClone, sawTrustConfig, sawOriginRetained, sawHooksDisabled, sawCredentialsDisabled, sawExportPrep, sawAuthPrep, sawUploadDaemon, sawProbe)
	}
}

func TestCloneWorkdirCannotOverlapAnyWorkspaceMount(t *testing.T) {
	for _, test := range []struct {
		name       string
		workdir    string
		workspaces []sandbox.Workspace
	}{
		{name: "explicit overlaps writable", workdir: "/workspace/project", workspaces: []sandbox.Workspace{{Path: "/host/source", GuestPath: cloneSourceGuestPath}, {Path: "/host/other", GuestPath: "/workspace", ReadOnly: false}}},
		{name: "explicit is parent of mount", workdir: "/workspace", workspaces: []sandbox.Workspace{{Path: "/host/source", GuestPath: cloneSourceGuestPath}, {Path: "/host/other", GuestPath: "/workspace/project"}}},
		{name: "implicit default overlaps writable", workdir: "/workspace/project", workspaces: []sandbox.Workspace{{Path: "/host/source", GuestPath: cloneSourceGuestPath}, {Path: "/host/other", GuestPath: "/workspace", ReadOnly: false}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateCloneWorkdirAgainstWorkspaces(test.workdir, test.workspaces); !errors.Is(err, core.ErrConflict) {
				t.Fatalf("overlapping clone workdir accepted: %v", err)
			}
		})
	}
	if err := validateCloneWorkdirAgainstWorkspaces("/home/agent/project", []sandbox.Workspace{{Path: "/host/source", GuestPath: cloneSourceGuestPath}, {Path: "/host/other", GuestPath: "/workspace", ReadOnly: false}}); err != nil {
		t.Fatalf("private non-overlapping clone destination rejected: %v", err)
	}
}

func TestCreateCloneRejectsExtraWorkspaceBeforeRuntimeSideEffects(t *testing.T) {
	requirePOSIXCloneHost(t)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "clone-extra-workspace.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeCloneRuntime{}
	svc := New(st, backend)
	source := makeCloneSourceRepository(t)
	other := t.TempDir()
	_, err = svc.Create(ctx, CreateRequest{Name: "clone-extra", Workspaces: []sandbox.Workspace{
		{Path: source}, {Path: other, GuestPath: "/workspace"},
	}, Clone: &sandbox.CloneOptions{SourceWorkspacePath: source}})
	if !errors.Is(err, core.ErrConflict) {
		t.Fatalf("clone with extra workspace error=%v, want conflict", err)
	}
	if backend.created != 0 || len(backend.execRequests) != 0 {
		t.Fatalf("runtime side effects happened before rejection: create=%d exec=%d", backend.created, len(backend.execRequests))
	}
}

func TestCreateCloneRejectsGuestPathSymlinkResolution(t *testing.T) {
	requirePOSIXCloneHost(t)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "clone-symlink.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeCloneRuntime{guestRealpaths: map[string]string{"/workspace": "/mnt/host-backed"}}
	svc := New(st, backend)
	source := makeCloneSourceRepository(t)
	_, err = svc.Create(ctx, CreateRequest{Name: "clone-symlink", Workspaces: []sandbox.Workspace{{Path: source}}, Clone: &sandbox.CloneOptions{SourceWorkspacePath: source, GuestWorkdir: ptrString("/workspace/project")}})
	if err == nil || !strings.Contains(err.Error(), "different or ambiguous destination") {
		t.Fatalf("symlinked guest path accepted: %v", err)
	}
	for _, request := range backend.execRequests {
		if strings.Contains(strings.Join(cloneGuestCommand(request.Argv), " "), "git clone") {
			t.Fatal("clone ran after guest path resolved through a symlink")
		}
	}
}

func TestCloneCreateFailureUnwindsRuntimeAndForward(t *testing.T) {
	requirePOSIXCloneHost(t)
	for _, test := range []struct {
		name            string
		execFailMatch   string
		gitUnavailable  bool
		forwardError    error
		wantForwardCall []bool
	}{
		{name: "clone command", execFailMatch: " clone "},
		{name: "missing git prerequisite", gitUnavailable: true},
		{name: "publish", forwardError: errors.New("synthetic gateway failure"), wantForwardCall: []bool{true, false}},
		{name: "git daemon readiness", execFailMatch: "ls-remote"},
		{name: "non-empty destination", execFailMatch: "ls -A"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			st, err := store.Open(ctx, filepath.Join(t.TempDir(), "clone-failure.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			backend := &fakeCloneRuntime{execFailMatch: test.execFailMatch, execFailure: errors.New("synthetic exec failure"), forwardError: test.forwardError, gitUnavailable: test.gitUnavailable}
			svc := New(st, backend)
			source := makeCloneSourceRepository(t)
			if _, err := svc.Create(ctx, CreateRequest{Name: "clone-fail", Workspaces: []sandbox.Workspace{{Path: source}}, Clone: &sandbox.CloneOptions{SourceWorkspacePath: source}}); err == nil {
				t.Fatal("clone failure was accepted")
			} else if test.gitUnavailable && !strings.Contains(err.Error(), "clone image must include a working Git client") {
				t.Fatalf("missing Git error is not actionable: %v", err)
			}
			if backend.deleted != 1 || !slices.Equal(backend.forwardCalls, test.wantForwardCall) {
				t.Fatalf("cleanup deleted=%d forward calls=%v", backend.deleted, backend.forwardCalls)
			}
			if _, err := svc.GetByName(ctx, "clone-fail"); !errors.Is(err, core.ErrNotFound) {
				t.Fatalf("failed clone persisted sandbox: %v", err)
			}
		})
	}
}

func TestCloneStartStopDeleteLifecyclePersistsEndpoint(t *testing.T) {
	requirePOSIXCloneHost(t)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "clone-lifecycle.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeCloneRuntime{forwardPorts: []uint16{49152, 49153}}
	svc := New(st, backend)
	source := makeCloneSourceRepository(t)
	op, err := svc.Create(ctx, CreateRequest{Name: "clone-life", Workspaces: []sandbox.Workspace{{Path: source}}, Clone: &sandbox.CloneOptions{SourceWorkspacePath: source}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(backend.execRequests, cloneExportPrepared) {
		t.Fatal("clone create did not prepare the Git export entry")
	}
	if !slices.ContainsFunc(backend.execRequests, cloneAuthPrepared) {
		t.Fatal("clone create did not install endpoint authentication")
	}
	created, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	firstToken := cloneEndpointToken(t, created.Meta.Clone.Info.GitEndpoint)
	stopFrom := len(backend.execRequests)
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(backend.execRequests[stopFrom:], cloneExportRemoved) {
		t.Fatal("clone stop did not remove the Git export directory")
	}
	if !slices.ContainsFunc(backend.execRequests[stopFrom:], cloneAuthRemoved) {
		t.Fatal("clone stop did not remove endpoint authentication")
	}
	stopped, err := svc.Get(ctx, op.SandboxID)
	if err != nil || stopped.State != sandbox.Stopped || stopped.Meta.Clone == nil || stopped.Meta.Clone.Info == nil || stopped.Meta.Clone.Info.GitEndpoint != nil {
		t.Fatalf("stopped clone = %+v, err=%v", stopped, err)
	}
	startFrom := len(backend.execRequests)
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(backend.execRequests[startFrom:], cloneExportPrepared) {
		t.Fatal("clone start did not recreate the Git export entry")
	}
	if !slices.ContainsFunc(backend.execRequests[startFrom:], cloneAuthPrepared) {
		t.Fatal("clone start did not install a fresh endpoint token")
	}
	running, err := svc.Get(ctx, op.SandboxID)
	if err != nil || running.State != sandbox.Running || running.Meta.Clone == nil || running.Meta.Clone.Info == nil || running.Meta.Clone.Info.GitEndpoint == nil || running.Meta.Clone.Info.GitEndpoint.Port != 49153 {
		t.Fatalf("restarted clone = %+v, err=%v", running, err)
	}
	if secondToken := cloneEndpointToken(t, running.Meta.Clone.Info.GitEndpoint); secondToken == firstToken {
		t.Fatal("clone start reused the previous endpoint token")
	}
	deleteFrom := len(backend.execRequests)
	if _, err := svc.Delete(ctx, op.SandboxID, true); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(backend.execRequests[deleteFrom:], cloneExportRemoved) {
		t.Fatal("clone delete did not remove the Git export directory")
	}
	if !slices.ContainsFunc(backend.execRequests[deleteFrom:], cloneAuthRemoved) {
		t.Fatal("clone delete did not remove endpoint authentication")
	}
	if _, err := svc.Get(ctx, op.SandboxID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("deleted clone still exists: %v", err)
	}
	if !slices.Equal(backend.forwardCalls, []bool{true, false, true, false}) {
		t.Fatalf("clone forward lifecycle = %v", backend.forwardCalls)
	}
}

func TestStartRunningCloneKeepsReachableForward(t *testing.T) {
	requirePOSIXCloneHost(t)
	ctx := context.Background()
	backend := &fakeCloneRuntime{forwardPorts: []uint16{49152, 49152}}
	svc, id := newCloneRepairSandbox(t, backend)
	execBefore := len(backend.execRequests)

	if _, err := svc.Start(ctx, id); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("Start error = %v, want already-running conflict", err)
	}
	sb, err := svc.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if sb.State != sandbox.Running || sb.Meta.Clone == nil || sb.Meta.Clone.Info == nil || sb.Meta.Clone.Info.GitEndpoint == nil || sb.Meta.Clone.Info.GitEndpoint.Port != 49152 {
		t.Fatalf("reachable clone was repaired unnecessarily: %+v", sb)
	}
	if !slices.Equal(backend.forwardCalls, []bool{true, true}) {
		t.Fatalf("reachable clone forward was republished: %v", backend.forwardCalls)
	}
	if len(backend.execRequests) <= execBefore {
		t.Fatal("reachable clone guest daemon was not verified")
	}
}

func TestStartRunningCloneRepublishesLostForward(t *testing.T) {
	requirePOSIXCloneHost(t)
	ctx := context.Background()
	backend := &fakeCloneRuntime{forwardPorts: []uint16{49152, 49153}}
	svc, id := newCloneRepairSandbox(t, backend)

	if _, err := svc.Start(ctx, id); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("Start error = %v, want already-running conflict", err)
	}
	sb, err := svc.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if sb.State != sandbox.Running || sb.Meta.Clone == nil || sb.Meta.Clone.Info == nil || sb.Meta.Clone.Info.GitEndpoint == nil || sb.Meta.Clone.Info.GitEndpoint.Port != 49153 {
		t.Fatalf("repaired clone endpoint = %+v", sb.Meta)
	}
	if !slices.Equal(backend.forwardCalls, []bool{true, true}) {
		t.Fatalf("clone forward repair calls = %v", backend.forwardCalls)
	}
}

func TestStartRunningCloneFailsClosedWithoutGateway(t *testing.T) {
	requirePOSIXCloneHost(t)
	ctx := context.Background()
	backend := &fakeCloneRuntime{forwardPorts: []uint16{49152}}
	svc, id := newCloneRepairSandbox(t, backend)
	backend.forwardError = errors.New("gateway for clone-repair is not running")
	backend.withdrawError = errors.New("gateway for clone-repair is not running")

	_, err := svc.Start(ctx, id)
	if !errors.Is(err, errCloneForwardUnavailable) {
		t.Fatalf("Start error = %v, want errCloneForwardUnavailable", err)
	}
	sb, err := svc.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if sb.State != sandbox.Unknown || sb.Error == "" {
		t.Fatalf("missing gateway left the clone running: %+v", sb)
	}
	if sb.Meta.Clone == nil || sb.Meta.Clone.Info == nil || sb.Meta.Clone.Info.GitEndpoint != nil {
		t.Fatalf("missing gateway kept a clone endpoint: %+v", sb.Meta)
	}
	if !slices.Equal(backend.forwardCalls, []bool{true, true, false}) {
		t.Fatalf("failed clone repair calls = %v", backend.forwardCalls)
	}
}

func TestStartRunningNonCloneIsUnchanged(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "plain-running.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeCloneRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "plain-running"})
	if err != nil {
		t.Fatal(err)
	}
	execBefore := len(backend.execRequests)

	if _, err := svc.Start(ctx, op.SandboxID); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("Start error = %v, want already-running conflict", err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.State != sandbox.Running || sb.Meta.Clone != nil {
		t.Fatalf("non-clone sandbox changed: %+v", sb)
	}
	if len(backend.forwardCalls) != 0 || len(backend.execRequests) != execBefore {
		t.Fatalf("non-clone sandbox ran clone repair: forwards=%v exec=%d", backend.forwardCalls, len(backend.execRequests)-execBefore)
	}
}

func newCloneRepairSandbox(t *testing.T, backend *fakeCloneRuntime) (*Service, string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "clone-repair.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, backend)
	source := makeCloneSourceRepository(t)
	op, err := svc.Create(ctx, CreateRequest{
		Name: "clone-repair", Workspaces: []sandbox.Workspace{{Path: source}},
		Clone: &sandbox.CloneOptions{SourceWorkspacePath: source},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, op.SandboxID
}

func TestReconcileClearsStaleCloneEndpoint(t *testing.T) {
	requirePOSIXCloneHost(t)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "clone-reconcile.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeCloneRuntime{forwardPorts: []uint16{49152}}
	svc := New(st, backend)
	source := makeCloneSourceRepository(t)
	op, err := svc.Create(ctx, CreateRequest{Name: "clone-reconcile", Workspaces: []sandbox.Workspace{{Path: source}}, Clone: &sandbox.CloneOptions{SourceWorkspacePath: source}})
	if err != nil {
		t.Fatal(err)
	}
	created, err := svc.Get(ctx, op.SandboxID)
	if err != nil || created.Meta.Clone == nil || created.Meta.Clone.Info == nil || created.Meta.Clone.Info.GitEndpoint == nil {
		t.Fatalf("created clone has no live endpoint: %+v, %v", created.Meta, err)
	}
	if _, err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile clone state: %v", err)
	}
	reconciled, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.State != sandbox.Unknown {
		t.Fatalf("reconciled clone state = %s, want unknown", reconciled.State)
	}
	if reconciled.Meta.Clone == nil || reconciled.Meta.Clone.Info == nil || reconciled.Meta.Clone.Info.GitEndpoint != nil {
		t.Fatalf("reconcile kept a stale Git endpoint: %+v", reconciled.Meta)
	}
	if reconciled.Meta.Clone.Options.SourceWorkspacePath != source {
		t.Fatalf("reconcile dropped the clone request: %+v", reconciled.Meta.Clone.Options)
	}
}

func TestCloneAccessHookRequiresSecretTokenAndRepository(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("clone access hook runs under a POSIX shell")
	}
	exportDir := t.TempDir()
	authDir := t.TempDir()
	token := strings.Repeat("ab", cloneTokenBytes)
	repository := "project"
	if err := os.WriteFile(filepath.Join(authDir, "token"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authDir, "repository"), []byte(repository), 0o600); err != nil {
		t.Fatal(err)
	}
	script := cloneAccessHookScript(authDir)
	if strings.Contains(script, token) {
		t.Fatal("access hook script contains the endpoint token")
	}
	hookPath := filepath.Join(authDir, "access-hook")
	if err := os.WriteFile(hookPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	runHook := func(path string) int {
		t.Helper()
		command := exec.Command("/bin/sh", hookPath, "upload-pack", path)
		err := command.Run()
		if err == nil {
			return 0
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run clone access hook: %v", err)
		}
		return exitErr.ExitCode()
	}
	good := filepath.Join(exportDir, token, repository, ".git")
	wrongFirst := "bb" + token[2:]
	wrongLast := token[:cloneTokenHexLength-2] + "bb"
	tests := []struct {
		name string
		path string
		want int
	}{
		{name: "current token and repository", path: good, want: 0},
		{name: "repository path without git suffix", path: filepath.Join(exportDir, token, repository), want: 0},
		{name: "wrong first token byte", path: filepath.Join(exportDir, wrongFirst, repository, ".git"), want: 1},
		{name: "wrong last token byte", path: filepath.Join(exportDir, wrongLast, repository, ".git"), want: 1},
		{name: "uppercase token", path: filepath.Join(exportDir, strings.ToUpper(token), repository, ".git"), want: 1},
		{name: "short token", path: filepath.Join(exportDir, token[:cloneTokenHexLength-1], repository, ".git"), want: 1},
		{name: "wrong repository", path: filepath.Join(exportDir, token, "other", ".git"), want: 1},
		{name: "extra path segment", path: filepath.Join(exportDir, token, repository, "extra", ".git"), want: 1},
		{name: "traversal", path: filepath.Join(exportDir, token, "..", repository, ".git"), want: 1},
		{name: "path without token segment", path: filepath.Join(t.TempDir(), repository, ".git"), want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := runHook(test.path); got != test.want {
				t.Fatalf("access hook exit = %d, want %d for %q", got, test.want, test.path)
			}
		})
	}
}

func TestCloneGitDaemonRejectsRequestsWithoutEndpointToken(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("clone access hook runs under a POSIX shell")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	token := strings.Repeat("ab", cloneTokenBytes)
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", work, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if output, err := exec.Command("git", "-C", work, "-c", "user.email=clone@example.com", "-c", "user.name=clone", "commit", "--allow-empty", "-qm", "init").CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
	exportDir := filepath.Join(root, "export")
	authDir := filepath.Join(root, "auth")
	if err := os.MkdirAll(filepath.Join(exportDir, token, "project"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(exportDir, token, "project", ".git"), []byte("gitdir: "+filepath.Join(work, ".git")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authDir, "token"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authDir, "repository"), []byte("project"), 0o600); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(authDir, "access-hook")
	if err := os.WriteFile(hookPath, []byte(cloneAccessHookScript(authDir)), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	daemonLogPath := filepath.Join(root, "daemon.log")
	daemonLog, err := os.Create(daemonLogPath)
	if err != nil {
		t.Fatal(err)
	}
	daemon := exec.Command("git", "daemon", "--reuseaddr", "--listen=127.0.0.1",
		"--port="+strconv.Itoa(port), "--base-path="+exportDir, "--export-all",
		"--enable=upload-pack", "--disable=receive-pack", "--access-hook="+hookPath,
		filepath.Join(exportDir, token, "project"))
	daemon.Env = []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "HOME=" + root}
	daemon.Stdout = daemonLog
	daemon.Stderr = daemonLog
	if err := daemon.Start(); err != nil {
		_ = daemonLog.Close()
		t.Fatalf("start git daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_ = daemon.Wait()
		_ = daemonLog.Close()
		if t.Failed() {
			if log, readErr := os.ReadFile(daemonLogPath); readErr == nil {
				t.Logf("git daemon log:\n%s", log)
			}
		}
	})
	goodURL := fmt.Sprintf("git://127.0.0.1:%d/%s/project", port, token)
	badURL := fmt.Sprintf("git://127.0.0.1:%d/project", port)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := exec.Command("git", "ls-remote", "--quiet", goodURL, "HEAD").CombinedOutput(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(daemonLogPath)
			t.Fatalf("authenticated Git daemon did not become ready:\n%s", log)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if output, err := exec.Command("git", "ls-remote", "--quiet", badURL, "HEAD").CombinedOutput(); err == nil {
		t.Fatalf("tokenless clone request succeeded: %s", output)
	}
}

func TestCloneErrorsNeverContainTheEndpointToken(t *testing.T) {
	requirePOSIXCloneHost(t)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "clone-redaction.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeCloneRuntime{execFailMatch: "git daemon", execFailEcho: true, execFailure: errors.New("synthetic exec failure")}
	svc := New(st, backend)
	source := makeCloneSourceRepository(t)
	_, err = svc.Create(ctx, CreateRequest{Name: "clone-redact", Workspaces: []sandbox.Workspace{{Path: source}}, Clone: &sandbox.CloneOptions{SourceWorkspacePath: source}})
	if err == nil {
		t.Fatal("clone creation unexpectedly succeeded")
	}
	var token string
	for _, request := range backend.execRequests {
		command := cloneGuestCommand(request.Argv)
		if len(command) == 8 && command[3] == "clone-export" {
			token = command[5]
		}
	}
	if token == "" {
		t.Fatal("test did not observe the generated endpoint token")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("clone error leaked the endpoint token: %v", err)
	}
	if !strings.Contains(err.Error(), cloneTokenRedaction) {
		t.Fatalf("clone error did not redact the token: %v", err)
	}
}

func TestRunningCloneRejectsLegacyTokenlessEndpoint(t *testing.T) {
	requirePOSIXCloneHost(t)
	ctx := context.Background()
	backend := &fakeCloneRuntime{forwardPorts: []uint16{49152}}
	svc, id := newCloneRepairSandbox(t, backend)
	legacy, err := svc.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Meta.Clone.Info.GitEndpoint.Repository = filepath.Base(legacy.Meta.Clone.Info.GuestWorkdir)
	if err := svc.store.Update(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, id); !errors.Is(err, errCloneForwardUnavailable) {
		t.Fatalf("Start error = %v, want errCloneForwardUnavailable", err)
	}
	sb, err := svc.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if sb.Meta.Clone == nil || sb.Meta.Clone.Info == nil || sb.Meta.Clone.Info.GitEndpoint != nil {
		t.Fatalf("legacy endpoint was not cleared: %+v", sb.Meta)
	}
	if !slices.Equal(backend.forwardCalls, []bool{true}) {
		t.Fatalf("legacy endpoint reached the gateway: %v", backend.forwardCalls)
	}
}

func ptrString(value string) *string { return &value }

// requirePOSIXCloneHost skips clone lifecycle tests on hosts whose workspace
// paths are not POSIX: clone mode places the private clone at the host path.
func requirePOSIXCloneHost(t *testing.T) {
	t.Helper()
	if goruntime.GOOS == "windows" {
		t.Skip("clone mode requires a POSIX host workspace path")
	}
}

func makeCloneSourceRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	if err := os.Mkdir(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte("[core]\n\trepositoryformatversion = 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestStateOnlyCreateValidatesGuestPathsBeforePersistence(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "state-only.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)

	hostPath := filepath.Join(t.TempDir(), "repo")
	op, err := svc.Create(ctx, CreateRequest{Name: "valid", Workspaces: []sandbox.Workspace{{Path: hostPath, GuestPath: "/workspace/repo"}}})
	if err != nil {
		t.Fatalf("state-only create with a valid guest path: %v", err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || len(sb.Workspaces) != 1 || sb.Workspaces[0].GuestPath != "/workspace/repo" {
		t.Fatalf("persisted workspace = %+v, err=%v", sb.Workspaces, err)
	}

	invalid := [][]sandbox.Workspace{
		{{Path: "/host/a", GuestPath: "relative"}},
		{{Path: "/host/a", GuestPath: "/workspace/../repo"}},
		{{Path: "/host/a", GuestPath: "/workspace,repo"}},
		{{Path: "/host/a", GuestPath: "/workspace=repo"}},
		{{Path: "/host/a", GuestPath: "/workspace\x00repo"}},
		{{Path: "/host/a", GuestPath: "/workspace\rrepo"}},
		{{Path: "/host/a", GuestPath: "/workspace\nrepo"}},
		{{Path: "/host/a", GuestPath: "/workspace/shared"}, {Path: "/host/b", GuestPath: "/workspace/shared"}},
		{{Path: "/workspace/shared"}, {Path: "/host/b", GuestPath: "/workspace/shared"}},
	}
	for i, workspaces := range invalid {
		name := fmt.Sprintf("invalid-%d", i)
		if _, err := svc.Create(ctx, CreateRequest{Name: name, Workspaces: workspaces}); !errors.Is(err, core.ErrConflict) {
			t.Errorf("state-only create accepted invalid workspaces %+v: %v", workspaces, err)
		}
		if _, err := svc.GetByName(ctx, name); !errors.Is(err, core.ErrNotFound) {
			t.Errorf("invalid state-only create %q persisted a sandbox: %v", name, err)
		}
	}
}

func TestCreateRejectsOccupiedHostPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, &fakeRuntime{})
	if _, err := svc.Create(ctx, CreateRequest{Name: "busy", Ports: []sandbox.Port{{Host: port, Guest: 80}}}); err == nil {
		t.Fatal("occupied host port was accepted")
	}
}

func TestCreateRejectsInvalidPorts(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, &fakeRuntime{})
	for _, ports := range [][]sandbox.Port{
		{{Host: 0, Guest: 3000}},
		{{Host: 8080, Guest: 0}},
		{{Host: 8080, Guest: 3000, Protocol: "sctp"}},
		{{Host: 8080, Guest: 3000}, {Host: 8080, Guest: 4000}},
	} {
		if _, err := svc.Create(ctx, CreateRequest{Name: "bad", Ports: ports}); err == nil {
			t.Fatalf("invalid ports accepted: %+v", ports)
		}
	}
}

func TestNormalizePortsHostIPAndFamily(t *testing.T) {
	ports, err := normalizePorts([]sandbox.Port{
		{Host: 8080, Guest: 3000, Protocol: "tcp4"},
		{Host: 8080, Guest: 3001, Protocol: "tcp6"},
		{Host: 8080, Guest: 3002, Protocol: "udp6"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ports[0].HostIP != "127.0.0.1" || ports[1].HostIP != "::1" || ports[2].HostIP != "::1" || ports[2].Protocol != "udp" {
		t.Fatalf("ports=%+v", ports)
	}
	for _, invalid := range [][]sandbox.Port{
		{{Host: 8080, Guest: 3000, HostIP: "192.0.2.10"}},
		{{Host: 8080, Guest: 3000, Protocol: "tcp4", HostIP: "::1"}},
		{{Host: 8080, Guest: 3000, Protocol: "tcp6", HostIP: "127.0.0.1"}},
		{{Host: 8080, Guest: 3000, HostIP: "127.0.0.1"}, {Host: 8080, Guest: 4000, HostIP: "127.0.0.1"}},
	} {
		if _, err := normalizePorts(invalid); err == nil {
			t.Fatalf("invalid ports accepted: %+v", invalid)
		}
	}
}

func TestProbeHostPortIPv6UDPUsesUDP6(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 UDP loopback unavailable: %v", err)
	}
	_ = probe.Close()
	closeProbe, err := probeHostPort(sandbox.Port{Host: 26759, Guest: 8083, Protocol: "udp", HostIP: "::1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := closeProbe(); err != nil {
		t.Fatal(err)
	}
}

func TestStartPassesPublishedPortsToRuntime(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	hostPort := availableHostTCPPort(t)
	op, err := svc.Create(ctx, CreateRequest{Name: "ported", Ports: []sandbox.Port{{Host: hostPort, Guest: 3000}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if len(backend.lastHandle.Ports) != 1 || backend.lastHandle.Ports[0].Host != hostPort || backend.lastHandle.Ports[0].Guest != 3000 {
		t.Fatalf("start handle=%+v", backend.lastHandle)
	}
}

func availableHostTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return uint16(port)
}

func TestCreatePassesAndStoresNetworkRules(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	svc.DefaultPolicyProfile = policyProfileDenyAll
	op, err := svc.Create(ctx, CreateRequest{Name: "ruled",
		Allow: []sandbox.NetworkRule{{Protocol: "tcp", CIDR: "0.0.0.0/0", Port: 80}},
		Deny:  []sandbox.NetworkRule{{Protocol: "udp", CIDR: "10.0.0.0/8", Port: 53}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(backend.lastConfig.Allow) != 1 || backend.lastConfig.Allow[0].Port != 80 ||
		len(backend.lastConfig.Deny) != 1 || backend.lastConfig.Deny[0].Protocol != "udp" {
		t.Fatalf("runtime rules=%+v/%+v", backend.lastConfig.Allow, backend.lastConfig.Deny)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.Policy == nil || len(sb.Policy.Allow) != 1 || len(sb.Policy.Deny) != 1 {
		t.Fatalf("sandbox policy=%+v err=%v", sb.Policy, err)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if len(backend.lastHandle.Allow) != 1 || backend.lastHandle.Allow[0].Port != 80 {
		t.Fatalf("start handle rules=%+v", backend.lastHandle.Allow)
	}
}

func TestCreateRejectsInvalidNetworkRules(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, &fakeRuntime{})
	for _, rules := range [][]sandbox.NetworkRule{
		{{Protocol: "icmp", CIDR: "0.0.0.0/0"}},
		{{Protocol: "tcp", CIDR: "domain.example"}},
		{{Protocol: "tcp", CIDR: "2001:db8::/32"}},
	} {
		if _, err := svc.Create(ctx, CreateRequest{Name: "bad", Allow: rules}); err == nil {
			t.Fatalf("invalid rules accepted: %+v", rules)
		}
	}
}

type fakeExecutorRuntime struct {
	fakeRuntime
	execs int
}

func (f *fakeExecutorRuntime) Exec(context.Context, runtime.Handle, runtime.ExecRequest) (int, error) {
	f.execs++
	return 0, nil
}

func TestExecUpdatesLastUsedAndPreservesMeta(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeExecutorRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "used", Agent: "shell", Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.Meta == nil || sb.Meta.Agent != "shell" || !sb.Meta.Detached {
		t.Fatalf("created meta=%+v err=%v", sb.Meta, err)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if code, err := svc.Exec(ctx, op.SandboxID, runtime.ExecRequest{Argv: []string{"true"}}); err != nil || code != 0 {
		t.Fatalf("exec code=%d err=%v", code, err)
	}
	used, err := svc.Get(ctx, op.SandboxID)
	if err != nil || used.Meta == nil || used.Meta.Agent != "shell" || !used.Meta.Detached {
		t.Fatalf("used meta=%+v err=%v", used.Meta, err)
	}
	if used.State != sandbox.Running || !used.Meta.LastUsedAt.After(sb.Meta.LastUsedAt) {
		t.Fatalf("state/meta after exec=%s/%v", used.State, used.Meta)
	}
}

type fakePolicyRuntime struct {
	fakeRuntime
	revision int
	allow    []runtime.Rule
	deny     []runtime.Rule
	err      error
	before   func()
	handles  []string
	failName string
}

func TestConcurrentPolicyMutationsPreserveRevocation(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	svc.DefaultPolicyProfile = policyProfileDenyAll
	op, err := svc.Create(ctx, CreateRequest{Name: "concurrent-policy"})
	if err != nil {
		t.Fatal(err)
	}
	oldRule := sandbox.NetworkRule{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 80}
	newRule := sandbox.NetworkRule{Protocol: "tcp", CIDR: "192.0.2.0/24", Port: 443}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "allow", oldRule); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, mutation := range []struct {
		action string
		rule   sandbox.NetworkRule
	}{{"rm", oldRule}, {"allow", newRule}} {
		wg.Go(func() {
			_, err := svc.MutatePolicy(ctx, op.SandboxID, mutation.action, mutation.rule)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.Policy == nil || len(sb.Policy.Allow) != 1 || !sameRule(sb.Policy.Allow[0], newRule) {
		t.Fatalf("policy=%+v err=%v", sb.Policy, err)
	}
}

func (f *fakePolicyRuntime) UpdatePolicy(_ context.Context, h runtime.Handle, allow, deny []runtime.Rule, revision int) error {
	if f.before != nil {
		f.before()
	}
	if f.failName != "" && h.ID == "rheic-"+f.failName {
		return errors.New("injected policy update failure")
	}
	if f.err != nil {
		return f.err
	}
	f.handles = append(f.handles, h.ID)
	f.revision = revision
	f.allow = allow
	f.deny = deny
	return nil
}

func TestUpdatePolicyAppliesLiveAndPersists(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakePolicyRuntime{}
	svc := New(st, backend)
	svc.DefaultPolicyProfile = policyProfileDenyAll
	op, err := svc.Create(ctx, CreateRequest{Name: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	backend.before = func() {
		stored, getErr := st.Get(ctx, op.SandboxID)
		if getErr != nil || stored.State != sandbox.Unknown || stored.Policy == nil || len(stored.Policy.Allow) != 1 {
			t.Fatalf("policy was not persisted before reload: %+v, %v", stored, getErr)
		}
	}
	updated, err := svc.UpdatePolicy(ctx, op.SandboxID, []sandbox.NetworkRule{{Protocol: "tcp", CIDR: "0.0.0.0/0", Port: 80}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if backend.revision <= 1 || len(backend.allow) != 1 || updated.Policy == nil || len(updated.Policy.Allow) != 1 {
		t.Fatalf("revision=%d allow=%+v policy=%+v", backend.revision, backend.allow, updated.Policy)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	stopped, err := svc.UpdatePolicy(ctx, op.SandboxID, nil, []sandbox.NetworkRule{{Protocol: "udp", CIDR: "10.0.0.0/8", Port: 53}})
	if err != nil || stopped.Policy == nil || len(stopped.Policy.Deny) != 1 {
		t.Fatalf("stopped update=%+v err=%v", stopped.Policy, err)
	}
}

func TestUpdatePolicyFailureMarksUnknown(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakePolicyRuntime{err: errors.New("synthetic reload failure")}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "policy-fail"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdatePolicy(ctx, op.SandboxID, []sandbox.NetworkRule{{Protocol: "tcp", CIDR: "0.0.0.0/0", Port: 80}}, nil); err == nil {
		t.Fatal("reload failure was hidden")
	}
	if backend.stopped != 1 {
		t.Fatal("failed reload did not attempt to stop the sandbox")
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.State != sandbox.Unknown {
		t.Fatalf("state=%s err=%v", sb.State, err)
	}
	if sb.Policy == nil || len(sb.Policy.Allow) != 1 {
		t.Fatalf("desired policy lost after reload failure: %+v", sb.Policy)
	}
}

type fakePortRuntime struct {
	fakeRuntime
	ports []runtime.Port
	err   error
}

func (f *fakePortRuntime) UpdatePorts(_ context.Context, _ runtime.Handle, ports []runtime.Port) error {
	if f.err != nil {
		return f.err
	}
	f.ports = ports
	return nil
}

func TestUpdatePortsLiveAndPersist(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakePortRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "ports"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := svc.UpdatePorts(ctx, op.SandboxID, []sandbox.Port{{Host: 18091, Guest: 8080, Protocol: "tcp"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(backend.ports) != 1 || backend.ports[0].Host != 18091 || len(updated.Ports) != 1 {
		t.Fatalf("runtime=%+v sandbox=%+v", backend.ports, updated.Ports)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	stopped, err := svc.UpdatePorts(ctx, op.SandboxID, nil)
	if err != nil || len(stopped.Ports) != 0 {
		t.Fatalf("stopped ports=%+v err=%v", stopped.Ports, err)
	}
}

type mapVault struct{ items map[string]string }

func (v *mapVault) Set(_ context.Context, service, account, secret string) error {
	if v.items == nil {
		v.items = make(map[string]string)
	}
	v.items[service+"/"+account] = secret
	return nil
}

func (v *mapVault) Get(_ context.Context, service, account string) (string, error) {
	value, ok := v.items[service+"/"+account]
	if !ok {
		return "", registrycredentials.ErrNotFound
	}
	return value, nil
}

func (v *mapVault) Delete(_ context.Context, service, account string) error {
	if _, ok := v.items[service+"/"+account]; !ok {
		return registrycredentials.ErrNotFound
	}
	delete(v.items, service+"/"+account)
	return nil
}

func TestRegistryCredentialListAndSandboxCleanup(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	credentials, err := registrycredentials.NewStore(&mapVault{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetRegistryCredentialStore(credentials)
	op, err := svc.Create(ctx, CreateRequest{Name: "scoped"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LoginRegistry(ctx, registrycredentials.Credential{
		Registry: "ghcr.io", Username: "alice", Password: []byte("synthetic"), Scope: registrycredentials.ScopeSandbox, SandboxName: "scoped",
	}); err != nil {
		t.Fatal(err)
	}
	items, err := svc.ListRegistryCredentials(ctx)
	if err != nil || len(items) != 1 || items[0].Registry != "ghcr.io" || items[0].SandboxName != "scoped" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, true); err != nil {
		t.Fatal(err)
	}
	items, err = svc.ListRegistryCredentials(ctx)
	if err != nil || len(items) != 0 {
		t.Fatalf("items after delete=%+v err=%v", items, err)
	}
}

func TestPolicyProfileGlobalAndMetadata(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	if profile, err := svc.GetPolicyProfile(ctx); err != nil || profile != "allow-all" {
		t.Fatalf("default profile=%q err=%v", profile, err)
	}
	if profile, err := svc.SetPolicyProfile(ctx, "deny-all"); err != nil || profile != "deny-all" {
		t.Fatalf("explicit deny-all profile=%q err=%v", profile, err)
	}
	if profile, err := svc.SetPolicyProfile(ctx, "balanced"); err != nil || profile != "balanced" {
		t.Fatalf("set profile=%q err=%v", profile, err)
	}
	op, err := svc.Create(ctx, CreateRequest{Name: "profile-default"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.Meta == nil || sb.Meta.PolicyProfile != "balanced" {
		t.Fatalf("metadata=%+v", sb.Meta)
	}
	if len(backend.lastConfig.Allow) != 4 {
		t.Fatalf("profile rules=%+v", backend.lastConfig.Allow)
	}
	if profile, err := svc.SetPolicyProfile(ctx, "sbx-compat"); err != nil || profile != "allow-all" {
		t.Fatalf("alias profile=%q err=%v", profile, err)
	}
	if _, err := svc.SetPolicyProfile(ctx, "unknown"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestDefaultPolicyProfileMatchesSBXAndExplicitDenyAllWins(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "default-profile.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)

	if profile, err := svc.GetPolicyProfile(ctx); err != nil || profile != policyProfileAllowAll {
		t.Fatalf("default profile=%q err=%v, want allow-all", profile, err)
	}

	op, err := svc.Create(ctx, CreateRequest{Name: "default-allow-all"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.Meta == nil || sb.Meta.PolicyProfile != policyProfileAllowAll {
		t.Fatalf("metadata=%+v, want allow-all profile", sb.Meta)
	}
	if len(backend.lastConfig.Allow) != 2 || len(backend.lastConfig.Deny) != 0 {
		t.Fatalf("runtime allow=%+v deny=%+v, want allow-all profile", backend.lastConfig.Allow, backend.lastConfig.Deny)
	}
	for _, rule := range backend.lastConfig.Allow {
		if rule.CIDR != anyIPv4CIDR || rule.Port != 0 {
			t.Fatalf("allow-all rule=%+v", rule)
		}
	}

	op, err = svc.Create(ctx, CreateRequest{Name: "explicit-deny-all", PolicyProfile: policyProfileDenyAll})
	if err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.Meta == nil || sb.Meta.PolicyProfile != policyProfileDenyAll {
		t.Fatalf("explicit metadata=%+v, want deny-all profile", sb.Meta)
	}
	if len(backend.lastConfig.Allow) != 0 || len(backend.lastConfig.Deny) != 0 {
		t.Fatalf("explicit deny-all runtime allow=%+v deny=%+v", backend.lastConfig.Allow, backend.lastConfig.Deny)
	}

	// A host setting that selects deny-all must still override the sbx default.
	settingsBackend := &fakeRuntime{}
	settingsSvc := New(st, settingsBackend)
	settingsSvc.DefaultPolicyProfile = policyProfileDenyAll
	if profile, err := settingsSvc.GetPolicyProfile(ctx); err != nil || profile != policyProfileDenyAll {
		t.Fatalf("settings profile=%q err=%v, want deny-all", profile, err)
	}
	op, err = settingsSvc.Create(ctx, CreateRequest{Name: "settings-deny-all"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err = settingsSvc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.Meta == nil || sb.Meta.PolicyProfile != policyProfileDenyAll {
		t.Fatalf("settings metadata=%+v, want deny-all profile", sb.Meta)
	}
	if len(settingsBackend.lastConfig.Allow) != 0 || len(settingsBackend.lastConfig.Deny) != 0 {
		t.Fatalf("settings deny-all runtime allow=%+v deny=%+v", settingsBackend.lastConfig.Allow, settingsBackend.lastConfig.Deny)
	}
}

func TestStartDockerProfileEnablesOnlyConfiguredRegistryMirror(t *testing.T) {
	backend := &fakeRuntime{}
	svc := &Service{backend: backend}
	handle := runtime.Handle{ID: "owned"}
	if err := svc.startDockerProfile(context.Background(), handle, false, false); err != nil {
		t.Fatal(err)
	}
	withoutMirror := strings.Join(backend.lastExec.Argv, " ")
	if strings.Contains(withoutMirror, "--registry-mirror=") {
		t.Fatal("registry mirror enabled without a scoped credential route")
	}
	if err := svc.startDockerProfile(context.Background(), handle, true, false); err != nil {
		t.Fatal(err)
	}
	withMirror := strings.Join(backend.lastExec.Argv, " ")
	if !strings.Contains(withMirror, "--registry-mirror="+registryMirrorURL) {
		t.Fatalf("configured registry mirror missing from dockerd command: %s", withMirror)
	}
}

func TestStartDockerProfileFailureReportsClassifiedDiagnostic(t *testing.T) {
	backend := &dockerProfileFailureRuntime{
		startCode: 1,
		log: strings.Repeat("noise\n", 2000) + strings.Repeat("y", 10000) +
			"\nfailed to start daemon: failed to setup IP tables\n",
	}
	svc := &Service{backend: backend}
	err := svc.startDockerProfile(context.Background(), runtime.Handle{ID: "owned"}, false, false)
	if err == nil {
		t.Fatal("expected dockerd startup failure")
	}
	want := "start dockerd: code=1: " + dockerdDiagnosticIptables
	if err.Error() != want {
		t.Fatalf("diagnostic = %q, want %q", err.Error(), want)
	}
	if len(backend.calls) != 2 {
		t.Fatalf("expected startup and diagnostic exec calls, got %d", len(backend.calls))
	}
	diagnostic := backend.calls[1]
	if len(diagnostic.Env) != 0 {
		t.Fatalf("diagnostic command received environment overrides: %v", diagnostic.Env)
	}
	if !strings.Contains(strings.Join(diagnostic.Argv, " "), "/var/log/dockerd.log") {
		t.Fatalf("diagnostic did not read the dockerd log: %v", diagnostic.Argv)
	}
}

func TestStartDockerProfileFailureClassifiesKnownSignatures(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want string
	}{
		{name: "cgroup", log: "failed to mount cgroup2 at /sys/fs/cgroup", want: dockerdDiagnosticCgroup},
		{name: "iptables", log: "FAILED TO SETUP IP TABLES: iptables v1.8.9", want: dockerdDiagnosticIptables},
		{name: "socket", log: "bind: address already in use", want: dockerdDiagnosticSocket},
		{name: "overlay", log: "failed to mount overlay: invalid argument", want: dockerdDiagnosticOverlay},
		{name: "no space", log: "write /var/lib/docker: no space left on device", want: dockerdDiagnosticNoSpace},
		{name: "permission", log: "open /var/run/docker.pid: permission denied", want: dockerdDiagnosticPermission},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backend := &dockerProfileFailureRuntime{startCode: 1, log: tc.log}
			svc := &Service{backend: backend}
			err := svc.startDockerProfile(context.Background(), runtime.Handle{ID: "owned"}, false, false)
			if err == nil {
				t.Fatal("expected dockerd startup failure")
			}
			want := "start dockerd: code=1: " + tc.want
			if err.Error() != want {
				t.Fatalf("diagnostic = %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestStartDockerProfileFailureNeverReturnsGuestLogText(t *testing.T) {
	secrets := []string{
		"SYNTHETIC-DOCKERD-TOKEN-7c1f0e",
		"hunter2",
		"alice:s3cret@example.invalid",
		"http://synthetic-user:synthetic-password@example.invalid/v2/",
		"/var/lib/dockerd/arbitrary-guest-path",
		"--registry-mirror=https://registry.invalid",
		"HTTP_PROXY=http://127.0.0.1:43134",
		"\x1b[31mred\x1b[0m",
		"\x1b]0;hostile-title\x07",
	}
	for i, secret := range secrets {
		t.Run(fmt.Sprintf("secret_%d", i), func(t *testing.T) {
			backend := &dockerProfileFailureRuntime{
				startCode: 1,
				log:       "failed to start daemon: failed to setup IP tables\n" + secret + "\n",
			}
			svc := &Service{backend: backend}
			err := svc.startDockerProfile(context.Background(), runtime.Handle{ID: "owned"}, false, false)
			if err == nil {
				t.Fatal("expected dockerd startup failure")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("guest log text %q reached the error: %q", secret, err.Error())
			}
			want := "start dockerd: code=1: " + dockerdDiagnosticIptables
			if err.Error() != want {
				t.Fatalf("diagnostic = %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestStartDockerProfileFailureUsesGenericDiagnosticForArbitraryLog(t *testing.T) {
	backend := &dockerProfileFailureRuntime{
		startCode: 1,
		log: "\x1b[2J\x1b]0;hostile-title\x07fatal guest content token=SYNTHETIC-DOCKERD-TOKEN\n" +
			"http://synthetic-user:synthetic-password@example.invalid/arbitrary/path\n",
	}
	svc := &Service{backend: backend}
	err := svc.startDockerProfile(context.Background(), runtime.Handle{ID: "owned"}, false, false)
	if err == nil {
		t.Fatal("expected dockerd startup failure")
	}
	want := "start dockerd: code=1: " + dockerdDiagnosticGeneric
	if err.Error() != want {
		t.Fatalf("diagnostic = %q, want %q", err.Error(), want)
	}
}

func TestStartDockerProfileTransportErrorWrapsCause(t *testing.T) {
	sentinel := errors.New("guest transport failed")
	backend := &dockerProfileFailureRuntime{
		startCode: 1,
		startErr:  sentinel,
		log:       "permission denied: SYNTHETIC-DOCKERD-TOKEN\n",
	}
	svc := &Service{backend: backend}
	err := svc.startDockerProfile(context.Background(), runtime.Handle{ID: "owned"}, false, false)
	if !errors.Is(err, sentinel) {
		t.Fatalf("transport cause was not wrapped: %v", err)
	}
	want := "start dockerd: code=1: " + dockerdDiagnosticPermission + ": " + sentinel.Error()
	if err.Error() != want {
		t.Fatalf("wrapped error = %q, want %q", err.Error(), want)
	}
}

func TestStartDockerProfileFailureSkipsDiagnosticsWhenContextIsDone(t *testing.T) {
	backend := &dockerProfileFailureRuntime{startCode: 1, log: "dockerd exploded\n"}
	svc := &Service{backend: backend}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := svc.startDockerProfile(ctx, runtime.Handle{ID: "owned"}, false, false)
	if err == nil {
		t.Fatal("expected dockerd startup failure")
	}
	want := "start dockerd: code=1: " + dockerdDiagnosticGeneric
	if err.Error() != want {
		t.Fatalf("diagnostic = %q, want %q", err.Error(), want)
	}
	if len(backend.calls) != 1 {
		t.Fatalf("diagnostic ran after context cancellation: %d calls", len(backend.calls))
	}
}

type dockerProfileFailureRuntime struct {
	fakeRuntime
	calls     []runtime.ExecRequest
	startCode int
	startErr  error
	log       string
}

func (f *dockerProfileFailureRuntime) ExecNative(_ context.Context, _ runtime.Handle, req runtime.ExecRequest) (int, error) {
	f.calls = append(f.calls, req)
	if len(f.calls) == 1 {
		return f.startCode, f.startErr
	}
	if req.Stdout != nil && f.log != "" {
		_, _ = io.WriteString(req.Stdout, f.log)
	}
	return 0, nil
}

func TestCreateWiresScopedDockerHubPullBrokerIntoGuest(t *testing.T) {
	if goruntime.GOOS == "windows" || !dockerVolumeSecuritySupported() {
		t.Skip("guest Docker profile requires supported Unix sockets and private volume semantics")
	}
	ctx := context.Background()
	stateDir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(stateDir, "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	registryStore, err := registrycredentials.NewStore(&mapVault{items: make(map[string]string)})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetRegistryCredentialStore(registryStore)
	if _, err := registryStore.Save(ctx, registrycredentials.Credential{
		Registry: dockerHubRegistry, Username: "host-only-user", Password: []byte("host-only-pat"),
		Scope: registrycredentials.ScopeHostOnly,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := registryStore.Save(ctx, registrycredentials.Credential{
		Registry: dockerHubRegistry, Username: "synthetic-user", Password: []byte("synthetic-pat"),
		Scope: registrycredentials.ScopeSandbox, SandboxName: "registry-pull",
	}); err != nil {
		t.Fatal(err)
	}
	manager := secretproxy.New()
	svc.SetSecretProxyManager(manager)
	helperPath := writeStaticProxyHelperFixture(t)
	proxyRoot, err := os.MkdirTemp("/tmp", "kq-reg-pull-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(proxyRoot) })
	svc.SetSecretProxyRuntime(helperPath, proxyRoot)
	svc.DockerVolumeDir = filepath.Join(stateDir, "docker-volumes")
	if err := os.Mkdir(svc.DockerVolumeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	svc.DockerVolumeSize = "512m"
	svc.MkfsExt4 = "true"
	sandboxID := ""
	t.Cleanup(func() {
		_ = manager.Close()
		if sandboxID != "" {
			_ = secretproxy.RemovePrivateDir(proxySocketDirectory(proxyRoot, sandboxID))
		}
	})

	op, err := svc.Create(ctx, CreateRequest{Name: "registry-pull", Image: "alpine:3.22", Privileged: true})
	if err != nil {
		t.Fatal(err)
	}
	sandboxID = op.SandboxID
	if backend.proxyGuestPort != dockerHubGuestPort || backend.proxyServiceHost != dockerHubRegistryHost {
		t.Fatalf("guest registry route = %s:%d", backend.proxyServiceHost, backend.proxyGuestPort)
	}
	if !strings.Contains(strings.Join(backend.lastExec.Argv, " "), "--registry-mirror="+registryMirrorURL) {
		t.Fatal("guest dockerd did not receive the pull mirror")
	}
	services, err := st.GetSetting(ctx, proxyServiceSettingKey(sandboxID))
	if err != nil || services != dockerHubProxyService {
		t.Fatalf("persisted proxy services=%q err=%v", services, err)
	}
	if !manager.Has("registry-pull", dockerHubProxyService) {
		t.Fatal("sandbox Docker Hub broker route was not kept active")
	}
	if scope, err := st.GetSetting(ctx, registryProxySettingKey(sandboxID)); err != nil || scope != string(registrycredentials.ScopeSandbox) {
		t.Fatalf("persisted registry scope=%q err=%v", scope, err)
	}
	if got, err := svc.availableDockerHubScope(ctx, "registry-pull", false); err != nil || got != registrycredentials.ScopeSandbox {
		t.Fatalf("selected registry scope=%q err=%v", got, err)
	}
	if _, err := registryStore.Delete(ctx, dockerHubRegistry, registrycredentials.ScopeSandbox, "registry-pull"); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.availableDockerHubScope(ctx, "registry-pull", true); err != nil || got != "" {
		t.Fatalf("host-only credential was exposed to guest pulls: scope=%q err=%v", got, err)
	}
}

func TestResolvedRegistryEgressAppliesDomainAndCIDRDenyRules(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "registry-policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	op, err := svc.Create(ctx, CreateRequest{Name: "registry-policy"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "allow", sandbox.NetworkRule{Protocol: "tcp", Domain: "auth.docker.io", Port: 443}); err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr("8.8.8.8")
	decision, err := svc.checkResolvedEgress(ctx, op.SandboxID, "auth.docker.io", address)
	if err != nil || !decision.Allowed {
		t.Fatalf("domain allow decision=%+v err=%v", decision, err)
	}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "deny", sandbox.NetworkRule{Protocol: "tcp", CIDR: "8.8.8.0/24", Port: 443}); err != nil {
		t.Fatal(err)
	}
	decision, err = svc.checkResolvedEgress(ctx, op.SandboxID, "auth.docker.io", address)
	if err != nil || decision.Allowed {
		t.Fatalf("CIDR deny decision=%+v err=%v", decision, err)
	}
}

func TestServiceProxyAddressAuthorizerAppliesCIDRDenyRules(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "service-proxy-policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	op, err := svc.Create(ctx, CreateRequest{Name: "service-proxy-policy"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "allow", sandbox.NetworkRule{Protocol: "tcp", Domain: "api.openai.com", Port: 443}); err != nil {
		t.Fatal(err)
	}
	vault, err := servicesecrets.NewStore(&fakeServiceSecretVault{items: make(map[string]string)})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetServiceSecretStore(vault)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("synthetic-key")); err != nil {
		t.Fatal(err)
	}
	sandboxRecord, err := st.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	route, _, err := svc.buildProxyRoute(ctx, sandboxRecord, "openai")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(route.Secret)
	if route.Service.AuthorizeAddress == nil {
		t.Fatal("service secret proxy omitted resolved-address policy authorization")
	}
	address := netip.MustParseAddr("8.8.8.8")
	allowed, err := route.Service.AuthorizeAddress(ctx, address)
	if err != nil || !allowed {
		t.Fatalf("domain allow positive control: allowed=%t err=%v", allowed, err)
	}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "deny", sandbox.NetworkRule{Protocol: "tcp", CIDR: "8.8.8.0/24", Port: 443}); err != nil {
		t.Fatal(err)
	}
	allowed, err = route.Service.AuthorizeAddress(ctx, address)
	if err != nil || allowed {
		t.Fatalf("CIDR deny negative control: allowed=%t err=%v", allowed, err)
	}
}

func TestDynamicServiceSecretProxyResolvesOnHostAndDoesNotUseSourceAsCredential(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "dynamic-service-secret.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	op, err := svc.Create(ctx, CreateRequest{Name: "dynamic-service-secret"})
	if err != nil {
		t.Fatal(err)
	}
	vault, err := servicesecrets.NewStore(&fakeServiceSecretVault{items: make(map[string]string)})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetServiceSecretStore(vault)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	command := "printf synthetic-proxy-key"
	if goruntime.GOOS == "windows" {
		command = "echo synthetic-proxy-key"
	}
	if _, err := svc.SetServiceSecretSource(ctx, "openai", servicesecrets.ScopeGlobal, "", servicesecrets.Source{
		Command: command, NoVerify: true,
	}); err != nil {
		t.Fatal(err)
	}
	sandboxRecord, err := st.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	route, _, err := svc.buildProxyRoute(ctx, sandboxRecord, "openai")
	if err != nil {
		t.Fatal(err)
	}
	if len(route.Secret) != 0 {
		t.Fatalf("dynamic source envelope was installed as route credential: %q", route.Secret)
	}
	if route.Service.Credential == nil {
		t.Fatal("dynamic route has no host credential resolver")
	}
	value, err := route.Service.Credential(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if string(value) != "synthetic-proxy-key" {
		t.Fatalf("resolved host credential=%q", value)
	}
}

func TestCreatePassesPrivileged(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "priv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	svc.DockerVolumeDir = filepath.Join(t.TempDir(), "docker-volumes")
	if err := os.Mkdir(svc.DockerVolumeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	svc.DockerVolumeSize = "512m"
	svc.MkfsExt4 = "true"
	_, err = svc.Create(ctx, CreateRequest{Name: "priv", Privileged: true})
	if !dockerVolumeSecuritySupported() {
		if err == nil || backend.created != 0 {
			t.Fatalf("privileged create did not fail closed on unsupported volume security: err=%v created=%d", err, backend.created)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if !backend.lastConfig.Privileged {
		t.Fatal("privileged request did not reach runtime")
	}
}

func sameRule(a, b sandbox.NetworkRule) bool {
	a.RuleID = ""
	b.RuleID = ""
	return reflect.DeepEqual(a, b)
}

func TestNormalizeDomainRules(t *testing.T) {
	rule := sandbox.NetworkRule{Protocol: "tcp", Domain: "*.Example.COM.", Port: 443}
	normalized, err := normalizeRules([]sandbox.NetworkRule{rule}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized) != 1 || normalized[0].Domain != "*.example.com" || !strings.HasPrefix(normalized[0].RuleID, "rul_") {
		t.Fatalf("normalized=%+v", normalized)
	}
	if _, err := normalizeRules([]sandbox.NetworkRule{{Protocol: "tcp", Domain: "example.com", CIDR: "192.0.2.0/24"}}, false); err == nil {
		t.Fatal("domain+cidr accepted")
	}
	if _, err := normalizeRules([]sandbox.NetworkRule{{Protocol: "tcp", Domain: "*"}}, false); err == nil {
		t.Fatal("bare wildcard accepted")
	}
	if _, err := normalizeRules([]sandbox.NetworkRule{{Protocol: "tcp", Domain: "192.0.2.10", Port: 443}}, false); err == nil {
		t.Fatal("IP literal accepted as a domain rule")
	}
}

func TestCheckPolicyAppliesGlobalProfileRules(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	if _, err := svc.SetPolicyProfile(ctx, policyProfileAllowAll); err != nil {
		t.Fatal(err)
	}
	decision, err := svc.CheckPolicy(ctx, "", "tcp", "192.0.2.1", "", 443, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("global allow-all profile must allow IPv4 tcp, got %+v", decision)
	}
	if _, err := svc.SetPolicyProfile(ctx, policyProfileDenyAll); err != nil {
		t.Fatal(err)
	}
	decision, err = svc.CheckPolicy(ctx, "", "tcp", "192.0.2.1", "", 443, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatalf("global deny-all profile must deny IPv4 tcp, got %+v", decision)
	}
	rule := sandbox.NetworkRule{Protocol: "tcp", Domain: "*.example.com", Port: 443}
	if _, _, err := svc.MutateGlobalPolicy(ctx, "allow", rule); err != nil {
		t.Fatal(err)
	}
	decision, err = svc.CheckPolicy(ctx, "", "tcp", "", "api.example.com", 443, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("explicit global domain rule must allow, got %+v", decision)
	}
	decision, err = svc.CheckPolicy(ctx, "", "udp", "", "api.example.com", 443, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatalf("tcp-only domain rule must not allow udp, got %+v", decision)
	}
}

func TestGlobalPolicyMergesIntoNewSandboxes(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	svc.DefaultPolicyProfile = policyProfileDenyAll
	rule := sandbox.NetworkRule{Protocol: "tcp", Domain: "*.example.com", Port: 443}
	if _, _, err := svc.MutateGlobalPolicy(ctx, "allow", rule); err != nil {
		t.Fatal(err)
	}
	op, err := svc.Create(ctx, CreateRequest{Name: "global-policy"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	allow, _, err := svc.effectivePolicy(ctx, sb)
	if err != nil || len(allow) != 1 || allow[0].Domain != "*.example.com" {
		t.Fatalf("effective allow=%+v err=%v", allow, err)
	}
	if _, _, err := svc.MutateGlobalPolicy(ctx, "rm", rule); err != nil {
		t.Fatal(err)
	}
}

type fakeServiceSecretVault struct {
	mu        sync.Mutex
	items     map[string]string
	deleteErr error
	setErr    error
	setErrAt  int
	setCalls  int
}

func (f *fakeServiceSecretVault) Set(_ context.Context, service, account, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls++
	if f.setErr != nil && f.setCalls == f.setErrAt {
		return f.setErr
	}
	f.items[service+"/"+account] = secret
	return nil
}

func (f *fakeServiceSecretVault) Get(_ context.Context, service, account string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.items[service+"/"+account]
	if !ok {
		return "", servicesecrets.ErrNotFound
	}
	return value, nil
}

func (f *fakeServiceSecretVault) Delete(_ context.Context, service, account string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	key := service + "/" + account
	if _, ok := f.items[key]; !ok {
		return servicesecrets.ErrNotFound
	}
	delete(f.items, key)
	return nil
}

type blockingServiceSecretVault struct {
	fakeServiceSecretVault
	entered      chan struct{}
	deleteCalled chan struct{}
	release      chan struct{}
	block        sync.Once
}

func (f *blockingServiceSecretVault) Set(ctx context.Context, service, account, secret string) error {
	f.block.Do(func() {
		close(f.entered)
		select {
		case <-f.release:
		case <-ctx.Done():
		}
	})
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.fakeServiceSecretVault.Set(ctx, service, account, secret)
}

func (f *blockingServiceSecretVault) Delete(ctx context.Context, service, account string) error {
	select {
	case f.deleteCalled <- struct{}{}:
	default:
	}
	return f.fakeServiceSecretVault.Delete(ctx, service, account)
}

func TestSetAndRemoveServiceSecretShareCanonicalCredentialGate(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "service-secret-set-remove.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	vault := &blockingServiceSecretVault{
		fakeServiceSecretVault: fakeServiceSecretVault{items: make(map[string]string)},
		entered:                make(chan struct{}),
		deleteCalled:           make(chan struct{}, 1),
		release:                make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseSet := func() { releaseOnce.Do(func() { close(vault.release) }) }
	t.Cleanup(releaseSet)
	secretStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(st, nil)
	svc.SetServiceSecretStore(secretStore)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	setDone := make(chan error, 1)
	go func() {
		_, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("synthetic-key"))
		setDone <- err
	}()
	<-vault.entered
	removeDone := make(chan error, 1)
	removeStarted := make(chan struct{})
	go func() {
		close(removeStarted)
		removed, err := svc.RemoveServiceSecret(ctx, " OPENAI ", servicesecrets.ScopeGlobal, "")
		if err == nil && !removed {
			err = errors.New("remove did not observe the completed set")
		}
		removeDone <- err
	}()
	<-removeStarted
	select {
	case <-vault.deleteCalled:
		t.Fatal("canonical alias removal reached the vault while the set held its gate")
	case <-time.After(50 * time.Millisecond):
	}
	releaseSet()
	if err := <-setDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-vault.deleteCalled:
	case <-time.After(time.Second):
		t.Fatal("serialized removal never reached the vault")
	}
	if err := <-removeDone; err != nil {
		t.Fatal(err)
	}
	if _, err := secretStore.Load(ctx, "openai", servicesecrets.ScopeGlobal, ""); !errors.Is(err, servicesecrets.ErrNotFound) {
		t.Fatalf("secret remains after serialized set/remove: %v", err)
	}
	entries, err := svc.ListServiceSecrets(ctx)
	if err != nil || len(entries) != 0 {
		t.Fatalf("secret index after serialized set/remove=%+v err=%v", entries, err)
	}
}

func TestRemoveServiceSecretCleansStaleIndexWithCanonicalScope(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "service-secret-remove-index.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	vault := &fakeServiceSecretVault{items: make(map[string]string)}
	secretStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(st, nil)
	svc.SetServiceSecretStore(secretStore)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	var manager *secretproxy.Manager
	if goruntime.GOOS != "windows" {
		manager = secretproxy.New()
		svc.SetSecretProxyManager(manager)
		t.Cleanup(func() { _ = manager.Close() })
	}
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("synthetic-key")); err != nil {
		t.Fatal(err)
	}
	if manager != nil {
		if _, err := manager.StartUnix(ctx, "dev", "openai", secretproxy.Service{
			Upstream: "http://127.0.0.1:1", Header: "Authorization", CredentialScope: "global",
		}, []byte("synthetic-key"), shortTestProxySocketPath(t), strings.Repeat("a", 64)); err != nil {
			t.Fatal(err)
		}
	}
	if err := vault.Delete(ctx, "com.rheic.service-secrets.v1", "openai/global"); err != nil {
		t.Fatal(err)
	}
	removed, err := svc.RemoveServiceSecret(ctx, " OPENAI ", "", " ")
	if err != nil || removed {
		t.Fatalf("stale-entry cleanup returned removed=%t err=%v", removed, err)
	}
	if manager != nil && manager.Has("dev", "openai") {
		t.Fatal("canonical global removal left an active proxy route")
	}
	entries, err := svc.ListServiceSecrets(ctx)
	if err != nil || len(entries) != 0 {
		t.Fatalf("stale secret index remains: entries=%+v err=%v", entries, err)
	}
}

func TestRemoveServiceSecretRevokesProxyBeforeVaultDelete(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("service proxy lifecycle requires Unix sockets")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "service-secret-remove-failure.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	vault := &fakeServiceSecretVault{items: make(map[string]string)}
	secretStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(st, nil)
	svc.SetServiceSecretStore(secretStore)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	manager := secretproxy.New()
	svc.SetSecretProxyManager(manager)
	t.Cleanup(func() { _ = manager.Close() })
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("synthetic-key")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.StartUnix(ctx, "dev", "openai", secretproxy.Service{
		Upstream: "http://127.0.0.1:1", Header: "Authorization", CredentialScope: "global",
	}, []byte("synthetic-key"), shortTestProxySocketPath(t), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	deleteErr := errors.New("synthetic keychain delete failure")
	vault.mu.Lock()
	vault.deleteErr = deleteErr
	vault.mu.Unlock()
	removed, err := svc.RemoveServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "")
	if removed || !errors.Is(err, deleteErr) {
		t.Fatalf("failed vault deletion returned removed=%t err=%v", removed, err)
	}
	if manager.Has("dev", "openai") {
		t.Fatal("active proxy remained usable after a failed secret removal")
	}
	entries, err := svc.ListServiceSecrets(ctx)
	if err != nil || len(entries) != 1 {
		t.Fatalf("metadata should remain for retry: entries=%+v err=%v", entries, err)
	}
	vault.mu.Lock()
	vault.deleteErr = nil
	vault.mu.Unlock()
	removed, err = svc.RemoveServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "")
	if !removed || err != nil {
		t.Fatalf("retry returned removed=%t err=%v", removed, err)
	}
	entries, err = svc.ListServiceSecrets(ctx)
	if err != nil || len(entries) != 0 {
		t.Fatalf("retry left metadata: entries=%+v err=%v", entries, err)
	}
}

func shortTestProxySocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "rheic-rm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return filepath.Join(directory, "proxy.sock")
}

func TestSetServiceSecretRollsBackVaultWhenIndexWriteFails(t *testing.T) {
	for _, hadPrevious := range []bool{false, true} {
		t.Run(fmt.Sprintf("previous=%t", hadPrevious), func(t *testing.T) {
			testSetServiceSecretIndexFailureRollback(t, hadPrevious)
		})
	}
}

func TestSetServiceSecretRollbackFailureDeletesCredentialAndRevokesProxy(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("service proxy lifecycle requires Unix sockets")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "service-secret-rollback-failure.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	vault := &fakeServiceSecretVault{items: make(map[string]string)}
	secretStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(st, nil)
	svc.SetServiceSecretStore(secretStore)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	manager := secretproxy.New()
	svc.SetSecretProxyManager(manager)
	t.Cleanup(func() { _ = manager.Close() })
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("old-synthetic-value")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.StartUnix(ctx, "dev", "openai", secretproxy.Service{
		Upstream: "http://127.0.0.1:1", Header: "Authorization", CredentialScope: "global",
	}, []byte("old-synthetic-value"), shortTestProxySocketPath(t), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `CREATE TRIGGER fail_service_secret_index BEFORE INSERT ON service_secret_index BEGIN SELECT RAISE(ABORT, 'synthetic index failure'); END`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	vault.mu.Lock()
	vault.setErrAt = 3 // old save, failed replacement write, then failed restore
	vault.setErr = errors.New("synthetic vault restore failure")
	vault.mu.Unlock()
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("new-synthetic-value")); err == nil {
		t.Fatal("set succeeded despite index and rollback failures")
	}
	if manager.Has("dev", "openai") {
		t.Fatal("proxy route remained active after rollback failure")
	}
	if _, err := secretStore.Load(ctx, "openai", servicesecrets.ScopeGlobal, ""); !errors.Is(err, servicesecrets.ErrNotFound) {
		t.Fatalf("credential remained after rollback failure cleanup: %v", err)
	}
	entries, err := svc.ListServiceSecrets(ctx)
	if err != nil || len(entries) != 0 {
		t.Fatalf("index remained after rollback failure cleanup: entries=%+v err=%v", entries, err)
	}
}

func testSetServiceSecretIndexFailureRollback(t *testing.T, hadPrevious bool) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "service-secret-index-failure.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	vault := &fakeServiceSecretVault{items: make(map[string]string)}
	secretStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(st, nil)
	svc.SetServiceSecretStore(secretStore)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	if hadPrevious {
		if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("old-synthetic-value")); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `CREATE TRIGGER fail_service_secret_index BEFORE INSERT ON service_secret_index BEGIN SELECT RAISE(ABORT, 'synthetic index failure'); END`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("new-synthetic-value")); err == nil {
		t.Fatal("set succeeded despite injected index failure")
	}
	value, err := secretStore.Load(ctx, "openai", servicesecrets.ScopeGlobal, "")
	if hadPrevious {
		if err != nil || string(value) != "old-synthetic-value" {
			t.Fatalf("previous vault value not restored: value=%q err=%v", value, err)
		}
		clear(value)
		entries, err := svc.ListServiceSecrets(ctx)
		if err != nil || len(entries) != 1 {
			t.Fatalf("existing index entry lost: entries=%+v err=%v", entries, err)
		}
		return
	}
	if !errors.Is(err, servicesecrets.ErrNotFound) {
		t.Fatalf("new vault value remained after rollback: value=%q err=%v", value, err)
	}
	entries, err := svc.ListServiceSecrets(ctx)
	if err != nil || len(entries) != 0 {
		t.Fatalf("index entry remained after rollback: entries=%+v err=%v", entries, err)
	}
}

func TestCreateServiceSecretIsAtomicForConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "create-only.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	vault := &fakeServiceSecretVault{items: make(map[string]string)}
	secretStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(st, nil)
	svc.SetServiceSecretStore(secretStore)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	const writers = 24
	var wg sync.WaitGroup
	var successes atomic.Int32
	var exists atomic.Int32
	var unexpected atomic.Int32
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, createErr := svc.CreateServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("synthetic-secret"))
			switch {
			case createErr == nil:
				successes.Add(1)
			case errors.Is(createErr, servicesecrets.ErrExists):
				exists.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || exists.Load() != writers-1 || unexpected.Load() != 0 {
		t.Fatalf("create outcomes: success=%d exists=%d unexpected=%d", successes.Load(), exists.Load(), unexpected.Load())
	}
	items, err := svc.ListServiceSecrets(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("secret index=%+v err=%v", items, err)
	}
}

type barrierServiceSecretVault struct {
	mu      sync.Mutex
	items   map[string]string
	gets    atomic.Int32
	ready   chan struct{}
	release chan struct{}
}

func (f *barrierServiceSecretVault) Set(_ context.Context, service, account, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[service+"/"+account] = secret
	return nil
}

func (f *barrierServiceSecretVault) Get(_ context.Context, service, account string) (string, error) {
	f.mu.Lock()
	value, ok := f.items[service+"/"+account]
	f.mu.Unlock()
	if f.gets.Add(1) == 2 {
		close(f.ready)
	}
	<-f.release
	if !ok {
		return "", servicesecrets.ErrNotFound
	}
	return value, nil
}

func (f *barrierServiceSecretVault) Delete(_ context.Context, service, account string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := service + "/" + account
	if _, ok := f.items[key]; !ok {
		return servicesecrets.ErrNotFound
	}
	delete(f.items, key)
	return nil
}

func TestCreateServiceSecretNormalizesIdentityBeforeAtomicGate(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "create-only-normalized.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	vault := &barrierServiceSecretVault{
		items: make(map[string]string), ready: make(chan struct{}), release: make(chan struct{}),
	}
	secretStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(st, nil)
	svc.SetServiceSecretStore(secretStore)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	errorsOut := make(chan error, 2)
	for _, service := range []string{"openai", " OPENAI "} {
		service := service
		go func() {
			_, createErr := svc.CreateServiceSecret(ctx, service, servicesecrets.ScopeGlobal, "", []byte("synthetic-"+service))
			errorsOut <- createErr
		}()
	}
	select {
	case <-vault.ready:
	case <-time.After(100 * time.Millisecond):
		// With a canonical gate, the second call must wait until the first
		// create has completed; release the first read so it can do so.
	}
	close(vault.release)
	var successes, exists int
	for range 2 {
		createErr := <-errorsOut
		switch {
		case createErr == nil:
			successes++
		case errors.Is(createErr, servicesecrets.ErrExists):
			exists++
		default:
			t.Fatalf("unexpected create error: %v", createErr)
		}
	}
	if successes != 1 || exists != 1 {
		t.Fatalf("canonical-equivalent create outcomes: success=%d exists=%d", successes, exists)
	}
}

func TestServiceSecretNeverPersistsValue(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	secretStore, err := servicesecrets.NewStore(&fakeServiceSecretVault{items: make(map[string]string)})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetServiceSecretStore(secretStore)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeSandbox, "dev", []byte("sk-synthetic-value")); err != nil {
		t.Fatal(err)
	}
	items, err := svc.ListServiceSecrets(ctx)
	if err != nil || len(items) != 1 || items[0].Service != "openai" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sk-synthetic-value") {
		t.Fatal("secret value was written to SQLite")
	}
	removed, err := svc.RemoveServiceSecret(ctx, "openai", servicesecrets.ScopeSandbox, "dev")
	if err != nil || !removed {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
}

func TestResolveSecretEnvRejectsGuestVisibleReferences(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	for _, entry := range []string{
		"OPENAI_API_KEY=${secret:openai}",
		"VALUE=prefix-${secret:openai}-suffix",
	} {
		env, err := svc.resolveSecretEnv(ctx, sandbox.Sandbox{Name: "dev"}, []string{entry, "PLAIN=value"})
		if !errors.Is(err, core.ErrConflict) || len(env) != 0 {
			t.Fatalf("secret reference was not rejected before exec: env=%q err=%v", env, err)
		}
		if strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatalf("error leaked a secret value: %v", err)
		}
	}
	env, err := svc.resolveSecretEnv(ctx, sandbox.Sandbox{Name: "dev"}, []string{"PLAIN=value"})
	if err != nil || len(env) != 1 || env[0] != "PLAIN=value" {
		t.Fatalf("ordinary environment variable rejected: env=%q err=%v", env, err)
	}
}

func TestResolveProxyEnvRequiresConfiguredCredentialVariable(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	secretStore, err := servicesecrets.NewStore(&fakeServiceSecretVault{items: make(map[string]string)})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetServiceSecretStore(secretStore)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{})
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("sk-synthetic-proxy")); err != nil {
		t.Fatal(err)
	}
	env, err := svc.resolveSecretEnv(ctx, sandbox.Sandbox{Name: "dev"}, []string{"OPENAI_BASE_URL=${proxy:openai}"})
	if err == nil || !strings.Contains(err.Error(), "proxy reference is not supported") || len(env) != 0 {
		t.Fatalf("env=%q err=%v", env, err)
	}
}

func TestResolveOpenAIOAuthProxyEnvUsesExplicitConfiguredRoute(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	sb := sandbox.Sandbox{ID: "sb-oauth", Name: "oauth"}
	if err := st.SetSetting(ctx, proxyServiceSettingKey(sb.ID), "openai-oauth"); err != nil {
		t.Fatal(err)
	}
	resolved, route, err := svc.resolveProxyEnvEntry(ctx, sb, "OPENAI_API_KEY", "${oauth:openai}")
	if err != nil || route != "openai-oauth" || resolved != "OPENAI_API_KEY=rheic-proxy-placeholder" {
		t.Fatalf("resolved=%q route=%q err=%v", resolved, route, err)
	}
	for _, value := range []string{"${oauth:anthropic}", "${oauth:openai}${proxy:openai}", "prefix${oauth:openai}"} {
		if _, _, err := svc.resolveProxyEnvEntry(ctx, sb, "OPENAI_API_KEY", value); err == nil {
			t.Errorf("accepted invalid OAuth proxy reference %q", value)
		}
	}
	if _, _, err := svc.resolveProxyEnvEntry(ctx, sb, "ANTHROPIC_API_KEY", "${oauth:openai}"); err == nil {
		t.Fatal("accepted OAuth proxy on the wrong credential variable")
	}
}

func TestStopSandboxByNameStopsRunningSandbox(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	op, err := svc.Create(ctx, CreateRequest{Name: "lost-gw", Image: "scratch"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if err := svc.StopSandboxByName(ctx, "lost-gw"); err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.State != sandbox.Stopped {
		t.Fatalf("sandbox after gateway loss = %+v, %v", sb, err)
	}
	if err := svc.StopSandboxByName(ctx, "missing"); err != nil {
		t.Fatalf("missing sandbox must be ignored: %v", err)
	}
}

func TestRefreshPoliciesAppliesToRunningOnly(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakePolicyRuntime{}
	svc := New(st, backend)
	_, err = svc.Create(ctx, CreateRequest{Name: "running-policy-refresh"})
	if err != nil {
		t.Fatal(err)
	}
	stoppedOp, err := svc.Create(ctx, CreateRequest{Name: "stopped-policy-refresh"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Stop(ctx, stoppedOp.SandboxID); err != nil {
		t.Fatal(err)
	}
	revisionBefore := backend.revision
	applied, err := svc.RefreshPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("applied=%d, want 1", applied)
	}
	if backend.revision <= revisionBefore {
		t.Fatalf("revision did not advance: %d -> %d", revisionBefore, backend.revision)
	}
}

func TestRefreshPoliciesPaginatesAllSandboxes(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "policy-pages.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakePolicyRuntime{}
	svc := New(st, backend)
	const total = 250
	base := time.Unix(1000, 0).UTC()
	for i := 0; i < total; i++ {
		sb := sandbox.Sandbox{
			ID: fmt.Sprintf("sb-policy-page-%03d", i), Name: fmt.Sprintf("policy-page-%03d", i),
			State: sandbox.Running, Generation: 1,
			CreatedAt: base.Add(time.Duration(i) * time.Second), UpdatedAt: base,
		}
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
	}
	applied, err := svc.RefreshPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if applied != total {
		t.Fatalf("applied = %d, want %d", applied, total)
	}
	if len(backend.handles) != total {
		t.Fatalf("runtime updates = %d, want %d", len(backend.handles), total)
	}
	last := fmt.Sprintf("rheic-policy-page-%03d", total-1)
	if !slices.Contains(backend.handles, last) {
		t.Fatalf("sandbox on the last page was not refreshed: %v", backend.handles)
	}
}

func TestRefreshPoliciesReportsPartialFailure(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "policy-partial.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	const total = 205
	failing := fmt.Sprintf("policy-fail-%03d", total-1)
	backend := &fakePolicyRuntime{failName: failing}
	svc := New(st, backend)
	base := time.Unix(2000, 0).UTC()
	for i := 0; i < total; i++ {
		name := fmt.Sprintf("policy-fail-%03d", i)
		sb := sandbox.Sandbox{
			ID: fmt.Sprintf("sb-policy-fail-%03d", i), Name: name,
			State: sandbox.Running, Generation: 1,
			CreatedAt: base.Add(time.Duration(i) * time.Second), UpdatedAt: base,
		}
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
	}
	applied, err := svc.RefreshPolicies(ctx)
	if err == nil {
		t.Fatal("partial refresh failure was reported as success")
	}
	if !strings.Contains(err.Error(), failing) || !strings.Contains(err.Error(), "injected policy update failure") {
		t.Fatalf("partial refresh error does not identify the sandbox: %v", err)
	}
	if applied != total-1 {
		t.Fatalf("applied = %d, want %d", applied, total-1)
	}
}

func TestResetGlobalPolicyClearsRulesAndProfile(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakePolicyRuntime{}
	svc := New(st, backend)
	if _, _, err := svc.MutateGlobalPolicy(ctx, "allow", sandbox.NetworkRule{Protocol: "tcp", CIDR: "192.0.2.0/24", Port: 443}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetPolicyProfile(ctx, "balanced"); err != nil {
		t.Fatal(err)
	}
	allow, deny, profile, err := svc.ResetGlobalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(allow) != 0 || len(deny) != 0 {
		t.Fatalf("rules not cleared: allow=%+v deny=%+v", allow, deny)
	}
	if profile != "allow-all" {
		t.Fatalf("profile=%q, want allow-all", profile)
	}
	storedAllow, storedDeny, err := svc.GlobalPolicy(ctx)
	if err != nil || len(storedAllow) != 0 || len(storedDeny) != 0 {
		t.Fatalf("stored global policy not cleared: %+v %+v %v", storedAllow, storedDeny, err)
	}
}

func TestSetPrivateRegistryValidation(t *testing.T) {
	svc := &Service{}
	if err := svc.SetPrivateRegistry("registry.example.test", "svc", []string{"auth.example.test/token", "auth-alt.example.test/oauth/token"}, []string{"cdn.example.test"}, nil); err != nil {
		t.Fatal(err)
	}
	if svc.privateRegistryHost != "registry.example.test" || len(svc.privateRegistryRealms) != 2 || svc.privateRegistryRealms[0].Path != "/token" || svc.privateRegistryRealms[1].Path != "/oauth/token" {
		t.Fatalf("private registry config = %+v", svc)
	}
	for name, call := range map[string]func() error{
		"wildcard host": func() error {
			return svc.SetPrivateRegistry("*.example.test", "svc", []string{"auth.example.test/token"}, nil, nil)
		},
		"missing service": func() error {
			return svc.SetPrivateRegistry("registry.example.test", "", []string{"auth.example.test/token"}, nil, nil)
		},
		"missing realm": func() error { return svc.SetPrivateRegistry("registry.example.test", "svc", nil, nil, nil) },
		"bad realm host": func() error {
			return svc.SetPrivateRegistry("registry.example.test", "svc", []string{"bad host/token"}, nil, nil)
		},
		"orphan config": func() error { return svc.SetPrivateRegistry("", "svc", nil, nil, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("invalid private registry config accepted")
			}
		})
	}
}

func TestStartDockerProfilePrivateRegistryUsesProxyEnvWithoutMirror(t *testing.T) {
	backend := &fakeRuntime{}
	svc := &Service{backend: backend}
	handle := runtime.Handle{ID: "owned"}
	if err := svc.startDockerProfile(context.Background(), handle, false, true); err != nil {
		t.Fatal(err)
	}
	argv := strings.Join(backend.lastExec.Argv, " ")
	if !strings.Contains(argv, "HTTPS_PROXY=http://127.0.0.1:43135") {
		t.Fatalf("private registry proxy env missing: %s", argv)
	}
	if strings.Contains(argv, "--registry-mirror=") {
		t.Fatalf("private registry unexpectedly enabled a Docker Hub mirror: %s", argv)
	}
}

func TestSingleProxyEndpointSelectsPrivateRegistry(t *testing.T) {
	svc := &Service{privateRegistryHost: "registry.example.test"}
	port, host := svc.singleProxyEndpoint([]string{privateRegistryProxyService}, []string{"registry-private=registry.example.test:43135"})
	if port != privateRegistryGuestPort || host != "registry.example.test" {
		t.Fatalf("endpoint = %d %q", port, host)
	}
}

func TestValidSandboxNameMatchesSbxRules(t *testing.T) {
	cases := map[string]bool{
		"dev":                   true,
		"1a":                    true,
		"a.b-c":                 true,
		"a":                     false, // at least two characters
		"":                      false,
		".":                     false,
		"..":                    false,
		"-dev":                  false, // must start with a letter or number
		".dev":                  false,
		"my_dev":                false, // underscores are not allowed
		"default":               false, // reserved
		"DEFAULT":               true,  // the reserved word is exact-match
		strings.Repeat("a", 63): true,
		strings.Repeat("a", 64): false,
	}
	for name, want := range cases {
		if got := validSandboxName(name); got != want {
			t.Fatalf("validSandboxName(%q) = %t, want %t", name, got, want)
		}
	}
}
