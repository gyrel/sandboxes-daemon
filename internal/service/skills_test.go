package service

import (
	"context"
	"debug/elf"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	runtimeapi "github.com/rheic/sandboxes-runtime"

	"github.com/rheic/sandboxes-daemon/internal/store"
)

func newSkillsTestService(t *testing.T, backend runtimeapi.Backend) *Service {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", "")
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "skills.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, backend)
}

func skillsHelperFixture(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix executable permission bits")
	}
	return writeProxyHelperCandidateFor(t, filepath.Join(t.TempDir(), skillsHelperNamePrefix+runtime.GOARCH), elf.EM_AARCH64)
}

func TestResolveSkillsMountReadOnly(t *testing.T) {
	store := t.TempDir()
	svc := newSkillsTestService(t, &fakeRuntime{})
	svc.SetSkillsRuntime(skillsHelperFixture(t), store)
	mount, err := svc.resolveSkillsMount(CreateRequest{Agent: "codex", Skills: &SkillsOptions{Mode: skillsModeReadOnly, StorePath: store}})
	if err != nil {
		t.Fatal(err)
	}
	if mount == nil || mount.StorePath != store || !mount.ReadOnly || mount.HelperPath == "" {
		t.Fatalf("mount=%+v", mount)
	}
}

func TestResolveSkillsMountRejectsUnsafeRequests(t *testing.T) {
	store := t.TempDir()
	svc := newSkillsTestService(t, &fakeRuntime{})
	svc.SetSkillsRuntime(skillsHelperFixture(t), store)
	cases := []struct {
		name string
		req  CreateRequest
		want string
	}{
		{name: "unspecified", req: CreateRequest{Agent: "codex", Skills: &SkillsOptions{}}, want: "mode is invalid"},
		{name: "readwrite", req: CreateRequest{Agent: "codex", Skills: &SkillsOptions{Mode: skillsModeReadWrite, StorePath: store}}, want: "not supported"},
		{name: "unknown-agent", req: CreateRequest{Agent: "shell", Skills: &SkillsOptions{Mode: skillsModeReadOnly, StorePath: store}}, want: "not available for agent"},
		{name: "off-with-path", req: CreateRequest{Agent: "codex", Skills: &SkillsOptions{Mode: skillsModeOff, StorePath: store}}, want: "off mode requires an empty store path"},
		{name: "wrong-store", req: CreateRequest{Agent: "codex", Skills: &SkillsOptions{Mode: skillsModeReadOnly, StorePath: t.TempDir()}}, want: "must equal the daemon store"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.resolveSkillsMount(tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestResolveSkillsMountRequiresRuntimeAndExistingStore(t *testing.T) {
	svc := newSkillsTestService(t, nil)
	if _, err := svc.resolveSkillsMount(CreateRequest{Agent: "codex", Skills: &SkillsOptions{Mode: skillsModeReadOnly, StorePath: t.TempDir()}}); err == nil || !strings.Contains(err.Error(), "require a VM runtime") {
		t.Fatalf("no runtime: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	svc = newSkillsTestService(t, &fakeRuntime{})
	svc.SetSkillsRuntime(skillsHelperFixture(t), missing)
	if _, err := svc.resolveSkillsMount(CreateRequest{Agent: "codex", Skills: &SkillsOptions{Mode: skillsModeReadOnly, StorePath: missing}}); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing store: %v", err)
	}
}

func TestInstallSharedSkillsUsesGuestHelper(t *testing.T) {
	backend := &fakeRuntime{}
	svc := newSkillsTestService(t, backend)
	if err := svc.installSharedSkills(context.Background(), runtimeapi.Handle{ID: "rheic-dev"}, "codex"); err != nil {
		t.Fatal(err)
	}
	want := []string{runtimeapi.SkillsHelperGuestPath, "link-skills", "--agent", "codex", "--store", runtimeapi.SkillsStoreGuestPath}
	if len(backend.lastExec.Argv) != len(want) {
		t.Fatalf("argv=%v", backend.lastExec.Argv)
	}
	for i := range want {
		if backend.lastExec.Argv[i] != want[i] {
			t.Fatalf("argv=%v, want %v", backend.lastExec.Argv, want)
		}
	}
}

func TestInstallSharedSkillsRequiresNativeExec(t *testing.T) {
	svc := newSkillsTestService(t, noExecRuntime{})
	if err := svc.installSharedSkills(context.Background(), runtimeapi.Handle{ID: "rheic-dev"}, "codex"); err == nil || !strings.Contains(err.Error(), "native exec") {
		t.Fatalf("got %v", err)
	}
}

type noExecRuntime struct{}

func (noExecRuntime) Capabilities(context.Context) (runtimeapi.Capabilities, error) {
	return runtimeapi.Capabilities{}, nil
}
func (noExecRuntime) Create(context.Context, runtimeapi.Config) (runtimeapi.Handle, error) {
	return runtimeapi.Handle{}, nil
}
func (noExecRuntime) Start(context.Context, runtimeapi.Handle) error { return nil }
func (noExecRuntime) Stop(context.Context, runtimeapi.Handle, time.Duration) error {
	return nil
}
func (noExecRuntime) Delete(context.Context, runtimeapi.Handle) error { return nil }
func (noExecRuntime) Handle(string) runtimeapi.Handle                 { return runtimeapi.Handle{} }

func TestCreateRunsSkillsHelperAfterRuntimeStart(t *testing.T) {
	storeDir := t.TempDir()
	backend := &fakeRuntime{}
	svc := newSkillsTestService(t, backend)
	svc.SetSkillsRuntime(skillsHelperFixture(t), storeDir)
	op, err := svc.Create(context.Background(), CreateRequest{
		Name: "skills-dev", Agent: "codex",
		Skills: &SkillsOptions{Mode: skillsModeReadOnly, StorePath: storeDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if op.SandboxID == "" || backend.created != 1 {
		t.Fatalf("op=%+v created=%d", op, backend.created)
	}
	if backend.lastConfig.Skills == nil || backend.lastConfig.Skills.StorePath != storeDir || !backend.lastConfig.Skills.ReadOnly {
		t.Fatalf("runtime skills=%+v", backend.lastConfig.Skills)
	}
	if len(backend.lastExec.Argv) < 2 || backend.lastExec.Argv[0] != runtimeapi.SkillsHelperGuestPath || backend.lastExec.Argv[1] != "link-skills" {
		t.Fatalf("helper exec=%v", backend.lastExec.Argv)
	}
}
