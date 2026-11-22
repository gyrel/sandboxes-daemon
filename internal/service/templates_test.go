package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"
	runtime "github.com/rheic/sandboxes-runtime"

	"github.com/rheic/sandboxes-daemon/internal/store"
)

type templateFakeBackend struct {
	*fakeRuntime
	saved    []runtime.TemplateSaveSpec
	loaded   []runtime.TemplateLoadSpec
	removed  []string
	exported [][2]string
	doc      runtime.TemplateBootDocument
	failSave error
}

func (f *templateFakeBackend) SaveTemplate(_ context.Context, _ runtime.Handle, spec runtime.TemplateSaveSpec) (runtime.TemplateInfo, error) {
	f.saved = append(f.saved, spec)
	if f.failSave != nil {
		return runtime.TemplateInfo{}, f.failSave
	}
	return runtime.TemplateInfo{Name: "docker.io/library/" + spec.Tag, Digest: "sha256:aa", SizeBytes: 4096, Layers: 3, Notice: Notice}, nil
}

const Notice = "warning: guest-resident secrets are stored inside this template; host-brokered credentials are not"

func (f *templateFakeBackend) LoadTemplate(_ context.Context, spec runtime.TemplateLoadSpec) (runtime.TemplateInfo, error) {
	f.loaded = append(f.loaded, spec)
	name := spec.Name
	if name == "" {
		name = "docker.io/library/from-archive:v1"
	}
	return runtime.TemplateInfo{Name: name, Digest: "sha256:beef", SizeBytes: 100, Layers: 2, Notice: Notice}, nil
}

func (f *templateFakeBackend) RemoveTemplate(_ context.Context, name string) error {
	f.removed = append(f.removed, name)
	return nil
}

func (f *templateFakeBackend) ExportTemplate(_ context.Context, name, tarPath string) error {
	f.exported = append(f.exported, [2]string{name, tarPath})
	return nil
}

func (f *templateFakeBackend) TemplateBootDocument(context.Context, string) (runtime.TemplateBootDocument, error) {
	if f.doc.EnvNames == nil {
		return runtime.TemplateBootDocument{}, errors.New("no doc")
	}
	return f.doc, nil
}

func templateFixture(t *testing.T) (*Service, *templateFakeBackend) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fake := &templateFakeBackend{fakeRuntime: &fakeRuntime{}}
	return New(st, fake), fake
}

func seedSandbox(t *testing.T, svc *Service, name, image string, state sandbox.State, ws []sandbox.Workspace) sandbox.Sandbox {
	t.Helper()
	now := time.Now().UTC()
	sb := sandbox.Sandbox{
		ID: "sb-" + name, Name: name, State: state, Image: image,
		Workspace: "/host", Workspaces: ws,
		Meta:      &sandbox.Meta{Agent: "codex"},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := svc.store.Create(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	return sb
}

func TestTemplateSaveStoppedStartsAndRestores(t *testing.T) {
	svc, fake := templateFixture(t)
	sb := seedSandbox(t, svc, "tpl-stop", "alpine:3.22", sandbox.Stopped,
		[]sandbox.Workspace{{Path: "/host", GuestPath: "/workspace"}, {Path: "/ro", GuestPath: "/mnt/data", ReadOnly: true}})
	info, err := svc.TemplateSave(context.Background(), sb.ID, "mytpl:v1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.saved) != 1 {
		t.Fatalf("saved=%d", len(fake.saved))
	}
	spec := fake.saved[0]
	if spec.BaseImage != "alpine:3.22" || spec.Tag != "mytpl:v1" {
		t.Fatalf("spec=%+v", spec)
	}
	joined := strings.Join(spec.Excludes, ",")
	if !strings.Contains(joined, "/workspace") || !strings.Contains(joined, "/mnt/data") {
		t.Fatalf("excludes lost mounts: %q", joined)
	}
	if fake.started != 1 || fake.stopped != 1 {
		t.Fatalf("state restoration: starts=%d stops=%d want 1/1", fake.started, fake.stopped)
	}
	rec, err := svc.store.GetTemplate(context.Background(), info.Name)
	if err != nil || rec.Flavor != "codex" || rec.BaseImage != "alpine:3.22" || rec.Digest != "sha256:aa" {
		t.Fatalf("record=%+v err=%v", rec, err)
	}
}

func TestTemplateSaveRunningCapturesInPlace(t *testing.T) {
	svc, fake := templateFixture(t)
	sb := seedSandbox(t, svc, "tpl-run", "alpine:3.22", sandbox.Running, nil)
	if _, err := svc.TemplateSave(context.Background(), sb.ID, "t:v1", ""); err != nil {
		t.Fatal(err)
	}
	if fake.started != 0 || fake.stopped != 0 {
		t.Fatalf("running sandbox lifecycle changed: starts=%d stops=%d", fake.started, fake.stopped)
	}
}

func TestTemplateSaveRejectsTransientStates(t *testing.T) {
	svc, _ := templateFixture(t)
	sb := seedSandbox(t, svc, "tpl-creating", "alpine:3.22", sandbox.Creating, nil)
	if _, err := svc.TemplateSave(context.Background(), sb.ID, "t:v1", ""); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("creating state accepted: %v", err)
	}
}

func TestTemplateRemoveReferenceGuard(t *testing.T) {
	svc, fake := templateFixture(t)
	sb := seedSandbox(t, svc, "tpl-ref", "docker.io/library/keep:v1", sandbox.Stopped, nil)
	_ = sb
	if err := svc.store.PutTemplate(context.Background(), store.TemplateRecord{Name: "docker.io/library/keep:v1", Digest: "sha256:1"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.TemplateRemove(context.Background(), "docker.io/library/keep:v1", true); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("referenced removal allowed: %v", err)
	}
	if len(fake.removed) != 0 {
		t.Fatal("backend removal ran despite guard")
	}
	if err := svc.TemplateRemove(context.Background(), "docker.io/library/free:v1", false); err != nil {
		t.Fatalf("unreferenced removal failed: %v", err)
	}
}

func TestTemplateBackendUnsupported(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, &fakeRuntime{}) // plain backend without TemplateBackend
	if _, err := svc.TemplateSave(context.Background(), "missing", "t:v1", ""); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("unsupported backend accepted: %v", err)
	}
}

func TestTemplateInspectMergesBootDocument(t *testing.T) {
	svc, fake := templateFixture(t)
	if err := svc.store.PutTemplate(context.Background(), store.TemplateRecord{Name: "docker.io/library/a:v1", Digest: "sha256:a", Flavor: "codex"}); err != nil {
		t.Fatal(err)
	}
	fake.doc = runtime.TemplateBootDocument{EnvNames: []string{"PATH", "CODEX_HOME"}, WorkingDir: "/workspace", User: "agent"}
	rec, doc, err := svc.TemplateInspect(context.Background(), "docker.io/library/a:v1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Flavor != "codex" || len(doc.EnvNames) != 2 || doc.WorkingDir != "/workspace" {
		t.Fatalf("rec=%+v doc=%+v", rec, doc)
	}
	// Missing boot document degrades to the stored record only, no error.
	fake.doc = runtime.TemplateBootDocument{}
	if _, _, err := svc.TemplateInspect(context.Background(), "docker.io/library/a:v1"); err != nil {
		t.Fatalf("inspect must tolerate boot document loss: %v", err)
	}
}

func TestTemplateLoadRecordsAndExport(t *testing.T) {
	svc, fake := templateFixture(t)
	info, err := svc.TemplateLoad(context.Background(), "/tmp/x.tar", "")
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "docker.io/library/from-archive:v1" {
		t.Fatalf("info=%+v", info)
	}
	if err := svc.TemplateExport(context.Background(), info.Name, "/tmp/out.tar"); err != nil {
		t.Fatal(err)
	}
	if len(fake.exported) != 1 || fake.exported[0][1] != "/tmp/out.tar" {
		t.Fatalf("exported=%v", fake.exported)
	}
	if err := svc.TemplateExport(context.Background(), "docker.io/library/unknown:v9", "/tmp/y"); err == nil {
		t.Fatal("export of unrecorded template must fail")
	}
}
