package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"github.com/rheic/sandboxes-core/sandbox"
	runtime "github.com/rheic/sandboxes-runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

type templateStubBackend struct {
	*templateFakeBackend
	saved runtime.TemplateSaveSpec
}

func (f *templateStubBackend) SaveTemplate(_ context.Context, _ runtime.Handle, spec runtime.TemplateSaveSpec) (runtime.TemplateInfo, error) {
	f.saved = spec
	return runtime.TemplateInfo{Name: "docker.io/library/" + spec.Tag, Digest: "sha256:aa", SizeBytes: 512, Layers: 4, Notice: "notice"}, nil
}

func (f *templateStubBackend) LoadTemplate(_ context.Context, spec runtime.TemplateLoadSpec) (runtime.TemplateInfo, error) {
	return runtime.TemplateInfo{Name: "docker.io/library/loaded:v1", Digest: "sha256:bb", SizeBytes: 999, Layers: 2, Notice: "notice"}, nil
}

func (f *templateStubBackend) RemoveTemplate(context.Context, string) error { return nil }

func (f *templateStubBackend) ExportTemplate(context.Context, string, string) error { return nil }

func (f *templateStubBackend) TemplateBootDocument(context.Context, string) (runtime.TemplateBootDocument, error) {
	return runtime.TemplateBootDocument{EnvNames: []string{"PATH"}, WorkingDir: "/workspace", User: "agent"}, nil
}

type templateFakeBackend struct{}

func (*templateFakeBackend) Capabilities(context.Context) (runtime.Capabilities, error) {
	return runtime.Capabilities{Workspace: true}, nil
}
func (*templateFakeBackend) Create(context.Context, runtime.Config) (runtime.Handle, error) {
	return runtime.Handle{ID: "fixture"}, nil
}
func (*templateFakeBackend) Start(context.Context, runtime.Handle) error               { return nil }
func (*templateFakeBackend) Stop(context.Context, runtime.Handle, time.Duration) error { return nil }
func (*templateFakeBackend) Delete(context.Context, runtime.Handle) error              { return nil }
func (*templateFakeBackend) Handle(string) runtime.Handle                              { return runtime.Handle{ID: "fixture"} }

func newTemplateServerFixture(t *testing.T) (*TemplateServer, *store.Store, *templateStubBackend) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "templates-server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	backend := &templateStubBackend{templateFakeBackend: &templateFakeBackend{}}
	svc := service.New(st, backend)
	seed := sandbox.Sandbox{ID: "sb-1", Name: "dev", State: sandbox.Stopped, Image: "alpine:3.22",
		Workspace: "/host", Meta: &sandbox.Meta{Agent: "codex"}, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := st.Create(ctx, seed); err != nil {
		t.Fatal(err)
	}
	return NewTemplate(svc), st, backend
}

func TestTemplateServerSaveListInspect(t *testing.T) {
	ctx := context.Background()
	ts, st, backend := newTemplateServerFixture(t)
	saved, err := ts.Save(ctx, &localv1.TemplateServiceSaveRequest{SandboxId: "sb-1", Tag: "mytpl:v1"})
	if err != nil {
		t.Fatal(err)
	}
	if saved.GetTemplate().GetName() != "docker.io/library/mytpl:v1" || saved.GetNotice() != "notice" {
		t.Fatalf("saved=%+v", saved)
	}
	if backend.saved.BaseImage != "alpine:3.22" {
		t.Fatalf("base=%q", backend.saved.BaseImage)
	}
	if _, err := st.GetTemplate(ctx, "docker.io/library/mytpl:v1"); err != nil {
		t.Fatalf("record missing after save: %v", err)
	}
	listed, err := ts.List(ctx, &localv1.TemplateServiceListRequest{})
	if err != nil || len(listed.GetTemplates()) != 1 {
		t.Fatalf("listed=%v err=%v", listed, err)
	}
	inspected, err := ts.Inspect(ctx, &localv1.TemplateServiceInspectRequest{Name: "docker.io/library/mytpl:v1"})
	if err != nil {
		t.Fatal(err)
	}
	if inspected.GetWorkingDir() != "/workspace" || len(inspected.GetEnvNames()) != 1 || inspected.GetUser() != "agent" {
		t.Fatalf("inspected=%+v", inspected)
	}
}

func TestTemplateServerExport(t *testing.T) {
	ctx := context.Background()
	ts, _, _ := newTemplateServerFixture(t)
	if _, err := ts.Export(ctx, &localv1.TemplateServiceExportRequest{Name: "docker.io/library/nope:v9", TarPath: "/tmp/x.tar"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unrecorded export: %v", err)
	}
	if _, err := ts.Export(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil export request: %v", err)
	}
	// Successful export stats the written archive: seed a template record
	// and a file at the destination via the service's stub backend export.
	if _, err := ts.Save(ctx, &localv1.TemplateServiceSaveRequest{SandboxId: "sb-1", Tag: "exp:v1"}); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "exp.tar")
	if err := writeExportStub(dest); err != nil {
		t.Fatal(err)
	}
	// templateStubBackend.ExportTemplate is a no-op; pre-create the file so
	// the server-side stat succeeds, then assert size passthrough.
	resp, err := ts.Export(ctx, &localv1.TemplateServiceExportRequest{Name: "docker.io/library/exp:v1", TarPath: dest})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetSizeBytes() <= 0 {
		t.Fatalf("size=%d", resp.GetSizeBytes())
	}
}

func writeExportStub(path string) error {
	return os.WriteFile(path, []byte("stub docker-save archive bytes"), 0o644)
}

func TestTemplateServerValidationAndMissing(t *testing.T) {
	ctx := context.Background()
	ts, _, _ := newTemplateServerFixture(t)
	if _, err := ts.Save(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil save: %v", err)
	}
	if _, err := ts.Save(ctx, &localv1.TemplateServiceSaveRequest{SandboxId: "sb-1", Tag: " "}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("blank tag: %v", err)
	}
	if _, err := ts.Inspect(ctx, &localv1.TemplateServiceInspectRequest{Name: "docker.io/library/nope:v1"}); status.Code(err) != codes.NotFound {
		t.Fatalf("missing inspect: %v", err)
	}
}
