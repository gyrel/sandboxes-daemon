package server

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"github.com/gyrel/sandboxes-core/sandbox"
	runtime "github.com/gyrel/sandboxes-runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/gyrel/sandboxes-daemon/internal/machinecode"
	"github.com/gyrel/sandboxes-daemon/internal/service"
	"github.com/gyrel/sandboxes-daemon/internal/store"
)

type labelsBackend struct {
	graceBackend
	creates int
}

func (b *labelsBackend) Create(ctx context.Context, cfg runtime.Config) (runtime.Handle, error) {
	b.creates++
	return b.graceBackend.Create(ctx, cfg)
}

type listHeaders struct {
	grpc.ServerTransportStream
	header metadata.MD
}

func (s *listHeaders) SetHeader(md metadata.MD) error {
	s.header = md
	return nil
}

func TestSandboxLabelsRoundTrip(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &labelsBackend{}
	svc := service.New(st, backend)
	defer svc.Close()
	srv := NewSandbox(svc)

	want := map[string]string{"team": "platform", "archived": ""}
	req := &localv1.CreateRequest{Name: "labeled", IdempotencyKey: "labeled-create", Labels: want}
	created, err := srv.Create(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	id := created.GetOperation().GetSandboxId()
	replayed, err := srv.Create(ctx, req)
	if err != nil || replayed.GetOperation().GetSandboxId() != id || backend.creates != 1 {
		t.Fatalf("create replay = %v, runtime creates = %d, err = %v", replayed, backend.creates, err)
	}
	if _, err := srv.Create(ctx, &localv1.CreateRequest{Name: "labeled", IdempotencyKey: "labeled-create", Labels: map[string]string{"team": "other"}}); err == nil {
		t.Fatal("create replay accepted different labels")
	}
	got, err := srv.Get(ctx, &localv1.GetRequest{Id: id})
	if err != nil || !maps.Equal(got.GetSandbox().GetLabels(), want) {
		t.Fatalf("Get labels = %v, err = %v", got.GetSandbox().GetLabels(), err)
	}

	if err := st.Create(ctx, sandbox.Sandbox{ID: "hidden", Name: "hidden", State: sandbox.Stopped, Labels: want}); err != nil {
		t.Fatal(err)
	}
	unset, err := srv.Create(ctx, &localv1.CreateRequest{Name: "unset", Labels: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	unsetID := unset.GetOperation().GetSandboxId()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, "UPDATE sandboxes SET install_id='foreign' WHERE id='hidden'"); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.QueryRowContext(ctx, "SELECT labels FROM sandboxes WHERE id=?", unsetID).Scan(&stored); err != nil || stored != "" {
		t.Fatalf("empty labels stored as %q, err = %v", stored, err)
	}

	stream := &listHeaders{}
	listed, err := srv.List(grpc.NewContextWithServerTransportStream(ctx, stream), &localv1.ListRequest{})
	if err != nil || len(listed.GetItems()) != 2 || !slices.Equal(stream.header.Get("sandbox-hidden-count"), []string{"1"}) {
		t.Fatalf("List = %v, headers = %v, err = %v", listed, stream.header, err)
	}
	for _, item := range listed.GetItems() {
		switch item.GetId() {
		case id:
			if !maps.Equal(item.GetLabels(), want) {
				t.Fatalf("List labels = %v, want %v", item.GetLabels(), want)
			}
		case unsetID:
			if item.GetLabels() != nil {
				t.Fatalf("unset labels = %v, want nil", item.GetLabels())
			}
		default:
			t.Fatalf("unexpected listed row %q", item.GetId())
		}
	}
}

func TestCreateRejectsInvalidLabelsWithoutSideEffects(t *testing.T) {
	tooMany := make(map[string]string)
	for i := range 17 {
		tooMany[fmt.Sprintf("label-%d", i)] = "value"
	}
	for _, tc := range []struct {
		name   string
		labels map[string]string
	}{
		{"too many pairs", tooMany},
		{"invalid key", map[string]string{"_team": "dev"}},
		{"long value", map[string]string{"team": strings.Repeat("x", 256)}},
		{"newline", map[string]string{"team": "line\nbreak"}},
		{"credential key", map[string]string{"github_token": "fixture"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			dir := t.TempDir()
			path := filepath.Join(dir, "sandboxes.db")
			st, err := store.Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			backend := &labelsBackend{}
			svc := service.New(st, backend)
			defer svc.Close()
			_, err = NewSandbox(svc).Create(ctx, &localv1.CreateRequest{Name: "rejected", Labels: tc.labels})
			details := status.Convert(err).Details()
			if len(details) != 1 {
				t.Fatalf("expected refusal details, got %v", err)
			}
			info, ok := details[0].(*errdetails.ErrorInfo)
			if !ok || info.GetReason() != string(machinecode.LabelInvalid) {
				t.Fatalf("expected LABEL_INVALID, got %v", details)
			}
			items, _, hidden, err := st.ListWithHiddenCount(ctx, sandbox.ListOptions{})
			if err != nil || len(items) != 0 || hidden != 0 {
				t.Fatalf("store contains %d visible and %d hidden rows, err = %v", len(items), hidden, err)
			}
			db, err := sql.Open("sqlite", "file:"+path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			var operations int
			if err := db.QueryRowContext(ctx, "SELECT count(*) FROM operations").Scan(&operations); err != nil || operations != 0 {
				t.Fatalf("operation count = %d, err = %v", operations, err)
			}
			journal, err := filepath.Glob(filepath.Join(dir, "journal", "*"))
			if err != nil || len(journal) != 0 || backend.creates != 0 {
				t.Fatalf("journal = %v, runtime creates = %d, err = %v", journal, backend.creates, err)
			}
		})
	}
}
