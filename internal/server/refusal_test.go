package server

import (
	"errors"
	"io"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/grpc"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	core "github.com/gyrel/sandboxes-core"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gyrel/sandboxes-daemon/internal/machinecode"
	"github.com/gyrel/sandboxes-daemon/internal/service"
	"github.com/gyrel/sandboxes-daemon/internal/store"
)

type emptyCopyStream struct {
	grpc.BidiStreamingServer[localv1.ExecSessionRequest, localv1.ExecSessionResponse]
}

func (emptyCopyStream) Recv() (*localv1.ExecSessionRequest, error) { return nil, io.EOF }

func TestVerbRefusals(t *testing.T) {
	ctx := t.Context()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "sandbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := NewSandbox(service.New(db, nil))
	_, name := srv.Create(ctx, &localv1.CreateRequest{Name: "../invalid"})
	_, page := srv.List(ctx, &localv1.ListRequest{PageToken: "!"})
	_, stop := srv.Stop(ctx, &localv1.StopRequest{GraceSeconds: -1})
	_, remove := srv.Delete(ctx, &localv1.DeleteRequest{Id: "missing"})
	_, prune := srv.Delete(ctx, &localv1.DeleteRequest{Id: "missing", Force: true})
	_, ports := srv.UpdatePorts(ctx, &localv1.UpdatePortsRequest{Id: "missing"})
	exec := srv.Exec(&localv1.ExecRequest{}, nil)
	for _, tc := range []struct {
		verb   string
		err    error
		grpc   codes.Code
		reason machinecode.Code
	}{
		{"create", name, codes.FailedPrecondition, machinecode.NameInvalid},
		{"list", page, codes.Internal, machinecode.SpecInvalid},
		{"stop", stop, codes.InvalidArgument, machinecode.SpecInvalid},
		{"remove", remove, codes.NotFound, machinecode.NotFound},
		{"prune-delete", prune, codes.NotFound, machinecode.NotFound},
		{"ports", ports, codes.NotFound, machinecode.NotFound},
		{"cp-session", srv.ExecSession(emptyCopyStream{}), codes.InvalidArgument, machinecode.SpecInvalid},
		{"exec", exec, codes.InvalidArgument, machinecode.SpecInvalid},
	} {
		t.Run(tc.verb, func(t *testing.T) {
			st := status.Convert(tc.err)
			if st.Code() != tc.grpc || len(st.Details()) != 1 {
				t.Fatalf("status = %v, details = %v", st, st.Details())
			}
			info, ok := st.Details()[0].(*errdetails.ErrorInfo)
			if !ok || info.Reason != string(tc.reason) || !slices.Contains(machinecode.All(), tc.reason) {
				t.Fatalf("reason = %v, want %s", info, tc.reason)
			}
		})
	}
}

func TestRegisteredReasonsSurviveMapping(t *testing.T) {
	cause := errors.New("existing message")
	for _, reason := range machinecode.All() {
		err := machinecode.Attach(reason, cause)
		st := status.Convert(mapVerbError(err))
		if !errors.Is(err, cause) || st.Message() != cause.Error() || len(st.Details()) != 1 {
			t.Fatalf("%s: %v", reason, st)
		}
		info, ok := st.Details()[0].(*errdetails.ErrorInfo)
		if !ok || info.Reason != string(reason) {
			t.Fatalf("%s: %v", reason, info)
		}
	}
}

func TestUnclassifiedVerbFailures(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason machinecode.Code
		grpc   codes.Code
	}{
		{core.ErrConflict, machinecode.SpecInvalid, codes.FailedPrecondition},
		{core.ErrNotFound, machinecode.NotFound, codes.NotFound},
		{errors.New("unclassified failure"), machinecode.UnknownState, codes.Internal},
	} {
		st := status.Convert(mapVerbError(tc.err))
		if st.Message() != tc.err.Error() || st.Code() != tc.grpc || len(st.Details()) != 1 {
			t.Fatalf("status %v", st)
		}
		info, ok := st.Details()[0].(*errdetails.ErrorInfo)
		if !ok || info.Reason != string(tc.reason) {
			t.Fatalf("details %v", info)
		}
	}
}
