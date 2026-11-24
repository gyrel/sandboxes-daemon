package server

import (
	"context"
	"errors"

	core "github.com/rheic/sandboxes-core"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rheic/sandboxes-daemon/internal/approvals"
	"github.com/rheic/sandboxes-daemon/internal/service"
)

// ApprovalServer implements the local ApprovalService RPCs.
type ApprovalServer struct {
	localv1.UnimplementedApprovalServiceServer
	svc *service.Service
}

// NewApproval creates an approval gRPC service.
func NewApproval(svc *service.Service) *ApprovalServer { return &ApprovalServer{svc: svc} }

func (s *ApprovalServer) List(ctx context.Context, req *localv1.ApprovalServiceListRequest) (*localv1.ApprovalServiceListResponse, error) {
	if req == nil {
		req = &localv1.ApprovalServiceListRequest{}
	}
	entries, err := s.svc.ListApprovals(ctx, req.GetSandboxId())
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]*localv1.Approval, 0, len(entries))
	for i := range entries {
		out = append(out, approvalToProto(entries[i]))
	}
	return &localv1.ApprovalServiceListResponse{Approvals: out}, nil
}

func (s *ApprovalServer) Inspect(ctx context.Context, req *localv1.ApprovalServiceInspectRequest) (*localv1.ApprovalServiceInspectResponse, error) {
	if req == nil || req.GetApprovalId() == "" {
		return nil, status.Error(codes.InvalidArgument, "approval ID is required")
	}
	entry, err := s.svc.InspectApproval(ctx, req.GetApprovalId(), req.GetSandboxId())
	if err != nil {
		if status.Code(err) == 0 {
			if isNotFound(err) {
				return nil, status.Error(codes.NotFound, "approval not found")
			}
			return nil, mapError(err)
		}
		return nil, err
	}
	return &localv1.ApprovalServiceInspectResponse{Approval: approvalToProto(entry)}, nil
}

func (s *ApprovalServer) Respond(ctx context.Context, req *localv1.ApprovalServiceRespondRequest) (*localv1.ApprovalServiceRespondResponse, error) {
	if req == nil || req.GetApprovalId() == "" {
		return nil, status.Error(codes.InvalidArgument, "approval ID is required")
	}
	decision := req.GetDecision()
	if decision == localv1.ApprovalDecision_APPROVAL_DECISION_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "approval decision is required")
	}
	persist := req.GetPersistScope()
	if persist == localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_UNSPECIFIED {
		persist = localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE
	}
	entry, persistedRuleID, err := s.svc.RespondApproval(ctx, req.GetApprovalId(), decision, persist)
	if err != nil {
		switch {
		case isNotFound(err):
			return nil, status.Error(codes.NotFound, "approval not found")
		case errors.Is(err, service.ErrApprovalInvalidDecision):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, service.ErrApprovalProviderUnavailable):
			return nil, status.Error(codes.FailedPrecondition, "trusted approval provider is unavailable")
		case errors.Is(err, service.ErrApprovalNotPending):
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		default:
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
	}
	return &localv1.ApprovalServiceRespondResponse{Approval: approvalToProto(entry), PersistedRuleId: persistedRuleID}, nil
}

//nolint:gocritic // entry-sized disclosure parameter
func approvalToProto(entry approvals.Entry) *localv1.Approval {
	sandboxID := entry.SandboxID
	if sandboxID == "" {
		sandboxID = entry.SandboxId
	}
	if sandboxID == "" {
		sandboxID = entry.Sandbox
	}
	envNames := entry.EnvNames
	if len(envNames) == 0 {
		envNames = entry.Env
	}
	cwd := entry.CwdSummary
	if cwd == "" {
		cwd = entry.Cwd
	}
	createdAt := entry.CreatedAtUnix
	if createdAt == 0 && !entry.CreatedAt.IsZero() {
		createdAt = entry.CreatedAt.Unix()
	}
	headers := entry.Headers
	if len(headers) == 0 {
		headers = entry.Header
	}
	return &localv1.Approval{
		Id:                entry.ID,
		Kind:              entry.Kind,
		State:             entry.State,
		SandboxId:         sandboxID,
		ActionSummary:     entry.ActionSummary,
		DestinationHost:   entry.DestinationHost,
		DestinationPath:   entry.DestinationPath,
		Headers:           headers,
		EnvNames:          envNames,
		EnvNamesTruncated: entry.EnvNamesTruncated || entry.EnvTruncated,
		CwdSummary:        cwd,
		CreatedAtUnix:     createdAt,
	}
}

func isNotFound(err error) bool {
	return errors.Is(err, core.ErrNotFound)
}
