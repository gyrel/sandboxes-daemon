package server

import (
	"context"
	"strings"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gyrel/sandboxes-daemon/internal/service"
)

// KitPolicyServer implements the local KitPolicyService RPCs.
type KitPolicyServer struct {
	localv1.UnimplementedKitPolicyServiceServer
	svc *service.Service
}

// NewKitPolicy creates a kit policy gRPC service.
func NewKitPolicy(svc *service.Service) *KitPolicyServer {
	return &KitPolicyServer{svc: svc}
}

func (s *KitPolicyServer) CheckKit(ctx context.Context, req *localv1.CheckKitRequest) (*localv1.CheckKitResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "kit policy check request is required")
	}
	kind := req.GetSourceKind()
	if kind == localv1.KitSourceKind_KIT_SOURCE_KIND_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "kit source kind is required")
	}
	reason, allowed, err := s.svc.CheckKitSource(ctx, kind, req.GetSourceRef(), req.GetSandboxId(), req.GetSignaturePresent())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.CheckKitResponse{
		Allowed:         allowed,
		Reason:          reason,
		Message:         kitPolicyMessage(reason),
		CheckedSettings: checkedSettingsFor(reason, kind),
	}, nil
}

func (s *KitPolicyServer) GetKitPolicyConfig(ctx context.Context, _ *localv1.GetKitPolicyConfigRequest) (*localv1.GetKitPolicyConfigResponse, error) {
	cfg, err := s.svc.GetKitPolicyConfig(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	allowed := make([]localv1.KitSourceKind, 0, len(cfg.AllowedSources))
	for _, source := range cfg.AllowedSources {
		allowed = append(allowed, kitSourceKindToProto(source))
	}
	return &localv1.GetKitPolicyConfigResponse{
		AllowedSources:   allowed,
		AllowLocalKits:   cfg.AllowLocalKits,
		RequireSignature: cfg.RequireSignature,
		Managed:          cfg.Managed,
	}, nil
}

func kitSourceKindToProto(source string) localv1.KitSourceKind {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "directory":
		return localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY
	case "zip":
		return localv1.KitSourceKind_KIT_SOURCE_KIND_ZIP
	case "git":
		return localv1.KitSourceKind_KIT_SOURCE_KIND_GIT
	case "oci":
		return localv1.KitSourceKind_KIT_SOURCE_KIND_OCI
	default:
		return localv1.KitSourceKind_KIT_SOURCE_KIND_UNSPECIFIED
	}
}

func kitPolicyMessage(reason localv1.CheckKitReason) string {
	switch reason {
	case localv1.CheckKitReason_CHECK_KIT_REASON_OK:
		return "kit source allowed"
	case localv1.CheckKitReason_CHECK_KIT_REASON_SOURCE_NOT_ALLOWED:
		return "kit source kind is not in the allowed sources list"
	case localv1.CheckKitReason_CHECK_KIT_REASON_LOCAL_DISABLED:
		return "local kits are disabled by policy"
	case localv1.CheckKitReason_CHECK_KIT_REASON_SIGNATURE_REQUIRED:
		return "kit signature is required by policy"
	case localv1.CheckKitReason_CHECK_KIT_REASON_POLICY_UNAVAILABLE:
		return "kit policy is unavailable"
	case localv1.CheckKitReason_CHECK_KIT_REASON_INVALID_REFERENCE:
		return "kit source reference contains userinfo or a query component"
	default:
		return "kit source denied"
	}
}

func checkedSettingsFor(reason localv1.CheckKitReason, kind localv1.KitSourceKind) []string {
	switch reason {
	case localv1.CheckKitReason_CHECK_KIT_REASON_SOURCE_NOT_ALLOWED:
		return []string{"kit.allowedSources"}
	case localv1.CheckKitReason_CHECK_KIT_REASON_LOCAL_DISABLED:
		return []string{"kit.allowLocalKits"}
	case localv1.CheckKitReason_CHECK_KIT_REASON_SIGNATURE_REQUIRED:
		return []string{"kit.requireSignature"}
	case localv1.CheckKitReason_CHECK_KIT_REASON_OK:
		out := []string{"kit.allowedSources"}
		if kind == localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY || kind == localv1.KitSourceKind_KIT_SOURCE_KIND_ZIP {
			out = append(out, "kit.allowLocalKits")
		}
		return out
	default:
		return nil
	}
}
