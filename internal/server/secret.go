package server

import (
	"context"
	"errors"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rheic/sandboxes-daemon/internal/customsecrets"
	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
)

// SecretServer implements the local service-secret RPCs.
type SecretServer struct {
	localv1.UnimplementedSecretServiceServer
	svc *service.Service
}

// NewSecret creates a service-secret server.
func NewSecret(svc *service.Service) *SecretServer { return &SecretServer{svc: svc} }

// Set stores one service secret. The value is cleared after the call.
func (s *SecretServer) Set(ctx context.Context, req *localv1.SecretServiceSetRequest) (*localv1.SecretServiceSetResponse, error) {
	value := req.GetValue()
	defer clear(value)
	scope, err := parseSecretScope(req.GetScope())
	if err != nil {
		return nil, err
	}
	var summary servicesecrets.Summary
	if source := req.GetSource(); source != nil {
		if len(value) != 0 {
			return nil, status.Error(codes.InvalidArgument, "provide either a secret value or a secret source")
		}
		summary, err = s.svc.SetServiceSecretSource(ctx, req.GetService(), scope, req.GetSandboxName(), servicesecrets.Source{
			Reference: source.GetReference(), Command: source.GetCommand(), Refresh: source.GetRefresh(),
			NoVerify: source.GetNoVerify(), ShowError: source.GetShowError(),
			OPAccount: source.GetOpAccount(), AWSProfile: source.GetAwsProfile(),
		})
	} else {
		summary, err = s.svc.SetServiceSecret(ctx, req.GetService(), scope, req.GetSandboxName(), value)
	}
	if err != nil {
		return nil, err
	}
	return &localv1.SecretServiceSetResponse{Secret: secretSummaryToProto(summary)}, nil
}

// Create stores a secret only when the requested scope is empty.
func (s *SecretServer) Create(ctx context.Context, req *localv1.SecretServiceCreateRequest) (*localv1.SecretServiceCreateResponse, error) {
	value := req.GetValue()
	defer clear(value)
	scope, err := parseSecretScope(req.GetScope())
	if err != nil {
		return nil, err
	}
	var summary servicesecrets.Summary
	if source := req.GetSource(); source != nil {
		if len(value) != 0 {
			return nil, status.Error(codes.InvalidArgument, "provide either a secret value or a secret source")
		}
		summary, err = s.svc.CreateServiceSecretSource(ctx, req.GetService(), scope, req.GetSandboxName(), servicesecrets.Source{
			Reference: source.GetReference(), Command: source.GetCommand(), Refresh: source.GetRefresh(),
			NoVerify: source.GetNoVerify(), ShowError: source.GetShowError(),
			OPAccount: source.GetOpAccount(), AWSProfile: source.GetAwsProfile(),
		})
	} else {
		summary, err = s.svc.CreateServiceSecret(ctx, req.GetService(), scope, req.GetSandboxName(), value)
	}
	if errors.Is(err, servicesecrets.ErrExists) {
		return nil, status.Error(codes.AlreadyExists, "service secret already exists; pass --force to replace it")
	}
	if err != nil {
		return nil, err
	}
	return &localv1.SecretServiceCreateResponse{Secret: secretSummaryToProto(summary)}, nil
}

// SetCustom stores a custom secret that a sandbox uses through a placeholder.
// The value is cleared after the call. The response carries the full placeholder
// once, never the value, and reference or command sources are refused until a
// trusted approval provider exists.
func (s *SecretServer) SetCustom(ctx context.Context, req *localv1.SecretServiceSetCustomRequest) (*localv1.SecretServiceSetCustomResponse, error) {
	value := req.GetValue()
	defer clear(value)
	scope, err := parseSecretScope(req.GetScope())
	if err != nil {
		return nil, err
	}
	source := req.GetSource()
	switch {
	case source != nil && len(value) != 0:
		return nil, status.Error(codes.InvalidArgument, "provide either a secret value or a secret source")
	case source == nil && len(value) == 0:
		return nil, status.Error(codes.InvalidArgument, "provide a secret value or a secret source")
	}
	request := service.CustomSecretSetRequest{
		Service: req.GetService(), Scope: scope, SandboxName: req.GetSandboxName(), Value: value,
		Env: req.GetEnv(), Placeholder: req.GetPlaceholder(), Hosts: req.GetHosts(),
	}
	if source != nil {
		request.Source = &servicesecrets.Source{
			Reference: source.GetReference(), Command: source.GetCommand(), Refresh: source.GetRefresh(),
			NoVerify: source.GetNoVerify(), ShowError: source.GetShowError(),
			OPAccount: source.GetOpAccount(), AWSProfile: source.GetAwsProfile(),
		}
	}
	summary, placeholder, err := s.svc.SetCustomSecret(ctx, request)
	if err != nil {
		return nil, customSecretError(err)
	}
	return &localv1.SecretServiceSetCustomResponse{Secret: customSecretSummaryToProto(summary), Placeholder: placeholder}, nil
}

// List returns non-secret summaries for service and custom secrets.
func (s *SecretServer) List(ctx context.Context, _ *localv1.SecretServiceListRequest) (*localv1.SecretServiceListResponse, error) {
	items, err := s.svc.ListServiceSecrets(ctx)
	if err != nil {
		return nil, err
	}
	custom, err := s.svc.ListCustomSecrets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*localv1.SecretSummary, 0, len(items)+len(custom))
	for index := range items {
		out = append(out, secretSummaryToProto(items[index]))
	}
	for index := range custom {
		out = append(out, customSecretSummaryToProto(custom[index]))
	}
	return &localv1.SecretServiceListResponse{Secrets: out}, nil
}

// customSecretSummaryToProto maps custom inventory metadata. The mask is the
// only placeholder form that leaves the daemon on inventory paths.
func customSecretSummaryToProto(summary customsecrets.Summary) *localv1.SecretSummary {
	return &localv1.SecretSummary{
		Service: summary.Service, Scope: string(summary.Scope), SandboxName: summary.SandboxName,
		CreatedAtUnix: unix(summary.CreatedAt), UpdatedAtUnix: unix(summary.UpdatedAt),
		SourceKind: string(servicesecrets.SourceKindValue), SecretType: servicesecrets.SecretTypeAPIKey,
		Origin: summary.Origin, EnvName: summary.EnvName, Hosts: summary.Hosts,
		PlaceholderMasked: summary.PlaceholderMasked,
	}
}

// customSecretError keeps input faults as InvalidArgument. Other failures follow
// the daemon's standard mapping, whose messages never include secret material.
func customSecretError(err error) error {
	if errors.Is(err, customsecrets.ErrInvalidHost) || errors.Is(err, customsecrets.ErrInvalidInput) ||
		errors.Is(err, customsecrets.ErrInvalidPlaceholder) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return mapError(err)
}

// secretSummaryToProto maps non-secret inventory metadata. It never copies a
// secret value, reference, command or environment value.
func secretSummaryToProto(summary servicesecrets.Summary) *localv1.SecretSummary {
	return &localv1.SecretSummary{
		Service: summary.Service, Scope: string(summary.Scope), SandboxName: summary.SandboxName,
		CreatedAtUnix: unix(summary.CreatedAt), UpdatedAtUnix: unix(summary.UpdatedAt),
		SourceKind: string(summary.SourceKind), Refresh: summary.Refresh, Refreshable: summary.Refreshable,
		SecretType: summary.SecretType, Origin: summary.Origin,
	}
}

// Remove deletes one custom or service secret. A custom secret is tried first;
// names that match no custom secret fall through to the service-secret path.
func (s *SecretServer) Remove(ctx context.Context, req *localv1.SecretServiceRemoveRequest) (*localv1.SecretServiceRemoveResponse, error) {
	scope, err := parseSecretScope(req.GetScope())
	if err != nil {
		return nil, err
	}
	removed, err := s.svc.RemoveCustomSecret(ctx, req.GetService(), scope, req.GetSandboxName())
	if err != nil {
		return nil, customSecretError(err)
	}
	if removed {
		return &localv1.SecretServiceRemoveResponse{Removed: true}, nil
	}
	removed, err = s.svc.RemoveServiceSecret(ctx, req.GetService(), scope, req.GetSandboxName())
	if err != nil {
		return nil, err
	}
	return &localv1.SecretServiceRemoveResponse{Removed: removed}, nil
}

func parseSecretScope(value string) (servicesecrets.Scope, error) {
	switch servicesecrets.Scope(value) {
	case "", servicesecrets.ScopeGlobal:
		return servicesecrets.ScopeGlobal, nil
	case servicesecrets.ScopeSandbox:
		return servicesecrets.ScopeSandbox, nil
	default:
		return "", status.Error(codes.InvalidArgument, "secret scope must be global or sandbox")
	}
}
