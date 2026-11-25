package server

import (
	"context"
	"math"
	"os"
	"strings"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gyrel/sandboxes-daemon/internal/service"
	"github.com/gyrel/sandboxes-daemon/internal/store"
)

// TemplateServer implements the local TemplateService (ADR-0008).
type TemplateServer struct {
	localv1.UnimplementedTemplateServiceServer
	svc *service.Service
}

// NewTemplate wires the template service.
func NewTemplate(svc *service.Service) *TemplateServer { return &TemplateServer{svc: svc} }

func (s *TemplateServer) Save(ctx context.Context, req *localv1.TemplateServiceSaveRequest) (*localv1.TemplateServiceSaveResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "template save request is required")
	}
	info, err := s.svc.TemplateSave(ctx, req.GetSandboxId(), req.GetTag(), req.GetOutputPath())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.TemplateServiceSaveResponse{
		Template:   templateProto(info.Name, info.Digest, info.SizeBytes, 0, "", "", info.Layers),
		OutputPath: req.GetOutputPath(),
		Notice:     info.Notice,
	}, nil
}

func (s *TemplateServer) Load(ctx context.Context, req *localv1.TemplateServiceLoadRequest) (*localv1.TemplateServiceLoadResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "template load request is required")
	}
	info, err := s.svc.TemplateLoad(ctx, req.GetTarPath(), req.GetName())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.TemplateServiceLoadResponse{
		Template: templateProto(info.Name, info.Digest, info.SizeBytes, 0, "", "", info.Layers),
	}, nil
}

func (s *TemplateServer) Remove(ctx context.Context, req *localv1.TemplateServiceRemoveRequest) (*localv1.TemplateServiceRemoveResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "template remove request is required")
	}
	if err := s.svc.TemplateRemove(ctx, req.GetName(), req.GetForce()); err != nil {
		return nil, mapError(err)
	}
	return &localv1.TemplateServiceRemoveResponse{}, nil
}

func (s *TemplateServer) List(ctx context.Context, _ *localv1.TemplateServiceListRequest) (*localv1.TemplateServiceListResponse, error) {
	records, err := s.svc.TemplateList(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]*localv1.Template, 0, len(records))
	for _, r := range records {
		out = append(out, recordProto(r))
	}
	return &localv1.TemplateServiceListResponse{Templates: out}, nil
}

func (s *TemplateServer) Inspect(ctx context.Context, req *localv1.TemplateServiceInspectRequest) (*localv1.TemplateServiceInspectResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "template inspect request is required")
	}
	rec, doc, err := s.svc.TemplateInspect(ctx, req.GetName())
	if err != nil {
		return nil, mapError(err)
	}
	envNames := make([]string, 0, len(doc.EnvNames))
	for _, name := range doc.EnvNames {
		envNames = append(envNames, strings.Clone(name))
	}
	return &localv1.TemplateServiceInspectResponse{
		Template:   recordProto(rec),
		EnvNames:   envNames,
		WorkingDir: doc.WorkingDir,
		User:       doc.User,
	}, nil
}

func (s *TemplateServer) Export(ctx context.Context, req *localv1.TemplateServiceExportRequest) (*localv1.TemplateServiceExportResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "template export request is required")
	}
	if err := s.svc.TemplateExport(ctx, req.GetName(), req.GetTarPath()); err != nil {
		return nil, mapError(err)
	}
	info, err := os.Stat(req.GetTarPath())
	if err != nil || !info.Mode().IsRegular() {
		return nil, status.Error(codes.Internal, "template export completed but the archive could not be verified")
	}
	return &localv1.TemplateServiceExportResponse{SizeBytes: info.Size()}, nil
}

func recordProto(r store.TemplateRecord) *localv1.Template {
	return templateProto(r.Name, r.Digest, r.SizeBytes, r.CreatedAt, r.BaseImage, r.Flavor, r.Layers)
}

func templateProto(name, digest string, size, created int64, base, flavor string, layers int) *localv1.Template {
	// Layer counts are small and bounded by the manifest; clamp explicitly
	// so an unexpected value cannot overflow the int32 wire field.
	protoLayers := layers
	if protoLayers < 0 {
		protoLayers = 0
	}
	if protoLayers > math.MaxInt32 {
		protoLayers = math.MaxInt32
	}
	return &localv1.Template{
		Name: name, Digest: digest, SizeBytes: size, CreatedUnix: created,
		BaseImage: base, Flavor: flavor, Layers: int32(protoLayers),
	}
}
