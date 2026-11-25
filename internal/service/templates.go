package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"
	runtime "github.com/rheic/sandboxes-runtime"
	"github.com/rheic/slogx/events"

	"github.com/rheic/sandboxes-daemon/internal/store"
)

// TemplateSave records a template from a stopped or running sandbox. The
// sandbox's own state is restored afterwards: stopped sandboxes are
// started only for the capture and stopped again; running sandboxes are
// captured in place and never stopped (ADR-0008 behavior probe).
func (s *Service) TemplateSave(ctx context.Context, idOrName, tag, outputPath string) (runtime.TemplateInfo, error) {
	if strings.TrimSpace(tag) == "" {
		return runtime.TemplateInfo{}, fmt.Errorf("%w: template tag is required", core.ErrConflict)
	}
	tb, err := s.templateBackend()
	if err != nil {
		emitTemplateSaved(ctx, events.OutcomeUnsupported, runtime.TemplateInfo{})
		return runtime.TemplateInfo{}, err
	}
	sb, err := s.Get(ctx, idOrName)
	if err != nil {
		return runtime.TemplateInfo{}, err
	}
	if sb.State == sandbox.Deleting || sb.State == sandbox.Deleted || sb.State == sandbox.Creating {
		return runtime.TemplateInfo{}, fmt.Errorf("%w: template save requires a stopped or running sandbox (state %s)", core.ErrConflict, sb.State)
	}
	switch sb.State {
	case sandbox.Stopped:
		// Boot primitives directly: the recorded sandbox row already carries
		// the effective policy/ports, so capture does not need a journal
		// Start operation (same sequence prepareSandboxForStart performs).
		startSB := sb
		if err := s.prepareSandboxForStart(ctx, &startSB); err != nil {
			return runtime.TemplateInfo{}, err
		}
		sb = startSB
		defer func() {
			restore := sb
			if _, err := s.stopRuntime(ctx, &restore, templateStopGrace); err != nil {
				return
			}
		}()
	case sandbox.Running:
	default:
		return runtime.TemplateInfo{}, fmt.Errorf("%w: template save requires a stopped or running sandbox (state %s)", core.ErrConflict, sb.State)
	}
	handle := s.backend.Handle(sb.Name)
	info, err := tb.SaveTemplate(ctx, handle, runtime.TemplateSaveSpec{
		Tag:        tag,
		BaseImage:  sb.Image,
		Excludes:   templateExcludesFor(sb),
		OutputPath: outputPath,
	})
	if err != nil {
		emitTemplateSaved(ctx, events.OutcomeFailed, runtime.TemplateInfo{})
		return runtime.TemplateInfo{}, err
	}
	if err := s.store.PutTemplate(ctx, storeTemplate(info, sb)); err != nil {
		emitTemplateSaved(ctx, events.OutcomeFailed, info)
		return runtime.TemplateInfo{}, fmt.Errorf("%w: record template: %w", core.ErrConflict, err)
	}
	emitTemplateSaved(ctx, events.OutcomeOK, info)
	return info, nil
}

func storeTemplate(info runtime.TemplateInfo, sb sandbox.Sandbox) store.TemplateRecord {
	return store.TemplateRecord{
		Name: info.Name, Digest: info.Digest, SizeBytes: info.SizeBytes,
		Layers: info.Layers, BaseImage: sb.Image, Flavor: agentFromMeta(sb),
	}
}

// TemplateExcludesFor lists guest paths that must never enter a template:
// every workspace mount (rw and ro) and reserved clone source paths.
func templateExcludesFor(sb sandbox.Sandbox) []string {
	var out []string
	for _, w := range sb.Workspaces {
		guest := w.GuestPath
		if guest == "" {
			guest = w.Path
		}
		if strings.HasPrefix(guest, "/") && guest != "/" {
			out = append(out, guest)
		}
	}
	if sb.Meta != nil && sb.Meta.Clone != nil {
		out = append(out, "/run/sandbox/source")
	}
	return out
}

func agentFromMeta(sb sandbox.Sandbox) string {
	if sb.Meta == nil {
		return ""
	}
	return sb.Meta.Agent
}

// TemplateLoad imports a template archive and records it.
func (s *Service) TemplateLoad(ctx context.Context, tarPath, name string) (runtime.TemplateInfo, error) {
	tb, err := s.templateBackend()
	if err != nil {
		emitTemplateLoaded(ctx, events.OutcomeUnsupported, runtime.TemplateInfo{})
		return runtime.TemplateInfo{}, err
	}
	info, err := tb.LoadTemplate(ctx, runtime.TemplateLoadSpec{TarPath: tarPath, Name: name})
	if err != nil {
		emitTemplateLoaded(ctx, events.OutcomeFailed, runtime.TemplateInfo{})
		return runtime.TemplateInfo{}, err
	}
	// Boot document readback may lag the import; the record stays valid with
	// an empty digest and inspect resolves it live.
	if err := s.store.PutTemplate(ctx, store.TemplateRecord{
		Name: info.Name, Digest: info.Digest, SizeBytes: info.SizeBytes, Layers: info.Layers,
	}); err != nil {
		emitTemplateLoaded(ctx, events.OutcomeFailed, info)
		return runtime.TemplateInfo{}, fmt.Errorf("%w: record loaded template: %w", core.ErrConflict, err)
	}
	emitTemplateLoaded(ctx, events.OutcomeOK, info)
	return info, nil
}

// TemplateRemove refuses to drop a template still referenced by any
// sandbox record, regardless of force.
func (s *Service) TemplateRemove(ctx context.Context, name string, force bool) error {
	sbCount, err := s.store.TemplateReferences(ctx, name)
	if err != nil {
		return err
	}
	if sbCount > 0 {
		// The reference guard is absolute: even force cannot orphan a live
		// sandbox from its boot image (baseline `rm` warns and refuses).
		_ = force
		return fmt.Errorf("%w: template %s is referenced by %d sandbox(es); remove those sandboxes first", core.ErrConflict, name, sbCount)
	}
	tb, err := s.templateBackend()
	if err != nil {
		return err
	}
	// Removal also accepts images imported out of band (no stored record);
	// the reference guard above still applies.
	if _, err := s.store.GetTemplate(ctx, name); err != nil && !errors.Is(err, store.ErrTemplateNotFound) {
		return err
	}
	if err := tb.RemoveTemplate(ctx, name); err != nil {
		return err
	}
	if err := s.store.DeleteTemplate(ctx, name); err != nil && !errors.Is(err, store.ErrTemplateNotFound) {
		return err
	}
	return nil
}

// TemplateList returns recorded templates ordered by creation.
func (s *Service) TemplateList(ctx context.Context) ([]store.TemplateRecord, error) {
	return s.store.ListTemplates(ctx)
}

// TemplateInspect merges the stored record with the live boot document.
func (s *Service) TemplateInspect(ctx context.Context, name string) (store.TemplateRecord, runtime.TemplateBootDocument, error) {
	rec, err := s.store.GetTemplate(ctx, name)
	if err != nil {
		return store.TemplateRecord{}, runtime.TemplateBootDocument{}, translateTemplateStoreErr(err, name)
	}
	// The live boot document degrades gracefully: template records remain
	// listed even if the image was removed from the store out of band.
	doc := runtime.TemplateBootDocument{}
	if tb, tbErr := s.templateBackend(); tbErr == nil {
		if live, docErr := tb.TemplateBootDocument(ctx, name); docErr == nil {
			doc = live
		}
	}
	return rec, doc, nil
}

// TemplateExport writes a docker-save archive for a recorded template.
func (s *Service) TemplateExport(ctx context.Context, name, tarPath string) error {
	if _, err := s.store.GetTemplate(ctx, name); err != nil {
		return translateTemplateStoreErr(err, name)
	}
	tb, err := s.templateBackend()
	if err != nil {
		return err
	}
	return tb.ExportTemplate(ctx, name, tarPath)
}

const templateStopGrace = 5 * time.Second

func translateTemplateStoreErr(err error, name string) error {
	if errors.Is(err, store.ErrTemplateNotFound) {
		return fmt.Errorf("%w: template %s", core.ErrNotFound, name)
	}
	return err
}

func (s *Service) templateBackend() (runtime.TemplateBackend, error) {
	tb, ok := s.backend.(runtime.TemplateBackend)
	if !ok {
		return nil, fmt.Errorf("%w: the local runtime does not support templates", core.ErrConflict)
	}
	return tb, nil
}
