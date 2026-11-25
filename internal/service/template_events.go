package service

import (
	"context"
	"log/slog"

	"github.com/rheic/sandboxes-core/ids"
	runtime "github.com/rheic/sandboxes-runtime"
	"github.com/rheic/slogx/events"
)

// emitTemplateSaved records one template save outcome. Only values the save
// flow already computed (name, layers, size, digest) reach the catalog;
// whiteouts, opaque dirs and workspace/secret warnings are not computed by
// the runtime and stay at their zero values.
func emitTemplateSaved(ctx context.Context, outcome events.Outcome, info runtime.TemplateInfo) {
	p := events.TemplateSaveParams{
		TemplateID: events.ID(info.Name),
		Digest:     events.Hash(info.Digest),
	}
	if info.Layers > 0 {
		p.Layers = uint64(info.Layers)
	}
	if info.SizeBytes > 0 {
		p.Bytes = uint64(info.SizeBytes)
	}
	event, err := events.TemplateSave(outcome, p)
	if err != nil {
		return
	}
	emitWithCorrelation(ctx, event)
}

// emitTemplateLoaded records one template load outcome with the same
// already-computed-field rule.
func emitTemplateLoaded(ctx context.Context, outcome events.Outcome, info runtime.TemplateInfo) {
	p := events.TemplateLoadParams{
		TemplateID: events.ID(info.Name),
		Digest:     events.Hash(info.Digest),
	}
	if info.Layers > 0 {
		p.Layers = uint64(info.Layers)
	}
	if info.SizeBytes > 0 {
		p.Bytes = uint64(info.SizeBytes)
	}
	event, err := events.TemplateLoad(outcome, p)
	if err != nil {
		return
	}
	emitWithCorrelation(ctx, event)
}

// emitWithCorrelation attaches validated op/req IDs from the context when
// present and writes the event through the default slog handler.
func emitWithCorrelation(ctx context.Context, event events.Event) {
	op, req := ids.FromContext(ctx)
	standard := events.Standard{}
	if ids.Validate(op) == nil {
		id := events.ID(op)
		standard.OpID = &id
	}
	if ids.Validate(req) == nil {
		id := events.ID(req)
		standard.ReqID = &id
	}
	event.Emit(ctx, slog.Default(), standard)
}
