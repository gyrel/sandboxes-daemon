package network

import (
	"context"
	"testing"

	"github.com/gyrel/sandboxes-core/ids"
	gateway "github.com/gyrel/sandboxes-gateway"
	"github.com/gyrel/sandboxes-gateway/policy"
)

// correlationManager is a fake gateway manager that captures every policy
// payload the adapter pushes. It also mimics the real manager's handle-level
// correlation fallback (gateway.Manager.effectiveCorrelation): the handle
// records the most recent ids, and a Reload that omits its own ids reuses the
// recorded ones. reloaded holds the raw payloads as forwarded by the adapter;
// effective holds the post-fallback payloads a real gateway would stamp.
type correlationManager struct {
	started   []policy.Policy
	reloaded  []policy.Policy
	effective []policy.Policy
	op, req   string
}

func (f *correlationManager) Start(_ context.Context, p policy.Policy) (gateway.Network, error) {
	f.started = append(f.started, p)
	f.op, f.req = p.OpID, p.ReqID
	return gateway.Network{}, nil
}

func (f *correlationManager) Reload(_ context.Context, p policy.Policy) error {
	f.reloaded = append(f.reloaded, p)
	if p.OpID == "" {
		p.OpID = f.op
	}
	if p.ReqID == "" {
		p.ReqID = f.req
	}
	f.effective = append(f.effective, p)
	f.op, f.req = p.OpID, p.ReqID
	return nil
}

func (f *correlationManager) SetPorts(_ context.Context, _ string, _ []policy.Port) error {
	return nil
}

func (f *correlationManager) Stop(_ context.Context, _ string) error { return nil }

func correlationCtx(op, req string) context.Context {
	ctx := context.Background()
	if op != "" {
		ctx = ids.WithOpID(ctx, op)
	}
	if req != "" {
		ctx = ids.WithReqID(ctx, req)
	}
	return ctx
}

func TestAdapterForwardsValidCorrelation(t *testing.T) {
	op, req := ids.NewOpID(), ids.NewReqID()
	manager := &correlationManager{}
	adapter := New(manager, t.TempDir())

	if _, err := adapter.Start(correlationCtx(op, req), "dev", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(manager.started) != 1 || manager.started[0].OpID != op || manager.started[0].ReqID != req {
		t.Fatalf("start policy = %+v, want op=%s req=%s", manager.started, op, req)
	}

	if err := adapter.UpdatePolicy(correlationCtx(op, req), "dev", nil, nil, nil, 2); err != nil {
		t.Fatal(err)
	}
	if len(manager.reloaded) != 1 || manager.reloaded[0].OpID != op || manager.reloaded[0].ReqID != req {
		t.Fatalf("reload policy = %+v, want op=%s req=%s", manager.reloaded, op, req)
	}
}

func TestAdapterOmitsInvalidCorrelation(t *testing.T) {
	manager := &correlationManager{}
	adapter := New(manager, t.TempDir())
	// Malformed ids must never be forwarded or fabricated.
	ctx := correlationCtx("op_!!!", "req_!")

	if _, err := adapter.Start(ctx, "dev", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if manager.started[0].OpID != "" || manager.started[0].ReqID != "" {
		t.Fatalf("invalid correlation must be omitted, got %+v", manager.started[0])
	}
	if err := adapter.UpdatePolicy(ctx, "dev", nil, nil, nil, 2); err != nil {
		t.Fatal(err)
	}
	if manager.reloaded[0].OpID != "" || manager.reloaded[0].ReqID != "" {
		t.Fatalf("invalid correlation must be omitted, got %+v", manager.reloaded[0])
	}
}

func TestAdapterOmitsPartiallyInvalidCorrelation(t *testing.T) {
	manager := &correlationManager{}
	adapter := New(manager, t.TempDir())
	// A valid op id is forwarded while the malformed req id is dropped.
	op := ids.NewOpID()
	ctx := correlationCtx(op, "req_!")

	if err := adapter.UpdatePolicy(ctx, "dev", nil, nil, nil, 2); err != nil {
		t.Fatal(err)
	}
	if got := manager.reloaded[0]; got.OpID != op || got.ReqID != "" {
		t.Fatalf("reload policy = %+v, want op=%s req=\"\"", got, op)
	}
}

func TestAdapterOmitsAbsentCorrelation(t *testing.T) {
	manager := &correlationManager{}
	adapter := New(manager, t.TempDir())

	if _, err := adapter.Start(context.Background(), "dev", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if manager.started[0].OpID != "" || manager.started[0].ReqID != "" {
		t.Fatalf("absent correlation must be empty, got %+v", manager.started[0])
	}
	if err := adapter.UpdatePolicy(context.Background(), "dev", nil, nil, nil, 2); err != nil {
		t.Fatal(err)
	}
	if manager.reloaded[0].OpID != "" || manager.reloaded[0].ReqID != "" {
		t.Fatalf("absent correlation must be empty, got %+v", manager.reloaded[0])
	}
}

func TestAdapterCorrelationPreservedAcrossSequentialUpdates(t *testing.T) {
	op1, req1 := ids.NewOpID(), ids.NewReqID()
	op2, req2 := ids.NewOpID(), ids.NewReqID()
	manager := &correlationManager{}
	adapter := New(manager, t.TempDir())

	if err := adapter.UpdatePolicy(correlationCtx(op1, req1), "dev", nil, nil, nil, 2); err != nil {
		t.Fatal(err)
	}
	if err := adapter.UpdatePolicy(correlationCtx(op2, req2), "dev", nil, nil, nil, 3); err != nil {
		t.Fatal(err)
	}
	// A revision pushed without ids (e.g. internal reconciliation) must leave
	// the forwarded fields empty, and the handle falls back to the last-known
	// ids rather than fabricating new ones.
	if err := adapter.UpdatePolicy(context.Background(), "dev", nil, nil, nil, 4); err != nil {
		t.Fatal(err)
	}

	if got := manager.reloaded[0]; got.OpID != op1 || got.ReqID != req1 {
		t.Fatalf("first reload = %+v, want op=%s req=%s", got, op1, req1)
	}
	if got := manager.reloaded[1]; got.OpID != op2 || got.ReqID != req2 {
		t.Fatalf("second reload = %+v, want op=%s req=%s", got, op2, req2)
	}
	if got := manager.reloaded[2]; got.OpID != "" || got.ReqID != "" {
		t.Fatalf("third reload must forward empty ids, got %+v", got)
	}
	if got := manager.effective[2]; got.OpID != op2 || got.ReqID != req2 {
		t.Fatalf("third reload fallback = %+v, want op=%s req=%s", got, op2, req2)
	}
}
