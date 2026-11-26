package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"github.com/gyrel/sandboxes-core/sandbox"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gyrel/sandboxes-daemon/internal/service"
	"github.com/gyrel/sandboxes-daemon/internal/store"
)

func TestMCPLoadInspectUnloadRPCs(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "mcp-p13.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Unix(100, 0).UTC()
	sb := sandbox.Sandbox{ID: "sb-1", Name: "dev", State: sandbox.Running, CreatedAt: now, UpdatedAt: now}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	server := NewSandbox(service.New(st, nil))
	server.svc.SetMCPApprovalProvider(mcpTestApprovalProvider{})
	command, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := server.MCPRegisterServer(ctx, &localv1.MCPRegisterServerRequest{Name: "fixture", Command: command, WorkingDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.MCPApproveRegistration(ctx, &localv1.MCPApproveRegistrationRequest{ApprovalId: pending.GetApprovalId()}); err != nil {
		t.Fatal(err)
	}

	if _, err := server.MCPLoadServer(ctx, &localv1.MCPLoadServerRequest{Name: "nope", SandboxId: "sb-1"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown server status=%s", status.Code(err))
	}
	if _, err := server.MCPLoadServer(ctx, &localv1.MCPLoadServerRequest{Name: "fixture", SandboxId: "sb-nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown sandbox status=%s", status.Code(err))
	}
	loaded, err := server.MCPLoadServer(ctx, &localv1.MCPLoadServerRequest{Name: "fixture", SandboxId: "sb-1"})
	if err != nil || !loaded.GetLoaded() {
		t.Fatalf("load=%+v err=%v", loaded, err)
	}
	loaded2, err := server.MCPLoadServer(ctx, &localv1.MCPLoadServerRequest{Name: "fixture", SandboxId: "sb-1"})
	if err != nil || !loaded2.GetLoaded() {
		t.Fatalf("idempotent load=%+v err=%v", loaded2, err)
	}
	insp, err := server.InspectMCPServer(ctx, &localv1.InspectMCPServerRequest{Name: "fixture", SandboxId: "sb-1"})
	if err != nil {
		t.Fatal(err)
	}
	if insp.GetServer().GetGatewayState() != localv1.MCPGatewayState_MCP_GATEWAY_STATE_LOADED {
		t.Fatalf("gateway state=%v", insp.GetServer().GetGatewayState())
	}
	unloaded, err := server.MCPUnloadServer(ctx, &localv1.MCPUnloadServerRequest{Name: "fixture", SandboxId: "sb-1"})
	if err != nil || !unloaded.GetUnloaded() {
		t.Fatalf("unload=%+v err=%v", unloaded, err)
	}
	unloaded2, err := server.MCPUnloadServer(ctx, &localv1.MCPUnloadServerRequest{Name: "fixture", SandboxId: "sb-1"})
	if err != nil || !unloaded2.GetUnloaded() {
		t.Fatalf("nonloaded unload=%+v err=%v", unloaded2, err)
	}
	insp2, err := server.InspectMCPServer(ctx, &localv1.InspectMCPServerRequest{Name: "fixture", SandboxId: "sb-1"})
	if err != nil {
		t.Fatal(err)
	}
	if insp2.GetServer().GetGatewayState() != localv1.MCPGatewayState_MCP_GATEWAY_STATE_UNLOADED {
		t.Fatalf("gateway state=%v", insp2.GetServer().GetGatewayState())
	}
}
