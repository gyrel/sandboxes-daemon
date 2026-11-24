package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rheic/sandboxes-daemon/internal/oauthsession"
	"github.com/rheic/sandboxes-daemon/internal/registrycredentials"
	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

type memoryOAuthVault struct {
	values map[string]string
}

func (v *memoryOAuthVault) Set(_ context.Context, service, account, secret string) error {
	v.values[service+"/"+account] = secret
	return nil
}
func (v *memoryOAuthVault) Get(_ context.Context, service, account string) (string, error) {
	value, ok := v.values[service+"/"+account]
	if !ok {
		return "", registrycredentials.ErrNotFound
	}
	return value, nil
}
func (v *memoryOAuthVault) Delete(_ context.Context, service, account string) error {
	key := service + "/" + account
	if _, ok := v.values[key]; !ok {
		return registrycredentials.ErrNotFound
	}
	delete(v.values, key)
	return nil
}

func TestMCPAuthStatusAndRemoveRPCs(t *testing.T) {
	ctx := context.Background()
	vault := &memoryOAuthVault{values: make(map[string]string)}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "mcp-auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := service.New(st, nil)
	svc.SetOAuthVault(vault)
	server := NewSandbox(svc)
	server.svc.SetMCPApprovalProvider(mcpTestApprovalProvider{})
	server.svc.SetMCPRemoteAllowlist([]string{"mcp.example.test"})

	// register remote server via RPC
	pending, err := server.MCPRegisterServer(ctx, &localv1.MCPRegisterServerRequest{Name: "remote", Url: "https://mcp.example.test/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.MCPApproveRegistration(ctx, &localv1.MCPApproveRegistrationRequest{ApprovalId: pending.GetApprovalId()}); err != nil {
		t.Fatal(err)
	}

	// not configured
	stt, err := server.GetMCPAuthStatus(ctx, &localv1.GetMCPAuthStatusRequest{Name: "remote"})
	if err != nil || stt.GetStatus() != localv1.MCPAuthStatus_MCP_AUTH_STATUS_NOT_CONFIGURED {
		t.Fatalf("status=%v err=%v", stt.GetStatus(), err)
	}

	// all
	all, err := server.GetMCPAuthStatus(ctx, &localv1.GetMCPAuthStatusRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.GetEntries()) != 1 {
		t.Fatalf("entries=%d", len(all.GetEntries()))
	}

	// expired mapping
	sink, err := oauthsession.NewVaultSink(vault, "remote")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Save(ctx, oauthsession.Tokens{AccessToken: "a", TokenType: "Bearer", ExpiresIn: 1}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	stt2, err := server.GetMCPAuthStatus(ctx, &localv1.GetMCPAuthStatusRequest{Name: "remote"})
	if err != nil || stt2.GetStatus() != localv1.MCPAuthStatus_MCP_AUTH_STATUS_EXPIRED {
		t.Fatalf("status=%v err=%v", stt2.GetStatus(), err)
	}

	// remove auth
	removed, err := server.RemoveMCPAuth(ctx, &localv1.RemoveMCPAuthRequest{Name: "remote"})
	if err != nil || !removed.GetRemoved() {
		t.Fatalf("removed=%+v err=%v", removed, err)
	}
	removed2, err := server.RemoveMCPAuth(ctx, &localv1.RemoveMCPAuthRequest{Name: "remote"})
	if err != nil || removed2.GetRemoved() {
		t.Fatalf("removed2=%+v err=%v", removed2, err)
	}

	// unknown server status
	if _, err := server.GetMCPAuthStatus(ctx, &localv1.GetMCPAuthStatusRequest{Name: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown status code=%s", status.Code(err))
	}
}

func TestStartMCPAuthNoFabrication(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "mcp-start.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	server := NewSandbox(service.New(st, nil))
	server.svc.SetMCPApprovalProvider(mcpTestApprovalProvider{})
	server.svc.SetMCPRemoteAllowlist([]string{"mcp.example.test"})
	pending, err := server.MCPRegisterServer(ctx, &localv1.MCPRegisterServerRequest{Name: "remote", Url: "https://mcp.example.test/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.MCPApproveRegistration(ctx, &localv1.MCPApproveRegistrationRequest{ApprovalId: pending.GetApprovalId()}); err != nil {
		t.Fatal(err)
	}
	resp, err := server.StartMCPAuth(ctx, &localv1.StartMCPAuthRequest{Name: "remote"})
	// expect FAILED_PRECONDITION
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code=%s resp=%+v err=%v", status.Code(err), resp, err)
	}
	// unknown server -> NotFound
	if _, err := server.StartMCPAuth(ctx, &localv1.StartMCPAuthRequest{Name: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown code=%s", status.Code(err))
	}
}
