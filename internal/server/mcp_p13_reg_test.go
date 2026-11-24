package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

func TestMCPRegistrationOAuthValidation(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "mcp-reg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	server := NewSandbox(service.New(st, nil))
	server.svc.SetMCPApprovalProvider(mcpTestApprovalProvider{})
	server.svc.SetMCPRemoteAllowlist([]string{"mcp.example.test"})
	command, _ := os.Executable()

	cases := []struct {
		name string
		req  *localv1.MCPRegisterServerRequest
		code codes.Code
	}{
		{"userinfo", &localv1.MCPRegisterServerRequest{Name: "a", Url: "https://mcp.example.test/mcp", OauthAuthorizationServer: "https://user:pass@example.test/auth"}, codes.InvalidArgument},
		{"query", &localv1.MCPRegisterServerRequest{Name: "b", Url: "https://mcp.example.test/mcp", OauthAuthorizationServer: "https://example.test/auth?x=1"}, codes.InvalidArgument},
		{"scopes+no_scope", &localv1.MCPRegisterServerRequest{Name: "c", Url: "https://mcp.example.test/mcp", Scopes: []string{"read"}, NoScope: true}, codes.InvalidArgument},
		{"port", &localv1.MCPRegisterServerRequest{Name: "d", Url: "https://mcp.example.test/mcp", CallbackPort: 70000}, codes.InvalidArgument},
		{"resource fragment", &localv1.MCPRegisterServerRequest{Name: "e", Url: "https://mcp.example.test/mcp", Resource: "https://example.test/res#frag"}, codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := server.MCPRegisterServer(ctx, tc.req)
			if status.Code(err) != tc.code {
				t.Fatalf("code=%s want=%s err=%v", status.Code(err), tc.code, err)
			}
		})
	}

	// valid remote registration stores and approves
	pending, err := server.MCPRegisterServer(ctx, &localv1.MCPRegisterServerRequest{
		Name:                     "ok",
		Url:                      "https://mcp.example.test/mcp",
		OauthAuthorizationServer: "https://example.test/auth",
		ClientId:                 "client",
		Resource:                 "https://example.test/res",
		Scopes:                   []string{"read"},
		CallbackPort:             8080,
		DisableHttp2:             true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.MCPApproveRegistration(ctx, &localv1.MCPApproveRegistrationRequest{ApprovalId: pending.GetApprovalId()}); err != nil {
		t.Fatal(err)
	}
	// inspect issuer host from oauth auth server
	insp, err := server.InspectMCPServer(ctx, &localv1.InspectMCPServerRequest{Name: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if insp.GetServer().GetIdentityIssuerHost() != "example.test" {
		t.Fatalf("issuer host=%s", insp.GetServer().GetIdentityIssuerHost())
	}

	// stdio registration with command works (unused opts)
	pending2, err := server.MCPRegisterServer(ctx, &localv1.MCPRegisterServerRequest{Name: "stdio", Command: command, WorkingDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.MCPApproveRegistration(ctx, &localv1.MCPApproveRegistrationRequest{ApprovalId: pending2.GetApprovalId()}); err != nil {
		t.Fatal(err)
	}
}
