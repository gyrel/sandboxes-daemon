package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"

	"github.com/rheic/sandboxes-daemon/internal/mcpmanager"
	"github.com/rheic/sandboxes-daemon/internal/oauthsession"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
)

// MCPInspectDetail is the daemon-side view returned by InspectMCPServer.
type MCPInspectDetail struct {
	Name                string
	SandboxID           string
	IdentityDisplayName string
	IdentityKind        string
	IdentityIssuerHost  string
	ToolsCount          uint32
	LastSyncAtUnix      int64
	AuthStatus          localv1.MCPAuthStatus
	GatewayState        localv1.MCPGatewayState
}

func (s *Service) mcpRegistry(ctx context.Context) (*mcpmanager.Manager, error) {
	s.mcpMu.Lock()
	defer s.mcpMu.Unlock()
	if s.mcpManager != nil {
		return s.mcpManager, nil
	}
	manager, err := mcpmanager.New(ctx, s.store)
	if err != nil {
		return nil, err
	}
	manager.SetRemoteAllowlist(s.mcpRemoteHosts)
	manager.SetApprovalProvider(s.mcpApprover)
	manager.SetApprovalStore(s.approvals)
	manager.SetRemoteSecretResolver(func(ctx context.Context, serverName, placeholder string) ([]byte, error) {
		if s.serviceSecrets == nil {
			return nil, servicesecrets.ErrNotFound
		}
		return s.serviceSecrets.Resolve(ctx, "mcp:"+serverName+":"+placeholder, servicesecrets.ScopeGlobal, "")
	})
	s.mcpManager = manager
	return manager, nil
}

// InitializeMCPRegistry loads the persisted MCP registry, applies the forward
// schema migration, and scrubs legacy static headers from pre-upgrade database
// backups before the daemon accepts RPCs. A failure aborts startup instead of
// serving or retaining un-migrated legacy headers.
func (s *Service) InitializeMCPRegistry(ctx context.Context) error {
	if _, err := s.mcpRegistry(ctx); err != nil {
		return err
	}
	return s.store.SanitizeBackupSetting(ctx, mcpmanager.RegistrySettingKey, mcpmanager.SanitizeRegistrySetting)
}

// SetMCPRemoteAllowlist installs the explicit host administrator policy used
// by remote MCP. An empty list keeps remote registration disabled.
func (s *Service) SetMCPRemoteAllowlist(hosts []string) {
	s.mcpMu.Lock()
	defer s.mcpMu.Unlock()
	s.mcpRemoteHosts = append([]string(nil), hosts...)
	if s.mcpManager != nil {
		s.mcpManager.SetRemoteAllowlist(hosts)
	}
}

// SetMCPApprovalProvider installs a trusted host-side consent mechanism.
// Production must configure an OS-backed provider before enabling host MCP
// execution; there is deliberately no RPC/CLI boolean fallback.
func (s *Service) SetMCPApprovalProvider(provider mcpmanager.ApprovalProvider) {
	s.mcpMu.Lock()
	defer s.mcpMu.Unlock()
	s.mcpApprover = provider
	if s.mcpManager != nil {
		s.mcpManager.SetApprovalProvider(provider)
	}
}

// Close releases daemon-owned host MCP processes before state storage closes.
func (s *Service) Close() error {
	s.mcpMu.Lock()
	manager := s.mcpManager
	s.mcpMu.Unlock()
	if manager == nil {
		return nil
	}
	return manager.Close()
}

func (s *Service) ListMCPServers(ctx context.Context, sandboxID string) ([]mcpmanager.Summary, error) {
	if sandboxID != "" {
		if _, err := s.store.Get(ctx, sandboxID); err != nil {
			return nil, err
		}
	}
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return nil, err
	}
	return manager.List(), nil
}
func (s *Service) RegisterMCPServer(ctx context.Context, name, command string, args []string, directory string, opts ...mcpmanager.RegistrationOptions) (string, error) {
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return "", err
	}
	return manager.Register(ctx, name, command, args, directory, opts...)
}

// RegisterRemoteMCPServer queues a remote (streamable HTTP) MCP server. The
// URL must satisfy the daemon's fail-closed host allowlist.
func (s *Service) RegisterRemoteMCPServer(ctx context.Context, name, rawURL string, headers, secretHeaders map[string]string, opts ...mcpmanager.RegistrationOptions) (string, error) {
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return "", err
	}
	return manager.RegisterRemote(ctx, name, rawURL, headers, secretHeaders, opts...)
}
func (s *Service) ApproveMCPRegistration(ctx context.Context, id string) (*mcpmanager.Summary, error) {
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return nil, err
	}
	return manager.ApproveRegistration(ctx, id)
}
func (s *Service) RemoveMCPServer(ctx context.Context, name string) (bool, error) {
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return false, err
	}
	return manager.Remove(ctx, name)
}
func (s *Service) RequestMCPCall(ctx context.Context, sandboxID, server, tool string, args string) (string, error) {
	sb, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		return "", err
	}
	if sb.State != sandbox.Running {
		return "", core.ErrConflict
	}
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return "", err
	}
	return manager.RequestCall(sandboxID, server, tool, json.RawMessage(args))
}
func (s *Service) ApproveMCPCall(ctx context.Context, id string) (json.RawMessage, error) {
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return nil, err
	}
	return manager.ApproveCall(ctx, id, func(ctx context.Context, sandboxID string) error {
		sb, err := s.store.Get(ctx, sandboxID)
		if err != nil {
			return err
		}
		if sb.State != sandbox.Running {
			return core.ErrConflict
		}
		return nil
	})
}

func (s *Service) LoadMCPServer(ctx context.Context, name, sandboxID string) (bool, error) {
	if name == "" || sandboxID == "" {
		return false, fmt.Errorf("%w: MCP server name and sandbox ID are required", errors.New("invalid argument"))
	}
	if _, err := s.store.Get(ctx, sandboxID); err != nil {
		return false, err
	}
	sb, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		return false, err
	}
	if sb.State != sandbox.Running {
		return false, core.ErrConflict
	}
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return false, err
	}
	return manager.Load(ctx, name, sandboxID)
}

func (s *Service) UnloadMCPServer(ctx context.Context, name, sandboxID string) (bool, error) {
	if name == "" || sandboxID == "" {
		return false, fmt.Errorf("%w: MCP server name and sandbox ID are required", errors.New("invalid argument"))
	}
	if _, err := s.store.Get(ctx, sandboxID); err != nil {
		return false, err
	}
	sb, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		return false, err
	}
	if sb.State != sandbox.Running {
		return false, core.ErrConflict
	}
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return false, err
	}
	return manager.Unload(ctx, name, sandboxID)
}

func (s *Service) InspectMCPServer(ctx context.Context, name, sandboxID string) (MCPInspectDetail, error) {
	if name == "" {
		return MCPInspectDetail{}, fmt.Errorf("%w: MCP server name is required", errors.New("invalid argument"))
	}
	if sandboxID != "" {
		if _, err := s.store.Get(ctx, sandboxID); err != nil {
			return MCPInspectDetail{}, err
		}
	}
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return MCPInspectDetail{}, err
	}
	server, loaded, err := manager.Inspect(name, sandboxID)
	if err != nil {
		return MCPInspectDetail{}, err
	}
	issuerHost := ""
	if server.OAuthAuthorizationServer != "" {
		if parsed, err := url.Parse(server.OAuthAuthorizationServer); err == nil && parsed.Host != "" {
			issuerHost = parsed.Hostname()
		}
	}
	if issuerHost == "" && server.URL != "" {
		if parsed, err := url.Parse(server.URL); err == nil {
			issuerHost = parsed.Hostname()
		}
	}
	gatewayState := localv1.MCPGatewayState_MCP_GATEWAY_STATE_UNLOADED
	if loaded {
		gatewayState = localv1.MCPGatewayState_MCP_GATEWAY_STATE_LOADED
	}
	return MCPInspectDetail{
		Name:                server.Name,
		SandboxID:           sandboxID,
		IdentityDisplayName: server.Name,
		IdentityKind:        server.Transport,
		IdentityIssuerHost:  issuerHost,
		ToolsCount:          0,
		LastSyncAtUnix:      0,
		AuthStatus:          s.mcpAuthStatusForServer(ctx, server),
		GatewayState:        gatewayState,
	}, nil
}

func isMCPAuthBearing(server mcpmanager.Server) bool {
	return server.Transport == "remote"
}

func (s *Service) mcpAuthStatusForServer(ctx context.Context, server mcpmanager.Server) localv1.MCPAuthStatus {
	if !isMCPAuthBearing(server) {
		return localv1.MCPAuthStatus_MCP_AUTH_STATUS_NOT_CONFIGURED
	}
	vault := s.oauthVault()
	sink, err := oauthsession.NewVaultSink(vault, server.Name)
	if err != nil {
		return localv1.MCPAuthStatus_MCP_AUTH_STATUS_ERROR
	}
	has, err := sink.HasTokens(ctx)
	if err != nil {
		return localv1.MCPAuthStatus_MCP_AUTH_STATUS_ERROR
	}
	if !has {
		return localv1.MCPAuthStatus_MCP_AUTH_STATUS_NOT_CONFIGURED
	}
	_, expiresAt, err := sink.Load(ctx)
	if err != nil {
		return localv1.MCPAuthStatus_MCP_AUTH_STATUS_ERROR
	}
	if !expiresAt.IsZero() && time.Now().UTC().After(expiresAt) {
		return localv1.MCPAuthStatus_MCP_AUTH_STATUS_EXPIRED
	}
	return localv1.MCPAuthStatus_MCP_AUTH_STATUS_READY
}

func (s *Service) GetMCPAuthStatus(ctx context.Context, name string, all bool) (localv1.MCPAuthStatus, []localv1.MCPServerAuthStatus, error) {
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return localv1.MCPAuthStatus_MCP_AUTH_STATUS_UNSPECIFIED, nil, err
	}
	if all {
		entries := make([]localv1.MCPServerAuthStatus, 0)
		for _, server := range manager.AllServers() { //nolint:gocritic
			if !isMCPAuthBearing(server) {
				continue
			}
			entries = append(entries, localv1.MCPServerAuthStatus{
				Name:   server.Name,
				Status: s.mcpAuthStatusForServer(ctx, server),
			})
		}
		return localv1.MCPAuthStatus_MCP_AUTH_STATUS_UNSPECIFIED, entries, nil
	}
	if name == "" {
		return localv1.MCPAuthStatus_MCP_AUTH_STATUS_UNSPECIFIED, nil, fmt.Errorf("%w: MCP server name is required", errors.New("invalid argument"))
	}
	server, ok := manager.GetServer(name)
	if !ok {
		return localv1.MCPAuthStatus_MCP_AUTH_STATUS_UNSPECIFIED, nil, core.ErrNotFound
	}
	if !isMCPAuthBearing(server) {
		return localv1.MCPAuthStatus_MCP_AUTH_STATUS_NOT_CONFIGURED, nil, nil
	}
	return s.mcpAuthStatusForServer(ctx, server), nil, nil
}

func (s *Service) RemoveMCPAuth(ctx context.Context, name string) (bool, error) {
	if name == "" {
		return false, fmt.Errorf("%w: MCP server name is required", errors.New("invalid argument"))
	}
	removed := false
	vault := s.oauthVault()
	sink, err := oauthsession.NewVaultSink(vault, name)
	if err == nil {
		has, herr := sink.HasTokens(ctx)
		if herr == nil && has {
			if derr := sink.Delete(ctx); derr == nil {
				removed = true
			}
		}
	}
	if manager, merr := s.mcpRegistry(ctx); merr == nil {
		manager.DropSession(name)
	}
	return removed, nil
}

func (s *Service) StartMCPAuth(ctx context.Context, name, sandboxID string, scopes []string, noScope, all bool) (bool, string, error) {
	if !all && name == "" {
		return false, "", fmt.Errorf("%w: MCP server name is required", errors.New("invalid argument"))
	}
	if name != "" {
		manager, err := s.mcpRegistry(ctx)
		if err != nil {
			return false, "", err
		}
		if _, ok := manager.GetServer(name); !ok {
			return false, "", core.ErrNotFound
		}
	}
	return false, "", fmt.Errorf("%w: interactive MCP OAuth discovery and DCR flow is not implemented in this daemon", core.ErrConflict)
}
