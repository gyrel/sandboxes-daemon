// Package daemon contains the local control plane.
package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	goruntime "runtime"
	"time"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	runtime "github.com/gyrel/sandboxes-runtime"
	"github.com/gyrel/slogx/events"
	"google.golang.org/grpc"

	"github.com/gyrel/sandboxes-daemon/internal/customsecrets"
	"github.com/gyrel/sandboxes-daemon/internal/lifecycle"
	"github.com/gyrel/sandboxes-daemon/internal/oauthsession"
	"github.com/gyrel/sandboxes-daemon/internal/obslog"
	"github.com/gyrel/sandboxes-daemon/internal/registrycredentials"
	"github.com/gyrel/sandboxes-daemon/internal/secretproxy"
	"github.com/gyrel/sandboxes-daemon/internal/server"
	"github.com/gyrel/sandboxes-daemon/internal/service"
	"github.com/gyrel/sandboxes-daemon/internal/servicesecrets"
	"github.com/gyrel/sandboxes-daemon/internal/store"
	"github.com/gyrel/sandboxes-daemon/internal/version"
)

// Config is the daemon configuration.
type Config struct {
	SocketPath          string
	RuntimeBundleDigest string
	ShutdownSignal      func() string
	StateDir            string
	Backend             runtime.Backend
	DefaultImage        string
	// IPv6Enabled accepts IPv6 CIDR rules only when the gateway datapath was
	// configured with the experimental IPv6 capability. It defaults to false.
	IPv6Enabled bool
	// QUICEnabled accepts UDP domain rules only when the gateway datapath was
	// configured with the experimental QUIC capability. It defaults to false.
	QUICEnabled    bool
	Cleanup        func() error
	OAuthProviders map[string]service.OAuthProvider
	OAuthVault     oauthsession.Vault
	// Settings are optional host-side overrides loaded before the daemon starts.
	DNSUpstream          string
	DefaultPolicyProfile string
	DefaultCPUs          uint32
	DefaultMemoryMiB     uint32
	DockerVolumeSize     string
	// OrgPolicyEnforce applies the stored organization policy bundle. It is off
	// by default and fails closed when no usable bundle exists.
	OrgPolicyEnforce bool
	OrgPolicyOrg     string
	// Kit policy settings.
	KitAllowedSources     []string
	KitAllowLocalKits     bool
	KitRequireSignature   bool
	MCPRemoteAllowedHosts []string
	// RegistryPrivate configures one allowlisted private registry reached
	// through the guest registry proxy (ADR-0006).
	RegistryDockerGrants     []string
	RegistryPrivateGrants    []string
	RegistryPrivateHost      string
	RegistryPrivateService   string
	RegistryPrivateRealms    []string
	RegistryPrivateRedirects []string
	RegistryPrivateCA        []byte
	// GatewayLost reports sandboxes whose gateway exited unexpectedly.
	GatewayLost      <-chan string
	ProxyHelperPath  string
	SkillsHelperPath string
	SkillsStorePath  string
	// PolicySync, when non-nil, enables the opt-in background policy sync. The
	// runner performs one attempt at startup and then a jittered periodic
	// attempt until the daemon context is canceled.
	PolicySync *PolicySyncConfig
	// Log rotation caps the daemon's own file sink ($STATE/daemon.log). Zero
	// values select the documented defaults (8 MiB per file, 5 files, 64 MiB).
	LogMaxSizeMiB  uint64
	LogMaxFiles    int
	LogTotalCapMiB uint64
}

// configureService applies host configuration, wires credential storage and
// starts the gateway-loss watcher.
func configureService(ctx context.Context, cfg *Config, svc *service.Service) (func() error, error) {
	applyConfig(svc, *cfg)
	if err := svc.SetRegistryRepositoryGrants(cfg.RegistryDockerGrants, cfg.RegistryPrivateGrants); err != nil {
		return nil, fmt.Errorf("configure registry repository grants: %w", err)
	}
	svc.SetSecretProxyRuntime(cfg.ProxyHelperPath, "/tmp")
	credentialCleanup, err := configureCredentialStores(svc)
	if err != nil {
		return nil, err
	}
	if cfg.RegistryPrivateHost != "" {
		if err := svc.SetPrivateRegistry(cfg.RegistryPrivateHost, cfg.RegistryPrivateService, cfg.RegistryPrivateRealms, cfg.RegistryPrivateRedirects, cfg.RegistryPrivateCA); err != nil {
			return nil, err
		}
	}
	if cfg.DefaultImage != "" {
		svc.DefaultImage = cfg.DefaultImage
	}
	configureDockerVolume(svc, cfg.StateDir)
	if cfg.GatewayLost != nil {
		go recoverLostGateways(ctx, svc, cfg.GatewayLost)
	}
	return credentialCleanup, nil
}

// recoverLostGateways stops sandboxes whose gateway exited: the guest packet
// socket points at the dead process, so the sandbox cannot reach the network
// until it is started again.
func recoverLostGateways(ctx context.Context, svc *service.Service, gatewayEvents <-chan string) {
	for {
		select {
		case <-ctx.Done():
			return
		case name := <-gatewayEvents:
			stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			err := svc.StopSandboxByName(stopCtx, name)
			cancel()
			if err != nil {
				slog.Error("stop sandbox after gateway loss", "sandbox", name, "error", err)
				continue
			}
			slog.Warn("sandbox stopped after gateway loss", "sandbox", name)
		}
	}
}

// Run starts the daemon and blocks until ctx is canceled.
//
//nolint:gocritic,gocyclo,cyclop,funlen,gocognit // Config is constructed once at the process boundary; startup is one linear sequence.
func Run(ctx context.Context, cfg Config) (runErr error) {
	started := time.Now()
	if cfg.SocketPath == "" || cfg.StateDir == "" {
		return fmt.Errorf("socket path and state dir are required")
	}
	sum := sha256.Sum256([]byte(cfg.SocketPath))
	kind := events.DaemonStartListenKindUnix
	if goruntime.GOOS == "windows" {
		kind = events.DaemonStartListenKindPipe
	}
	start, eventErr := events.DaemonStart(events.OutcomeOK, events.DaemonStartParams{ListenKind: kind, SocketPathHash: events.Hash(hex.EncodeToString(sum[:12])), UID: effectiveUID(), RuntimeBundleDigest: events.Hash(cfg.RuntimeBundleDigest), ManagedVerify: events.DaemonStartManagedVerifyOk})
	if eventErr == nil {
		start.Emit(ctx, slog.Default(), events.Standard{})
	}
	if err := prepareDaemonStateDirectory(cfg.StateDir); err != nil {
		return fmt.Errorf("prepare state dir: %w", err)
	}
	lock, err := lockStateDirectory(cfg.StateDir)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	defer func() { runErr = errors.Join(runErr, runCleanup(cfg.Cleanup)) }()

	sink, err := obslog.Install(ctx, obslog.Config{
		StateDir:    cfg.StateDir,
		MaxSizeMiB:  cfg.LogMaxSizeMiB,
		MaxFiles:    cfg.LogMaxFiles,
		TotalCapMiB: cfg.LogTotalCapMiB,
	})
	if err != nil {
		return fmt.Errorf("open log sink: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, sink.Close()) }()

	st, err := store.Open(ctx, filepath.Join(cfg.StateDir, "sandboxes.db"))
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	svc := service.New(st, cfg.Backend)
	defer func() { runErr = errors.Join(runErr, svc.Close()) }()
	credentialCleanup, err := configureService(ctx, &cfg, svc)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, credentialCleanup()) }()
	if err := svc.InitializeMCPRegistry(ctx); err != nil {
		return fmt.Errorf("initialize MCP registry: %w", err)
	}
	changed, err := svc.Reconcile(ctx)
	if err != nil {
		return fmt.Errorf("reconcile: %w", err)
	}
	if changed > 0 {
		slog.Info("reconciled interrupted state", "records", changed)
	}
	_, err = svc.RecoverRuntimeJournal(ctx)
	if err != nil {
		// Systemic recovery failure must not brick the daemon, but it is
		// loud: journals remain for the next start and operators see why.
		slog.Error("runtime journal recovery incomplete", "error", err)
	}
	var policySync *policySyncRunner
	if err := configurePolicySync(&cfg, st, &policySync); err != nil {
		return err
	}
	lis, err := listenDaemon(ctx, cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen local daemon endpoint: %w", err)
	}
	registration, err := lifecycle.Register(cfg.StateDir, cfg.SocketPath, version.Version)
	if err != nil {
		_ = lis.Close()
		return fmt.Errorf("register daemon lifecycle: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, registration.Close()) }()
	if policySync != nil {
		defer startPolicySync(ctx, policySync)()
	}

	// The MCP contract caps JSON results at 4 MiB. Allow bounded protobuf
	// framing overhead while keeping all daemon responses size-limited.
	grpcServer := grpc.NewServer(grpc.MaxSendMsgSize(5<<20), grpc.UnaryInterceptor(server.UnaryCorrelationInterceptor), grpc.StreamInterceptor(server.StreamCorrelationInterceptor))
	defer grpcServer.Stop()
	registerLocalServices(grpcServer, svc)

	runDone := make(chan struct{})
	defer close(runDone)
	go stopGRPCOnCancel(ctx, runDone, grpcServer)

	ready, eventErr := events.DaemonReady(events.OutcomeOK, events.DaemonReadyParams{StartupMs: uint64(max(0, time.Since(started).Milliseconds())), RecoveredCount: uint64(max(0, changed))})
	if eventErr == nil {
		ready.Emit(ctx, slog.Default(), events.Standard{})
	}
	defer func() {
		signal := ""
		if cfg.ShutdownSignal != nil {
			signal = cfg.ShutdownSignal()
		}
		event, err := events.DaemonShutdown(events.OutcomeOK, events.DaemonShutdownParams{Signal: events.ID(signal), FlushOk: sink.Flush() == nil})
		if err == nil {
			event.Emit(context.WithoutCancel(ctx), slog.Default(), events.Standard{})
		}
	}()
	slog.Info("daemon listening", "socket", cfg.SocketPath, "state", cfg.StateDir)
	if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func configurePolicySync(cfg *Config, st *store.Store, target **policySyncRunner) error {
	if cfg.PolicySync == nil {
		return nil
	}
	runner, err := newPolicySyncRunner(*cfg.PolicySync, st)
	if err != nil {
		return fmt.Errorf("configure policy sync: %w", err)
	}
	*target = runner
	return nil
}

//nolint:gocritic // Config is a value object assembled by the caller.
func applyConfig(svc *service.Service, cfg Config) {
	if cfg.DefaultCPUs != 0 {
		svc.DefaultCPUs = cfg.DefaultCPUs
	}
	if cfg.DefaultMemoryMiB != 0 {
		svc.DefaultMemoryMiB = cfg.DefaultMemoryMiB
	}
	svc.DefaultPolicyProfile = cfg.DefaultPolicyProfile
	svc.IPv6Enabled = cfg.IPv6Enabled
	svc.QUICEnabled = cfg.QUICEnabled
	svc.OrgPolicyEnforce = cfg.OrgPolicyEnforce
	svc.OrgPolicyOrg = cfg.OrgPolicyOrg
	svc.KitAllowedSources = cfg.KitAllowedSources
	svc.KitAllowLocalKits = cfg.KitAllowLocalKits
	svc.KitRequireSignature = cfg.KitRequireSignature
	svc.SetMCPRemoteAllowlist(cfg.MCPRemoteAllowedHosts)
	if cfg.DockerVolumeSize != "" {
		svc.DockerVolumeSize = cfg.DockerVolumeSize
	}
	svc.SetSkillsRuntime(cfg.SkillsHelperPath, cfg.SkillsStorePath)
	configureOAuth(svc, cfg)
}

func configureCredentialStores(svc *service.Service) (func() error, error) {
	registryCredentialStore, err := registrycredentials.NewStore(registrycredentials.NativeVault{})
	if err != nil {
		return nil, fmt.Errorf("create registry credential store: %w", err)
	}
	svc.SetRegistryCredentialStore(registryCredentialStore)
	serviceSecretStore, err := servicesecrets.NewStore(servicesecrets.NativeVault{})
	if err != nil {
		return nil, fmt.Errorf("create service secret store: %w", err)
	}
	svc.SetServiceSecretStore(serviceSecretStore)
	customSecretStore, err := customsecrets.NewStore(servicesecrets.NativeVault{}, servicesecrets.ErrNotFound)
	if err != nil {
		return nil, fmt.Errorf("create custom secret store: %w", err)
	}
	svc.SetCustomSecretStore(customSecretStore)
	proxyManager := secretproxy.New()
	svc.SetSecretProxyManager(proxyManager)
	return proxyManager.Close, nil
}

func registerLocalServices(grpcServer *grpc.Server, svc *service.Service) {
	localv1.RegisterSandboxServiceServer(grpcServer, server.NewSandbox(svc))
	localv1.RegisterOperationServiceServer(grpcServer, server.NewOperation(svc))
	localv1.RegisterRegistryCredentialServiceServer(grpcServer, server.NewRegistryCredential(svc))
	localv1.RegisterAccountServiceServer(grpcServer, server.NewAccount(svc))
	localv1.RegisterSecretServiceServer(grpcServer, server.NewSecret(svc))
	localv1.RegisterTemplateServiceServer(grpcServer, server.NewTemplate(svc))
	localv1.RegisterApprovalServiceServer(grpcServer, server.NewApproval(svc))
	localv1.RegisterKitPolicyServiceServer(grpcServer, server.NewKitPolicy(svc))
}

//nolint:gocritic // Config is a value object assembled by the caller.
func configureOAuth(svc *service.Service, cfg Config) {
	svc.SetOAuthProviders(cfg.OAuthProviders)
	if cfg.OAuthVault != nil {
		svc.SetOAuthVault(cfg.OAuthVault)
	}
}

func runCleanup(cleanup func() error) error {
	if cleanup == nil {
		return nil
	}
	return cleanup()
}

func stopGRPCOnCancel(ctx context.Context, runDone <-chan struct{}, grpcServer *grpc.Server) {
	select {
	case <-runDone:
		return
	case <-ctx.Done():
	}
	graceDone := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(graceDone)
	}()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-graceDone:
	case <-timer.C:
		grpcServer.Stop()
	}
}

func configureDockerVolume(svc *service.Service, stateDir string) {
	svc.DockerVolumeDir = filepath.Join(stateDir, "docker")
	if svc.DockerVolumeSize == "" {
		svc.DockerVolumeSize = "10g"
	}
	if svc.MkfsExt4 == "" {
		svc.MkfsExt4 = "mkfs.ext4"
	}
	if value := os.Getenv("DOCKER_SANDBOXES_DOCKER_SIZE"); value != "" {
		svc.DockerVolumeSize = value
	}
	if value := os.Getenv("DOCKER_SANDBOXES_MKFS_EXT4"); value != "" {
		svc.MkfsExt4 = value
	}
}

func effectiveUID() uint64 {
	uid := os.Geteuid()
	if uid < 0 {
		return 0
	}
	return uint64(uid)
}
