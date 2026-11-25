package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	gateway "github.com/rheic/sandboxes-gateway"
	runtime "github.com/rheic/sandboxes-runtime"
	runtimectr "github.com/rheic/sandboxes-runtime/ctr"
	"github.com/rheic/slogx"

	daemon "github.com/rheic/sandboxes-daemon"
	"github.com/rheic/sandboxes-daemon/internal/lifecycle"
	daemonnetwork "github.com/rheic/sandboxes-daemon/internal/network"
	"github.com/rheic/sandboxes-daemon/internal/oauthsession"
	"github.com/rheic/sandboxes-daemon/internal/policysync"
	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/settings"
	"github.com/rheic/sandboxes-daemon/internal/version"
)

type options struct {
	socketPath            string
	stateDir              string
	containerdPath        string
	artifactDigests       string
	runtimeArtifacts      artifactList
	allowUnmanagedRuntime bool
	ctrPath               string
	runtimeName           string
	snapshotter           string
	image                 string
	fifoDir               string
	gvproxyPath           string
	runDir                string
	proxyHelperPath       string
	skillsHelperPath      string
	skillsStorePath       string
	dnsUpstream           string
	settingsPath          string
	policy                string
	defaultPolicyProfile  string
	defaultCPUs           uint32
	defaultMemoryMiB      uint32
	dockerVolumeSize      string
	mcpRemoteAllowedHosts []string
	registryDockerGrants  []string
	registryPrivateGrants []string
	registryPrivateHost   string
	registryPrivateSvc    string
	registryPrivateRealms []string
	registryPrivateRedirs []string
	registryPrivateCAPath string
	ipv6Experimental      bool
	quicExperimental      bool
	orgPolicyEnforce      bool
	orgPolicyOrg          string
	kitAllowedSources     []string
	kitAllowLocalKits     bool
	kitRequireSignature   bool
	policySyncURL         string
	policySyncOrg         string
	policySyncPublicKey   string
	policySyncTokenFile   string
	policySyncInterval    time.Duration
	showVersion           bool
}

// controlledHandler keeps the live daemon log level from lifecycle.LevelVar
// while delegating record formatting and masking to slogx.
type controlledHandler struct {
	slog.Handler
	level slog.Leveler
}

// Enabled consults the live controller level instead of the handler's startup
// threshold. The wrapped handler writes records without re-checking Enabled.
func (h *controlledHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.level != nil && level >= h.level.Level()
}

func main() {
	os.Exit(run())
}

//nolint:funlen // Process setup is kept together.
func run() int {
	if len(os.Args) > 1 && os.Args[1] == gateway.SupervisorArgument {
		if err := gateway.RunSupervisor(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "gateway supervisor:", err)
			return 1
		}
		return 0
	}
	opts := parseOptions()
	if opts.showVersion {
		_, _ = fmt.Fprintln(os.Stdout, version.Version)
		return 0
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	var signalMu sync.Mutex
	shutdownSignal := ""
	go func() {
		select {
		case sig := <-signals:
			signalMu.Lock()
			shutdownSignal = sig.String()
			signalMu.Unlock()
			stop()
		case <-ctx.Done():
		}
	}()
	if controller, err := lifecycle.OpenLogController(opts.stateDir); err != nil {
		slog.Warn("log-level control unavailable; using info", "error", err)
	} else {
		logger := slogx.New(
			slogx.WithOutput(os.Stderr),
			slogx.WithFormat(slogx.FormatText),
			slogx.WithLevel(controller.Leveler().Level()),
		)
		slog.SetDefault(slog.New(&controlledHandler{Handler: logger.Handler(), level: controller.Leveler()}))
		go controller.Watch(ctx)
	}
	lost := make(chan string, 8)
	backend, cleanup, err := buildBackend(&opts, lost)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}
	privateCA, caErr := readPrivateRegistryCA(opts.registryPrivateCAPath)
	if caErr != nil {
		slog.Error("read private registry CA", "error", caErr)
		return 1
	}
	policySync, syncErr := loadPolicySync(&opts)
	if syncErr != nil {
		slog.Error("load policy sync configuration", "error", syncErr)
		return 1
	}
	bundleDigest := ""
	if opts.artifactDigests != "" {
		if data, readErr := os.ReadFile(opts.artifactDigests); readErr == nil {
			sum := sha256.Sum256(data)
			bundleDigest = hex.EncodeToString(sum[:])
		}
	}
	err = daemon.Run(ctx, daemon.Config{
		RuntimeBundleDigest:      bundleDigest,
		ShutdownSignal:           func() string { signalMu.Lock(); defer signalMu.Unlock(); return shutdownSignal },
		SocketPath:               opts.socketPath,
		StateDir:                 opts.stateDir,
		Backend:                  backend,
		DefaultImage:             opts.image,
		IPv6Enabled:              ipv6RuleCapability(&opts),
		QUICEnabled:              quicRuleCapability(&opts),
		OrgPolicyEnforce:         opts.orgPolicyEnforce,
		OrgPolicyOrg:             opts.orgPolicyOrg,
		KitAllowedSources:        opts.kitAllowedSources,
		KitAllowLocalKits:        opts.kitAllowLocalKits,
		KitRequireSignature:      opts.kitRequireSignature,
		Cleanup:                  cleanup,
		OAuthProviders:           dockerOAuthProviders(),
		DNSUpstream:              opts.dnsUpstream,
		DefaultPolicyProfile:     opts.defaultPolicyProfile,
		DefaultCPUs:              opts.defaultCPUs,
		DefaultMemoryMiB:         opts.defaultMemoryMiB,
		DockerVolumeSize:         opts.dockerVolumeSize,
		MCPRemoteAllowedHosts:    opts.mcpRemoteAllowedHosts,
		RegistryDockerGrants:     opts.registryDockerGrants,
		RegistryPrivateGrants:    opts.registryPrivateGrants,
		RegistryPrivateHost:      opts.registryPrivateHost,
		RegistryPrivateService:   opts.registryPrivateSvc,
		RegistryPrivateRealms:    opts.registryPrivateRealms,
		RegistryPrivateRedirects: opts.registryPrivateRedirs,
		RegistryPrivateCA:        privateCA,
		GatewayLost:              lost,
		ProxyHelperPath:          opts.proxyHelperPath,
		SkillsHelperPath:         opts.skillsHelperPath,
		SkillsStorePath:          opts.skillsStorePath,
		PolicySync:               policySync,
	})
	if err != nil {
		slog.Error("daemon stopped", "error", err)
		return 1
	}
	return 0
}

func parseOptions() options {
	var opts options
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	defaultState := filepath.Join(home, ".sandboxes")
	flag.StringVar(&opts.stateDir, "state", defaultState, "state directory")
	flag.StringVar(&opts.socketPath, "socket", filepath.Join(defaultState, "sandboxesd.sock"), "local daemon endpoint")
	flag.StringVar(&opts.containerdPath, "containerd", "", "containerd socket; empty keeps state-only mode")
	flag.StringVar(&opts.artifactDigests, "artifact-digests", "", "runtime digests.yaml for managed artifact verification")
	flag.Var(&opts.runtimeArtifacts, "runtime-artifact", "name=absolute-path of a runtime artifact to verify (repeatable)")
	flag.BoolVar(&opts.allowUnmanagedRuntime, "allow-unmanaged-runtime", false, "explicitly allow host-provided runtime artifacts without digest verification")
	flag.StringVar(&opts.ctrPath, "ctr", "ctr", "ctr binary path")
	flag.StringVar(&opts.runtimeName, "runtime", "io.containerd.nerdbox.v1", "containerd runtime name")
	flag.StringVar(&opts.snapshotter, "snapshotter", "erofs", "containerd snapshotter")
	flag.StringVar(&opts.image, "image", "alpine:3.22", "default image")
	flag.StringVar(&opts.fifoDir, "fifo-dir", "", "runtime FIFO directory")
	flag.StringVar(&opts.gvproxyPath, "gvproxy", "", "patched gvproxy binary; empty disables networking")
	flag.StringVar(&opts.runDir, "run-dir", "", "gateway runtime directory")
	flag.StringVar(&opts.proxyHelperPath, "proxy-helper", "", "static Linux guest proxy helper; empty discovers next to the daemon executable")
	flag.StringVar(&opts.skillsHelperPath, "skills-helper", "", "static Linux guest skills helper; empty discovers next to the daemon executable")
	flag.StringVar(&opts.skillsStorePath, "skills-store", "", "host skills store directory; empty uses the user config directory")
	flag.StringVar(&opts.dnsUpstream, "dns-upstream", "", "optional DNS upstream")
	flag.BoolVar(&opts.ipv6Experimental, "ipv6-experimental", false, "enable the experimental IPv6 guest datapath (acceptance only)")
	flag.BoolVar(&opts.quicExperimental, "quic-experimental", false, "enable experimental UDP domain policy backed by QUIC classification (acceptance only)")
	flag.StringVar(&opts.settingsPath, "settings", settings.DefaultPath(), "user settings file")
	flag.StringVar(&opts.policy, "policy", "", "override the default network policy profile (allow-all, balanced or deny-all); the default is allow-all")
	flag.BoolVar(&opts.showVersion, "version", false, "print version")
	flag.Parse()
	values, err := settings.Load(opts.settingsPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "load settings:", err)
		os.Exit(2)
	}
	if err := applyPolicyOverride(&values, opts.policy); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	opts.applySettings(&values)
	return opts
}

func applyPolicyOverride(values *settings.Values, policy string) error {
	if policy == "" {
		return nil
	}
	switch policy {
	case "allow-all", "balanced", "deny-all":
		values.DefaultPolicyProfile = policy
		return nil
	default:
		return errors.New(`--policy must be "allow-all", "balanced" or "deny-all"`)
	}
}

func (opts *options) applySettings(values *settings.Values) {
	if opts.dnsUpstream == "" {
		opts.dnsUpstream = values.DNSUpstream
	}
	opts.defaultPolicyProfile = values.DefaultPolicyProfile
	opts.defaultCPUs = values.DefaultCPUs
	opts.defaultMemoryMiB = values.DefaultMemoryMiB
	opts.dockerVolumeSize = values.DockerVolumeSize
	opts.mcpRemoteAllowedHosts = values.MCPRemoteAllowedHosts
	opts.registryDockerGrants = values.RegistryDockerGrants
	opts.registryPrivateGrants = values.RegistryPrivateGrants
	opts.registryPrivateHost = values.RegistryPrivateHost
	opts.registryPrivateSvc = values.RegistryPrivateService
	opts.registryPrivateRealms = values.RegistryPrivateRealms
	opts.registryPrivateRedirs = values.RegistryPrivateRedirects
	opts.registryPrivateCAPath = values.RegistryPrivateCA
	opts.orgPolicyEnforce = values.OrgPolicyEnforce
	opts.orgPolicyOrg = values.OrgPolicyOrg
	opts.kitAllowedSources = values.KitAllowedSources
	opts.kitAllowLocalKits = values.KitAllowLocalKits
	opts.kitRequireSignature = values.KitRequireSignature
	opts.policySyncURL = values.PolicySyncURL
	opts.policySyncOrg = values.PolicySyncOrg
	opts.policySyncPublicKey = values.PolicySyncPublicKeyFile
	opts.policySyncTokenFile = values.PolicySyncTokenFile
	opts.policySyncInterval = values.PolicySyncInterval
}

// loadPolicySync reads the protected token and public-key files only when the
// all-or-none settings block is present. The token is never accepted from a
// command-line flag, so it cannot leak through the process list.
func loadPolicySync(opts *options) (*daemon.PolicySyncConfig, error) {
	if opts.policySyncURL == "" {
		return nil, nil //nolint:nilnil // nil config means policy sync is disabled.
	}
	publicKey, err := policysync.LoadPublicKeyFile(opts.policySyncPublicKey)
	if err != nil {
		return nil, err
	}
	token, err := policysync.LoadTokenFile(opts.policySyncTokenFile)
	if err != nil {
		return nil, err
	}
	client, err := policysync.New(policysync.Config{
		BaseURL:   opts.policySyncURL,
		OrgID:     opts.policySyncOrg,
		Token:     token,
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, err
	}
	return &daemon.PolicySyncConfig{Client: client, Interval: opts.policySyncInterval}, nil
}

func dockerOAuthProviders() map[string]service.OAuthProvider {
	provider, err := oauthsession.NewDockerHubProvider(http.DefaultTransport)
	if err != nil {
		slog.Error("Docker Hub OAuth provider configuration is invalid", "error", err)
		return nil
	}
	openai, err := oauthsession.NewOpenAICodexProvider(http.DefaultTransport)
	if err != nil {
		slog.Error("OpenAI OAuth provider configuration is invalid", "error", err)
		return nil
	}
	return map[string]service.OAuthProvider{
		"docker": {
			Device:         provider,
			RevokeEndpoint: oauthsession.DockerOAuthRevokeURL,
			DeviceHandoff: func(ctx context.Context, _ string, verificationURI string) error {
				return oauthsession.OpenBrowser(ctx, verificationURI)
			},
		},
		"openai": {
			Config: openai,
			RevokeToken: func(ctx context.Context, token string) error {
				return oauthsession.RevokeOpenAI(ctx, openai.Transport, token)
			},
			OpenBrowser: oauthsession.OpenBrowser,
		},
	}
}

func buildBackend(opts *options, gatewayLost chan<- string) (runtime.Backend, func() error, error) {
	if opts.containerdPath == "" {
		return nil, nil, nil
	}
	fifoDir := opts.fifoDir
	if fifoDir == "" {
		fifoDir = filepath.Join(opts.stateDir, "fifo")
	}
	if err := os.MkdirAll(fifoDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create fifo dir: %w", err)
	}
	network, manager, err := buildNetwork(opts, gatewayLost)
	if err != nil {
		return nil, nil, err
	}
	artifacts, digests, err := runtimeVerification(opts)
	if err != nil {
		return nil, nil, err
	}
	backend, err := runtimectr.NewBackend(runtimectr.Config{
		Socket:      opts.containerdPath,
		CTR:         opts.ctrPath,
		Runtime:     opts.runtimeName,
		Snapshotter: opts.snapshotter,
	}, runtimectr.BackendOptions{StateDir: opts.stateDir, Image: opts.image, FIFODir: fifoDir, Network: network, Artifacts: artifacts, DigestsPath: digests})
	if err != nil {
		return nil, nil, fmt.Errorf("create runtime backend: %w", err)
	}
	cleanup := func() error {
		if manager != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := manager.Close(ctx); err != nil {
				return fmt.Errorf("cleanup gateway manager: %w", err)
			}
		}
		return nil
	}
	return backend, cleanup, nil
}

// runtimeVerification makes managed versus host-provided runtime artifacts
// explicit. A managed configuration requires both a digest file and at least
// one artifact; host-provided mode needs an explicit opt-in.
func runtimeVerification(opts *options) (map[string]string, string, error) {
	artifacts := make(map[string]string, len(opts.runtimeArtifacts))
	for _, value := range opts.runtimeArtifacts {
		name, path, ok := strings.Cut(value, "=")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(path) == "" {
			return nil, "", fmt.Errorf("invalid --runtime-artifact %q: want name=absolute-path", value)
		}
		if !filepath.IsAbs(path) {
			return nil, "", fmt.Errorf("runtime artifact %s path must be absolute", name)
		}
		artifacts[name] = path
	}
	switch {
	case opts.artifactDigests == "" && len(artifacts) == 0:
		if !opts.allowUnmanagedRuntime {
			return nil, "", errors.New("runtime artifacts are unmanaged: pass --artifact-digests with --runtime-artifact, or --allow-unmanaged-runtime explicitly")
		}
		return nil, "", nil
	case opts.artifactDigests == "" || len(artifacts) == 0:
		return nil, "", errors.New("managed runtime verification requires both --artifact-digests and at least one --runtime-artifact")
	default:
		return artifacts, opts.artifactDigests, nil
	}
}

type artifactList []string

func (a *artifactList) String() string { return strings.Join(*a, ",") }

func (a *artifactList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("runtime artifact must not be empty")
	}
	*a = append(*a, value)
	return nil
}

func buildNetwork(opts *options, gatewayLost chan<- string) (runtime.Network, *gateway.Manager, error) {
	if opts.gvproxyPath == "" {
		return nil, nil, nil
	}
	runDir := opts.runDir
	if runDir == "" {
		runDir = filepath.Join(opts.stateDir, "run")
	}
	supervisor, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("locate gateway supervisor: %w", err)
	}
	manager, err := gateway.New(gateway.Config{
		GVProxy:     opts.gvproxyPath,
		Supervisor:  supervisor,
		RunDir:      runDir,
		DNSUpstream: opts.dnsUpstream,
		OnExit: func(name string) {
			select {
			case gatewayLost <- name:
			default:
				slog.Warn("gateway loss event dropped", "sandbox", name)
			}
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create gateway manager: %w", err)
	}
	if err := configureExperimentalIPv6(opts.ipv6Experimental, manager); err != nil {
		return nil, nil, err
	}
	if err := configureExperimentalQUIC(opts.quicExperimental, manager); err != nil {
		return nil, nil, err
	}
	return daemonnetwork.New(manager, runDir), manager, nil
}

type experimentalIPv6Configurator interface {
	SetIPv6Enabled(bool) error
}

type experimentalQUICConfigurator interface {
	SetQUICEnabled(bool) error
}

// ipv6RuleCapability is true only when the operator asked for the
// experimental datapath and a patched gvproxy is configured. Without gvproxy
// the gateway capability cannot be enabled, so v6 rules stay rejected.
func ipv6RuleCapability(opts *options) bool {
	return opts.ipv6Experimental && opts.gvproxyPath != ""
}

// quicRuleCapability mirrors ipv6RuleCapability for UDP domain policy. The
// gateway only accepts UDP domain rules when the patched datapath is present
// and the operator enabled it explicitly.
func quicRuleCapability(opts *options) bool {
	return opts.quicExperimental && opts.gvproxyPath != ""
}

func configureExperimentalIPv6(enabled bool, target any) error {
	if !enabled {
		return nil
	}
	configurator, ok := target.(experimentalIPv6Configurator)
	if !ok {
		return errors.New("configured gateway module does not support experimental IPv6")
	}
	if err := configurator.SetIPv6Enabled(true); err != nil {
		return fmt.Errorf("enable experimental IPv6 gateway: %w", err)
	}
	return nil
}

func configureExperimentalQUIC(enabled bool, target any) error {
	if !enabled {
		return nil
	}
	configurator, ok := target.(experimentalQUICConfigurator)
	if !ok {
		return errors.New("configured gateway module does not support experimental QUIC")
	}
	if err := configurator.SetQUICEnabled(true); err != nil {
		return fmt.Errorf("enable experimental QUIC gateway: %w", err)
	}
	return nil
}

func readPrivateRegistryCA(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("private registry CA must be a regular file under 1 MiB")
	}
	return os.ReadFile(path) //nolint:gosec // trusted host-only settings path, validated as a regular file under 1 MiB.
}
