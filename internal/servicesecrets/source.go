package servicesecrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	defaultSourceRefresh = 55 * time.Minute
	resolverTimeout      = 30 * time.Second
	maxResolvedSecret    = 8192
	maxResolverStderr    = 4096
	maxCachedSources     = 256
	maxResolverLocks     = 4096
	maxUsedApprovals     = 4096
	approvalTokenBytes   = 32
	defaultApprovalTTL   = 10 * time.Minute
	secretSourcePrefix   = "\x00rheic-secret-source:v1:"
)

// ApprovalProvider obtains consent for a host shell command through a
// daemon-trusted host UI or OS authorization service. An RPC field, CLI flag,
// challenge identifier, or caller identity must never implement this
// interface by itself.
type ApprovalProvider interface {
	Approve(context.Context, ApprovalRequest) error
}

// ApprovalRequest describes the exact host execution that needs approval. It
// never contains a resolved secret value. Cwd, Argv, and EnvKeys are bound into
// the approval token so a later execution cannot substitute a different
// command, working directory, or environment.
type ApprovalRequest struct {
	Action      string
	Service     string
	Scope       Scope
	SandboxName string
	Command     string
	Argv        []string
	Cwd         string
	EnvKeys     []string
	Binding     string
}

type sourceApproval struct {
	Token     string    `json:"token"`
	Binding   string    `json:"binding"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used,omitempty"`
}

var awsSecretARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$`)

// Source is a supported host-side dynamic credential source.
type Source struct {
	Reference  string
	Command    string
	Refresh    string
	NoVerify   bool
	ShowError  bool
	OPAccount  string
	AWSProfile string
	// WorkDir is an absolute, per-source resolver directory created fresh for
	// each execution. Command sources receive it during approval so execution
	// cannot silently change the approved working directory.
	WorkDir  string
	approval *sourceApproval
}

type sourceEnvelope struct {
	Reference  string          `json:"reference"`
	Command    string          `json:"command,omitempty"`
	Refresh    string          `json:"refresh"`
	OPAccount  string          `json:"op_account,omitempty"`
	AWSProfile string          `json:"aws_profile,omitempty"`
	WorkDir    string          `json:"work_dir,omitempty"`
	Approval   *sourceApproval `json:"approval,omitempty"`
}

type sourceCacheEntry struct {
	value     []byte
	expiresAt time.Time
}

type sourceResolver struct {
	mu           sync.Mutex
	locks        map[string]*sync.Mutex
	entries      map[string]sourceCacheEntry
	overflowLock sync.Mutex

	approvalMu    sync.Mutex
	approver      ApprovalProvider
	approvalTTL   time.Duration
	now           func() time.Time
	usedApprovals map[string]time.Time
	persistUsed   func(context.Context, string, Source) error
}

func newSourceResolver() *sourceResolver {
	return &sourceResolver{
		locks:         make(map[string]*sync.Mutex),
		entries:       make(map[string]sourceCacheEntry),
		approvalTTL:   defaultApprovalTTL,
		now:           time.Now,
		usedApprovals: make(map[string]time.Time),
	}
}

// SetApprovalProvider installs the trusted host-side consent mechanism used
// for command sources. A nil provider fails closed.
func (s *Store) SetApprovalProvider(provider ApprovalProvider) {
	r := s.resolver()
	r.approvalMu.Lock()
	r.approver = provider
	r.approvalMu.Unlock()
}

func validateSource(source Source) (Source, error) {
	source.Reference = strings.TrimSpace(source.Reference)
	source.OPAccount = strings.TrimSpace(source.OPAccount)
	source.AWSProfile = strings.TrimSpace(source.AWSProfile)
	if err := validateSourceForm(&source); err != nil {
		return Source{}, err
	}
	if err := validateSourceProfile(source); err != nil {
		return Source{}, err
	}
	if source.WorkDir != "" {
		if source.Command == "" || !filepath.IsAbs(source.WorkDir) || len(source.WorkDir) > 4096 ||
			strings.ContainsRune(source.WorkDir, '\x00') ||
			!strings.HasPrefix(filepath.Base(source.WorkDir), "rheic-secret-ref-") {
			return Source{}, fmt.Errorf("%w: invalid secret resolver working directory", ErrInvalid)
		}
	}
	if source.approval != nil {
		if err := validateApprovalRecord(source.approval); err != nil {
			return Source{}, err
		}
	}
	refresh, err := normalizeRefresh(source.Refresh)
	if err != nil {
		return Source{}, err
	}
	source.Refresh = refresh
	if source.NoVerify && source.ShowError {
		return Source{}, fmt.Errorf("%w: --show-error cannot be combined with --no-verify", ErrInvalid)
	}
	return source, nil
}

func validateApprovalRecord(approval *sourceApproval) error {
	if approval == nil {
		return nil
	}
	if len(approval.Token) != hex.EncodedLen(approvalTokenBytes) || len(approval.Binding) != sha256.Size*2 || approval.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: invalid secret source approval", ErrInvalid)
	}
	if _, err := hex.DecodeString(approval.Token); err != nil {
		return fmt.Errorf("%w: invalid secret source approval", ErrInvalid)
	}
	if _, err := hex.DecodeString(approval.Binding); err != nil {
		return fmt.Errorf("%w: invalid secret source approval", ErrInvalid)
	}
	return nil
}

func validateSourceForm(source *Source) error {
	referenceProvided := source.Reference != ""
	commandProvided := strings.TrimSpace(source.Command) != ""
	if referenceProvided == commandProvided {
		return fmt.Errorf("%w: provide exactly one secret reference or command", ErrInvalid)
	}
	if !commandProvided {
		source.Command = ""
	}
	if source.Reference != "" {
		if len(source.Reference) > 4096 || strings.ContainsAny(source.Reference, "\x00\r\n") {
			return fmt.Errorf("%w: invalid secret reference", ErrInvalid)
		}
		return validateReference(source.Reference)
	}
	if len(source.Command) > 8192 || strings.ContainsRune(source.Command, '\x00') {
		return fmt.Errorf("%w: command must be at most 8192 bytes and contain no NUL", ErrInvalid)
	}
	return nil
}

func validateSourceProfile(source Source) error {
	if len(source.OPAccount) > 256 || strings.ContainsAny(source.OPAccount, "\x00\r\n") ||
		len(source.AWSProfile) > 256 || strings.ContainsAny(source.AWSProfile, "\x00\r\n") {
		return fmt.Errorf("%w: invalid provider account or profile", ErrInvalid)
	}
	if source.OPAccount != "" && !strings.HasPrefix(source.Reference, "op://") ||
		source.AWSProfile != "" && !strings.HasPrefix(source.Reference, "arn:") {
		return fmt.Errorf("%w: provider account/profile does not match secret source", ErrInvalid)
	}
	return nil
}

func validateReference(reference string) error {
	switch {
	case strings.HasPrefix(reference, "op://"):
		parsed, err := url.Parse(reference)
		if err != nil || parsed.Scheme != "op" || parsed.Host == "" || strings.Trim(parsed.Path, "/") == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("%w: invalid 1Password reference", ErrInvalid)
		}
	case awsSecretARN.MatchString(reference):
		return nil
	default:
		return fmt.Errorf("%w: reference must be a 1Password op:// URL or AWS Secrets Manager ARN", ErrInvalid)
	}
	return nil
}

func normalizeRefresh(refresh string) (string, error) {
	if refresh == "" {
		return defaultSourceRefresh.String(), nil
	}
	if refresh == "on-demand" {
		return refresh, nil
	}
	duration, err := time.ParseDuration(refresh)
	if err != nil || duration <= 0 {
		return "", fmt.Errorf("%w: refresh must be on-demand or a positive duration", ErrInvalid)
	}
	return duration.String(), nil
}

func encodeSource(source Source) ([]byte, error) {
	source, err := validateSource(source)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(sourceEnvelope{
		Reference: source.Reference, Command: source.Command, Refresh: source.Refresh,
		OPAccount: source.OPAccount, AWSProfile: source.AWSProfile,
		WorkDir: source.WorkDir, Approval: source.approval,
	})
	if err != nil {
		return nil, fmt.Errorf("encode secret source: %w", err)
	}
	return append([]byte(secretSourcePrefix), encoded...), nil
}

func decodeSource(value []byte) (Source, bool, error) {
	if !bytes.HasPrefix(value, []byte(secretSourcePrefix)) {
		return Source{}, false, nil
	}
	var envelope sourceEnvelope
	if err := json.Unmarshal(value[len(secretSourcePrefix):], &envelope); err != nil {
		return Source{}, true, fmt.Errorf("decode secret source: %w", ErrInvalid)
	}
	source, err := validateSource(Source{
		Reference: envelope.Reference, Command: envelope.Command, Refresh: envelope.Refresh,
		OPAccount: envelope.OPAccount, AWSProfile: envelope.AWSProfile,
		WorkDir: envelope.WorkDir, approval: envelope.Approval,
	})
	if err != nil {
		return Source{}, true, err
	}
	return source, true, nil
}

func (s *Store) SaveSource(ctx context.Context, service string, scope Scope, sandboxName string, source Source) (Summary, error) {
	summary, err := validate(service, scope, sandboxName)
	if err != nil {
		return Summary{}, err
	}
	source, err = validateSource(source)
	if err != nil {
		return Summary{}, err
	}
	if source.Command != "" {
		if err := s.approveCommandSource(ctx, summary, &source); err != nil {
			return Summary{}, err
		}
	}
	if !source.NoVerify {
		if err := s.verifySource(ctx, source); err != nil {
			return Summary{}, err
		}
	}
	encoded, err := encodeSource(source)
	if err != nil {
		return Summary{}, err
	}
	defer clear(encoded)
	if err := s.vault.Set(ctx, vaultService, account(summary), string(encoded)); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Summary{}, err
		}
		return Summary{}, errors.New("store service secret source in host keychain")
	}
	s.resolver().invalidate(account(summary))
	return summary, nil
}

func (s *Store) verifySource(ctx context.Context, source Source) error {
	var resolved []byte
	var err error
	if source.Command != "" {
		env := resolverEnvironment(source)
		if err := validateSourceApproval(source, s.resolver().now(), env); err != nil {
			return err
		}
		resolved, err = executeSource(ctx, source, source.WorkDir, env)
	} else {
		resolved, err = resolveSource(ctx, source)
	}
	clear(resolved)
	return err
}

func (s *Store) approveCommandSource(ctx context.Context, summary Summary, source *Source) error {
	r := s.resolver()
	r.approvalMu.Lock()
	approver := r.approver
	ttl := r.approvalTTL
	now := r.now
	r.approvalMu.Unlock()
	if approver == nil {
		return ErrApprovalRequired
	}
	if ttl <= 0 || ttl > defaultApprovalTTL*2 {
		return ErrApprovalRequired
	}
	workDir, err := newResolverWorkDir()
	if err != nil {
		return err
	}
	source.WorkDir = workDir
	env := resolverEnvironment(*source)
	argv := resolverArgv(*source)
	binding := sourceApprovalBinding(argv, workDir, env)
	if err := approver.Approve(ctx, ApprovalRequest{
		Action: "store", Service: summary.Service, Scope: summary.Scope,
		SandboxName: summary.SandboxName, Command: source.Command,
		Argv: append([]string(nil), argv...), Cwd: workDir,
		EnvKeys: approvalEnvironmentKeys(env), Binding: binding,
	}); err != nil {
		return ErrApprovalDenied
	}
	tokenBytes := make([]byte, approvalTokenBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		return errors.New("create secret source approval token")
	}
	source.approval = &sourceApproval{
		Token:     hex.EncodeToString(tokenBytes),
		Binding:   binding,
		ExpiresAt: now().Add(ttl).UTC(),
	}
	return nil
}

func newResolverWorkDir() (string, error) {
	dir, err := os.MkdirTemp("", "rheic-secret-ref-")
	if err != nil {
		return "", errors.New("prepare isolated secret resolver directory")
	}
	if !filepath.IsAbs(dir) {
		_ = os.RemoveAll(dir)
		return "", errors.New("secret resolver temporary directory must be absolute")
	}
	if err := os.Remove(dir); err != nil {
		return "", errors.New("prepare isolated secret resolver directory")
	}
	return dir, nil
}

func approvalEnvironmentKeys(env []string) []string {
	keys := make([]string, 0, len(env))
	for _, entry := range env {
		if key, _, ok := strings.Cut(entry, "="); ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func sourceApprovalBinding(argv []string, cwd string, env []string) string {
	canonical := struct {
		Argv []string `json:"argv"`
		Cwd  string   `json:"cwd"`
		Env  []string `json:"env"`
	}{Argv: append([]string(nil), argv...), Cwd: cwd, Env: append([]string(nil), env...)}
	sort.Strings(canonical.Env)
	encoded, _ := json.Marshal(canonical)
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return hex.EncodeToString(digest[:])
}

func validateSourceApproval(source Source, now time.Time, env []string) error {
	if source.Command == "" {
		return nil
	}
	approval := source.approval
	if approval == nil {
		return ErrApprovalRequired
	}
	if err := validateApprovalRecord(approval); err != nil {
		return err
	}
	if approval.Used {
		return ErrApprovalUsed
	}
	if !now.Before(approval.ExpiresAt) {
		return ErrApprovalExpired
	}
	if source.WorkDir == "" {
		return ErrApprovalMismatch
	}
	expected := sourceApprovalBinding(resolverArgv(source), source.WorkDir, env)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(approval.Binding)) != 1 {
		return ErrApprovalMismatch
	}
	return nil
}

// Resolve loads a secret value or resolves its saved host-side source. Callers
// must keep the returned value in memory only and clear it after use.
func (s *Store) Resolve(ctx context.Context, service string, scope Scope, sandboxName string) ([]byte, error) {
	value, err := s.Load(ctx, service, scope, sandboxName)
	if err != nil {
		return nil, err
	}
	source, dynamic, err := decodeSource(value)
	if err != nil {
		clear(value)
		return nil, err
	}
	if !dynamic {
		return value, nil
	}
	clear(value)
	summary, err := validate(service, scope, sandboxName)
	if err != nil {
		return nil, err
	}
	return s.resolver().resolve(ctx, account(summary), source)
}

// IsDynamic reports whether the stored item is a resolver configuration.
func (s *Store) IsDynamic(ctx context.Context, service string, scope Scope, sandboxName string) (bool, error) {
	value, err := s.Load(ctx, service, scope, sandboxName)
	if err != nil {
		return false, err
	}
	_, dynamic, decodeErr := decodeSource(value)
	clear(value)
	return dynamic, decodeErr
}

func (s *Store) resolver() *sourceResolver {
	if s.sourceResolver == nil {
		s.sourceResolver = newSourceResolver()
	}
	return s.sourceResolver
}

func (r *sourceResolver) resolve(ctx context.Context, key string, source Source) ([]byte, error) {
	source, err := validateSource(source)
	if err != nil {
		return nil, err
	}
	if source.Command != "" {
		if err := validateSourceApproval(source, r.now(), resolverEnvironment(source)); err != nil {
			return nil, err
		}
	}
	if source.Refresh == "on-demand" {
		return r.resolveApproved(ctx, key, source)
	}
	cacheKey, err := sourceCacheKey(key, source)
	if err != nil {
		return nil, err
	}
	duration, _ := time.ParseDuration(source.Refresh)
	lock := r.keyLock(key)
	lock.Lock()
	defer lock.Unlock()
	// Recheck under the per-account lock so concurrent callers holding the same
	// pre-consumption envelope cannot both observe it as unused.
	if source.Command != "" && r.approvalUsed(source.approval) {
		return nil, ErrApprovalUsed
	}
	r.mu.Lock()
	if entry, ok := r.entries[cacheKey]; ok && r.now().Before(entry.expiresAt) {
		r.mu.Unlock()
		return append([]byte(nil), entry.value...), nil
	}
	r.mu.Unlock()
	value, err := r.resolveApproved(ctx, key, source)
	if err != nil {
		return nil, err
	}
	r.cache(cacheKey, value, r.now().Add(duration))
	return value, nil
}

func (r *sourceResolver) resolveApproved(ctx context.Context, key string, source Source) ([]byte, error) {
	if source.Command == "" {
		return resolveSource(ctx, source)
	}
	env := resolverEnvironment(source)
	if err := validateSourceApproval(source, r.now(), env); err != nil {
		return nil, err
	}
	if err := r.consumeApproval(ctx, key, source); err != nil {
		return nil, err
	}
	return executeSource(ctx, source, source.WorkDir, env)
}

func (r *sourceResolver) consumeApproval(ctx context.Context, key string, source Source) error {
	approval := source.approval
	if approval == nil {
		return ErrApprovalRequired
	}
	r.approvalMu.Lock()
	now := r.now()
	r.pruneUsedApprovalsLocked(now)
	if _, used := r.usedApprovals[approval.Token]; used {
		r.approvalMu.Unlock()
		return ErrApprovalUsed
	}
	if len(r.usedApprovals) >= maxUsedApprovals {
		r.approvalMu.Unlock()
		return errors.New("secret source approval capacity is exhausted")
	}
	r.usedApprovals[approval.Token] = approval.ExpiresAt
	persist := r.persistUsed
	r.approvalMu.Unlock()

	// Mark the approval used in the host vault before starting the process. A
	// failed write must not run the command, and a successful write makes the
	// single-use property survive a daemon restart.
	consumed := source
	consumed.approval = &sourceApproval{
		Token: approval.Token, Binding: approval.Binding,
		ExpiresAt: approval.ExpiresAt, Used: true,
	}
	if persist == nil {
		return ErrApprovalRequired
	}
	return persist(ctx, key, consumed)
}

func (r *sourceResolver) approvalUsed(approval *sourceApproval) bool {
	if approval == nil {
		return true
	}
	r.approvalMu.Lock()
	defer r.approvalMu.Unlock()
	_, used := r.usedApprovals[approval.Token]
	return used
}

func (r *sourceResolver) pruneUsedApprovalsLocked(now time.Time) {
	for token, expires := range r.usedApprovals {
		if !now.Before(expires) {
			delete(r.usedApprovals, token)
		}
	}
}

func sourceCacheKey(account string, source Source) (string, error) {
	fingerprint := source
	fingerprint.approval = nil
	encoded, err := encodeSource(fingerprint)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return account + "\x00" + hex.EncodeToString(digest[:]), nil
}

func (r *sourceResolver) keyLock(key string) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	lock := r.locks[key]
	if lock == nil {
		if len(r.locks) >= maxResolverLocks {
			return &r.overflowLock
		}
		lock = &sync.Mutex{}
		r.locks[key] = lock
	}
	return lock
}

func (r *sourceResolver) cache(key string, value []byte, expiresAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[key]; !exists && len(r.entries) >= maxCachedSources {
		oldestKey := ""
		var oldest time.Time
		for candidate, entry := range r.entries {
			if !time.Now().Before(entry.expiresAt) {
				oldestKey = candidate
				break
			}
			if oldestKey == "" || entry.expiresAt.Before(oldest) {
				oldestKey, oldest = candidate, entry.expiresAt
			}
		}
		if entry, ok := r.entries[oldestKey]; ok {
			clear(entry.value)
			delete(r.entries, oldestKey)
		}
	}
	if prior, ok := r.entries[key]; ok {
		clear(prior.value)
	}
	r.entries[key] = sourceCacheEntry{value: append([]byte(nil), value...), expiresAt: expiresAt}
}

func (r *sourceResolver) invalidate(key string) {
	lock := r.keyLock(key)
	lock.Lock()
	defer lock.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	prefix := key + "\x00"
	for cacheKey, entry := range r.entries {
		if cacheKey != key && !strings.HasPrefix(cacheKey, prefix) {
			continue
		}
		clear(entry.value)
		delete(r.entries, cacheKey)
	}
}

func resolveSource(ctx context.Context, source Source) ([]byte, error) {
	source, err := validateSource(source)
	if err != nil {
		return nil, err
	}
	if source.Command != "" {
		if err := validateSourceApproval(source, time.Now(), resolverEnvironment(source)); err != nil {
			return nil, err
		}
	}
	return executeSource(ctx, source, source.WorkDir, resolverEnvironment(source))
}

func prepareResolverWorkDir(workDir string) (string, error) {
	if workDir == "" {
		dir, err := os.MkdirTemp("", "rheic-secret-ref-")
		if err != nil {
			return "", errors.New("prepare isolated secret resolver directory")
		}
		return dir, nil
	}
	if !filepath.IsAbs(workDir) {
		return "", errors.New("secret resolver working directory must be absolute")
	}
	if err := os.Mkdir(workDir, 0o700); err != nil {
		return "", errors.New("prepare approved secret resolver directory")
	}
	return workDir, nil
}

// executeSource starts an already approved resolver command. Callers must
// validate the approval binding before invoking it.
func executeSource(ctx context.Context, source Source, workDir string, env []string) (resolved []byte, retErr error) {
	if _, err := validateSource(source); err != nil {
		return nil, err
	}
	commandCtx, cancel := context.WithTimeout(ctx, resolverTimeout)
	defer cancel()
	workDir, err := prepareResolverWorkDir(workDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := os.RemoveAll(workDir); cleanupErr != nil {
			clear(resolved)
			resolved = nil
			retErr = errors.New("clean up secret resolver directory")
		}
	}()
	command := resolverCommand(commandCtx, source)
	command.Dir = workDir
	command.Env = env
	stdout, stderr, runErr := boundedCommandOutput(commandCtx, command)
	if runErr != nil {
		return nil, sourceResolutionError(source, stdout, stderr, runErr)
	}
	clear(stderr)
	value := bytes.TrimSpace(stdout)
	if len(value) == 0 || len(value) > maxResolvedSecret || bytes.Equal(value, []byte("None")) || !utf8.Valid(value) || bytes.Contains(value, []byte{0}) || bytes.ContainsAny(value, "\r\n") {
		clear(stdout)
		return nil, fmt.Errorf("%w: resolver output must be one non-empty UTF-8 value of at most %d bytes", ErrInvalid, maxResolvedSecret)
	}
	resolved = append([]byte(nil), value...)
	clear(stdout)
	return resolved, nil
}

func sourceResolutionError(source Source, stdout, stderr []byte, runErr error) error {
	var providerError string
	if source.ShowError && len(stderr) != 0 {
		providerError = strings.TrimSpace(string(stderr))
	}
	clear(stdout)
	clear(stderr)
	if providerError != "" {
		return fmt.Errorf("resolve secret reference: %s", providerError)
	}
	if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
		return runErr
	}
	return errors.New("resolve secret reference with the configured host provider")
}

func resolverArgv(source Source) []string {
	if source.Command != "" {
		return hostShellArgv(source.Command)
	}
	if strings.HasPrefix(source.Reference, "op://") {
		return []string{"op", "read", source.Reference}
	}
	return []string{"aws", "secretsmanager", "get-secret-value", "--secret-id", source.Reference, "--query", "SecretString", "--output", "text"}
}

func resolverCommand(ctx context.Context, source Source) *exec.Cmd {
	if source.Command != "" {
		return hostShellCommand(ctx, source.Command)
	}
	argv := resolverArgv(source)
	//nolint:gosec // Fixed executable; the validated reference is one argv token and no shell is involved.
	return exec.CommandContext(ctx, argv[0], argv[1:]...)
}

func resolverEnvironment(source Source) []string {
	allowed := []string{
		"PATH", "HOME", "XDG_CONFIG_HOME", "OP_CONFIG_DIR",
		"AWS_REGION", "AWS_DEFAULT_REGION",
		"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CA_BUNDLE",
	}
	if runtime.GOOS == "windows" {
		allowed = append(allowed,
			"USERPROFILE", "APPDATA", "LOCALAPPDATA",
			"SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
		)
	}
	env := make([]string, 0, len(allowed))
	for _, key := range allowed {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	if source.OPAccount != "" {
		env = append(env, "OP_ACCOUNT="+source.OPAccount)
	}
	if source.AWSProfile != "" {
		env = append(env, "AWS_PROFILE="+source.AWSProfile)
	}
	return env
}

var errResolverOutputLimit = errors.New("secret resolver output exceeded its limit")

type boundedCommandCapture struct {
	mu          sync.Mutex
	data        []byte
	limit       int
	exceeded    bool
	signalLimit func()
}

func (w *boundedCommandCapture) Write(p []byte) (int, error) {
	w.mu.Lock()
	if w.exceeded {
		w.mu.Unlock()
		return 0, errResolverOutputLimit
	}
	remaining := w.limit - len(w.data)
	if len(p) > remaining {
		if remaining > 0 {
			w.data = append(w.data, p[:remaining]...)
		}
		w.exceeded = true
		signal := w.signalLimit
		w.mu.Unlock()
		if signal != nil {
			signal()
		}
		return remaining, errResolverOutputLimit
	}
	w.data = append(w.data, p...)
	w.mu.Unlock()
	return len(p), nil
}

func (w *boundedCommandCapture) take() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	data, exceeded := w.data, w.exceeded
	w.data = nil
	return data, exceeded
}

func boundedCommandOutput(ctx context.Context, command *exec.Cmd) (stdout, stderr []byte, retErr error) {
	outputLimit := make(chan struct{})
	var signalLimit sync.Once
	stdoutCapture := &boundedCommandCapture{limit: maxResolvedSecret, signalLimit: func() { signalLimit.Do(func() { close(outputLimit) }) }}
	stderrCapture := &boundedCommandCapture{limit: maxResolverStderr, signalLimit: func() { signalLimit.Do(func() { close(outputLimit) }) }}
	command.Stdout = stdoutCapture
	command.Stderr = stderrCapture
	terminate, cleanup, err := startResolverProcess(command)
	if err != nil {
		return nil, nil, errors.New("start secret resolver")
	}
	defer func() {
		cleanupErr := errors.Join(terminate(), cleanup())
		if cleanupErr != nil {
			clear(stdout)
			clear(stderr)
			stdout, stderr = nil, nil
			retErr = errors.Join(retErr, errors.New("clean up secret resolver process"))
		}
	}()
	stopWatch := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = terminate()
		case <-outputLimit:
			_ = terminate()
		case <-stopWatch:
		}
	}()
	waitErr := command.Wait()
	close(stopWatch)
	<-watcherDone
	stdout, stdoutExceeded := stdoutCapture.take()
	stderr, stderrExceeded := stderrCapture.take()
	if ctx.Err() != nil {
		clear(stdout)
		clear(stderr)
		return nil, nil, ctx.Err()
	}
	if stdoutExceeded || stderrExceeded {
		clear(stdout)
		clear(stderr)
		return nil, nil, errResolverOutputLimit
	}
	if waitErr != nil {
		return stdout, stderr, waitErr
	}
	return stdout, stderr, nil
}
