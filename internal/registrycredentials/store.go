// Package registrycredentials stores registry logins in the host credential vault.
package registrycredentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const vaultService = "com.rheic.registry-credentials.v1"
const registryHTTPScheme = "https"
const registryActionPull = "pull"
const registryActionPush = "push"
const registryV2Path = "/v2/"
const registryBlobPath = "blobs"
const registryUploadsPath = "uploads"
const registryUploadInitKind = "upload-init"
const registryUploadKind = "upload"

var ErrInvalidCredential = errors.New("invalid registry credential")
var ErrNotFound = errors.New("registry credential not found")

type Scope string

const (
	ScopeHostOnly     Scope = "host-only"
	ScopeAllSandboxes Scope = "all-sandboxes"
	ScopeSandbox      Scope = "sandbox"
)

type Credential struct {
	Registry    string
	Username    string
	Password    []byte
	Scope       Scope
	SandboxName string
}

const (
	// OriginLocal identifies entries written by the local daemon.
	OriginLocal = "local"
)

// Summary is non-secret metadata. It never contains a password or other
// secret material.
type Summary struct {
	Registry    string
	Username    string
	Scope       Scope
	SandboxName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Origin      string
}

type Vault interface {
	Set(ctx context.Context, service, account, secret string) error
	Get(ctx context.Context, service, account string) (string, error)
	Delete(ctx context.Context, service, account string) error
}

type Store struct {
	vault Vault
	mu    sync.Mutex
}

// Load reads only the explicitly selected scope; it never falls back to another.
func (s *Store) Load(ctx context.Context, registry string, scope Scope, sandboxName string) (Credential, error) {
	host, err := canonicalRegistry(registry)
	if err != nil {
		return Credential{}, err
	}
	scope, sandboxName, err = validateScope(scope, sandboxName)
	if err != nil {
		return Credential{}, err
	}
	value, err := s.vault.Get(ctx, vaultService, credentialAccount(host, scope, sandboxName))
	if errors.Is(err, ErrNotFound) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return Credential{}, err
	}
	if err != nil {
		return Credential{}, errors.New("read registry credential from host keychain")
	}
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.Unmarshal([]byte(value), &payload) != nil {
		return Credential{}, errors.New("invalid stored registry credential")
	}
	credential := Credential{Registry: host, Username: payload.Username, Password: []byte(payload.Password), Scope: scope, SandboxName: sandboxName}
	if _, err := validateCredential(credential); err != nil {
		clear(credential.Password)
		return Credential{}, errors.New("invalid stored registry credential")
	}
	return credential, nil
}

func NewStore(vault Vault) (*Store, error) {
	if vault == nil {
		return nil, fmt.Errorf("host credential vault is required")
	}
	return &Store{vault: vault}, nil
}

// Save validates and stores one registry login. There is no plaintext fallback.
func (s *Store) Save(ctx context.Context, credential Credential) (Summary, error) {
	if err := ctx.Err(); err != nil {
		return Summary{}, err
	}
	summary, err := validateCredential(credential)
	if err != nil {
		return Summary{}, err
	}
	payload, err := json.Marshal(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{Username: summary.Username, Password: string(credential.Password)})
	if err != nil {
		return Summary{}, fmt.Errorf("encode registry credential: %w", err)
	}
	defer clear(payload)
	account := credentialAccount(summary.Registry, summary.Scope, summary.SandboxName)
	if err := s.vault.Set(ctx, vaultService, account, string(payload)); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Summary{}, err
		}
		return Summary{}, fmt.Errorf("store registry credential in host keychain")
	}
	summary.Origin = OriginLocal
	return summary, nil
}

func validateCredential(credential Credential) (Summary, error) {
	registry, err := canonicalRegistry(credential.Registry)
	if err != nil {
		return Summary{}, err
	}
	if err := validateUsername(credential.Username); err != nil {
		return Summary{}, err
	}
	if len(credential.Password) == 0 || len(credential.Password) > 2048 || !utf8.Valid(credential.Password) {
		return Summary{}, fmt.Errorf("%w: password must be valid UTF-8 and 1 to 2048 bytes", ErrInvalidCredential)
	}
	scope, sandboxName, err := validateScope(credential.Scope, credential.SandboxName)
	if err != nil {
		return Summary{}, err
	}
	return Summary{Registry: registry, Username: credential.Username, Scope: scope, SandboxName: sandboxName}, nil
}

func validateUsername(username string) error {
	if username == "" || len(username) > 256 || !utf8.ValidString(username) || strings.ContainsAny(username, ":\x00\r\n") {
		return fmt.Errorf("%w: registry username is invalid", ErrInvalidCredential)
	}
	return nil
}

func validateScope(scope Scope, sandboxName string) (Scope, string, error) {
	if scope == "" {
		scope = ScopeHostOnly
	}
	if scope != ScopeHostOnly && scope != ScopeAllSandboxes && scope != ScopeSandbox {
		return "", "", fmt.Errorf("%w: scope is invalid", ErrInvalidCredential)
	}
	sandboxName = strings.TrimSpace(sandboxName)
	if scope == ScopeSandbox && (sandboxName == "" || len(sandboxName) > 63 || strings.ContainsAny(sandboxName, "/\\\x00\r\n")) {
		return "", "", fmt.Errorf("%w: sandbox scope requires a valid sandbox name", ErrInvalidCredential)
	}
	if scope != ScopeSandbox && sandboxName != "" {
		return "", "", fmt.Errorf("%w: sandbox name is only valid with sandbox scope", ErrInvalidCredential)
	}
	return scope, sandboxName, nil
}

// Delete removes one scoped registry credential from the host vault.
func (s *Store) Delete(ctx context.Context, registry string, scope Scope, sandboxName string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	host, err := canonicalRegistry(registry)
	if err != nil {
		return false, err
	}
	scope, sandboxName, err = validateScope(scope, sandboxName)
	if err != nil {
		return false, err
	}
	err = s.vault.Delete(ctx, vaultService, credentialAccount(host, scope, sandboxName))
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false, err
	}
	if err != nil {
		return false, fmt.Errorf("delete registry credential from host keychain")
	}
	return true, nil
}

func credentialAccount(registry string, scope Scope, sandboxName string) string {
	account := registry + "/" + string(scope)
	if sandboxName != "" {
		account += "/" + sandboxName
	}
	return account
}

func canonicalRegistry(value string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(value))
	if host == "" {
		host = "docker.io"
	}
	endpoint, err := ParseRegistryEndpoint(host)
	if err != nil {
		return "", fmt.Errorf("%w: registry must be a host name or IP literal with an optional port", ErrInvalidCredential)
	}
	return endpoint.Authority(), nil
}

//nolint:unused // retained for package-level compatibility with earlier callers.
func splitRegistryHostPort(host string) (string, string, error) {
	endpoint, err := ParseRegistryEndpoint(host)
	if err != nil {
		return "", "", fmt.Errorf("%w: registry host or port is invalid", ErrInvalidCredential)
	}
	if !endpoint.portSet {
		return endpoint.Hostname, "", nil
	}
	return endpoint.Hostname, endpoint.port, nil
}

func validRegistryHostname(hostname string) bool {
	if net.ParseIP(hostname) != nil {
		return true
	}
	if len(hostname) > 253 || hostname == "" {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}
