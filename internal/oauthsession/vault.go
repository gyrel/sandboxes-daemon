package oauthsession

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/registrycredentials"
)

const oauthVaultService = "com.rheic.oauth.v1"
const vaultChunkSize = 1800
const vaultMaxChunks = 96
const vaultManifestPrefix = "rheic-keychain-chunks-v1:"

type vaultManifest struct {
	Nonce  string `json:"nonce"`
	Count  int    `json:"count"`
	Digest string `json:"digest"`
}

var ErrNoTokens = errors.New("OAuth tokens are not stored")

// ErrHostKeychainUnavailable reports that the host credential store could not
// be reached at all, as opposed to holding no record for the account.
var ErrHostKeychainUnavailable = errors.New("OAuth host keychain is unavailable")
var ErrNoCredentialFingerprint = errors.New("OAuth credential fingerprint is not stored")

// Vault is the host credential store. No file fallback is provided here.
type Vault interface {
	Set(context.Context, string, string, string) error
	Get(context.Context, string, string) (string, error)
	Delete(context.Context, string, string) error
}

// VaultSink stores a single host-selected provider's token record.
type VaultSink struct {
	vault   Vault
	account string
}

type tokenRecord struct {
	Tokens    Tokens    `json:"tokens"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewVaultSink binds storage to a trusted host-selected provider identifier.
func NewVaultSink(vault Vault, provider string) (*VaultSink, error) {
	if vault == nil || provider == "" || len(provider) > 128 || strings.ContainsAny(provider, "\x00\r\n/\\") {
		return nil, errors.New("invalid OAuth vault configuration")
	}
	return &VaultSink{vault: vault, account: provider}, nil
}

// Save stores a token record in the host vault. Large records use bounded
// keychain items and an integrity-checked manifest committed last.
func (s *VaultSink) Save(ctx context.Context, tokens Tokens) error {
	if tokens.AccessToken == "" || !strings.EqualFold(tokens.TokenType, "bearer") || tokens.ExpiresIn < 0 || tokens.ExpiresIn > int64((365*24*time.Hour)/time.Second) {
		return errors.New("invalid OAuth tokens")
	}
	record := tokenRecord{Tokens: tokens}
	if tokens.ExpiresIn > 0 {
		record.ExpiresAt = time.Now().UTC().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return errors.New("encode OAuth tokens failed")
	}
	defer clear(payload)
	if err := s.savePayload(ctx, payload); err != nil {
		return errors.New("store OAuth tokens failed")
	}
	return nil
}

// Load retrieves the exact record from the host vault.
func (s *VaultSink) Load(ctx context.Context) (Tokens, time.Time, error) {
	value, err := s.loadPayload(ctx)
	if err != nil {
		if errors.Is(err, registrycredentials.ErrNotFound) {
			return Tokens{}, time.Time{}, ErrNoTokens
		}
		return Tokens{}, time.Time{}, fmt.Errorf("%w: read OAuth tokens failed", ErrHostKeychainUnavailable)
	}
	var record tokenRecord
	if json.Unmarshal([]byte(value), &record) != nil || record.Tokens.AccessToken == "" || !strings.EqualFold(record.Tokens.TokenType, "bearer") {
		return Tokens{}, time.Time{}, errors.New("invalid stored OAuth tokens")
	}
	return record.Tokens, record.ExpiresAt, nil
}

// HasTokens reports whether a complete provider token record exists. It never
// returns token values.
func (s *VaultSink) HasTokens(ctx context.Context) (bool, error) {
	_, err := s.loadPayload(ctx)
	if errors.Is(err, registrycredentials.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: inspect OAuth credential presence failed", ErrHostKeychainUnavailable)
	}
	return true, nil
}

// HasRefreshToken reports only whether the stored record carries a non-empty
// refresh token. The decoded payload is cleared before returning; token values
// never leave this method.
func (s *VaultSink) HasRefreshToken(ctx context.Context) (bool, error) {
	value, err := s.loadPayload(ctx)
	if errors.Is(err, registrycredentials.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: inspect OAuth credential presence failed", ErrHostKeychainUnavailable)
	}
	payload := []byte(value)
	defer clear(payload)
	var record struct {
		Tokens struct {
			RefreshToken string `json:"refresh_token"`
		} `json:"tokens"`
	}
	if json.Unmarshal(payload, &record) != nil {
		return false, errors.New("invalid stored OAuth tokens")
	}
	return record.Tokens.RefreshToken != "", nil
}

// Delete removes only this provider's vault record.
func (s *VaultSink) Delete(ctx context.Context) error {
	value, err := s.vault.Get(ctx, oauthVaultService, s.account)
	if err != nil && !errors.Is(err, registrycredentials.ErrNotFound) {
		return errors.New("delete OAuth tokens failed")
	}
	if manifest, ok := parseVaultManifest(value); ok {
		if err := s.deleteChunks(ctx, manifest); err != nil {
			return errors.New("delete OAuth tokens failed")
		}
	} else if strings.HasPrefix(value, vaultManifestPrefix) {
		return errors.New("delete OAuth tokens failed")
	}
	if err := s.vault.Delete(ctx, oauthVaultService, s.account); err != nil {
		return errors.New("delete OAuth tokens failed")
	}
	return nil
}

func (s *VaultSink) savePayload(ctx context.Context, payload []byte) error {
	count := (len(payload) + vaultChunkSize - 1) / vaultChunkSize
	if count > vaultMaxChunks {
		return errors.New("OAuth record exceeds vault limit")
	}
	old, hadOld, err := s.currentManifest(ctx)
	if err != nil {
		return err
	}
	if len(payload) <= vaultChunkSize {
		if err := s.vault.Set(ctx, oauthVaultService, s.account, string(payload)); err != nil {
			return err
		}
		if hadOld {
			return s.deleteChunks(ctx, old)
		}
		return nil
	}
	return s.saveChunks(ctx, payload, count, old, hadOld)
}

func (s *VaultSink) currentManifest(ctx context.Context) (vaultManifest, bool, error) {
	value, err := s.vault.Get(ctx, oauthVaultService, s.account)
	if errors.Is(err, registrycredentials.ErrNotFound) {
		return vaultManifest{}, false, nil
	}
	if err != nil {
		return vaultManifest{}, false, err
	}
	manifest, ok := parseVaultManifest(value)
	if !ok && strings.HasPrefix(value, vaultManifestPrefix) {
		return vaultManifest{}, false, errors.New("invalid OAuth vault manifest")
	}
	return manifest, ok, nil
}

func (s *VaultSink) saveChunks(ctx context.Context, payload []byte, count int, old vaultManifest, hadOld bool) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	manifest := vaultManifest{Nonce: hex.EncodeToString(nonce[:]), Count: count, Digest: hex.EncodeToString(digest[:])}
	for i := 0; i < count; i++ {
		end := min((i+1)*vaultChunkSize, len(payload))
		if err := s.vault.Set(ctx, oauthVaultService, s.chunkAccount(manifest, i), string(payload[i*vaultChunkSize:end])); err != nil {
			_ = s.deleteChunks(ctx, vaultManifest{Nonce: manifest.Nonce, Count: i})
			return err
		}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		_ = s.deleteChunks(ctx, manifest)
		return err
	}
	if err := s.vault.Set(ctx, oauthVaultService, s.account, vaultManifestPrefix+string(encoded)); err != nil {
		_ = s.deleteChunks(ctx, manifest)
		return err
	}
	if hadOld {
		return s.deleteChunks(ctx, old)
	}
	return nil
}

func (s *VaultSink) loadPayload(ctx context.Context) (string, error) {
	value, err := s.vault.Get(ctx, oauthVaultService, s.account)
	if err != nil {
		return "", err
	}
	manifest, ok := parseVaultManifest(value)
	if !ok {
		if strings.HasPrefix(value, vaultManifestPrefix) {
			return "", errors.New("invalid OAuth vault manifest")
		}
		return value, nil
	}
	var b strings.Builder
	for i := 0; i < manifest.Count; i++ {
		chunk, err := s.vault.Get(ctx, oauthVaultService, s.chunkAccount(manifest, i))
		if err != nil || len(chunk) > vaultChunkSize {
			return "", errors.New("invalid OAuth vault chunk")
		}
		b.WriteString(chunk)
	}
	value = b.String()
	digest := sha256.Sum256([]byte(value))
	if hex.EncodeToString(digest[:]) != manifest.Digest {
		return "", errors.New("invalid OAuth vault digest")
	}
	return value, nil
}

func parseVaultManifest(value string) (vaultManifest, bool) {
	if !strings.HasPrefix(value, vaultManifestPrefix) {
		return vaultManifest{}, false
	}
	var m vaultManifest
	if json.Unmarshal([]byte(strings.TrimPrefix(value, vaultManifestPrefix)), &m) != nil || m.Count < 1 || m.Count > vaultMaxChunks || len(m.Nonce) != 32 || len(m.Digest) != 64 {
		return vaultManifest{}, false
	}
	if _, err := hex.DecodeString(m.Nonce); err != nil {
		return vaultManifest{}, false
	}
	if _, err := hex.DecodeString(m.Digest); err != nil {
		return vaultManifest{}, false
	}
	return m, true
}

func (s *VaultSink) chunkAccount(m vaultManifest, i int) string {
	return fmt.Sprintf("%s:chunk:%s:%d", s.account, m.Nonce, i)
}

func (s *VaultSink) deleteChunks(ctx context.Context, m vaultManifest) error {
	for i := 0; i < m.Count; i++ {
		if err := s.vault.Delete(ctx, oauthVaultService, s.chunkAccount(m, i)); err != nil && !errors.Is(err, registrycredentials.ErrNotFound) {
			return err
		}
	}
	return nil
}

// SaveDockerHubPATFingerprint records ownership metadata for the PAT created
// by this OAuth session. The fingerprint is not sufficient to authenticate.
func (s *VaultSink) SaveDockerHubPATFingerprint(ctx context.Context, fingerprint string) error {
	decoded, err := hex.DecodeString(fingerprint)
	if err != nil || len(decoded) != 32 {
		return errors.New("invalid OAuth credential fingerprint")
	}
	clear(decoded)
	if err := s.vault.Set(ctx, oauthVaultService, s.account+":docker-hub-pat-sha256", fingerprint); err != nil {
		return errors.New("store OAuth credential ownership failed")
	}
	return nil
}

// DockerHubPATFingerprint retrieves local ownership metadata for cleanup.
func (s *VaultSink) DockerHubPATFingerprint(ctx context.Context) (string, error) {
	value, err := s.vault.Get(ctx, oauthVaultService, s.account+":docker-hub-pat-sha256")
	if errors.Is(err, registrycredentials.ErrNotFound) {
		return "", ErrNoCredentialFingerprint
	}
	if err != nil {
		return "", fmt.Errorf("%w: read OAuth credential ownership failed", ErrHostKeychainUnavailable)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return "", errors.New("invalid OAuth credential ownership record")
	}
	clear(decoded)
	return value, nil
}

// HasDockerHubPATFingerprint validates only the presence and shape of the
// non-authenticating ownership marker without returning its value.
func (s *VaultSink) HasDockerHubPATFingerprint(ctx context.Context) (bool, error) {
	value, err := s.vault.Get(ctx, oauthVaultService, s.account+":docker-hub-pat-sha256")
	if errors.Is(err, registrycredentials.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: inspect Docker Hub credential presence failed", ErrHostKeychainUnavailable)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return false, errors.New("invalid Docker Hub credential ownership record")
	}
	clear(decoded)
	return true, nil
}

// DeleteDockerHubPATFingerprint clears only this provider's ownership marker.
func (s *VaultSink) DeleteDockerHubPATFingerprint(ctx context.Context) error {
	err := s.vault.Delete(ctx, oauthVaultService, s.account+":docker-hub-pat-sha256")
	if errors.Is(err, registrycredentials.ErrNotFound) {
		return nil
	}
	if err != nil {
		return errors.New("delete OAuth credential ownership failed")
	}
	return nil
}
