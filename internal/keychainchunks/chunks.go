// Package keychainchunks stores records that may exceed one host keychain item.
// A large record is split into bounded items, and an integrity-checked manifest
// naming them is committed last. The format is shared by every daemon vault
// (OAuth sessions and custom secrets) so one reader covers all records.
package keychainchunks

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// Prefix marks a keychain value that is a manifest rather than a payload.
	// legacy-compat: see RENAME-MAP §2 — persisted in keychain values; rename deferred.
	Prefix = "rheic-keychain-chunks-v1:"
	// ChunkSize bounds one keychain item. Payloads up to this size are inline.
	ChunkSize = 1800
	// MaxChunks bounds the items one record may occupy.
	MaxChunks = 96
)

// ErrInvalidManifest reports a stored manifest that is malformed or whose
// chunks do not match its digest.
var ErrInvalidManifest = errors.New("invalid keychain chunk manifest")

// ErrRecordTooLarge reports a payload that needs more than MaxChunks items.
var ErrRecordTooLarge = errors.New("keychain record exceeds chunk limit")

// Vault is the host keychain subset used for records.
type Vault interface {
	Set(ctx context.Context, service, account, secret string) error
	Get(ctx context.Context, service, account string) (string, error)
	Delete(ctx context.Context, service, account string) error
}

// Manifest names the chunk items of one record. Nonce makes chunk accounts
// unique per write so a replaced record never overwrites its predecessor's
// chunks before the new manifest is committed.
type Manifest struct {
	Nonce  string `json:"nonce"`
	Count  int    `json:"count"`
	Digest string `json:"digest"`
}

// Store reads and writes records under one keychain service. NotFound is the
// error the vault returns for a missing item; it is returned unwrapped so
// callers can compare it with errors.Is.
type Store struct {
	Vault    Vault
	Service  string
	NotFound error
}

// Save writes payload under account. Payloads that fit one item are stored
// inline; larger payloads are chunked and the manifest is committed last.
func (s Store) Save(ctx context.Context, account string, payload []byte) error {
	if strings.HasPrefix(string(payload), Prefix) {
		return ErrInvalidManifest
	}
	count := (len(payload) + ChunkSize - 1) / ChunkSize
	if count > MaxChunks {
		return ErrRecordTooLarge
	}
	old, hadOld, err := s.currentManifest(ctx, account)
	if err != nil {
		return err
	}
	if len(payload) <= ChunkSize {
		if err := s.Vault.Set(ctx, s.Service, account, string(payload)); err != nil {
			return err
		}
		if hadOld {
			return s.deleteChunks(ctx, account, old)
		}
		return nil
	}
	return s.saveChunks(ctx, account, payload, count, old, hadOld)
}

// Load returns the complete payload stored under account. A missing record
// returns the vault's NotFound error unchanged.
func (s Store) Load(ctx context.Context, account string) (string, error) {
	value, err := s.Vault.Get(ctx, s.Service, account)
	if err != nil {
		return "", err
	}
	manifest, ok := ParseManifest(value)
	if !ok {
		if strings.HasPrefix(value, Prefix) {
			return "", ErrInvalidManifest
		}
		return value, nil
	}
	var b strings.Builder
	for i := 0; i < manifest.Count; i++ {
		chunk, err := s.Vault.Get(ctx, s.Service, ChunkAccount(account, manifest, i))
		if err != nil || len(chunk) > ChunkSize {
			return "", ErrInvalidManifest
		}
		b.WriteString(chunk)
	}
	value = b.String()
	digest := sha256.Sum256([]byte(value))
	if hex.EncodeToString(digest[:]) != manifest.Digest {
		return "", ErrInvalidManifest
	}
	return value, nil
}

// Delete removes the record under account and every chunk it names. A missing
// record is not an error only when the vault reports it as NotFound.
func (s Store) Delete(ctx context.Context, account string) error {
	value, err := s.Vault.Get(ctx, s.Service, account)
	if err != nil && !s.IsNotFound(err) {
		return err
	}
	if manifest, ok := ParseManifest(value); ok {
		if err := s.deleteChunks(ctx, account, manifest); err != nil {
			return err
		}
	} else if strings.HasPrefix(value, Prefix) {
		return ErrInvalidManifest
	}
	return s.Vault.Delete(ctx, s.Service, account)
}

// IsNotFound reports whether err is the vault's missing-item error.
func (s Store) IsNotFound(err error) bool {
	return s.NotFound != nil && errors.Is(err, s.NotFound)
}

func (s Store) currentManifest(ctx context.Context, account string) (Manifest, bool, error) {
	value, err := s.Vault.Get(ctx, s.Service, account)
	if s.IsNotFound(err) {
		return Manifest{}, false, nil
	}
	if err != nil {
		return Manifest{}, false, err
	}
	manifest, ok := ParseManifest(value)
	if !ok && strings.HasPrefix(value, Prefix) {
		return Manifest{}, false, ErrInvalidManifest
	}
	return manifest, ok, nil
}

func (s Store) saveChunks(ctx context.Context, account string, payload []byte, count int, old Manifest, hadOld bool) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	manifest := Manifest{Nonce: hex.EncodeToString(nonce[:]), Count: count, Digest: hex.EncodeToString(digest[:])}
	for i := 0; i < count; i++ {
		end := min((i+1)*ChunkSize, len(payload))
		if err := s.Vault.Set(ctx, s.Service, ChunkAccount(account, manifest, i), string(payload[i*ChunkSize:end])); err != nil {
			_ = s.deleteChunks(ctx, account, Manifest{Nonce: manifest.Nonce, Count: i})
			return err
		}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		_ = s.deleteChunks(ctx, account, manifest)
		return err
	}
	if err := s.Vault.Set(ctx, s.Service, account, Prefix+string(encoded)); err != nil {
		_ = s.deleteChunks(ctx, account, manifest)
		return err
	}
	if hadOld {
		return s.deleteChunks(ctx, account, old)
	}
	return nil
}

func (s Store) deleteChunks(ctx context.Context, account string, m Manifest) error {
	for i := 0; i < m.Count; i++ {
		if err := s.Vault.Delete(ctx, s.Service, ChunkAccount(account, m, i)); err != nil && !s.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// ParseManifest decodes a manifest value. It reports false for payloads and
// for manifests whose count, nonce or digest are out of bounds.
func ParseManifest(value string) (Manifest, bool) {
	if !strings.HasPrefix(value, Prefix) {
		return Manifest{}, false
	}
	var m Manifest
	if json.Unmarshal([]byte(strings.TrimPrefix(value, Prefix)), &m) != nil || m.Count < 1 || m.Count > MaxChunks || len(m.Nonce) != 32 || len(m.Digest) != 64 {
		return Manifest{}, false
	}
	if _, err := hex.DecodeString(m.Nonce); err != nil {
		return Manifest{}, false
	}
	if _, err := hex.DecodeString(m.Digest); err != nil {
		return Manifest{}, false
	}
	return m, true
}

// ChunkAccount names chunk i of the manifest m under the record account.
func ChunkAccount(account string, m Manifest, i int) string {
	return fmt.Sprintf("%s:chunk:%s:%d", account, m.Nonce, i)
}
