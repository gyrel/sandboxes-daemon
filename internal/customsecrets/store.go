package customsecrets

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/keychainchunks"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
)

const vaultService = "com.rheic.custom-secrets.v1"

// ErrNotFound reports that no custom secret record exists for the key.
var ErrNotFound = errors.New("custom secret not found")

// ErrKeychain reports a host keychain failure. Its message is deliberately
// generic: backend errors may carry account names and must not reach RPCs.
var ErrKeychain = errors.New("custom secret host keychain operation failed")

// Record is the host-vault payload of one custom secret. The placeholder is
// stored here, not in SQLite, so substitution can find it on the host while
// inventories only ever see a mask.
type Record struct {
	Placeholder string `json:"placeholder"`
	Value       string `json:"value"`
}

// Summary is the non-secret inventory view of one custom secret. It never holds
// the value or the full placeholder.
type Summary struct {
	Service           string
	Scope             servicesecrets.Scope
	SandboxName       string
	EnvName           string
	Hosts             []string
	PlaceholderMasked string
	Origin            string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Store keeps custom secret records in the host keychain. Records above one
// keychain item use the shared chunked format.
type Store struct {
	records keychainchunks.Store
}

// NewStore creates a record store. notFound must be the error the vault returns
// for a missing item, so that absence is distinguishable from failure.
func NewStore(vault keychainchunks.Vault, notFound error) (*Store, error) {
	if vault == nil || notFound == nil {
		return nil, errors.New("host credential vault is required")
	}
	return &Store{records: keychainchunks.Store{Vault: vault, Service: vaultService, NotFound: notFound}}, nil
}

// Save stores or replaces the record for one custom secret.
func (s *Store) Save(ctx context.Context, service string, scope servicesecrets.Scope, sandboxName string, record Record) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return ErrKeychain
	}
	defer clear(payload)
	return s.mapError(s.records.Save(ctx, account(service, scope, sandboxName), payload))
}

// Load returns the record for one custom secret. Callers must not log it.
func (s *Store) Load(ctx context.Context, service string, scope servicesecrets.Scope, sandboxName string) (Record, error) {
	value, err := s.records.Load(ctx, account(service, scope, sandboxName))
	if err != nil {
		return Record{}, s.mapError(err)
	}
	var record Record
	if err := json.Unmarshal([]byte(value), &record); err != nil || record.Placeholder == "" || record.Value == "" {
		return Record{}, errors.New("invalid stored custom secret")
	}
	return record, nil
}

// Delete removes the record for one custom secret.
func (s *Store) Delete(ctx context.Context, service string, scope servicesecrets.Scope, sandboxName string) error {
	return s.mapError(s.records.Delete(ctx, account(service, scope, sandboxName)))
}

// IsNotFound reports whether err means the record is absent.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

func (s *Store) mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, keychainchunks.ErrInvalidManifest):
		return errors.New("invalid stored custom secret")
	case s.records.IsNotFound(err):
		return ErrNotFound
	}
	return ErrKeychain
}

func account(service string, scope servicesecrets.Scope, sandboxName string) string {
	if scope == servicesecrets.ScopeSandbox {
		return service + "/sandbox/" + sandboxName
	}
	return service + "/global"
}
