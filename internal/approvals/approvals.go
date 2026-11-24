// Package approvals owns the daemon's pending-approval queue. Entries are
// memory-only consent-gathering state: listing or inspecting one never grants
// it. The store keeps only the contract's disclosure fields (api 0.0.36): no
// header values, environment values or secret material can be represented in an
// entry. Gating on a trusted provider is the caller's (service layer's)
// responsibility; the store is a pure bounded queue.
package approvals

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

const (
	// DefaultCapacity bounds retained resolved approvals available to Inspect.
	DefaultCapacity = 100
	// DefaultWindow is the maximum age of a resolved approval that can still
	// be inspected.
	DefaultWindow = 24 * time.Hour
	// maxPendingBounds the pending queue against flooding.
	maxPending = 1000
	// maxEnvNames bounds disclosed environment variable names.
	maxEnvNames = 64
	// maxEnvNameBytes bounds one environment variable name.
	maxEnvNameBytes = 128
	// maxCwdSummaryBytes bounds the redacted working-directory summary.
	maxCwdSummaryBytes = 256
)

// ErrNotFound reports that no approval matches the requested ID.
var ErrNotFound = errors.New("approval not found")

// Entry is one pending or recently resolved approval. It mirrors the contract
// message and carries no secret material by construction.
type Entry struct {
	ID                string
	Kind              localv1.ApprovalKind
	State             localv1.ApprovalState
	SandboxID         string
	ActionSummary     string
	DestinationHost   string
	DestinationPath   string
	Headers           []*localv1.ApprovalHeader
	EnvNames          []string
	EnvNamesTruncated bool
	CwdSummary        string
	CreatedAtUnix     int64

	createdAt  time.Time
	resolvedAt time.Time
}

// CreateRequest describes a new approval. IDs and timestamps are assigned by
// the store; no field can carry a secret value.
type CreateRequest struct {
	Kind              localv1.ApprovalKind
	SandboxID         string
	ActionSummary     string
	DestinationHost   string
	DestinationPath   string
	Headers           []*localv1.ApprovalHeader
	EnvNames          []string
	EnvNamesTruncated bool
	CwdSummary        string
}

// Config tunes the store; the zero value uses defaults.
type Config struct {
	// Now is the clock, injectable for tests.
	Now func() time.Time
	// Capacity bounds retained resolved approvals (default DefaultCapacity).
	Capacity int
	// Window bounds resolved-approval age for inspection (default DefaultWindow).
	Window time.Duration
}

// Store is a memory-only approval queue with bounded retention.
type Store struct {
	mu       sync.Mutex
	entries  map[string]Entry
	order    []string
	now      func() time.Time
	window   time.Duration
	capacity int
}

// New builds a store from cfg.
func New(cfg Config) *Store {
	s := &Store{
		entries:  make(map[string]Entry),
		now:      cfg.Now,
		window:   cfg.Window,
		capacity: cfg.Capacity,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.window <= 0 {
		s.window = DefaultWindow
	}
	if s.capacity <= 0 {
		s.capacity = DefaultCapacity
	}
	return s
}

func (s *Store) nowTime() time.Time { return s.now().UTC() }

// Create adds one pending approval and returns the stored entry.
func (s *Store) Create(req CreateRequest) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked()

	id, err := newID()
	if err != nil {
		return Entry{}, err
	}
	headers := cloneHeaders(req.Headers)
	envNames, truncated := normalizeEnvNames(req.EnvNames)
	if req.EnvNamesTruncated {
		truncated = true
	}
	host, path := normalizeDestination(req.DestinationHost, req.DestinationPath)
	now := s.nowTime()
	entry := Entry{
		ID:                id,
		Kind:              req.Kind,
		State:             localv1.ApprovalState_APPROVAL_STATE_PENDING,
		SandboxID:         strings.TrimSpace(req.SandboxID),
		ActionSummary:     strings.TrimSpace(req.ActionSummary),
		DestinationHost:   host,
		DestinationPath:   path,
		Headers:           headers,
		EnvNames:          envNames,
		EnvNamesTruncated: truncated,
		CwdSummary:        truncateBytes(strings.TrimSpace(req.CwdSummary), maxCwdSummaryBytes),
		CreatedAtUnix:     now.Unix(),
		createdAt:         now,
	}
	s.entries[id] = entry
	s.order = append(s.order, id)
	s.evictLocked()
	slog.Info("approval created", "approval_id", id, "kind", entry.Kind)
	return entry, nil
}

// Get returns one approval (pending or retained resolved) by ID.
func (s *Store) Get(id string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked()
	e, ok := s.entries[id]
	return e, ok
}

// ListPending returns pending approvals oldest-first, optionally filtered by
// sandbox ID. The contract lists pending only.
func (s *Store) ListPending(sandboxID string) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked()
	return s.listLocked(sandboxID, func(e Entry) bool {
		return e.State == localv1.ApprovalState_APPROVAL_STATE_PENDING
	})
}

// Resolve records a decision for a pending approval. UNSPECIFIED decisions
// never change state (callers map them to INVALID_ARGUMENT).
func (s *Store) Resolve(id string, decision localv1.ApprovalDecision, persist localv1.ApprovalPersistScope) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked()
	e, ok := s.entries[id]
	if !ok {
		return Entry{}, ErrNotFound
	}
	switch decision {
	case localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE:
		e.State = localv1.ApprovalState_APPROVAL_STATE_APPROVED
	case localv1.ApprovalDecision_APPROVAL_DECISION_DENY:
		e.State = localv1.ApprovalState_APPROVAL_STATE_DENIED
	case localv1.ApprovalDecision_APPROVAL_DECISION_UNSPECIFIED:
		return e, nil
	}
	e.resolvedAt = s.nowTime()
	s.entries[id] = e
	slog.Info("approval resolved", "approval_id", id, "kind", e.Kind, "decision", decision, "persist_scope", persist)
	return e, nil
}

func (s *Store) listLocked(sandboxID string, keep func(Entry) bool) []Entry {
	out := make([]Entry, 0, len(s.order))
	for _, id := range s.order {
		e, ok := s.entries[id]
		if !ok || !keep(e) {
			continue
		}
		if sandboxID != "" && e.SandboxID != sandboxID {
			continue
		}
		out = append(out, e)
	}
	return out
}

func newID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate approval id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func truncateBytes(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// normalizeEnvNames enforces the disclosure bounds (64 names, 128 bytes each)
// and reports whether anything was cut.
func normalizeEnvNames(names []string) ([]string, bool) {
	truncated := false
	if len(names) > maxEnvNames {
		names = names[:maxEnvNames]
		truncated = true
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if len(name) > maxEnvNameBytes {
			name = name[:maxEnvNameBytes]
			truncated = true
		}
		out = append(out, name)
	}
	return out, truncated
}

// normalizeDestination keeps host and path free of query, userinfo and
// fragment per the disclosure contract.
func normalizeDestination(host, path string) (string, string) {
	host = strings.TrimSpace(host)
	path = strings.TrimSpace(path)
	if host == "" {
		return "", stripQueryFragment(path)
	}
	if strings.ContainsAny(host, "/@?#") || strings.Contains(host, "://") {
		host, path = parseURLHost(host, path)
		if idx := strings.LastIndex(host, "@"); idx >= 0 {
			host = host[idx+1:]
		}
	}
	host = strings.TrimPrefix(host, "//")
	if idx := strings.IndexAny(host, "/?#"); idx >= 0 {
		host = host[:idx]
	}
	return strings.ToLower(host), stripQueryFragment(path)
}

// parseURLHost replaces a URL-shaped host with its authority and adopts the
// embedded path when the caller supplied none.
func parseURLHost(host, path string) (string, string) {
	parsed, err := url.Parse(host)
	if err != nil || parsed.Host == "" {
		return host, path
	}
	if path == "" {
		path = parsed.EscapedPath()
	}
	return parsed.Host, path
}

func stripQueryFragment(path string) string {
	if idx := strings.IndexAny(path, "?#"); idx >= 0 {
		return path[:idx]
	}
	return path
}

func cloneHeaders(headers []*localv1.ApprovalHeader) []*localv1.ApprovalHeader {
	out := make([]*localv1.ApprovalHeader, 0, len(headers))
	for _, h := range headers {
		if h == nil {
			continue
		}
		out = append(out, &localv1.ApprovalHeader{
			Name:              h.Name,
			ValueClass:        h.ValueClass,
			VaultReferenceIds: append([]string(nil), h.VaultReferenceIds...),
		})
	}
	return out
}

func (s *Store) evictLocked() {
	s.evictExpiredResolved()
	s.evictResolvedOverflow()
	s.evictPendingOverflow()
}

func (s *Store) evictExpiredResolved() {
	now := s.nowTime()
	expired := make([]string, 0)
	for id := range s.entries {
		e := s.entries[id]
		if e.State == localv1.ApprovalState_APPROVAL_STATE_PENDING {
			continue
		}
		if e.resolvedAt.IsZero() {
			e.resolvedAt = e.createdAt
			s.entries[id] = e
		}
		if now.Sub(e.resolvedAt) > s.window {
			expired = append(expired, id)
		}
	}
	for _, id := range expired {
		delete(s.entries, id)
		s.removeFromOrder(id)
	}
}

func (s *Store) evictResolvedOverflow() {
	resolved := make([]string, 0)
	for _, id := range s.order {
		if e, ok := s.entries[id]; ok && e.State != localv1.ApprovalState_APPROVAL_STATE_PENDING {
			resolved = append(resolved, id)
		}
	}
	for _, id := range resolved[:max(0, len(resolved)-s.capacity)] {
		delete(s.entries, id)
		s.removeFromOrder(id)
	}
}

func (s *Store) evictPendingOverflow() {
	pending := make([]string, 0)
	for _, id := range s.order {
		if e, ok := s.entries[id]; ok && e.State == localv1.ApprovalState_APPROVAL_STATE_PENDING {
			pending = append(pending, id)
		}
	}
	for _, id := range pending[:max(0, len(pending)-maxPending)] {
		delete(s.entries, id)
		s.removeFromOrder(id)
	}
}

func (s *Store) removeFromOrder(id string) {
	out := make([]string, 0, len(s.order))
	for _, existing := range s.order {
		if existing != id {
			out = append(out, existing)
		}
	}
	s.order = out
}
