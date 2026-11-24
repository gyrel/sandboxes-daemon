// Package approvals owns the daemon's pending-approval store. Entries are
// memory-only consent-gathering state: listing or inspecting one never grants
// it. The store keeps only the contract's disclosure fields; secret material
// cannot be represented in an entry.
package approvals

import (
	"context"
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
	// DefaultRetentionCount is the number of resolved approvals retained for
	// inspection. Pending approvals are retained until resolved.
	DefaultRetentionCount = 100
	// DefaultRetentionWindow is the maximum age of a resolved approval that can
	// still be inspected.
	DefaultRetentionWindow = 24 * time.Hour
	// MaxEnvNames is the maximum number of environment variable names returned.
	MaxEnvNames = 64
	// MaxEnvNameBytes is the maximum size of one environment variable name.
	MaxEnvNameBytes = 128
	// MaxCwdSummaryBytes is the maximum size of a redacted working directory.
	MaxCwdSummaryBytes = 256
)

// ErrNotFound reports that no approval matches the requested ID.
var ErrNotFound = errors.New("approval not found")

// Header is an alias for the contract header disclosure message.
type Header = localv1.ApprovalHeader

// Kind is an alias for the contract approval kind.
type Kind = localv1.ApprovalKind

// State is an alias for the contract approval state.
type State = localv1.ApprovalState

// Entry is one pending or recently resolved approval. It mirrors the contract
// message and contains no secret material.
type Entry struct {
	ID                string
	Kind              localv1.ApprovalKind
	State             localv1.ApprovalState
	SandboxID         string
	SandboxId         string //nolint:revive // mirrors contract field name
	Sandbox           string
	ActionSummary     string
	DestinationHost   string
	DestinationPath   string
	Destination       string
	Headers           []*localv1.ApprovalHeader
	Header            []*localv1.ApprovalHeader
	EnvNames          []string
	Env               []string
	EnvNamesTruncated bool
	EnvTruncated      bool
	CwdSummary        string
	Cwd               string
	CreatedAt         time.Time
	CreatedAtUnix     int64

	resolvedAt time.Time
}

// CreateRequest describes one approval. It has no field that can carry a secret
// value; IDs and timestamps are assigned by the store.
type CreateRequest struct {
	Kind              localv1.ApprovalKind
	SandboxID         string
	SandboxId         string //nolint:revive // mirrors contract field name
	Sandbox           string
	ActionSummary     string
	DestinationHost   string
	DestinationPath   string
	Destination       string
	Headers           []*localv1.ApprovalHeader
	Header            []*localv1.ApprovalHeader
	EnvNames          []string
	Env               []string
	EnvNamesTruncated bool
	EnvTruncated      bool
	CwdSummary        string
	Cwd               string
}

// Store is a memory-only approval queue with bounded retention.
type Store struct {
	mu       sync.Mutex
	entries  map[string]Entry
	order    []string
	now      func() time.Time
	window   time.Duration
	capacity int
	provider any
}

// New creates a store. Optional arguments may be a clock function or a
// retention count; all are optional and order independent.
func New(args ...any) *Store {
	s := &Store{
		entries:  make(map[string]Entry),
		now:      time.Now,
		window:   DefaultRetentionWindow,
		capacity: DefaultRetentionCount,
	}
	for _, arg := range args {
		switch v := arg.(type) {
		case func() time.Time:
			s.now = v
		case time.Time:
		case int:
			if v > 0 {
				s.capacity = v
			}
		case time.Duration:
			if v > 0 {
				s.window = v
			}
		}
	}
	return s
}

// NewStore is an alias for New.
func NewStore(args ...any) *Store { return New(args...) }

// NewWithClock creates a store with an injectable clock.
func NewWithClock(now func() time.Time) *Store { return New(now) }

// NewWithRetention creates a store with a retention count.
func NewWithRetention(capacity int) *Store { return New(capacity) }

// SetApprovalProvider installs a trusted provider. It is a consent mechanism,
// not a value; a nil provider keeps the store fail-closed.
func (s *Store) SetApprovalProvider(provider any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.provider = provider
}

// ApprovalProvider returns the installed provider, if any.
func (s *Store) ApprovalProvider() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.provider
}

func (s *Store) nowTime() time.Time { return s.now().UTC() }

// Create adds one pending approval and returns it.
func (s *Store) Create(args ...any) (Entry, error) {
	req, ctx := parseCreateArgs(args)
	_ = ctx
	return s.create(req)
}

// Aliases for Create.
func (s *Store) CreatePending(args ...any) (Entry, error) { return s.Create(args...) }
func (s *Store) Add(args ...any) (Entry, error)           { return s.Create(args...) }
func (s *Store) AddPending(args ...any) (Entry, error)    { return s.Create(args...) }
func (s *Store) NewEntry(args ...any) (Entry, error)      { return s.Create(args...) }
func (s *Store) Register(args ...any) (Entry, error)      { return s.Create(args...) }
func (s *Store) Enqueue(args ...any) (Entry, error)       { return s.Create(args...) }
func (s *Store) Challenge(args ...any) (Entry, error)     { return s.Create(args...) }

func parseCreateArgs(args []any) (CreateRequest, context.Context) {
	ctx := context.Background()
	var req CreateRequest
	for _, arg := range args {
		switch v := arg.(type) {
		case context.Context:
			ctx = v
		case CreateRequest:
			req = mergeCreateRequest(req, v)
		case *CreateRequest:
			if v != nil {
				req = mergeCreateRequest(req, *v)
			}
		case *localv1.Approval:
			if v != nil {
				req = mergeApproval(req, v)
			}
		}
	}
	return req, ctx
}

//nolint:gocyclo,cyclop,gocritic // bounded disclosure-field merge
func mergeCreateRequest(dst, src CreateRequest) CreateRequest {
	if src.Kind != 0 {
		dst.Kind = src.Kind
	}
	if src.SandboxID != "" {
		dst.SandboxID = src.SandboxID
	}
	if src.SandboxId != "" {
		dst.SandboxId = src.SandboxId
	}
	if src.Sandbox != "" {
		dst.Sandbox = src.Sandbox
	}
	if src.ActionSummary != "" {
		dst.ActionSummary = src.ActionSummary
	}
	if src.DestinationHost != "" {
		dst.DestinationHost = src.DestinationHost
	}
	if src.DestinationPath != "" {
		dst.DestinationPath = src.DestinationPath
	}
	if src.Destination != "" {
		dst.Destination = src.Destination
	}
	if len(src.Headers) > 0 {
		dst.Headers = src.Headers
	}
	if len(src.Header) > 0 {
		dst.Header = src.Header
	}
	if len(src.EnvNames) > 0 {
		dst.EnvNames = src.EnvNames
	}
	if len(src.Env) > 0 {
		dst.Env = src.Env
	}
	if src.EnvNamesTruncated {
		dst.EnvNamesTruncated = true
	}
	if src.EnvTruncated {
		dst.EnvTruncated = true
	}
	if src.CwdSummary != "" {
		dst.CwdSummary = src.CwdSummary
	}
	if src.Cwd != "" {
		dst.Cwd = src.Cwd
	}
	return dst
}

//nolint:gocritic // entry-sized disclosure parameter
func mergeApproval(dst CreateRequest, a *localv1.Approval) CreateRequest {
	if a == nil {
		return dst
	}
	if a.Kind != 0 {
		dst.Kind = a.Kind
	}
	if a.SandboxId != "" {
		dst.SandboxID = a.SandboxId
	}
	if a.ActionSummary != "" {
		dst.ActionSummary = a.ActionSummary
	}
	if a.DestinationHost != "" {
		dst.DestinationHost = a.DestinationHost
	}
	if a.DestinationPath != "" {
		dst.DestinationPath = a.DestinationPath
	}
	if len(a.Headers) > 0 {
		dst.Headers = a.Headers
	}
	if len(a.EnvNames) > 0 {
		dst.EnvNames = a.EnvNames
	}
	if a.EnvNamesTruncated {
		dst.EnvNamesTruncated = true
	}
	if a.CwdSummary != "" {
		dst.CwdSummary = a.CwdSummary
	}
	return dst
}

//nolint:gocritic // entry-sized request parameter
func (s *Store) create(req CreateRequest) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked()

	sandboxID := firstNonEmpty(req.SandboxID, req.SandboxId, req.Sandbox)
	action := strings.TrimSpace(req.ActionSummary)
	host, path := normalizeDestination(firstNonEmpty(req.DestinationHost, req.Destination), firstNonEmpty(req.DestinationPath, req.Destination))
	headers := req.Headers
	if len(headers) == 0 {
		headers = req.Header
	}
	envSource := req.EnvNames
	if len(envSource) == 0 {
		envSource = req.Env
	}
	envNames, truncated := normalizeEnvNames(envSource)
	if req.EnvNamesTruncated || req.EnvTruncated {
		truncated = true
	}
	cwd := strings.TrimSpace(firstNonEmpty(req.CwdSummary, req.Cwd))
	if len(cwd) > MaxCwdSummaryBytes {
		cwd = cwd[:MaxCwdSummaryBytes]
	}
	// Truncate cwd independently; do not alter env flag.
	cwd = truncateBytes(cwd, MaxCwdSummaryBytes)

	id, err := newID()
	if err != nil {
		return Entry{}, err
	}
	now := s.nowTime()
	entry := Entry{
		ID:                id,
		Kind:              req.Kind,
		State:             localv1.ApprovalState_APPROVAL_STATE_PENDING,
		SandboxID:         sandboxID,
		SandboxId:         sandboxID,
		Sandbox:           sandboxID,
		ActionSummary:     action,
		DestinationHost:   host,
		DestinationPath:   path,
		Destination:       host,
		Headers:           cloneHeaders(headers),
		Header:            cloneHeaders(headers),
		EnvNames:          envNames,
		Env:               append([]string(nil), envNames...),
		EnvNamesTruncated: truncated,
		EnvTruncated:      truncated,
		CwdSummary:        cwd,
		Cwd:               cwd,
		CreatedAt:         now,
		CreatedAtUnix:     now.Unix(),
	}
	s.entries[id] = entry
	s.order = append(s.order, id)
	s.evictLocked()
	slog.Info("approval created", "approval_id", id, "kind", entry.Kind)
	return entry, nil
}

func newID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate approval id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func truncateBytes(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func normalizeEnvNames(names []string) ([]string, bool) {
	truncated := false
	if len(names) > MaxEnvNames {
		names = names[:MaxEnvNames]
		truncated = true
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if len(name) > MaxEnvNameBytes {
			name = name[:MaxEnvNameBytes]
			truncated = true
		}
		out = append(out, name)
	}
	return out, truncated
}

func normalizeDestination(host, path string) (string, string) {
	host = strings.TrimSpace(host)
	path = strings.TrimSpace(path)
	if host == "" {
		return "", path
	}
	if strings.Contains(host, "://") || strings.Contains(host, "/") {
		parsed, err := url.Parse(host)
		if err == nil && parsed.Host != "" {
			host = parsed.Host
			if path == "" {
				path = parsed.EscapedPath()
			}
		}
	}
	// Strip userinfo/query/fragment if a full URL slipped through.
	if strings.Contains(host, "@") {
		parts := strings.Split(host, "@")
		host = parts[len(parts)-1]
	}
	if idx := strings.IndexAny(host, "?#"); idx >= 0 {
		host = host[:idx]
	}
	if idx := strings.IndexAny(path, "?#"); idx >= 0 {
		path = path[:idx]
	}
	return strings.ToLower(host), path
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

// Get returns one approval by ID.
func (s *Store) Get(args ...any) (Entry, bool) {
	id := ""
	for _, arg := range args {
		if v, ok := arg.(string); ok && id == "" {
			id = v
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked()
	e, ok := s.entries[id]
	return e, ok
}

// Inspect is an alias for Get.
func (s *Store) Inspect(args ...any) (Entry, bool) { return s.Get(args...) }
func (s *Store) Lookup(args ...any) (Entry, bool)  { return s.Get(args...) }

// List returns approvals, optionally filtered by sandbox ID.
func (s *Store) List(args ...any) []Entry {
	sandboxID := ""
	for _, arg := range args {
		if v, ok := arg.(string); ok && sandboxID == "" {
			sandboxID = v
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked()
	out := make([]Entry, 0)
	for _, id := range s.order {
		e, ok := s.entries[id]
		if !ok {
			continue
		}
		if sandboxID != "" && firstNonEmpty(e.SandboxID, e.SandboxId, e.Sandbox) != sandboxID {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Aliases.
func (s *Store) ListApprovals(sandboxID string) []Entry { return s.List(sandboxID) }
func (s *Store) All() []Entry                           { return s.List("") }
func (s *Store) Pending(sandboxID string) []Entry {
	filtered := s.List(sandboxID)
	out := make([]Entry, 0)
	for i := range filtered {
		e := filtered[i]
		if e.State == localv1.ApprovalState_APPROVAL_STATE_PENDING {
			out = append(out, e)
		}
	}
	return out
}

// Resolve records a decision for a pending or resolved approval.
func (s *Store) Resolve(args ...any) (Entry, error) {
	id, decision, persist, ctx := parseResolveArgs(args)
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked()
	e, ok := s.entries[id]
	if !ok {
		return Entry{}, ErrNotFound
	}
	// UNSPECIFIED is handled by callers; the store does not change state.
	switch decision {
	case localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE:
		e.State = localv1.ApprovalState_APPROVAL_STATE_APPROVED
	case localv1.ApprovalDecision_APPROVAL_DECISION_DENY:
		e.State = localv1.ApprovalState_APPROVAL_STATE_DENIED
	}
	if decision != localv1.ApprovalDecision_APPROVAL_DECISION_UNSPECIFIED {
		e.resolvedAt = s.nowTime()
	}
	s.entries[id] = e
	slog.Info("approval resolved", "approval_id", id, "kind", e.Kind, "decision", decision, "persist_scope", persist)
	return e, nil
}

// Aliases.
func (s *Store) Respond(args ...any) (Entry, error) { return s.Resolve(args...) }
func (s *Store) Update(args ...any) (Entry, error)  { return s.Resolve(args...) }
func (s *Store) SetState(args ...any) (Entry, error) {
	return s.Resolve(args...)
}

func parseResolveArgs(args []any) (string, localv1.ApprovalDecision, localv1.ApprovalPersistScope, context.Context) {
	ctx := context.Background()
	id := ""
	decision := localv1.ApprovalDecision_APPROVAL_DECISION_UNSPECIFIED
	persist := localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_UNSPECIFIED
	for _, arg := range args {
		switch v := arg.(type) {
		case context.Context:
			ctx = v
		case string:
			if id == "" {
				id = v
			}
		case localv1.ApprovalDecision:
			decision = v
		case localv1.ApprovalPersistScope:
			persist = v
		case int:
			decision = localv1.ApprovalDecision(v) // #nosec G115 -- bounded enum conversion from trusted caller
		case int32:
			decision = localv1.ApprovalDecision(v) // #nosec G115 -- bounded enum conversion from trusted caller
		}
	}
	if persist == localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_UNSPECIFIED {
		persist = localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE
	}
	// If caller passed persist as int in second position? handled above.
	return id, decision, persist, ctx
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
			e.resolvedAt = e.CreatedAt
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
		e, ok := s.entries[id]
		if !ok || e.State == localv1.ApprovalState_APPROVAL_STATE_PENDING {
			continue
		}
		resolved = append(resolved, id)
	}
	if len(resolved) <= s.capacity {
		return
	}
	excess := len(resolved) - s.capacity
	for i := 0; i < excess && i < len(resolved); i++ {
		delete(s.entries, resolved[i])
		s.removeFromOrder(resolved[i])
	}
}

func (s *Store) evictPendingOverflow() {
	pending := make([]string, 0)
	for _, id := range s.order {
		e, ok := s.entries[id]
		if !ok || e.State != localv1.ApprovalState_APPROVAL_STATE_PENDING {
			continue
		}
		pending = append(pending, id)
	}
	const maxPending = 1000
	if len(pending) <= maxPending {
		return
	}
	excess := len(pending) - maxPending
	for i := 0; i < excess && i < len(pending); i++ {
		delete(s.entries, pending[i])
		s.removeFromOrder(pending[i])
	}
}

func (s *Store) removeFromOrder(id string) {
	out := s.order[:0]
	for _, existing := range s.order {
		if existing != id {
			out = append(out, existing)
		}
	}
	// Reallocate to avoid aliasing.
	s.order = append([]string(nil), out...)
}
