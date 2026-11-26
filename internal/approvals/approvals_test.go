package approvals

import (
	"errors"
	"strings"
	"testing"
	"time"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
)

func fixedClock(start time.Time) (*time.Time, func() time.Time) {
	now := start
	return &now, func() time.Time { return now }
}

func TestCreateEnforcesDisclosureBounds(t *testing.T) {
	names := make([]string, 0, maxEnvNames+10)
	for i := 0; i < maxEnvNames+10; i++ {
		names = append(names, "VAR"+strings.Repeat("X", i))
	}
	names = append(names, strings.Repeat("L", maxEnvNameBytes+64))
	store := New(Config{})
	entry, err := store.Create(CreateRequest{
		Kind:       localv1.ApprovalKind_APPROVAL_KIND_HOST_COMMAND,
		EnvNames:   names,
		CwdSummary: strings.Repeat("d", maxCwdSummaryBytes+50),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.EnvNames) != maxEnvNames {
		t.Fatalf("env names = %d want %d", len(entry.EnvNames), maxEnvNames)
	}
	if !entry.EnvNamesTruncated {
		t.Fatal("truncation flag missing")
	}
	if len(entry.CwdSummary) != maxCwdSummaryBytes {
		t.Fatalf("cwd summary length = %d want %d", len(entry.CwdSummary), maxCwdSummaryBytes)
	}
}

func TestCreateNormalizesDestination(t *testing.T) {
	store := New(Config{})
	entry, err := store.Create(CreateRequest{
		Kind:            localv1.ApprovalKind_APPROVAL_KIND_MCP_CALL,
		DestinationHost: "HTTPS://secretuser@api.example.com/v1/items?page=2#frag",
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry.DestinationHost != "api.example.com" {
		t.Fatalf("host = %q", entry.DestinationHost)
	}
	if strings.Contains(entry.DestinationPath, "?") || strings.Contains(entry.DestinationPath, "#") {
		t.Fatalf("path leaks query/fragment: %q", entry.DestinationPath)
	}
}

func TestCreateClonesHeaders(t *testing.T) {
	store := New(Config{})
	header := &localv1.ApprovalHeader{Name: "Authorization", ValueClass: localv1.HeaderValueClass_HEADER_VALUE_CLASS_VAULT, VaultReferenceIds: []string{"vault-1"}}
	if _, err := store.Create(CreateRequest{Kind: localv1.ApprovalKind_APPROVAL_KIND_MCP_REGISTRATION, Headers: []*localv1.ApprovalHeader{header}}); err != nil {
		t.Fatal(err)
	}
	header.VaultReferenceIds[0] = "MUTATED"
	list := store.ListPending("")
	if len(list) != 1 || list[0].Headers[0].VaultReferenceIds[0] != "vault-1" {
		t.Fatalf("stored headers aliased caller memory: %+v", list[0].Headers)
	}
}

func TestListPendingFiltersAndExcludesResolved(t *testing.T) {
	store := New(Config{})
	a, err := store.Create(CreateRequest{Kind: localv1.ApprovalKind_APPROVAL_KIND_OTHER, SandboxID: "sb-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(CreateRequest{Kind: localv1.ApprovalKind_APPROVAL_KIND_OTHER, SandboxID: "sb-b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(a.ID, localv1.ApprovalDecision_APPROVAL_DECISION_DENY, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE); err != nil {
		t.Fatal(err)
	}
	if got := store.ListPending(""); len(got) != 1 || got[0].SandboxID != "sb-b" {
		t.Fatalf("pending after resolve: %+v", got)
	}
	if got := store.ListPending("sb-a"); len(got) != 0 {
		t.Fatalf("resolved entry listed for sb-a: %+v", got)
	}
	if entry, ok := store.Get(a.ID); !ok || entry.State != localv1.ApprovalState_APPROVAL_STATE_DENIED {
		t.Fatalf("resolved retention broken: %+v ok=%t", entry, ok)
	}
}

func TestResolveStates(t *testing.T) {
	store := New(Config{})
	entry, err := store.Create(CreateRequest{Kind: localv1.ApprovalKind_APPROVAL_KIND_HOST_COMMAND})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(entry.ID, localv1.ApprovalDecision_APPROVAL_DECISION_UNSPECIFIED, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.Get(entry.ID); got.State != localv1.ApprovalState_APPROVAL_STATE_PENDING {
		t.Fatal("unspecified decision changed state")
	}
	approved, err := store.Resolve(entry.ID, localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_EXACT)
	if err != nil || approved.State != localv1.ApprovalState_APPROVAL_STATE_APPROVED {
		t.Fatalf("approve: %+v err=%v", approved, err)
	}
	if _, err := store.Resolve("deadbeef", localv1.ApprovalDecision_APPROVAL_DECISION_DENY, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id err = %v", err)
	}
}

func TestRetentionCapacityAndWindow(t *testing.T) {
	now, clock := fixedClock(time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC))
	store := New(Config{Now: clock, Capacity: 2})
	ids := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		e, err := store.Create(CreateRequest{Kind: localv1.ApprovalKind_APPROVAL_KIND_OTHER})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Resolve(e.ID, localv1.ApprovalDecision_APPROVAL_DECISION_DENY, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
	}
	if _, ok := store.Get(ids[0]); ok {
		t.Fatal("oldest resolved entry exceeded capacity and survived")
	}
	if _, ok := store.Get(ids[2]); !ok {
		t.Fatal("newest resolved entry missing")
	}
	*now = now.Add(DefaultWindow + time.Hour)
	if _, ok := store.Get(ids[2]); ok {
		t.Fatal("resolved entry survived the retention window")
	}
}

func TestIDsUnique(t *testing.T) {
	store := New(Config{})
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		e, err := store.Create(CreateRequest{Kind: localv1.ApprovalKind_APPROVAL_KIND_OTHER})
		if err != nil {
			t.Fatal(err)
		}
		if seen[e.ID] {
			t.Fatalf("duplicate approval id %s", e.ID)
		}
		seen[e.ID] = true
	}
}
