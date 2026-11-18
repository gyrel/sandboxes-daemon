package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

type allowHostCommands struct {
	request HostCommandApprovalRequest
	err     error
}

func (a *allowHostCommands) ApproveHostCommand(_ context.Context, request HostCommandApprovalRequest) error {
	a.request = request
	return a.err
}

func commandForMarker(marker string) string {
	if runtime.GOOS == "windows" {
		return "echo marker > " + marker
	}
	return "printf marker > " + marker
}

func newSecretService(t *testing.T) (*Service, *servicesecrets.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "host-command.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, nil)
	vault, err := servicesecrets.NewStore(&fakeServiceSecretVault{items: make(map[string]string)})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetServiceSecretStore(vault)
	return svc, vault
}

func TestHostCommandSecretSourceRequiresApproval(t *testing.T) {
	svc, _ := newSecretService(t)
	marker := filepath.Join(t.TempDir(), "marker")
	_, err := svc.SetServiceSecretSource(context.Background(), "openai", servicesecrets.ScopeGlobal, "", servicesecrets.Source{
		Command: commandForMarker(marker),
	})
	if err == nil {
		t.Fatal("command source without an approval provider was accepted")
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("command ran without approval: %v", statErr)
	}
}

func TestHostCommandSecretSourceDeniedBeforeExecution(t *testing.T) {
	svc, _ := newSecretService(t)
	svc.SetHostCommandApprovalProvider(&allowHostCommands{err: errors.New("denied")})
	marker := filepath.Join(t.TempDir(), "marker")
	_, err := svc.SetServiceSecretSource(context.Background(), "openai", servicesecrets.ScopeGlobal, "sandbox-a", servicesecrets.Source{
		Command: commandForMarker(marker),
	})
	if err == nil {
		t.Fatal("denied command source was accepted")
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("denied command ran: %v", statErr)
	}
}

func TestHostCommandSecretSourceApprovalBindsExactRequest(t *testing.T) {
	svc, _ := newSecretService(t)
	approver := &allowHostCommands{}
	svc.SetHostCommandApprovalProvider(approver)
	const command = "printf synthetic-host-command"
	if _, err := svc.SetServiceSecretSource(context.Background(), "github", servicesecrets.ScopeSandbox, "sandbox-b", servicesecrets.Source{
		Command: command, NoVerify: true, Refresh: "on-demand",
	}); err != nil {
		t.Fatal(err)
	}
	want := HostCommandApprovalRequest{Command: command, Service: "github", Scope: servicesecrets.ScopeSandbox, SandboxName: "sandbox-b"}
	if approver.request != want {
		t.Fatalf("approval request = %+v, want %+v", approver.request, want)
	}
}
