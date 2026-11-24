package server

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/rheic/sandboxes-daemon/internal/customsecrets"
	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

type customRPCFixture struct {
	secrets *SecretServer
	vault   *secretTestVault
	dbPath  string
	logs    *bytes.Buffer
}

func newCustomRPCFixture(t *testing.T) customRPCFixture {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	state, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	vault := &secretTestVault{values: make(map[string]string)}
	serviceStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	customStore, err := customsecrets.NewStore(vault, servicesecrets.ErrNotFound)
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(state, nil)
	svc.SetServiceSecretStore(serviceStore)
	svc.SetCustomSecretStore(customStore)

	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return customRPCFixture{secrets: NewSecret(svc), vault: vault, dbPath: dbPath, logs: &logs}
}

func (f customRPCFixture) sqliteBytes(t *testing.T) []byte {
	t.Helper()
	var all []byte
	for _, path := range []string{f.dbPath, f.dbPath + "-wal", f.dbPath + "-shm"} {
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		all = append(all, data...)
	}
	return all
}

func TestSetCustomResponsesAndInventoryNeverCarryValue(t *testing.T) {
	ctx := context.Background()
	fixture := newCustomRPCFixture(t)
	const canary = "synthetic-rpc-canary-value-91be"
	response, err := fixture.secrets.SetCustom(ctx, &localv1.SecretServiceSetCustomRequest{
		Scope: "global", Value: []byte(canary), Env: "EXAMPLE_KEY", Hosts: []string{"api.example.test", "*.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	full := response.GetPlaceholder()
	if full == "" || strings.Contains(full, canary) || response.GetSecret().GetPlaceholderMasked() == full {
		t.Fatalf("placeholder=%q masked=%q", full, response.GetSecret().GetPlaceholderMasked())
	}
	if response.GetSecret().GetService() != "api.example.test" || response.GetSecret().GetEnvName() != "EXAMPLE_KEY" {
		t.Fatalf("summary=%+v", response.GetSecret())
	}
	if response.GetApprovalRequired() || response.GetApprovalId() != "" {
		t.Fatal("inline value must not request approval")
	}

	list, err := fixture.secrets.List(ctx, &localv1.SecretServiceListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetSecrets()) != 1 || list.GetSecrets()[0].GetPlaceholderMasked() == "" {
		t.Fatalf("list = %+v", list.GetSecrets())
	}

	for name, message := range map[string]proto.Message{"set-custom response": response, "list": list} {
		encoded, err := protojson.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), canary) {
			t.Fatalf("%s exposed the value: %s", name, encoded)
		}
		if name == "list" && strings.Contains(string(encoded), full) {
			t.Fatalf("inventory exposed the full placeholder: %s", encoded)
		}
	}
	if leaks := bytes.Count(fixture.sqliteBytes(t), []byte(canary)); leaks != 0 {
		t.Fatalf("value persisted in SQLite files: %d", leaks)
	}
	if bytes.Contains(fixture.sqliteBytes(t), []byte(full)) {
		t.Fatal("full placeholder persisted in SQLite files")
	}
	if !bytes.Contains(fixture.sqliteBytes(t), []byte(response.GetSecret().GetPlaceholderMasked())) {
		t.Fatal("positive control: masked placeholder missing from SQLite")
	}
	stored := false
	for _, value := range fixture.vault.values {
		stored = stored || strings.Contains(value, canary)
	}
	if !stored {
		t.Fatal("positive control: value not in the host keychain")
	}
	for _, needle := range []string{canary, full} {
		if strings.Contains(fixture.logs.String(), needle) {
			t.Fatalf("daemon logs leaked %q", needle)
		}
	}
}

func TestSetCustomValidationAndSourceCodes(t *testing.T) {
	ctx := context.Background()
	fixture := newCustomRPCFixture(t)
	cases := map[string]struct {
		request *localv1.SecretServiceSetCustomRequest
		code    codes.Code
	}{
		"value and source": {
			request: &localv1.SecretServiceSetCustomRequest{Value: []byte("v"), Hosts: []string{"api.example.test"},
				Source: &localv1.SecretSource{Reference: "op://vault/item/field"}},
			code: codes.InvalidArgument,
		},
		"neither value nor source": {
			request: &localv1.SecretServiceSetCustomRequest{Hosts: []string{"api.example.test"}},
			code:    codes.InvalidArgument,
		},
		"reference source without approval": {
			request: &localv1.SecretServiceSetCustomRequest{Hosts: []string{"api.example.test"},
				Source: &localv1.SecretSource{Reference: "op://vault/item/field"}},
			code: codes.OK,
		},
		"command source without approval": {
			request: &localv1.SecretServiceSetCustomRequest{Hosts: []string{"api.example.test"},
				Source: &localv1.SecretSource{Command: "echo synthetic"}},
			code: codes.OK,
		},
		"invalid host": {
			request: &localv1.SecretServiceSetCustomRequest{Value: []byte("v"), Hosts: []string{"user@api.example.test"}},
			code:    codes.InvalidArgument,
		},
		"placeholder equals value": {
			request: &localv1.SecretServiceSetCustomRequest{Value: []byte("synthetic-equal"), Hosts: []string{"api.example.test"}, Placeholder: "synthetic-equal"},
			code:    codes.InvalidArgument,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := fixture.secrets.SetCustom(ctx, tc.request)
			if got := status.Code(err); got != tc.code {
				t.Fatalf("code = %v (%v), want %v", got, err, tc.code)
			}
		})
	}
	if len(fixture.vault.values) != 0 {
		t.Fatalf("rejected SetCustom requests wrote %d keychain items", len(fixture.vault.values))
	}
	list, err := fixture.secrets.List(ctx, &localv1.SecretServiceListRequest{})
	if err != nil || len(list.GetSecrets()) != 0 {
		t.Fatalf("rejected SetCustom requests wrote inventory: %+v, %v", list, err)
	}
}

func TestRemoveRPCPrefersCustomAndKeepsServiceSecretFallback(t *testing.T) {
	ctx := context.Background()
	fixture := newCustomRPCFixture(t)
	if _, err := fixture.secrets.Set(ctx, &localv1.SecretServiceSetRequest{Service: "github", Scope: "global", Value: []byte("synthetic-github-value")}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.secrets.SetCustom(ctx, &localv1.SecretServiceSetCustomRequest{
		Service: "api.example.test", Scope: "global", Value: []byte("synthetic-custom-value"), Hosts: []string{"api.example.test"}}); err != nil {
		t.Fatal(err)
	}

	removed, err := fixture.secrets.Remove(ctx, &localv1.SecretServiceRemoveRequest{Service: "api.example.test", Scope: "global"})
	if err != nil || !removed.GetRemoved() {
		t.Fatalf("custom remove = %+v, %v", removed, err)
	}
	fallback, err := fixture.secrets.Remove(ctx, &localv1.SecretServiceRemoveRequest{Service: "github", Scope: "global"})
	if err != nil || !fallback.GetRemoved() {
		t.Fatalf("service fallback remove = %+v, %v", fallback, err)
	}
	// Once the custom entry is gone, the name is unknown to both namespaces. The
	// service-secret path reports that as it always has, rather than succeeding.
	if none, err := fixture.secrets.Remove(ctx, &localv1.SecretServiceRemoveRequest{Service: "api.example.test", Scope: "global"}); err == nil || none.GetRemoved() {
		t.Fatalf("second remove = %+v, %v; want an error for an unknown service", none, err)
	}
	list, err := fixture.secrets.List(ctx, &localv1.SecretServiceListRequest{})
	if err != nil || len(list.GetSecrets()) != 0 {
		t.Fatalf("inventory after removals = %+v, %v", list.GetSecrets(), err)
	}
}
