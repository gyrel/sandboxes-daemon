package server

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/gyrel/sandboxes-daemon/internal/registrycredentials"
	"github.com/gyrel/sandboxes-daemon/internal/service"
	"github.com/gyrel/sandboxes-daemon/internal/servicesecrets"
	"github.com/gyrel/sandboxes-daemon/internal/store"
)

// sbxSecretItem mirrors commands.secretJSON from sbx v0.50.1.
type sbxSecretItem struct {
	Scope       string   `json:"scope"`
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Secret      string   `json:"secret,omitempty"`
	Username    string   `json:"username,omitempty"`
	Kind        string   `json:"kind,omitempty"`
	Source      string   `json:"source,omitempty"`
	Refresh     string   `json:"refresh,omitempty"`
	SecretType  string   `json:"secret_type,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	Header      string   `json:"header,omitempty"`
	Format      string   `json:"format,omitempty"`
	Env         string   `json:"env,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
}

type sbxSecretList struct {
	Secrets          []sbxSecretItem `json:"secrets"`
	CustomSecrets    []any           `json:"custom_secrets"`
	ShadowedServices []string        `json:"shadowed_services"`
	EnvOnlyCount     int             `json:"env_only_count"`
}

func sbxTime(unixSeconds int64) string {
	if unixSeconds == 0 {
		return ""
	}
	return time.Unix(unixSeconds, 0).UTC().Format(time.RFC3339)
}

func sbxServiceSecret(item *localv1.SecretSummary, createdAt int64) sbxSecretItem {
	scope := item.GetScope()
	if item.GetSandboxName() != "" {
		scope = item.GetSandboxName()
	}
	return sbxSecretItem{
		Scope: scope, Type: "service", Name: item.GetService(), Secret: "(stored)",
		Kind: item.GetSourceKind(), Source: item.GetOrigin(), Refresh: item.GetRefresh(),
		SecretType: item.GetSecretType(), CreatedAt: sbxTime(createdAt),
	}
}

func sbxRegistryCredential(item *localv1.RegistryCredentialSummary, createdAt int64) sbxSecretItem {
	scope := item.GetScope()
	if item.GetSandboxName() != "" {
		scope = item.GetSandboxName()
	}
	return sbxSecretItem{
		Scope: scope, Type: "registry", Name: item.GetRegistry(), Secret: "(stored)",
		Username: item.GetUsername(), Source: item.GetOrigin(), CreatedAt: sbxTime(createdAt),
	}
}

func TestSecretListRPCMatchesSbxJSONShape(t *testing.T) {
	ctx := context.Background()
	state, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	svc := service.New(state, nil)
	vault := &secretTestVault{values: make(map[string]string)}
	secretStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	registryStore, err := registrycredentials.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetServiceSecretStore(secretStore)
	svc.SetRegistryCredentialStore(registryStore)

	const synthetic = "synthetic-secret-value-do-not-print"
	secretServer := NewSecret(svc)
	if _, err := secretServer.Set(ctx, &localv1.SecretServiceSetRequest{
		Service: "github", Scope: "global", Value: []byte(synthetic),
	}); err != nil {
		t.Fatal(err)
	}
	registryServer := NewRegistryCredential(svc)
	if _, err := registryServer.Login(ctx, &localv1.RegistryCredentialServiceLoginRequest{
		Registry: "ghcr.io", Username: "alice", Password: []byte(synthetic),
	}); err != nil {
		t.Fatal(err)
	}

	secrets, err := secretServer.List(ctx, &localv1.SecretServiceListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets.GetSecrets()) != 1 {
		t.Fatalf("secrets=%+v", secrets.GetSecrets())
	}
	secret := secrets.GetSecrets()[0]
	if secret.GetCreatedAtUnix() == 0 || secret.GetUpdatedAtUnix() == 0 ||
		secret.GetSourceKind() != string(servicesecrets.SourceKindValue) ||
		secret.GetSecretType() != servicesecrets.SecretTypeAPIKey || secret.GetOrigin() != servicesecrets.OriginLocal {
		t.Fatalf("service metadata=%+v", secret)
	}

	credentials, err := registryServer.List(ctx, &localv1.RegistryCredentialServiceListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials.GetCredentials()) != 1 {
		t.Fatalf("credentials=%+v", credentials.GetCredentials())
	}
	credential := credentials.GetCredentials()[0]
	if credential.GetCreatedAtUnix() == 0 || credential.GetUpdatedAtUnix() == 0 ||
		credential.GetOrigin() != registrycredentials.OriginLocal {
		t.Fatalf("registry metadata=%+v", credential)
	}

	list := sbxSecretList{
		Secrets: []sbxSecretItem{
			sbxServiceSecret(secret, time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC).Unix()),
			sbxRegistryCredential(credential, time.Date(2026, 11, 16, 9, 10, 0, 0, time.UTC).Unix()),
		},
		CustomSecrets:    make([]any, 0),
		ShadowedServices: make([]string, 0),
	}
	got, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "secret_ls.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Git may check the golden file out with CRLF on Windows runners.
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(want)) {
		t.Fatalf("secret JSON shape mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestSecretRPCResponsesNeverCarrySecretMaterial(t *testing.T) {
	ctx := context.Background()
	state, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	svc := service.New(state, nil)
	vault := &secretTestVault{values: make(map[string]string)}
	secretStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	registryStore, err := registrycredentials.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetServiceSecretStore(secretStore)
	svc.SetRegistryCredentialStore(registryStore)

	const synthetic = "synthetic-secret-value-do-not-print"
	secretServer := NewSecret(svc)
	if _, err := secretServer.Set(ctx, &localv1.SecretServiceSetRequest{
		Service: "github", Scope: "global", Value: []byte(synthetic),
	}); err != nil {
		t.Fatal(err)
	}
	registryServer := NewRegistryCredential(svc)
	if _, err := registryServer.Login(ctx, &localv1.RegistryCredentialServiceLoginRequest{
		Registry: "ghcr.io", Username: "alice", Password: []byte(synthetic),
	}); err != nil {
		t.Fatal(err)
	}

	secrets, err := secretServer.List(ctx, &localv1.SecretServiceListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := registryServer.List(ctx, &localv1.RegistryCredentialServiceListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for name, message := range map[string]proto.Message{
		"secrets": secrets, "credentials": credentials,
	} {
		encoded, err := protojson.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), synthetic) {
			t.Fatalf("%s exposed a secret value: %s", name, encoded)
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"value", "password", "token", "secret_value", "reference", "command", "op_account", "aws_profile"} {
			if containsKey(decoded, forbidden) {
				t.Fatalf("%s contains forbidden field %q: %s", name, forbidden, encoded)
			}
		}
	}
}

func containsKey(value any, key string) bool {
	switch typed := value.(type) {
	case map[string]any:
		if _, ok := typed[key]; ok {
			return true
		}
		for _, nested := range typed {
			if containsKey(nested, key) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if containsKey(nested, key) {
				return true
			}
		}
	}
	return false
}
