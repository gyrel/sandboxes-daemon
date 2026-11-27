package redactcheck_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gyrel/sandboxes-core/sandbox"
	runtime "github.com/gyrel/sandboxes-runtime"
	_ "modernc.org/sqlite"

	"github.com/gyrel/sandboxes-daemon/internal/service"
	"github.com/gyrel/sandboxes-daemon/internal/store"
	"github.com/gyrel/sandboxes-daemon/internal/testsupport/redactcheck"
)

const maxCaptureBytes = 4 << 20

// logSink is an in-memory slog handler sink. It deliberately uses the plain
// standard-library JSON handler, not the production slogx handler: production
// redaction must not be able to hide a leak from this control.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf.Len() < maxCaptureBytes {
		remaining := maxCaptureBytes - s.buf.Len()
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = s.buf.Write(p)
	}
	return len(p), nil
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *logSink) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Reset()
}

type fakeBackend struct {
	mu    sync.Mutex
	execs []runtime.ExecRequest
	ports []runtime.Port
}

func (f *fakeBackend) Capabilities(context.Context) (runtime.Capabilities, error) {
	return runtime.Capabilities{Workspace: true}, nil
}

func (f *fakeBackend) Create(_ context.Context, cfg runtime.Config) (runtime.Handle, error) {
	return runtime.Handle{ID: "gyrel-" + cfg.Name, Ports: cfg.Ports}, nil
}

func (f *fakeBackend) Start(context.Context, runtime.Handle) error { return nil }

func (f *fakeBackend) Stop(context.Context, runtime.Handle, time.Duration) error { return nil }

func (f *fakeBackend) Delete(context.Context, runtime.Handle) error { return nil }

func (f *fakeBackend) Handle(name string) runtime.Handle {
	return runtime.Handle{ID: "gyrel-" + name}
}

func (f *fakeBackend) Exec(_ context.Context, _ runtime.Handle, req runtime.ExecRequest) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, req)
	return 0, nil
}

func (f *fakeBackend) ExecNative(_ context.Context, _ runtime.Handle, req runtime.ExecRequest) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, req)
	return 0, nil
}

func (f *fakeBackend) UpdatePorts(_ context.Context, _ runtime.Handle, ports []runtime.Port) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ports = append([]runtime.Port(nil), ports...)
	return nil
}

type harness struct {
	ctx     context.Context
	t       *testing.T
	root    string
	dbPath  string
	store   *store.Store
	backend *fakeBackend
	svc     *service.Service
	logs    *logSink
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "daemon.sqlite")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	backend := &fakeBackend{}
	h := &harness{
		ctx:     ctx,
		t:       t,
		root:    root,
		dbPath:  dbPath,
		store:   st,
		backend: backend,
		svc:     service.New(st, backend),
		logs:    &logSink{},
	}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		slog.SetDefault(previous)
		_ = h.svc.Close()
		_ = st.Close()
	})
	return h
}

func (h *harness) scanOptions() redactcheck.Options {
	return redactcheck.Options{
		AllowRoot:  h.root,
		HomeDir:    currentHome(),
		GuestRoots: []string{"/workspace"},
	}
}

func currentHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

type scenario struct {
	name string
	verb string
	run  func(context.Context, *harness) (any, error)
}

func harnessScenarios() []scenario {
	return []scenario{
		{name: "create-ok", verb: "create", run: scenarioCreateOK},
		{name: "create-workspace-root", verb: "create", run: scenarioCreateWorkspaceRoot},
		{name: "create-invalid-name", verb: "create", run: scenarioCreateInvalidName},
		{name: "create-invalid-workspace", verb: "create", run: scenarioCreateInvalidWorkspace},
		{name: "exec-ok", verb: "exec", run: scenarioExecOK},
		{name: "exec-unknown", verb: "exec", run: scenarioExecUnknown},
		{name: "list-ok", verb: "list", run: scenarioListOK},
		{name: "stop-ok", verb: "stop", run: scenarioStopOK},
		{name: "stop-unknown", verb: "stop", run: scenarioStopUnknown},
		{name: "remove-ok", verb: "remove", run: scenarioRemoveOK},
		{name: "remove-unknown", verb: "remove", run: scenarioRemoveUnknown},
		{name: "ports-ok", verb: "ports", run: scenarioPortsOK},
		{name: "ports-invalid", verb: "ports", run: scenarioPortsInvalid},
	}
}

func scenarioCreateOK(ctx context.Context, h *harness) (any, error) {
	return h.svc.Create(ctx, service.CreateRequest{Name: "create-ok"})
}

func scenarioCreateWorkspaceRoot(ctx context.Context, h *harness) (any, error) {
	return h.svc.Create(ctx, service.CreateRequest{Name: "create-root", Workspace: h.root})
}

func scenarioCreateInvalidName(ctx context.Context, h *harness) (any, error) {
	return h.svc.Create(ctx, service.CreateRequest{Name: "../escape"})
}

func scenarioCreateInvalidWorkspace(ctx context.Context, h *harness) (any, error) {
	return h.svc.Create(ctx, service.CreateRequest{Name: "bad-workspace", Workspace: "relative/path"})
}

func scenarioExecOK(ctx context.Context, h *harness) (any, error) {
	op, err := h.svc.Create(ctx, service.CreateRequest{Name: "exec-ok"})
	if err != nil {
		return nil, err
	}
	exit, err := h.svc.Exec(ctx, op.SandboxID, runtime.ExecRequest{Argv: []string{"echo", "redaction-check"}})
	return map[string]any{"exit": exit}, err
}

func scenarioExecUnknown(ctx context.Context, h *harness) (any, error) {
	return h.svc.Exec(ctx, "sb_missing", runtime.ExecRequest{Argv: []string{"true"}})
}

func scenarioListOK(ctx context.Context, h *harness) (any, error) {
	for _, name := range []string{"list-a", "list-b"} {
		if _, err := h.svc.Create(ctx, service.CreateRequest{Name: name}); err != nil {
			return nil, err
		}
	}
	list, _, err := h.svc.List(ctx, sandbox.ListOptions{})
	return list, err
}

func scenarioStopOK(ctx context.Context, h *harness) (any, error) {
	op, err := h.svc.Create(ctx, service.CreateRequest{Name: "stop-ok"})
	if err != nil {
		return nil, err
	}
	return h.svc.Stop(ctx, op.SandboxID)
}

func scenarioStopUnknown(ctx context.Context, h *harness) (any, error) {
	return h.svc.Stop(ctx, "sb_missing")
}

func scenarioRemoveOK(ctx context.Context, h *harness) (any, error) {
	op, err := h.svc.Create(ctx, service.CreateRequest{Name: "remove-ok"})
	if err != nil {
		return nil, err
	}
	if _, err := h.svc.Stop(ctx, op.SandboxID); err != nil {
		return nil, err
	}
	return h.svc.Delete(ctx, op.SandboxID, false)
}

func scenarioRemoveUnknown(ctx context.Context, h *harness) (any, error) {
	return h.svc.Delete(ctx, "sb_missing", false)
}

func scenarioPortsOK(ctx context.Context, h *harness) (any, error) {
	op, err := h.svc.Create(ctx, service.CreateRequest{Name: "ports-ok"})
	if err != nil {
		return nil, err
	}
	port := availableHostTCPPort(h.t)
	updated, err := h.svc.UpdatePorts(ctx, op.SandboxID, []sandbox.Port{{Host: port, Guest: 8080}})
	if err != nil {
		return nil, err
	}
	cleared, err := h.svc.UpdatePorts(ctx, op.SandboxID, nil)
	return map[string]any{"host_port": port, "updated": updated.Ports, "cleared": cleared.Ports}, err
}

func scenarioPortsInvalid(ctx context.Context, h *harness) (any, error) {
	op, err := h.svc.Create(ctx, service.CreateRequest{Name: "ports-invalid"})
	if err != nil {
		return nil, err
	}
	return h.svc.UpdatePorts(ctx, op.SandboxID, []sandbox.Port{{Host: 0, Guest: 80}})
}

func availableHostTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate host port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release host port: %v", err)
	}
	return uint16(port)
}

func (h *harness) artifacts(name string, result any, runErr error) ([]redactcheck.Artifact, error) {
	var artifacts []redactcheck.Artifact
	if runErr != nil {
		artifacts = append(artifacts, redactcheck.Artifact{Name: "error:" + name, Data: []byte(runErr.Error())})
	}
	if result != nil {
		data, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("marshal result for %s: %w", name, err)
		}
		artifacts = append(artifacts, redactcheck.Artifact{Name: "result:" + name, Data: data})
	}
	if logs := h.logs.String(); logs != "" {
		artifacts = append(artifacts, redactcheck.Artifact{Name: "slog:" + name, Data: []byte(logs)})
	}
	audit, err := h.auditArtifacts(name)
	if err != nil {
		return nil, err
	}
	artifacts = append(artifacts, audit...)
	rows, err := h.sqliteArtifacts(name)
	if err != nil {
		return nil, err
	}
	artifacts = append(artifacts, rows...)
	return artifacts, nil
}

func (h *harness) auditArtifacts(name string) ([]redactcheck.Artifact, error) {
	var artifacts []redactcheck.Artifact
	err := filepath.WalkDir(h.root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(h.root, path)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, redactcheck.Artifact{Name: "audit:" + name + ":" + filepath.ToSlash(rel), Data: data})
		return nil
	})
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Name < artifacts[j].Name })
	return artifacts, err
}

func (h *harness) sqliteArtifacts(name string) ([]redactcheck.Artifact, error) {
	db, err := sql.Open("sqlite", "file:"+h.dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open sqlite read-only: %w", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list sqlite tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			_ = rows.Close()
			return nil, err
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	var artifacts []redactcheck.Artifact
	for _, table := range tables {
		tableRows, err := db.Query(`SELECT * FROM "` + strings.ReplaceAll(table, `"`, `""`) + `"`)
		if err != nil {
			return nil, fmt.Errorf("read sqlite table %s: %w", table, err)
		}
		columns, err := tableRows.Columns()
		if err != nil {
			_ = tableRows.Close()
			return nil, err
		}
		rowIndex := 0
		for tableRows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := tableRows.Scan(pointers...); err != nil {
				_ = tableRows.Close()
				return nil, err
			}
			var record strings.Builder
			for i, column := range columns {
				if i != 0 {
					record.WriteByte('\t')
				}
				record.WriteString(column)
				record.WriteByte('=')
				record.WriteString(sqlValue(values[i]))
			}
			artifacts = append(artifacts, redactcheck.Artifact{
				Name: fmt.Sprintf("sqlite:%s:%s:%d", name, table, rowIndex),
				Data: []byte(record.String()),
			})
			rowIndex++
		}
		if err := tableRows.Err(); err != nil {
			_ = tableRows.Close()
			return nil, err
		}
		_ = tableRows.Close()
	}
	return artifacts, nil
}

func sqlValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return "NULL"
	case []byte:
		return string(typed)
	default:
		return fmt.Sprint(typed)
	}
}

func assertClean(t *testing.T, scenarioName string, artifacts []redactcheck.Artifact, opts redactcheck.Options) {
	t.Helper()
	findings := redactcheck.ScanArtifacts(artifacts, opts)
	for _, finding := range findings {
		t.Errorf("LEAK %s (scenario %s)\n%s", finding, scenarioName, findingContext(finding, artifacts))
	}
	if len(findings) != 0 {
		t.Fatalf("scenario %s produced %d redaction findings across %d artifacts", scenarioName, len(findings), len(artifacts))
	}
}

// findingContext renders the artifact bytes around a finding so a CI failure
// names the exact spelling that escaped the allowlist. Only test-owned artifact
// data is shown; the finding itself still never retains the matched value.
func findingContext(finding redactcheck.Finding, artifacts []redactcheck.Artifact) string {
	var data []byte
	for _, artifact := range artifacts {
		if artifact.Name == finding.Artifact {
			data = artifact.Data
			break
		}
	}
	return "diagnostic " + diagnosticWindow(data, finding.Offset)
}

// diagnosticWindow escapes the slice [offset-64, offset+128) of data, clipped
// to data. Non-printable bytes are escaped so a raw NUL or JSON escape is
// visible in the failure output.
func diagnosticWindow(data []byte, offset int64) string {
	if len(data) == 0 {
		return "artifact=<empty>"
	}
	position := int(offset)
	if position < 0 {
		position = 0
	}
	if position > len(data) {
		position = len(data)
	}
	start := position - 64
	if start < 0 {
		start = 0
	}
	end := position + 128
	if end > len(data) {
		end = len(data)
	}
	return fmt.Sprintf("bytes[%d:%d] offset=%d %s", start, end, offset, escapeNonPrintable(data[start:end]))
}

func escapeNonPrintable(data []byte) string {
	var escaped strings.Builder
	escaped.Grow(len(data))
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			escaped.WriteByte(b)
			continue
		}
		fmt.Fprintf(&escaped, `\x%02x`, b)
	}
	return escaped.String()
}

func TestRedactionHarness(t *testing.T) {
	scenarios := harnessScenarios()
	if len(scenarios) < 8 {
		t.Fatalf("harness has %d scenarios, want at least 8", len(scenarios))
	}
	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			h := newHarness(t)
			result, runErr := sc.run(h.ctx, h)
			artifacts, err := h.artifacts(sc.name, result, runErr)
			if err != nil {
				t.Fatalf("collect artifacts: %v", err)
			}
			assertClean(t, sc.name, artifacts, h.scanOptions())
			t.Logf("POS verb=%s scenario=%s artifacts=%d findings=0 returned_error=%t", sc.verb, sc.name, len(artifacts), runErr != nil)
		})
	}
}

func TestRedactionHarnessDetectionControl(t *testing.T) {
	h := newHarness(t)
	result, runErr := scenarioCreateInvalidName(h.ctx, h)
	baseline, err := h.artifacts("detection-control", result, runErr)
	if err != nil {
		t.Fatalf("collect baseline artifacts: %v", err)
	}
	opts := h.scanOptions()
	if findings := redactcheck.ScanArtifacts(baseline, opts); len(findings) != 0 {
		t.Fatalf("detection-control baseline is not clean: %+v", findings)
	}
	injected := append(append([]redactcheck.Artifact(nil), baseline...), redactcheck.Artifact{
		Name: "error:injected",
		Data: []byte("copy failed: open /Users/someone/secret.key: permission denied"),
	})
	findings := redactcheck.ScanArtifacts(injected, opts)
	if len(findings) == 0 {
		t.Fatal("detection control failed: injected /Users/someone/secret.key was not detected")
	}
	named := false
	for _, finding := range findings {
		t.Logf("NEG finding: %s", finding)
		if finding.Artifact == "error:injected" && strings.HasPrefix(finding.Rule, "host_path_") {
			named = true
		}
	}
	if !named {
		t.Fatalf("detection control failed: findings did not name error:injected as a host path: %+v", findings)
	}
}

func TestRedactionHarnessSecretRules(t *testing.T) {
	opts := redactcheck.Options{AllowRoot: "/tmp/redactcheck-allow", HomeDir: "/Users/someone"}
	cases := []struct {
		name string
		data string
		rule string
	}{
		{"openai", "sk-abcdefghijklmnop", redactcheck.RuleOpenAIKey},
		{"aws", "AKIAABCDEFGHIJKLMNOP", redactcheck.RuleAWSAccessKey},
		{"github", "ghp_abcdefghijklmnop", redactcheck.RuleGitHubToken},
		{"slack", "xoxb-1234567890-abcdefgh", redactcheck.RuleSlackToken},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.payload", redactcheck.RuleJWTPrefix},
		{"pem", "-----BEGIN PRIVATE KEY-----", redactcheck.RulePEMPrivateKey},
		{"base64", "QWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OTAx", redactcheck.RuleHighEntropyB64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := "error:" + tc.name
			findings := redactcheck.ScanArtifacts([]redactcheck.Artifact{{Name: name, Data: []byte(tc.data)}}, opts)
			if len(findings) == 0 {
				t.Fatalf("canary %s was not detected", tc.name)
			}
			for _, finding := range findings {
				if finding.Artifact != name || finding.Rule != tc.rule {
					t.Fatalf("canary %s finding = %s, want artifact %s rule %s", tc.name, finding, name, tc.rule)
				}
			}
		})
	}
}

func TestRedactionHarnessAuditCollector(t *testing.T) {
	h := newHarness(t)
	auditDir := filepath.Join(h.root, "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatal(err)
	}
	safePath := filepath.Join(auditDir, "safe.audit.jsonl")
	if err := os.WriteFile(safePath, []byte(`{"decision":"allow","sandbox_id":"sbx_test"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifacts, err := h.artifacts("audit-safe", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	foundSafe := false
	for _, artifact := range artifacts {
		if artifact.Name == "audit:audit-safe:audit/safe.audit.jsonl" {
			foundSafe = true
		}
	}
	if !foundSafe {
		t.Fatalf("audit collector did not capture safe.audit.jsonl: %+v", artifactNames(artifacts))
	}
	assertClean(t, "audit-safe", artifacts, h.scanOptions())

	leakPath := filepath.Join(auditDir, "leaky.audit.jsonl")
	if err := os.WriteFile(leakPath, []byte(`{"leak":"/Users/someone/secret.key"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifacts, err = h.artifacts("audit-leaky", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	findings := redactcheck.ScanArtifacts(artifacts, h.scanOptions())
	named := false
	for _, finding := range findings {
		if finding.Artifact == "audit:audit-leaky:audit/leaky.audit.jsonl" {
			named = true
			t.Logf("audit detection control: %s", finding)
		}
	}
	if !named {
		t.Fatalf("audit detection control failed: %+v", findings)
	}
}

func artifactNames(artifacts []redactcheck.Artifact) []string {
	names := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		names = append(names, artifact.Name)
	}
	sort.Strings(names)
	return names
}
