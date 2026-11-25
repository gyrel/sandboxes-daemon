package mcpmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRegistrationEventsRedactInputs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX executable fixture")
	}
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx := context.Background()
	manager, err := New(ctx, &memoryState{values: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	manager.SetApprovalProvider(testApprovalProvider{})
	command := filepath.Join(t.TempDir(), "synthetic-canary-command")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := manager.Register(ctx, "synthetic-canary-name", command, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApproveRegistration(ctx, id); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two events, got %s", output.String())
	}
	for i, line := range lines {
		var record struct {
			Event   string `json:"event"`
			Outcome string `json:"outcome"`
			Stored  bool   `json:"stored"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record.Event != "gyrel.mcp.register" || record.Outcome != "ok" || record.Stored != (i == 1) {
			t.Fatalf("unexpected event: %s", line)
		}
	}
	for _, canary := range []string{"synthetic-canary-name", "synthetic-canary-command", id} {
		if strings.Contains(output.String(), canary) {
			t.Fatalf("event leaked %q", canary)
		}
	}
}

func TestLoadEventRedactsInputs(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx := context.Background()
	manager, err := New(ctx, &memoryState{values: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	manager.servers["secret-shaped-server-value"] = Server{}
	if _, err := manager.Load(ctx, "secret-shaped-server-value", "secret-shaped-sandbox-value"); err != nil {
		t.Fatal(err)
	}
	var record struct {
		Event   string `json:"event"`
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record.Event != "gyrel.mcp.load" || record.Outcome != "ok" {
		t.Fatalf("unexpected event: %s", output.String())
	}
	if strings.Contains(output.String(), "secret-shaped-") {
		t.Fatalf("event leaked input: %s", output.String())
	}
}
