package lifecycle

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateLevelAndCategory(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		if err := ValidateLevel(level); err != nil {
			t.Errorf("ValidateLevel(%q) = %v", level, err)
		}
	}
	for _, level := range []string{"", "INFO", "warning", "trace", "nope"} {
		if err := ValidateLevel(level); !errors.Is(err, ErrInvalidLogLevel) {
			t.Errorf("ValidateLevel(%q) = %v, want ErrInvalidLogLevel", level, err)
		}
	}
	for _, category := range []string{"general", "proxy", "all"} {
		if err := ValidateCategory(category); err != nil {
			t.Errorf("ValidateCategory(%q) = %v", category, err)
		}
	}
	for _, category := range []string{"", "http", "all-proxy"} {
		if err := ValidateCategory(category); !errors.Is(err, ErrInvalidLogCategory) {
			t.Errorf("ValidateCategory(%q) = %v, want ErrInvalidLogCategory", category, err)
		}
	}
}

func TestApplyLevelMutatesOnlyRequestedCategories(t *testing.T) {
	levels := DefaultLevels()
	next, err := ApplyLevel(levels, "general", "debug")
	if err != nil || next.General != "debug" || next.Proxy != "info" {
		t.Fatalf("general = %+v, %v", next, err)
	}
	if levels.General != "info" {
		t.Fatalf("ApplyLevel mutated its input: %+v", levels)
	}
	next, err = ApplyLevel(next, "proxy", "error")
	if err != nil || next.General != "debug" || next.Proxy != "error" {
		t.Fatalf("proxy = %+v, %v", next, err)
	}
	next, err = ApplyLevel(next, "all", "warn")
	if err != nil || next.General != "warn" || next.Proxy != "warn" {
		t.Fatalf("all = %+v, %v", next, err)
	}
	if _, err := ApplyLevel(levels, "general", "verbose"); !errors.Is(err, ErrInvalidLogLevel) {
		t.Fatalf("invalid level error = %v", err)
	}
	if _, err := ApplyLevel(levels, "network", "debug"); !errors.Is(err, ErrInvalidLogCategory) {
		t.Fatalf("invalid category error = %v", err)
	}
}

func TestSetLevelPersistsAcrossReload(t *testing.T) {
	stateDir := t.TempDir()
	levels, err := SetLevel(stateDir, "general", "debug")
	if err != nil {
		t.Fatal(err)
	}
	if levels.General != "debug" || levels.Proxy != "info" {
		t.Fatalf("levels = %+v", levels)
	}
	loaded, err := LoadLevels(stateDir)
	if err != nil || loaded != levels {
		t.Fatalf("LoadLevels() = %+v, %v", loaded, err)
	}
	info, err := os.Stat(LevelPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("level file mode = %o", info.Mode().Perm())
	}
}

func TestLoadLevelsDefaultsWhenMissingAndRejectsMalformed(t *testing.T) {
	stateDir := t.TempDir()
	levels, err := LoadLevels(stateDir)
	if err != nil || levels != DefaultLevels() {
		t.Fatalf("LoadLevels() = %+v, %v", levels, err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, LogLevelFileName), []byte(`{"general":"loud","proxy":"info"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLevels(stateDir); !errors.Is(err, ErrInvalidLogLevel) {
		t.Fatalf("LoadLevels() = %v, want ErrInvalidLogLevel", err)
	}
}

func TestLogControllerReloadsChangedFile(t *testing.T) {
	stateDir := t.TempDir()
	controller, err := OpenLogController(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if controller.Levels() != DefaultLevels() {
		t.Fatalf("initial levels = %+v", controller.Levels())
	}
	if _, err := SetLevel(stateDir, "general", "debug"); err != nil {
		t.Fatal(err)
	}
	if err := controller.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := controller.Levels().General; got != "debug" {
		t.Fatalf("reloaded general = %q", got)
	}
	if got := controller.Leveler().Level(); got != slog.LevelDebug {
		t.Fatalf("leveler = %v, want debug", got)
	}
}

func TestLogControllerWatchObservesCliWrite(t *testing.T) {
	stateDir := t.TempDir()
	controller, err := OpenLogController(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go controller.Watch(ctx)
	if _, err := SetLevel(stateDir, "all", "warn"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if controller.Levels().General == "warn" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("watcher did not reload: %+v", controller.Levels())
}

func TestOpenLogControllerRepairsMissingFile(t *testing.T) {
	stateDir := t.TempDir()
	if _, err := OpenLogController(stateDir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(LevelPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"general":"info"`) {
		t.Fatalf("level file = %q", data)
	}
}
