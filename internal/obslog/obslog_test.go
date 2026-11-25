package obslog

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rheic/slogx/rotate"
)

func TestRotateConfig(t *testing.T) {
	tests := []struct {
		name  string
		size  uint64
		files int
		cap   uint64
		want  rotate.Config
	}{
		{name: "defaults", want: rotate.Config{MaxSizeBytes: 8 << 20, MaxFiles: 5, TotalCapBytes: 64 << 20}},
		{name: "explicit", size: 16, files: 3, cap: 128, want: rotate.Config{MaxSizeBytes: 16 << 20, MaxFiles: 3, TotalCapBytes: 128 << 20}},
		{name: "partial files", files: 10, want: rotate.Config{MaxSizeBytes: 8 << 20, MaxFiles: 10, TotalCapBytes: 64 << 20}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := RotateConfig(test.size, test.files, test.cap)
			if got != test.want {
				t.Fatalf("RotateConfig(%d, %d, %d) = %+v, want %+v", test.size, test.files, test.cap, got, test.want)
			}
		})
	}
}

func TestInstallFansOutAndFlushes(t *testing.T) {
	prev := slog.Default()
	defer slog.SetDefault(prev)

	var primary bytes.Buffer
	base := slog.New(slog.NewJSONHandler(&primary, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(base)

	dir := t.TempDir()
	sink, err := Install(context.Background(), Config{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}

	slog.Info("fanout check", "k", "v")
	if err := sink.Flush(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(primary.String(), "fanout check") {
		t.Fatalf("primary sink did not receive record: %q", primary.String())
	}
	file, err := os.ReadFile(filepath.Join(dir, LogFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(file), "fanout check") {
		t.Fatalf("file sink did not receive record: %q", file)
	}

	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if slog.Default() != base {
		t.Fatal("slog.Default() was not restored to the pre-install logger")
	}
}

// gateWriter blocks its first Write until released, simulating a slow sink that
// makes a bounded async queue overflow.
type gateWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *gateWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(p), nil
}

func TestSampleDropsEmitsToStderrWithoutRecursion(t *testing.T) {
	gate := &gateWriter{started: make(chan struct{}), release: make(chan struct{})}
	async := rotate.NewAsync(gate, 1)
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(gate.release) })
		_ = async.Close()
	})

	var stderr bytes.Buffer
	stderrLogger := slog.New(slog.NewJSONHandler(&stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sink := &Sink{async: async, stderr: stderrLogger, queueCap: 1}

	for _, rec := range []string{"a", "b", "c", "d"} {
		if _, err := async.Write([]byte(rec)); err != nil {
			t.Fatal(err)
		}
	}
	<-gate.started // the first write is now blocked inside the slow sink

	dropped := sink.sampleDrops(context.Background())
	if dropped == 0 {
		t.Fatal("expected dropped records, got 0")
	}
	if got := async.Dropped(); got != 0 {
		t.Fatalf("drop counter not drained after sampleDrops: %d", got)
	}
	// A second sample must see nothing: the drop report went to stderr, not back
	// through the overflowing queue (no log-about-log recursion).
	if got := sink.sampleDrops(context.Background()); got != 0 {
		t.Fatalf("second sampleDrops reported %d drops, want 0 (recursion)", got)
	}

	var event map[string]any
	if err := json.Unmarshal(stderr.Bytes(), &event); err != nil {
		t.Fatalf("stderr output is not JSON: %v: %q", err, stderr.String())
	}
	if event["event"] != "rheic.obs.log_dropped" {
		t.Fatalf("event = %v, want rheic.obs.log_dropped", event["event"])
	}
	if event["component"] != "daemon" {
		t.Fatalf("component = %v, want daemon", event["component"])
	}
	dc, ok := event["dropped_count"].(float64)
	if !ok || uint64(dc) != dropped {
		t.Fatalf("dropped_count = %v, want %d", event["dropped_count"], dropped)
	}
	ql, ok := event["queue_len"].(float64)
	if !ok || uint64(ql) != 1 {
		t.Fatalf("queue_len = %v, want 1", event["queue_len"])
	}
}
