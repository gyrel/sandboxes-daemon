// Package obslog wires the daemon's rotating file sink alongside the stderr
// handler installed by the launcher.
//
// The launcher (the `sbx daemon start` supervisor) redirects the daemon's
// stdout/stderr to $STATE/daemon.log for detached starts, so stderr must keep
// working. The file sink here is additive: every record is fanned out to the
// existing stderr handler and to a rotating JSON file owned by the daemon.
// Rotation caps disk usage so a detached daemon cannot grow the state directory
// without bound.
package obslog

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/gyrel/slogx/events"
	"github.com/gyrel/slogx/rotate"
)

const (
	// DefaultMaxSizeMiB is the default per-file size cap (8 MiB).
	DefaultMaxSizeMiB = 8
	// DefaultMaxFiles is the default number of archived files kept (5).
	DefaultMaxFiles = 5
	// DefaultTotalCapMiB is the default cap across the active file and archives
	// (64 MiB).
	DefaultTotalCapMiB = 64
	// QueueCapacity bounds the async write queue feeding the file sink.
	QueueCapacity = 2048
	// LogFileName is the rotating file's name inside the state directory.
	LogFileName = "daemon.log"
	// dropCheckInterval is how often the monitor samples the async drop counter.
	dropCheckInterval = time.Minute
)

// Config configures the rotating file sink. Zero size fields select the
// documented defaults.
type Config struct {
	StateDir    string
	MaxSizeMiB  uint64
	MaxFiles    int
	TotalCapMiB uint64
}

// RotateConfig maps the daemon log settings to a rotate.Config. Zero values
// select the documented defaults (8 MiB per file, 5 files, 64 MiB total).
func RotateConfig(maxSizeMiB uint64, maxFiles int, totalCapMiB uint64) rotate.Config {
	if maxSizeMiB == 0 {
		maxSizeMiB = DefaultMaxSizeMiB
	}
	if maxFiles == 0 {
		maxFiles = DefaultMaxFiles
	}
	if totalCapMiB == 0 {
		totalCapMiB = DefaultTotalCapMiB
	}
	return rotate.Config{
		MaxSizeBytes:  int64(maxSizeMiB) << 20,
		MaxFiles:      maxFiles,
		TotalCapBytes: int64(totalCapMiB) << 20,
	}
}

// Sink owns the rotating file sink and its drop monitor.
type Sink struct {
	async    *rotate.Async
	stderr   *slog.Logger
	queueCap int
	previous *slog.Logger
	cancel   context.CancelFunc
	done     chan struct{}
}

// Install opens the rotating file sink, fans slog.Default() out to the existing
// stderr handler and a JSON file handler, and starts the drop monitor. The
// previous default logger is restored by Close.
func Install(ctx context.Context, cfg Config) (*Sink, error) {
	previous := slog.Default()
	primary := previous.Handler()

	writer, err := rotate.New(filepath.Join(cfg.StateDir, LogFileName), RotateConfig(cfg.MaxSizeMiB, cfg.MaxFiles, cfg.TotalCapMiB))
	if err != nil {
		return nil, fmt.Errorf("open rotating log: %w", err)
	}
	async := rotate.NewAsync(writer, QueueCapacity)
	fileHandler := slog.NewJSONHandler(async, &slog.HandlerOptions{Level: slog.LevelDebug})

	// slog.SetDefault routes the stdlib log package through the new handler when
	// it is not a *defaultHandler. Wrapping the stdlib defaultHandler (the
	// "log-level control unavailable" fallback and the zero-config test default)
	// in the fan-out would otherwise deadlock: the fan-out calls the
	// defaultHandler, which writes via log.Output, whose destination was just
	// repointed at the fan-out. Restore the stdlib log output and flags so the
	// primary writes straight to stderr.
	previousLogWriter := log.Writer()
	previousLogFlags := log.Flags()
	slog.SetDefault(slog.New(&fanoutHandler{primary: primary, file: fileHandler}))
	log.SetOutput(previousLogWriter)
	log.SetFlags(previousLogFlags)

	monCtx, cancel := context.WithCancel(ctx)
	sink := &Sink{
		async:    async,
		stderr:   slog.New(primary),
		queueCap: QueueCapacity,
		previous: previous,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	go sink.monitor(monCtx)
	return sink, nil
}

// Flush drains records accepted so far and syncs the active file to disk.
func (s *Sink) Flush() error {
	return s.async.Flush()
}

// Close stops the drop monitor, restores the previous default logger, and
// drains, flushes and closes the file sink.
func (s *Sink) Close() error {
	s.cancel()
	<-s.done
	slog.SetDefault(s.previous)
	return s.async.Close()
}

// monitor samples the async drop counter and reports overflow to stderr only.
func (s *Sink) monitor(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(dropCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sampleDrops(ctx)
		}
	}
}

// sampleDrops drains the drop counter and, when records were dropped, emits
// gyrel.obs.log_dropped to the stderr logger. The event deliberately bypasses
// the file sink: the queue that just overflowed must not be asked to record its
// own failure, which would recurse (a dropped drop-report would itself bump the
// counter and trigger another report). The stderr logger was captured before the
// fan-out, so it never reaches the async file queue.
func (s *Sink) sampleDrops(ctx context.Context) uint64 {
	dropped := s.async.Dropped()
	if dropped == 0 {
		return 0
	}
	event, err := events.ObsLogDropped(events.OutcomeFailed, events.ObsLogDroppedParams{
		Component:    events.ComponentDaemon,
		DroppedCount: dropped,
		QueueLen:     uint64(s.queueCap), //nolint:gosec // capacity is a non-negative constant.
	})
	if err == nil {
		event.Emit(ctx, s.stderr, events.Standard{})
	}
	return dropped
}

// fanoutHandler writes each record to the stderr handler and the file handler.
// The stderr handler is the level gate: the file mirrors the stderr threshold so
// the two sinks stay consistent.
type fanoutHandler struct {
	primary slog.Handler
	file    slog.Handler
}

func (h *fanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.primary.Enabled(ctx, level)
}

func (h *fanoutHandler) Handle(ctx context.Context, r slog.Record) error { //nolint:gocritic // slog.Handler interface signature; Record is passed by value.
	return errors.Join(h.primary.Handle(ctx, r), h.file.Handle(ctx, r))
}

func (h *fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &fanoutHandler{primary: h.primary.WithAttrs(attrs), file: h.file.WithAttrs(attrs)}
}

func (h *fanoutHandler) WithGroup(name string) slog.Handler {
	return &fanoutHandler{primary: h.primary.WithGroup(name), file: h.file.WithGroup(name)}
}
