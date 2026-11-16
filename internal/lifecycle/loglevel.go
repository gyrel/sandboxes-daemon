package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DefaultLogLevel is used when no persisted level exists.
	DefaultLogLevel  = "info"
	logWatchInterval = 500 * time.Millisecond
	maxLogLevelBytes = 4096
)

var (
	// ErrInvalidLogLevel means a level is not one of debug, info, warn or error.
	ErrInvalidLogLevel = errors.New("invalid log level")
	// ErrInvalidLogCategory means a category is not general, proxy or all.
	ErrInvalidLogCategory = errors.New("invalid log category")
)

// Levels is the persistent per-category daemon log configuration. The proxy
// category is accepted for sbx grammar parity and reserved for proxy logs.
type Levels struct {
	General string `json:"general" yaml:"general"`
	Proxy   string `json:"proxy" yaml:"proxy"`
}

// DefaultLevels returns the startup log configuration.
func DefaultLevels() Levels {
	return Levels{General: DefaultLogLevel, Proxy: DefaultLogLevel}
}

// ValidateLevel checks the sbx log-level grammar.
func ValidateLevel(level string) error {
	switch level {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("%w %q (want debug|info|warn|error)", ErrInvalidLogLevel, level)
	}
}

// ValidateCategory checks a log-level target category.
func ValidateCategory(category string) error {
	switch category {
	case "general", "proxy", "all":
		return nil
	default:
		return fmt.Errorf("%w %q (want general|proxy|all)", ErrInvalidLogCategory, category)
	}
}

// ApplyLevel updates one category (or all) and returns the new configuration.
func ApplyLevel(current Levels, category, level string) (Levels, error) {
	if err := ValidateCategory(category); err != nil {
		return Levels{}, err
	}
	if err := ValidateLevel(level); err != nil {
		return Levels{}, err
	}
	switch category {
	case "general":
		current.General = level
	case "proxy":
		current.Proxy = level
	case "all":
		current.General = level
		current.Proxy = level
	}
	return current, nil
}

// LoadLevels reads the persisted configuration. A missing file yields defaults.
func LoadLevels(stateDir string) (Levels, error) {
	file, err := openPrivateRead(LevelPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return DefaultLevels(), nil
	}
	if err != nil {
		return Levels{}, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxLogLevelBytes))
	if err != nil {
		return Levels{}, fmt.Errorf("read log levels: %w", err)
	}
	var levels Levels
	if err := decodeLevels(data, &levels); err != nil {
		return Levels{}, err
	}
	if err := validateLevels(levels); err != nil {
		return Levels{}, err
	}
	return levels, nil
}

// WriteLevels validates and atomically persists a log configuration.
func WriteLevels(stateDir string, levels Levels) error {
	if err := validateLevels(levels); err != nil {
		return err
	}
	if err := ensurePrivateDir(stateDir); err != nil {
		return err
	}
	data, err := marshalLevels(levels)
	if err != nil {
		return err
	}
	if err := writePrivateFile(LevelPath(stateDir), data); err != nil {
		return fmt.Errorf("write log levels: %w", err)
	}
	return nil
}

// SetLevel validates and persists a category change.
func SetLevel(stateDir, category, level string) (Levels, error) {
	current, err := LoadLevels(stateDir)
	if err != nil {
		return Levels{}, err
	}
	next, err := ApplyLevel(current, category, level)
	if err != nil {
		return Levels{}, err
	}
	if err := WriteLevels(stateDir, next); err != nil {
		return Levels{}, err
	}
	return next, nil
}

// LevelPath returns the persisted log-level file path.
func LevelPath(stateDir string) string {
	return filepath.Join(stateDir, LogLevelFileName)
}

func validateLevels(levels Levels) error {
	if err := ValidateLevel(levels.General); err != nil {
		return fmt.Errorf("general: %w", err)
	}
	if err := ValidateLevel(levels.Proxy); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	return nil
}

// LogController applies persisted levels to the daemon's slog logger and
// watches the file for changes made by the CLI.
type LogController struct {
	stateDir string
	general  slog.LevelVar
	mu       sync.RWMutex
	levels   Levels
	stamp    fileStamp
}

type fileStamp struct {
	modTime time.Time
	size    int64
}

// OpenLogController loads the persisted levels, writes defaults when the file
// is absent, and returns a controller ready for the default slog handler.
func OpenLogController(stateDir string) (*LogController, error) {
	if err := ensurePrivateDir(stateDir); err != nil {
		return nil, err
	}
	levels, err := LoadLevels(stateDir)
	if err != nil {
		return nil, err
	}
	controller := &LogController{stateDir: stateDir}
	controller.apply(levels)
	if err := WriteLevels(stateDir, levels); err != nil {
		return nil, err
	}
	controller.stamp, _ = statStamp(LevelPath(stateDir))
	return controller, nil
}

// Leveler is the handler level for general daemon records.
func (c *LogController) Leveler() slog.Leveler {
	return &c.general
}

// Levels returns the active configuration.
func (c *LogController) Levels() Levels {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.levels
}

// Reload re-reads the file and applies valid changes.
func (c *LogController) Reload() error {
	levels, err := LoadLevels(c.stateDir)
	if err != nil {
		return err
	}
	c.apply(levels)
	c.stamp, _ = statStamp(LevelPath(c.stateDir))
	return nil
}

// Watch polls the level file until ctx is canceled. SIGHUP is not required so
// the same control surface works on Windows.
func (c *LogController) Watch(ctx context.Context) {
	ticker := time.NewTicker(logWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stamp, err := statStamp(LevelPath(c.stateDir))
			if err != nil || stamp == c.stamp {
				continue
			}
			if err := c.Reload(); err != nil {
				slog.Warn("reload log levels", "error", err)
			}
		}
	}
}

func (c *LogController) apply(levels Levels) {
	c.mu.Lock()
	c.levels = levels
	c.mu.Unlock()
	c.general.Set(parseLevel(levels.General))
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func decodeLevels(data []byte, levels *Levels) error {
	if err := json.Unmarshal(data, levels); err != nil {
		return fmt.Errorf("decode log levels: %w", err)
	}
	return nil
}

func marshalLevels(levels Levels) ([]byte, error) {
	data, err := json.Marshal(levels)
	if err != nil {
		return nil, fmt.Errorf("encode log levels: %w", err)
	}
	return append(data, '\n'), nil
}

func statStamp(path string) (fileStamp, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{modTime: info.ModTime(), size: info.Size()}, nil
}
