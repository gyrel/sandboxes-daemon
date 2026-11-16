// Package lifecycle defines the local daemon control surface.
//
// The daemon cannot supervise its own process. This package therefore keeps a
// small, private control record in the daemon state directory so a local
// supervisor (the CLI) can prove which process owns the state directory before
// it starts, stops or restarts the daemon. The record is written after the
// daemon socket is listening and removed on graceful shutdown.
//
// The on-disk contract is deliberately small and stable:
//
//   - daemon.installation contains one random installation identifier.
//   - daemon.control.json contains the installation identifier, state
//     directory, socket, PID, and an opaque process-start identifier.
//   - daemon.loglevel.json contains the persistent general/proxy log levels.
//
// A supervisor must refuse to signal a PID unless the current process-start
// identifier still matches the recorded one, the record names the same state
// directory and socket, and the installation identifier matches. Missing or
// unverifiable identity data fails closed.
package lifecycle

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	// ControlFileName is the private daemon identity record.
	ControlFileName = "daemon.control.json"
	// InstallationFileName stores the random state-directory installation ID.
	InstallationFileName = "daemon.installation"
	// LogLevelFileName stores the persistent per-category log levels.
	LogLevelFileName = "daemon.loglevel.json"
	// SchemaVersion is the current control-record schema.
	SchemaVersion  = 1
	maxRecordBytes = 64 << 10
)

var installationIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

var (
	// ErrNoRecord means the state directory has no daemon control record.
	ErrNoRecord = errors.New("daemon control record not found")
	// ErrInvalidRecord means the control record is malformed or incomplete.
	ErrInvalidRecord = errors.New("daemon control record is invalid")
	// ErrInstallationMismatch means the record belongs to another installation.
	ErrInstallationMismatch = errors.New("daemon control record belongs to another installation")
	// ErrProcessNotFound means the recorded PID no longer exists.
	ErrProcessNotFound = errors.New("daemon process not found")
	// ErrIdentityMismatch means the PID now belongs to a different process.
	ErrIdentityMismatch = errors.New("daemon process identity does not match the control record")
	// ErrIdentityUnverifiable means the process identity could not be proven.
	ErrIdentityUnverifiable = errors.New("daemon process identity cannot be verified")
)

// Record is the private on-disk descriptor of the running daemon process.
type Record struct {
	SchemaVersion  int       `json:"schema_version"`
	InstallationID string    `json:"installation_id"`
	StateDir       string    `json:"state_dir"`
	Socket         string    `json:"socket"`
	PID            int       `json:"pid"`
	ProcessStartID string    `json:"process_start_id"`
	StartedAt      time.Time `json:"started_at"`
	Version        string    `json:"version,omitempty"`
}

// Scope identifies the installation a supervisor intends to control.
type Scope struct {
	StateDir string
	Socket   string
}

// Canonical returns the absolute, cleaned form of the scope.
func (s Scope) Canonical() (Scope, error) {
	stateDir, err := canonicalPath(s.StateDir)
	if err != nil {
		return Scope{}, fmt.Errorf("resolve state directory: %w", err)
	}
	socket, err := canonicalPath(s.Socket)
	if err != nil {
		return Scope{}, fmt.Errorf("resolve socket: %w", err)
	}
	return Scope{StateDir: stateDir, Socket: socket}, nil
}

// ControlPath returns the control-record path for a state directory.
func ControlPath(stateDir string) string {
	return filepath.Join(stateDir, ControlFileName)
}

// InstallationPath returns the installation-ID path for a state directory.
func InstallationPath(stateDir string) string {
	return filepath.Join(stateDir, InstallationFileName)
}

// EnsureInstallationID reads or creates the random installation identifier.
func EnsureInstallationID(stateDir string) (string, error) {
	path := InstallationPath(stateDir)
	id, err := readInstallationID(path)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := ensurePrivateDir(stateDir); err != nil {
		return "", err
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate installation identifier: %w", err)
	}
	id = hex.EncodeToString(buf)
	file, err := openExclusivePrivate(path)
	if errors.Is(err, os.ErrExist) {
		return readInstallationID(path)
	}
	if err != nil {
		return "", fmt.Errorf("create installation identifier: %w", err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString(id + "\n"); err != nil {
		return "", fmt.Errorf("write installation identifier: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync installation identifier: %w", err)
	}
	return id, nil
}

func readInstallationID(path string) (string, error) {
	file, err := openPrivateRead(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return "", fmt.Errorf("read installation identifier: %w", err)
	}
	id := string(data)
	if id != "" && id[len(id)-1] == '\n' {
		id = id[:len(id)-1]
	}
	if !installationIDPattern.MatchString(id) {
		return "", fmt.Errorf("%w: installation identifier is malformed", ErrInvalidRecord)
	}
	return id, nil
}

// ReadRecord reads and validates the private control record.
func ReadRecord(stateDir string) (Record, error) {
	file, err := openPrivateRead(ControlPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, fmt.Errorf("%w: %s", ErrNoRecord, ControlPath(stateDir))
	}
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = file.Close() }()
	var record Record
	decoder := json.NewDecoder(io.LimitReader(file, maxRecordBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fmt.Errorf("%w: decode control record: %w", ErrInvalidRecord, err)
	}
	if err := validateRecordFields(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validateRecordFields(record Record) error {
	if record.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported schema version %d", ErrInvalidRecord, record.SchemaVersion)
	}
	if !installationIDPattern.MatchString(record.InstallationID) {
		return fmt.Errorf("%w: installation identifier is malformed", ErrInvalidRecord)
	}
	if record.StateDir == "" || record.Socket == "" {
		return fmt.Errorf("%w: state directory and socket are required", ErrInvalidRecord)
	}
	if record.PID <= 0 || record.ProcessStartID == "" {
		return fmt.Errorf("%w: PID and process start identity are required", ErrInvalidRecord)
	}
	return nil
}

// WriteRecord atomically replaces the private control record.
func WriteRecord(stateDir string, record Record) error {
	if err := validateRecordFields(record); err != nil {
		return err
	}
	if err := ensurePrivateDir(stateDir); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode control record: %w", err)
	}
	data = append(data, '\n')
	if err := writePrivateFile(ControlPath(stateDir), data); err != nil {
		return fmt.Errorf("write control record: %w", err)
	}
	return nil
}

// RemoveRecord removes the control record only when it still names the supplied
// process identity. A missing or different record is left untouched.
func RemoveRecord(stateDir string, record Record) error {
	current, err := ReadRecord(stateDir)
	if errors.Is(err, ErrNoRecord) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.InstallationID != record.InstallationID ||
		current.PID != record.PID ||
		current.ProcessStartID != record.ProcessStartID {
		return fmt.Errorf("%w: refusing to remove a different process record", ErrIdentityMismatch)
	}
	if err := os.Remove(ControlPath(stateDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove control record: %w", err)
	}
	return nil
}

// CheckInstallation checks that a record names the requested installation.
func CheckInstallation(record Record, scope Scope, installationID string) error {
	if err := validateRecordFields(record); err != nil {
		return err
	}
	if record.InstallationID != installationID {
		return fmt.Errorf("%w: record %s, installation %s", ErrInstallationMismatch, record.InstallationID, installationID)
	}
	canonical, err := scope.Canonical()
	if err != nil {
		return err
	}
	recordState, err := canonicalPath(record.StateDir)
	if err != nil {
		return fmt.Errorf("%w: invalid recorded state directory: %w", ErrInvalidRecord, err)
	}
	recordSocket, err := canonicalPath(record.Socket)
	if err != nil {
		return fmt.Errorf("%w: invalid recorded socket: %w", ErrInvalidRecord, err)
	}
	if !samePath(recordState, canonical.StateDir) {
		return fmt.Errorf("%w: record state directory %s, requested %s", ErrInstallationMismatch, recordState, canonical.StateDir)
	}
	if !samePath(recordSocket, canonical.Socket) {
		return fmt.Errorf("%w: record socket %s, requested %s", ErrInstallationMismatch, recordSocket, canonical.Socket)
	}
	return nil
}

// Verify checks that a record belongs to the requested installation and still
// names the live process. An inspector error that means "no such process" is
// reported as ErrProcessNotFound; every other lookup failure fails closed as
// ErrIdentityUnverifiable.
func Verify(record Record, scope Scope, installationID string, inspector ProcessInspector) error {
	if err := CheckInstallation(record, scope, installationID); err != nil {
		return err
	}
	current, err := inspector.StartIdentity(record.PID)
	if err != nil {
		if errors.Is(err, ErrProcessNotFound) {
			return fmt.Errorf("%w: PID %d", ErrProcessNotFound, record.PID)
		}
		return fmt.Errorf("%w: PID %d: %w", ErrIdentityUnverifiable, record.PID, err)
	}
	if current != record.ProcessStartID {
		return fmt.Errorf("%w: PID %d was reused", ErrIdentityMismatch, record.PID)
	}
	return nil
}

// LoadVerified reads the control record, installation ID and process identity
// and proves that all three describe the requested installation.
func LoadVerified(scope Scope, inspector ProcessInspector) (Record, error) {
	canonical, err := scope.Canonical()
	if err != nil {
		return Record{}, err
	}
	record, err := ReadRecord(canonical.StateDir)
	if err != nil {
		return Record{}, err
	}
	installationID, err := readInstallationID(InstallationPath(canonical.StateDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, fmt.Errorf("%w: installation identifier is missing", ErrInstallationMismatch)
		}
		return Record{}, err
	}
	if err := Verify(record, canonical, installationID, inspector); err != nil {
		return Record{}, err
	}
	return record, nil
}

// Registration owns the control record written by the running daemon.
type Registration struct {
	stateDir string
	record   Record
	closed   bool
}

// Register writes a control record for the current process after the daemon
// socket is listening.
func Register(stateDir, socket, version string) (*Registration, error) {
	canonical, err := Scope{StateDir: stateDir, Socket: socket}.Canonical()
	if err != nil {
		return nil, err
	}
	installationID, err := EnsureInstallationID(canonical.StateDir)
	if err != nil {
		return nil, fmt.Errorf("installation identifier: %w", err)
	}
	startID, err := CurrentProcessStartID()
	if err != nil {
		return nil, fmt.Errorf("read current process start identity: %w", err)
	}
	record := Record{
		SchemaVersion:  SchemaVersion,
		InstallationID: installationID,
		StateDir:       canonical.StateDir,
		Socket:         canonical.Socket,
		PID:            os.Getpid(),
		ProcessStartID: startID,
		StartedAt:      time.Now().UTC(),
		Version:        version,
	}
	if err := WriteRecord(canonical.StateDir, record); err != nil {
		return nil, err
	}
	return &Registration{stateDir: canonical.StateDir, record: record}, nil
}

// Close removes the record if it still belongs to this process.
func (r *Registration) Close() error {
	if r == nil || r.closed {
		return nil
	}
	r.closed = true
	return RemoveRecord(r.stateDir, r.record)
}

func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".daemon-private-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer func() { _ = os.Remove(temp) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func canonicalPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}
