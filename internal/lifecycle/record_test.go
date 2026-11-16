package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeInspector struct {
	identity string
	err      error
	calls    int
}

func (f *fakeInspector) StartIdentity(int) (string, error) {
	f.calls++
	return f.identity, f.err
}

func testRecord(t *testing.T, stateDir string) Record {
	t.Helper()
	id, err := EnsureInstallationID(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := (Scope{StateDir: stateDir, Socket: filepath.Join(stateDir, "daemon.sock")}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return Record{
		SchemaVersion:  SchemaVersion,
		InstallationID: id,
		StateDir:       scope.StateDir,
		Socket:         scope.Socket,
		PID:            4321,
		ProcessStartID: "fixture:start",
		StartedAt:      time.Now().UTC(),
	}
}

func TestVerifyProvesIdentityAndInstallation(t *testing.T) {
	stateDir := t.TempDir()
	record := testRecord(t, stateDir)
	scope := Scope{StateDir: stateDir, Socket: record.Socket}
	if err := Verify(record, scope, record.InstallationID, &fakeInspector{identity: record.ProcessStartID}); err != nil {
		t.Fatalf("Verify() = %v", err)
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	stateDir := t.TempDir()
	record := testRecord(t, stateDir)
	otherDir := t.TempDir()
	tests := []struct {
		name       string
		record     func(Record) Record
		scope      Scope
		installID  string
		inspector  ProcessInspector
		wantErr    error
		wantDetail string
	}{
		{
			name:       "pid reused",
			record:     func(r Record) Record { return r },
			scope:      Scope{StateDir: stateDir, Socket: record.Socket},
			installID:  record.InstallationID,
			inspector:  &fakeInspector{identity: "fixture:different"},
			wantErr:    ErrIdentityMismatch,
			wantDetail: "PID 4321 was reused",
		},
		{
			name:       "process gone",
			record:     func(r Record) Record { return r },
			scope:      Scope{StateDir: stateDir, Socket: record.Socket},
			installID:  record.InstallationID,
			inspector:  &fakeInspector{err: ErrProcessNotFound},
			wantErr:    ErrProcessNotFound,
			wantDetail: "PID 4321",
		},
		{
			name:       "identity unverifiable",
			record:     func(r Record) Record { return r },
			scope:      Scope{StateDir: stateDir, Socket: record.Socket},
			installID:  record.InstallationID,
			inspector:  &fakeInspector{err: errors.New("permission denied")},
			wantErr:    ErrIdentityUnverifiable,
			wantDetail: "permission denied",
		},
		{
			name:       "another installation id",
			record:     func(r Record) Record { return r },
			scope:      Scope{StateDir: stateDir, Socket: record.Socket},
			installID:  strings.Repeat("0", 32),
			inspector:  &fakeInspector{identity: record.ProcessStartID},
			wantErr:    ErrInstallationMismatch,
			wantDetail: "belongs to another installation",
		},
		{
			name:       "another state directory",
			record:     func(r Record) Record { return r },
			scope:      Scope{StateDir: otherDir, Socket: record.Socket},
			installID:  record.InstallationID,
			inspector:  &fakeInspector{identity: record.ProcessStartID},
			wantErr:    ErrInstallationMismatch,
			wantDetail: otherDir,
		},
		{
			name:       "another socket",
			record:     func(r Record) Record { return r },
			scope:      Scope{StateDir: stateDir, Socket: filepath.Join(stateDir, "other.sock")},
			installID:  record.InstallationID,
			inspector:  &fakeInspector{identity: record.ProcessStartID},
			wantErr:    ErrInstallationMismatch,
			wantDetail: "other.sock",
		},
		{
			name: "wrong schema",
			record: func(r Record) Record {
				r.SchemaVersion = 99
				return r
			},
			scope:      Scope{StateDir: stateDir, Socket: record.Socket},
			installID:  record.InstallationID,
			inspector:  &fakeInspector{identity: record.ProcessStartID},
			wantErr:    ErrInvalidRecord,
			wantDetail: "schema version",
		},
		{
			name: "missing start identity",
			record: func(r Record) Record {
				r.ProcessStartID = ""
				return r
			},
			scope:      Scope{StateDir: stateDir, Socket: record.Socket},
			installID:  record.InstallationID,
			inspector:  &fakeInspector{identity: record.ProcessStartID},
			wantErr:    ErrInvalidRecord,
			wantDetail: "start identity",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Verify(test.record(record), test.scope, test.installID, test.inspector)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Verify() = %v, want %v", err, test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantDetail) {
				t.Fatalf("Verify() error %q lacks %q", err, test.wantDetail)
			}
		})
	}
}

func TestRegistrationWritesAndRemovesOwnedRecord(t *testing.T) {
	stateDir := t.TempDir()
	socket := filepath.Join(stateDir, "daemon.sock")
	registration, err := Register(stateDir, socket, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	record, err := ReadRecord(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if record.PID != os.Getpid() || record.Version != "test-version" || record.InstallationID == "" {
		t.Fatalf("record = %+v", record)
	}
	if _, err := LoadVerified(Scope{StateDir: stateDir, Socket: socket}, SystemInspector{}); err != nil {
		t.Fatalf("LoadVerified() = %v", err)
	}
	if err := registration.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecord(stateDir); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("ReadRecord() after Close = %v, want ErrNoRecord", err)
	}
}

func TestRemoveRecordRefusesDifferentProcess(t *testing.T) {
	stateDir := t.TempDir()
	record := testRecord(t, stateDir)
	if err := WriteRecord(stateDir, record); err != nil {
		t.Fatal(err)
	}
	other := record
	other.ProcessStartID = "fixture:other"
	if err := RemoveRecord(stateDir, other); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("RemoveRecord() = %v, want ErrIdentityMismatch", err)
	}
	if _, err := ReadRecord(stateDir); err != nil {
		t.Fatalf("record was removed: %v", err)
	}
}

func TestInstallationIDIsStableAndPrivate(t *testing.T) {
	stateDir := t.TempDir()
	first, err := EnsureInstallationID(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnsureInstallationID(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !installationIDPattern.MatchString(first) {
		t.Fatalf("identifiers = %q, %q", first, second)
	}
	info, err := os.Stat(InstallationPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("installation file mode = %o", info.Mode().Perm())
	}
}

func TestCurrentProcessStartIDIsStable(t *testing.T) {
	first, err := CurrentProcessStartID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := CurrentProcessStartID()
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("start identities = %q, %q", first, second)
	}
}
