package service

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestResolveProxyHelperPathExplicitWins(t *testing.T) {
	skipProxyHelperPermissionChecks(t)
	directory := t.TempDir()
	writeProxyHelperCandidate(t, filepath.Join(directory, proxyHelperNamePrefix+runtime.GOARCH))
	explicit := writeStaticProxyHelperFixtureFor(t, elf.EM_X86_64)

	got, err := resolveProxyHelperPath(explicit, filepath.Join(directory, "sandboxesd"))
	if err != nil {
		t.Fatalf("explicit helper rejected: %v", err)
	}
	if got != explicit {
		t.Fatalf("resolved helper = %q, want explicit %q", got, explicit)
	}
}

func TestResolveProxyHelperPathExplicitRelativeFails(t *testing.T) {
	skipProxyHelperPermissionChecks(t)
	directory := t.TempDir()
	writeProxyHelperCandidate(t, filepath.Join(directory, proxyHelperNamePrefix+runtime.GOARCH))
	_, err := resolveProxyHelperPath("gyrel-proxy-helper-linux-"+runtime.GOARCH, filepath.Join(directory, "sandboxesd"))
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("relative explicit helper error = %v", err)
	}
}

func TestResolveProxyHelperPathNextToExecutable(t *testing.T) {
	skipProxyHelperPermissionChecks(t)
	directory := t.TempDir()
	want := writeProxyHelperCandidate(t, filepath.Join(directory, proxyHelperNamePrefix+runtime.GOARCH))

	got, err := resolveProxyHelperPath("", filepath.Join(directory, "sandboxesd"))
	if err != nil {
		t.Fatalf("discover helper: %v", err)
	}
	if got != want {
		t.Fatalf("resolved helper = %q, want %q", got, want)
	}
}

func TestResolveProxyHelperPathInBinDirectory(t *testing.T) {
	skipProxyHelperPermissionChecks(t)
	directory := t.TempDir()
	want := writeProxyHelperCandidate(t, filepath.Join(directory, "bin", proxyHelperNamePrefix+runtime.GOARCH))

	got, err := resolveProxyHelperPath("", filepath.Join(directory, "sandboxesd"))
	if err != nil {
		t.Fatalf("discover helper: %v", err)
	}
	if got != want {
		t.Fatalf("resolved helper = %q, want %q", got, want)
	}
}

func TestResolveProxyHelperPathMissingListsLocations(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "sandboxesd")
	name := proxyHelperNamePrefix + runtime.GOARCH

	_, err := resolveProxyHelperPath("", executable)
	if err == nil {
		t.Fatal("missing helper error = nil, want fail-closed error")
	}
	for _, want := range []string{
		"proxy helper not found",
		strconv.Quote(filepath.Join(directory, name)),
		strconv.Quote(filepath.Join(directory, "bin", name)),
		"--proxy-helper",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("missing helper error %q does not contain %q", err, want)
		}
	}
}

func TestResolveProxyHelperPathIgnoresPATH(t *testing.T) {
	skipProxyHelperPermissionChecks(t)
	pathDirectory := t.TempDir()
	writeProxyHelperCandidate(t, filepath.Join(pathDirectory, proxyHelperNamePrefix+runtime.GOARCH))
	t.Setenv("PATH", pathDirectory)
	directory := t.TempDir()

	if got, err := resolveProxyHelperPath("", filepath.Join(directory, "sandboxesd")); err == nil || !strings.Contains(err.Error(), "proxy helper not found") {
		t.Fatalf("helper at %q was discovered from PATH or unexpected error: %v", got, err)
	}
}

func TestResolveProxyHelperPathRejectsWrongArchitecture(t *testing.T) {
	skipProxyHelperPermissionChecks(t)
	directory := t.TempDir()
	candidate := writeProxyHelperCandidateFor(t, filepath.Join(directory, proxyHelperNamePrefix+runtime.GOARCH), elf.EM_RISCV)

	_, err := resolveProxyHelperPath("", filepath.Join(directory, "sandboxesd"))
	if err == nil {
		t.Fatal("wrong-architecture helper accepted")
	}
	for _, want := range []string{"invalid", candidate, "ARM64 or AMD64"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("wrong-architecture error %q does not contain %q", err, want)
		}
	}
}

func TestResolveProxyHelperPathRejectsSymlink(t *testing.T) {
	skipProxyHelperPermissionChecks(t)
	directory := t.TempDir()
	target := writeStaticProxyHelperFixtureFor(t, elf.EM_AARCH64)
	candidate := filepath.Join(directory, proxyHelperNamePrefix+runtime.GOARCH)
	if err := os.Symlink(target, candidate); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, err := resolveProxyHelperPath("", filepath.Join(directory, "sandboxesd"))
	if err == nil || !strings.Contains(err.Error(), "regular executable file") {
		t.Fatalf("symlink helper error = %v", err)
	}
}

func TestResolveProxyHelperPathRejectsNonExecutable(t *testing.T) {
	skipProxyHelperPermissionChecks(t)
	directory := t.TempDir()
	candidate := writeProxyHelperCandidate(t, filepath.Join(directory, proxyHelperNamePrefix+runtime.GOARCH))
	if err := os.Chmod(candidate, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := resolveProxyHelperPath("", filepath.Join(directory, "sandboxesd"))
	if err == nil || !strings.Contains(err.Error(), "regular executable file") {
		t.Fatalf("non-executable helper error = %v", err)
	}
}

func TestResolveProxyHelperPathRejectsDynamicLinker(t *testing.T) {
	skipProxyHelperPermissionChecks(t)
	directory := t.TempDir()
	candidate := filepath.Join(directory, proxyHelperNamePrefix+runtime.GOARCH)
	writeInterpProxyHelperFixture(t, candidate)

	_, err := resolveProxyHelperPath("", filepath.Join(directory, "sandboxesd"))
	if err == nil || !strings.Contains(err.Error(), "dynamic linker") {
		t.Fatalf("dynamic-linker helper error = %v", err)
	}
}

func writeProxyHelperCandidate(t *testing.T, path string) string {
	t.Helper()
	return writeProxyHelperCandidateFor(t, path, elf.EM_AARCH64)
}

func writeProxyHelperCandidateFor(t *testing.T, path string, machine elf.Machine) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, staticProxyHelperFixtureData(machine), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func staticProxyHelperFixtureData(machine elf.Machine) []byte {
	data := make([]byte, 64)
	copy(data[:4], []byte{0x7f, 'E', 'L', 'F'})
	data[4], data[5], data[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(data[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(data[18:20], uint16(machine))
	binary.LittleEndian.PutUint32(data[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(data[52:54], 64)
	return data
}

func writeInterpProxyHelperFixture(t *testing.T, path string) {
	t.Helper()
	data := make([]byte, 64+56)
	copy(data, staticProxyHelperFixtureData(elf.EM_AARCH64))
	binary.LittleEndian.PutUint64(data[32:40], 64)
	binary.LittleEndian.PutUint16(data[54:56], 56)
	binary.LittleEndian.PutUint16(data[56:58], 1)
	binary.LittleEndian.PutUint32(data[64:68], uint32(elf.PT_INTERP))
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
}

func skipProxyHelperPermissionChecks(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix executable permission bits")
	}
}
