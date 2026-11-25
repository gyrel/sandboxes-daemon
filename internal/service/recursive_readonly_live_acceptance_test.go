//go:build darwin && gyrel_rro_live

package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gyrel/sandboxes-core/sandbox"
	daemonnetwork "github.com/gyrel/sandboxes-daemon/internal/network"
	"github.com/gyrel/sandboxes-daemon/internal/store"
	gateway "github.com/gyrel/sandboxes-gateway"
	rt "github.com/gyrel/sandboxes-runtime"
	"github.com/gyrel/sandboxes-runtime/ctr"
)

const (
	rroLiveAcceptanceTimeout = 12 * time.Minute
	rroLiveGuestRepoPath     = "/workspace/repo"
)

// TestRecursiveReadOnlyNestedSubmountLiveAcceptanceAgainstOwnedVM proves that
// the runtime's recursive read-only workspace mounts keep a nested workspace
// mount read-only in the guest.
//
// Why a second workspace entry is the nested-mount construction: the guest
// container has no CAP_SYS_ADMIN, so it cannot create a submount itself. On
// macOS the host user also cannot bind-mount a directory under the repository
// without root. The daemon therefore creates the "nested submount inside the
// repository" by mounting a second host directory at
// <repo guest path>/nested. /proc/self/mountinfo must show that mount as a
// child of the repository mount, and writes through either path must fail with
// the kernel's "Read-only file system" error.
func TestRecursiveReadOnlyNestedSubmountLiveAcceptanceAgainstOwnedVM(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("recursive read-only live acceptance requires macOS ARM64")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("recursive read-only live acceptance requires macOS")
	}
	inputs := getRROLiveInputs(t)

	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), rroLiveAcceptanceTimeout)
	defer cancel()

	root, err := os.MkdirTemp("/private/tmp", "rrolive-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	// Registered first so it runs after every process/log cleanup below.
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove owned recursive read-only directory: %v", err)
		}
	})
	if evidenceDir := os.Getenv("GYREL_CLONE_EVIDENCE_DIR"); evidenceDir != "" {
		// Registered after the removal cleanup so evidence is captured first.
		t.Cleanup(func() { copyRROLiveEvidence(t, root, evidenceDir) })
	}

	binDir := filepath.Join(root, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ source, name string }{
		{inputs.shim, "containerd-shim-nerdbox-v1"},
		{inputs.kernel, "nerdbox-kernel-arm64"},
		{inputs.rootfs, "nerdbox-rootfs-arm64.erofs"},
	} {
		if err := os.Symlink(item.source, filepath.Join(binDir, item.name)); err != nil {
			t.Fatal(err)
		}
	}

	containerdSocket := filepath.Join(root, "containerd.sock")
	containerdConfig := filepath.Join(root, "containerd.toml")
	config := fmt.Sprintf("version = 4\nroot = %q\nstate = %q\n[plugins.'io.containerd.server.v1.grpc']\naddress = %q\nuid = %d\ngid = %d\n[plugins.'io.containerd.server.v1.ttrpc']\naddress = %q\nuid = %d\ngid = %d\n",
		filepath.Join(root, "root"), filepath.Join(root, "state"), containerdSocket, os.Getuid(), os.Getgid(), containerdSocket+".ttrpc", os.Getuid(), os.Getgid())
	if err := os.WriteFile(containerdConfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	containerdLogPath := filepath.Join(root, "containerd.log")
	containerdLog, err := os.Create(containerdLogPath)
	if err != nil {
		t.Fatal(err)
	}
	containerd := exec.Command(inputs.containerd, "--config", containerdConfig)
	containerd.Env = append(os.Environ(),
		"PATH="+strings.Join([]string{binDir, "/opt/homebrew/bin", "/opt/homebrew/opt/e2fsprogs/sbin", "/usr/local/bin", "/usr/bin", "/bin"}, string(os.PathListSeparator)),
		"LIBKRUN_PATH="+inputs.libkrun,
		"SAILOR_PATH="+filepath.Join(filepath.Dir(inputs.shim), "lib"),
	)
	containerd.Stdout, containerd.Stderr = containerdLog, containerdLog
	if err := containerd.Start(); err != nil {
		_ = containerdLog.Close()
		t.Fatal(err)
	}
	containerdDone := make(chan struct{})
	containerdResult := make(chan error, 1)
	go func() {
		containerdResult <- containerd.Wait()
		close(containerdDone)
	}()
	defer func() {
		select {
		case <-containerdDone:
			if err := <-containerdResult; err != nil {
				t.Errorf("owned containerd exited: %v", err)
			}
		default:
			_ = containerd.Process.Signal(os.Interrupt)
			select {
			case <-containerdDone:
				if err := <-containerdResult; err != nil {
					t.Errorf("stop owned containerd: %v", err)
				}
			case <-time.After(15 * time.Second):
				_ = containerd.Process.Kill()
				<-containerdDone
				_ = <-containerdResult
				t.Error("owned containerd did not stop after SIGINT")
			}
		}
		if err := containerdLog.Close(); err != nil {
			t.Errorf("close containerd log: %v", err)
		}
	}()

	if err := waitRROLiveContainerd(ctx, inputs.ctr, containerdSocket, containerdDone); err != nil {
		t.Fatalf("wait for owned containerd: %v (log %s)", err, containerdLogPath)
	}

	// The runtime does not pull images itself, so do a bounded explicit pull.
	pullCtx, pullCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer pullCancel()
	pull := exec.CommandContext(pullCtx, inputs.ctr, "--address", containerdSocket, "--namespace", "default", "images", "pull", inputs.image)
	pullOutput, err := pull.CombinedOutput()
	if err != nil {
		t.Fatalf("pre-pull %s: %v\n%s", inputs.image, err, strings.TrimSpace(string(pullOutput)))
	}

	networkManager, err := gateway.New(gateway.Config{
		GVProxy: inputs.gvproxy, Supervisor: inputs.daemon, RunDir: filepath.Join(root, "run", "gateway"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer closeCancel()
		if err := networkManager.Close(closeCtx); err != nil {
			t.Errorf("close owned gateway manager: %v", err)
		}
	}()
	backend, err := ctr.NewBackend(
		ctr.Config{Socket: containerdSocket, CTR: inputs.ctr, Runtime: "io.containerd.nerdbox.v1", Snapshotter: "erofs", Platform: "linux/arm64"},
		ctr.BackendOptions{Image: inputs.image, FIFODir: filepath.Join(root, "fifo"), Network: daemonnetwork.New(networkManager, filepath.Join(root, "run", "audit"))},
	)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.Open(ctx, filepath.Join(root, "sandboxes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := state.Close(); err != nil {
			t.Errorf("close owned daemon state: %v", err)
		}
	}()

	repoDir, nestedHostDir, trackedContent, nestedContent := makeRROLiveWorkspaces(t, root)
	// Synthetic host IPC fixtures, under the owned temporary workspace only.
	fifoPath := filepath.Join(repoDir, "ipc-probe.fifo")
	if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
		t.Fatal(err)
	}
	fifo, err := os.OpenFile(fifoPath, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fifo.Close()
	if _, err := fifo.WriteString("fixture-token"); err != nil {
		t.Fatal(err)
	}
	localToken := make([]byte, len("fixture-token"))
	if n, err := fifo.Read(localToken); err != nil || n != len(localToken) || string(localToken) != "fixture-token" {
		t.Fatalf("host FIFO positive control failed: n=%d err=%v", n, err)
	}
	if _, err := fifo.WriteString("fixture-token"); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(repoDir, "ipc-probe.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// The owned host socket must accept a local connection before guest probing.
	hostClient, err := net.Dial("unix", filepath.Join(repoDir, "ipc-probe.sock"))
	if err != nil {
		t.Fatalf("host socket positive control dial: %v", err)
	}
	hostServer, err := listener.Accept()
	if err != nil {
		t.Fatalf("host socket positive control accept: %v", err)
	}
	if err := hostClient.Close(); err != nil {
		t.Fatal(err)
	}
	if err := hostServer.Close(); err != nil {
		t.Fatal(err)
	}

	svc := New(state, backend)
	svc.DefaultImage = inputs.image

	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	sandboxName := "rro-live-" + hex.EncodeToString(nonce[:])

	op, err := svc.Create(ctx, CreateRequest{
		Name:  sandboxName,
		Image: inputs.image,
		Workspaces: []sandbox.Workspace{
			{Path: repoDir, GuestPath: rroLiveGuestRepoPath, ReadOnly: true},
			{Path: nestedHostDir, GuestPath: rroLiveGuestRepoPath + "/nested", ReadOnly: true},
		},
	})
	if err != nil {
		t.Fatalf("service Create with nested read-only workspaces: %v", err)
	}
	sandboxID := op.SandboxID
	if sandboxID == "" {
		t.Fatal("service Create returned an empty sandbox ID")
	}
	deleted := false
	defer func() {
		if deleted {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanupCancel()
		if _, err := svc.Delete(cleanupCtx, sandboxID, true); err != nil {
			t.Errorf("delete owned recursive read-only sandbox: %v", err)
		}
	}()

	sb := loadRROLiveSandbox(t, ctx, svc, state, sandboxID)
	if len(sb.Workspaces) != 2 || !sb.Workspaces[0].ReadOnly || !sb.Workspaces[1].ReadOnly {
		t.Fatalf("daemon did not persist two read-only workspaces: %+v", sb.Workspaces)
	}
	if sb.Workspaces[0].GuestPath != rroLiveGuestRepoPath || sb.Workspaces[1].GuestPath != rroLiveGuestRepoPath+"/nested" {
		t.Fatalf("daemon changed the nested workspace destinations: %+v", sb.Workspaces)
	}

	// 1. Both host directories are visible at their read-only destinations.
	out, stderr, code, err := execRROLiveGuest(ctx, svc, sandboxID,
		[]string{"/bin/sh", "-c", "cat " + rroLiveGuestRepoPath + "/tracked.txt"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("read repository file: code=%d err=%v stderr=%q", code, err, stderr)
	}
	if out != trackedContent {
		t.Fatalf("repository file content = %q, want %q", out, trackedContent)
	}
	out, stderr, code, err = execRROLiveGuest(ctx, svc, sandboxID,
		[]string{"/bin/sh", "-c", "cat " + rroLiveGuestRepoPath + "/nested/nested.txt"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("read nested file: code=%d err=%v stderr=%q", code, err, stderr)
	}
	if out != nestedContent {
		t.Fatalf("nested file content = %q, want %q", out, nestedContent)
	}

	// Probe only synthetic, owned IPC objects; a regular file above is the
	// positive control proving the guest sees this mounted directory.
	out, stderr, code, err = execRROLiveGuest(ctx, svc, sandboxID,
		[]string{"/bin/sh", "-c", "if test -p /workspace/repo/ipc-probe.fifo; then timeout 3 head -c 13 /workspace/repo/ipc-probe.fifo; else echo FIFO_NOT_EXPOSED; fi"}, nil)
	t.Logf("synthetic FIFO probe: exit=%d err=%v stdout=%q stderr=%q", code, err, out, stderr)
	if err != nil && code != 124 {
		t.Fatalf("could not execute FIFO probe: exit=%d: %v", code, err)
	}
	if out == "fixture-token" {
		t.Error("guest read from host FIFO across read-only workspace")
	}
	out, stderr, code, err = execRROLiveGuest(ctx, svc, sandboxID,
		[]string{"/bin/sh", "-c", "if test -S /workspace/repo/ipc-probe.sock; then echo SOCKET_EXPOSED; else echo SOCKET_NOT_EXPOSED; fi"}, nil)
	t.Logf("synthetic socket visibility probe: exit=%d err=%v stdout=%q stderr=%q", code, err, out, stderr)
	if err != nil || code != 0 {
		t.Fatalf("could not execute socket visibility probe: %v", err)
	}
	unixListener := listener.(*net.UnixListener)
	if err := unixListener.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan bool, 1)
	go func() {
		conn, err := unixListener.Accept()
		if err != nil {
			accepted <- false
			return
		}
		defer conn.Close()
		accepted <- true
	}()
	out, stderr, code, err = execRROLiveGuest(ctx, svc, sandboxID, []string{"/bin/sh", "-c", `if command -v python3 >/dev/null; then python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect("/workspace/repo/ipc-probe.sock")'; else echo PYTHON_NOT_AVAILABLE; fi`}, nil)
	connected := <-accepted
	t.Logf("synthetic socket connect probe: exit=%d err=%v stdout=%q stderr=%q host_accepted=%v", code, err, out, stderr, connected)
	if connected {
		t.Error("guest connected to host Unix socket across read-only workspace")
	}
	if strings.Contains(out, "PYTHON_NOT_AVAILABLE") {
		t.Fatal("socket probe is inconclusive: python3 is unavailable in the guest")
	}
	if err == nil || !strings.Contains(stderr, "ConnectionRefusedError") {
		t.Fatalf("socket probe is inconclusive: exit=%d err=%v stderr=%q", code, err, stderr)
	}

	// 2. The nested destination is a real mount nested inside the repository
	// mount, and both mounts are read-only. mountinfo fields are:
	//   id parent major:minor root mountpoint options optional... - fstype source superopts
	mountInfo, stderr, code, err := execRROLiveGuest(ctx, svc, sandboxID,
		[]string{"/bin/sh", "-c", "cat /proc/self/mountinfo"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("read mountinfo: code=%d err=%v stderr=%q", code, err, stderr)
	}
	repoMount, nestedMount := parseRROLiveMountInfo(t, mountInfo)
	if !strings.Contains(repoMount.options, "ro") {
		t.Fatalf("repository mount is not read-only: %q", repoMount.line)
	}
	if !strings.Contains(nestedMount.options, "ro") {
		t.Fatalf("nested mount is not read-only: %q", nestedMount.line)
	}
	if nestedMount.parentID != repoMount.id {
		t.Fatalf("nested mount is not a child of the repository mount: nested parent=%s repository id=%s\nrepo: %s\nnested: %s",
			nestedMount.parentID, repoMount.id, repoMount.line, nestedMount.line)
	}
	if nestedMount.id == repoMount.id {
		t.Fatalf("nested destination is not a separate mount: %s", nestedMount.line)
	}
	t.Logf("mount info: repo id=%s options=%q fstype=%s source=%s; nested id=%s parent=%s options=%q fstype=%s source=%s",
		repoMount.id, repoMount.options, repoMount.fstype, repoMount.source,
		nestedMount.id, nestedMount.parentID, nestedMount.options, nestedMount.fstype, nestedMount.source)

	// 3. Writing through the top-level read-only mount must fail with EROFS.
	assertRROLiveWriteBlocked(t, ctx, svc, sandboxID, rroLiveGuestRepoPath+"/tracked.txt")
	assertRROLiveWriteBlocked(t, ctx, svc, sandboxID, rroLiveGuestRepoPath+"/.rro-live-write-probe")
	// 4. Writing through the nested mount must fail with EROFS too.
	assertRROLiveWriteBlocked(t, ctx, svc, sandboxID, rroLiveGuestRepoPath+"/nested/nested.txt")
	assertRROLiveWriteBlocked(t, ctx, svc, sandboxID, rroLiveGuestRepoPath+"/nested/.rro-live-write-probe")

	// 5. The guest probes must not have changed the host sources.
	assertRROLiveHostFile(t, filepath.Join(repoDir, "tracked.txt"), trackedContent)
	assertRROLiveHostFile(t, filepath.Join(nestedHostDir, "nested.txt"), nestedContent)
	for _, path := range []string{
		filepath.Join(repoDir, ".rro-live-write-probe"),
		filepath.Join(repoDir, "nested", ".rro-live-write-probe"),
		filepath.Join(nestedHostDir, ".rro-live-write-probe"),
	} {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("guest write probe left a host artifact at %s", path)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat host probe artifact %s: %v", path, err)
		}
	}

	// 6. Deleting the sandbox removes it from the durable store and leaves no
	// host-side process or mount behind.
	if _, err := svc.Delete(ctx, sandboxID, true); err != nil {
		t.Fatalf("service Delete(force): %v", err)
	}
	deleted = true
	if _, err := state.Get(ctx, sandboxID); err == nil {
		t.Fatal("deleted sandbox is still readable")
	}

	if err := ctx.Err(); err != nil {
		t.Fatalf("recursive read-only live acceptance exceeded the 12-minute deadline: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= rroLiveAcceptanceTimeout {
		t.Fatalf("recursive read-only live acceptance exceeded 12 minutes: %s", elapsed)
	}
	t.Logf("PASS: recursive read-only nested submount name=%s repo=%s nested=%s nested_target=%s/%s repo_mount=%s nested_mount_parent=%s nested_fstype=%s",
		sandboxName, repoDir, nestedHostDir, rroLiveGuestRepoPath, "nested",
		repoMount.options, nestedMount.parentID, nestedMount.fstype)
}

type rroLiveInputs struct {
	containerd, ctr, shim, kernel, rootfs, libkrun, gvproxy, daemon, image string
}

func getRROLiveInputs(t *testing.T) rroLiveInputs {
	t.Helper()
	get := func(name string) string {
		value := os.Getenv(name)
		if value == "" {
			t.Skipf("set %s to explicitly select owned-VM test input", name)
		}
		if _, err := os.Stat(value); err != nil {
			t.Fatalf("%s is unavailable: %v", name, err)
		}
		return value
	}
	image := os.Getenv("GYREL_CLONE_IMAGE")
	if image == "" {
		image = "docker.io/library/buildpack-deps:bookworm-scm"
	}
	return rroLiveInputs{
		containerd: get("GYREL_CLONE_CONTAINERD"), ctr: get("GYREL_CLONE_CTR"),
		shim: get("GYREL_CLONE_SHIM"), kernel: get("GYREL_CLONE_KERNEL"),
		rootfs: get("GYREL_CLONE_ROOTFS"), libkrun: get("GYREL_CLONE_LIBKRUN"),
		gvproxy: get("GYREL_CLONE_GVPROXY"), daemon: get("GYREL_CLONE_DAEMON"),
		image: image,
	}
}

func waitRROLiveContainerd(ctx context.Context, ctrPath, socket string, done <-chan struct{}) error {
	for {
		command := exec.CommandContext(ctx, ctrPath, "--address", socket, "version")
		if err := command.Run(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return errors.New("owned containerd exited before socket readiness")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// makeRROLiveWorkspaces creates a Git repository with a tracked file and an
// empty "nested" mount target directory, plus a separate host directory that
// is mounted at <repo guest path>/nested.
func makeRROLiveWorkspaces(t *testing.T, root string) (repoDir, nestedHostDir, trackedContent, nestedContent string) {
	t.Helper()
	repoDir = filepath.Join(root, "source-repo")
	nestedHostDir = filepath.Join(root, "nested-mount-source")
	trackedContent = "gyrel recursive read-only acceptance\n"
	nestedContent = "gyrel nested submount read-only acceptance\n"
	if err := os.Mkdir(repoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repoDir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(nestedHostDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "tracked.txt"), []byte(trackedContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nestedHostDir, "nested.txt"), []byte(nestedContent), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		command := exec.Command("git", args...)
		command.Dir = repoDir
		command.Env = append(os.Environ(),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_TERMINAL_PROMPT=0",
		)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	run("init", "-q")
	run("config", "user.email", "rro-live@example.invalid")
	run("config", "user.name", "Gyrel Recursive Read-Only Live")
	run("add", "tracked.txt")
	run("commit", "-q", "-m", "initial")
	return repoDir, nestedHostDir, trackedContent, nestedContent
}

func execRROLiveGuest(ctx context.Context, svc *Service, sandboxID string, argv, env []string) (stdout, stderr string, code int, err error) {
	execCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var out, errOut strings.Builder
	// Workdir is explicitly / because Service.Exec otherwise defaults to the
	// host workspace path, which is not present at that path inside the guest.
	code, err = svc.Exec(execCtx, sandboxID, rt.ExecRequest{
		Argv: argv, Env: env, Workdir: "/", Stdout: &out, Stderr: &errOut,
	})
	return out.String(), errOut.String(), code, err
}

func loadRROLiveSandbox(t *testing.T, ctx context.Context, svc *Service, state *store.Store, id string) sandbox.Sandbox {
	t.Helper()
	sb, err := svc.Get(ctx, id)
	if err == nil {
		return sb
	}
	sb, storeErr := state.Get(ctx, id)
	if storeErr != nil {
		t.Fatalf("load sandbox %s: service=%v store=%v", id, err, storeErr)
	}
	return sb
}

// assertRROLiveWriteBlocked attempts a write through the guest mount and
// requires a clean "Read-only file system" failure with no zero exit code.
func assertRROLiveWriteBlocked(t *testing.T, ctx context.Context, svc *Service, sandboxID, path string) {
	t.Helper()
	// The braces make the shell's own redirection error part of the captured
	// output; without them the EROFS message bypasses the command substitution.
	script := fmt.Sprintf(`err=$( { printf probe > %q; } 2>&1 ); rc=$?; if [ "$rc" -eq 0 ]; then echo WRITE_SUCCEEDED; else echo WRITE_BLOCKED; printf '%%s\n' "$err"; fi`, path)
	out, stderr, code, err := execRROLiveGuest(ctx, svc, sandboxID, []string{"/bin/sh", "-c", script}, nil)
	if err != nil || code != 0 {
		t.Fatalf("write probe %s: code=%d err=%v stderr=%q", path, code, err, stderr)
	}
	if !strings.Contains(out, "WRITE_BLOCKED") || strings.Contains(out, "WRITE_SUCCEEDED") {
		t.Fatalf("write to %s unexpectedly succeeded: out=%q stderr=%q", path, out, stderr)
	}
	if !strings.Contains(out, "Read-only file system") {
		t.Fatalf("write to %s failed for a reason other than a read-only mount: out=%q stderr=%q", path, out, stderr)
	}
}

func assertRROLiveHostFile(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read host file %s: %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("host file %s = %q, want %q", path, string(data), want)
	}
}

type rroLiveMount struct {
	line                       string
	id, parentID, mountpoint   string
	options, fstype, source    string
	superOptions               string
	root, majorMinor, optional string
}

// parseRROLiveMountInfo extracts the repository and nested mounts from
// /proc/self/mountinfo. mountinfo escapes spaces and special characters with
// octal escapes; the paths used here contain none.
func parseRROLiveMountInfo(t *testing.T, mountInfo string) (repo, nested rroLiveMount) {
	t.Helper()
	var foundRepo, foundNested bool
	for _, line := range strings.Split(mountInfo, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+3 >= len(fields) {
			continue
		}
		mount := rroLiveMount{
			line:         line,
			id:           fields[0],
			parentID:     fields[1],
			majorMinor:   fields[2],
			root:         fields[3],
			mountpoint:   fields[4],
			options:      fields[5],
			fstype:       fields[separator+1],
			source:       fields[separator+2],
			superOptions: fields[separator+3],
		}
		if len(fields) > 6 {
			mount.optional = strings.Join(fields[6:separator], " ")
		}
		switch mount.mountpoint {
		case rroLiveGuestRepoPath:
			repo, foundRepo = mount, true
		case rroLiveGuestRepoPath + "/nested":
			nested, foundNested = mount, true
		}
	}
	if !foundRepo {
		t.Fatalf("mountinfo has no mount at %s:\n%s", rroLiveGuestRepoPath, mountInfo)
	}
	if !foundNested {
		t.Fatalf("mountinfo has no mount at %s/nested:\n%s", rroLiveGuestRepoPath, mountInfo)
	}
	return repo, nested
}

func copyRROLiveEvidence(t *testing.T, root, evidenceDir string) {
	t.Helper()
	if err := os.MkdirAll(evidenceDir, 0o700); err != nil {
		t.Errorf("create recursive read-only evidence directory: %v", err)
		return
	}
	prefix := "rro-live-" + filepath.Base(root)
	copyOne := func(source, name string) {
		data, err := os.ReadFile(source)
		if err != nil {
			if !os.IsNotExist(err) {
				t.Errorf("read recursive read-only evidence %s: %v", source, err)
			}
			return
		}
		if err := os.WriteFile(filepath.Join(evidenceDir, name), data, 0o600); err != nil {
			t.Errorf("write recursive read-only evidence %s: %v", name, err)
		}
	}
	copyOne(filepath.Join(root, "containerd.log"), prefix+"-containerd.log")
	gatewayDir := filepath.Join(root, "run", "gateway")
	_ = filepath.WalkDir(gatewayDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".gateway.log") {
			return err
		}
		copyOne(path, prefix+"-"+entry.Name())
		return nil
	})
}
