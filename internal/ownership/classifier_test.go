package ownership

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gyrel/sandboxes-core/sandbox"

	"github.com/gyrel/sandboxes-daemon/internal/machinecode"
)

func TestOwnershipClassifier(t *testing.T) {
	root := t.TempDir()
	install := strings.Repeat("a", 32)
	uid := os.Getuid()
	namespace := filepath.Join(root, "sandboxes")
	if err := os.MkdirAll(filepath.Join(namespace, "present"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(namespace, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "absent"), filepath.Join(namespace, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(namespace, "file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id      string
		state   sandbox.State
		uid     int
		install string
		want    machinecode.Code
	}{
		{"present", sandbox.Pending, uid, install, ""}, {"creating", sandbox.Creating, uid, install, ""}, {"running", sandbox.Running, uid, install, ""},
		{"stopping", sandbox.Stopping, uid, install, ""}, {"stopped", sandbox.Stopped, uid, install, ""}, {"deleting", sandbox.Deleting, uid, install, ""},
		{"deleted", sandbox.Deleted, uid, install, ""}, {"failed", sandbox.Failed, uid, install, ""}, {"unknown", sandbox.Unknown, uid, install, ""},
		{"uid", sandbox.Stopped, uid + 1, install, machinecode.NotOwned}, {"installation", sandbox.Stopped, uid, strings.Repeat("b", 32), machinecode.NotOwned},
		{"empty", sandbox.Stopped, uid, "", machinecode.UnknownState}, {"malformed", sandbox.Stopped, uid, strings.Repeat("z", 32), machinecode.UnknownState},
		{"state", "invalid", uid, install, machinecode.UnknownState}, {"file", sandbox.Stopped, uid, install, machinecode.UnknownState},
		{"../templates", sandbox.Stopped, uid, install, machinecode.PathEscape}, {".", sandbox.Stopped, uid, install, machinecode.PathEscape},
		{"/absolute", sandbox.Stopped, uid, install, machinecode.PathEscape}, {"nested/id", sandbox.Stopped, uid, install, machinecode.PathEscape},
		{"linked", sandbox.Stopped, uid, install, machinecode.PathEscape}, {"dangling", sandbox.Stopped, uid, install, machinecode.PathEscape},
	} {
		t.Run(tc.id, func(t *testing.T) {
			err := Classify(root, install, sandbox.Sandbox{ID: tc.id, Name: "inventory", State: tc.state}, tc.uid, tc.install)
			got, _ := machinecode.Of(err)
			if got != tc.want || (err == nil) != (tc.want == "") {
				t.Fatalf("got %q (%v), want %q", got, err, tc.want)
			}
		})
	}
}
