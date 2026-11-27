// Package ownership classifies persisted sandbox inventory before use.
package ownership

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	core "github.com/gyrel/sandboxes-core"
	"github.com/gyrel/sandboxes-core/sandbox"

	"github.com/gyrel/sandboxes-daemon/internal/machinecode"
)

// Classify returns nil for owned rows. Refusal reasons distinguish foreign
// identity from malformed evidence and namespace escapes.
func Classify(root, installation string, sb sandbox.Sandbox, uid int, stored string) error {
	switch sb.State {
	case sandbox.Pending, sandbox.Creating, sandbox.Running, sandbox.Stopping, sandbox.Stopped, sandbox.Deleting, sandbox.Deleted, sandbox.Failed, sandbox.Unknown:
	default:
		return unknown()
	}
	if len(stored) != 32 || strings.ToLower(stored) != stored {
		return unknown()
	}
	if _, err := hex.DecodeString(stored); err != nil {
		return unknown()
	}
	if !component(sb.ID) || !component(sb.Name) {
		return escape()
	}
	if !ValidName(sb.Name) {
		return unknown()
	}
	if uid != os.Getuid() || stored != installation {
		return machinecode.Attach(machinecode.NotOwned, fmt.Errorf("%w: sandbox is not owned", core.ErrConflict))
	}
	return checkNamespace(root, sb.ID)
}

func checkNamespace(root, id string) error {
	// The logical namespace may precede runtime directory creation. Every
	// existing component below the state root must be a real directory.
	namespace := filepath.Join(root, "sandboxes")
	for _, path := range []string{root, namespace, filepath.Join(namespace, id)} {
		info, err := os.Lstat(path)
		if path != root && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return unknown()
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return escape()
		}
		if !info.IsDir() {
			return unknown()
		}
	}
	return nil
}

func component(s string) bool {
	return filepath.IsLocal(s) && s != "." && !strings.ContainsAny(s, "/\\:\x00")
}

func unknown() error {
	return machinecode.Attach(machinecode.UnknownState, errors.New("invalid sandbox record"))
}

func escape() error {
	return machinecode.Attach(machinecode.PathEscape, fmt.Errorf("%w: unsafe sandbox namespace", core.ErrConflict))
}

// ValidName checks the daemon sandbox name contract for creation and persisted rows.
func ValidName(name string) bool {
	if len(name) < 2 || len(name) > 63 || name == "default" {
		return false
	}
	if !isNameStartByte(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !isNameByte(name[i]) {
			return false
		}
	}
	return true
}

func isNameStartByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isNameByte(c byte) bool {
	return isNameStartByte(c) || c == '-' || c == '.'
}
