//go:build windows

package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func openPrivateRead(path string) (*os.File, error) {
	file, err := os.Open(path) // #nosec G304 -- path is fixed by the control-surface contract.
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := validatePrivateFile(info); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return file, nil
}

func validatePrivateFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("must be a regular non-reparse file")
	}
	return nil
}

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must be a real directory, not a reparse point")
	}
	return nil
}

func openExclusivePrivate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path is fixed by the control-surface contract.
}

func samePath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}
