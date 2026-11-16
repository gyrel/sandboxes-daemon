//go:build linux

package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func startIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", ErrProcessNotFound
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)) // #nosec G304 -- PID is validated and the path is fixed.
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrProcessNotFound
	}
	if err != nil {
		return "", err
	}
	// The command name may contain spaces and parentheses. Fields after the
	// final ')' start at field 3 (state); starttime is field 22.
	text := string(data)
	end := strings.LastIndexByte(text, ')')
	if end < 0 || end+2 >= len(text) {
		return "", errors.New("parse /proc stat: missing command terminator")
	}
	fields := strings.Fields(text[end+2:])
	const startTimeOffset = 22 - 3
	if len(fields) <= startTimeOffset {
		return "", errors.New("parse /proc stat: missing starttime")
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("read boot id: %w", err)
	}
	boot := strings.TrimSpace(string(bootID))
	if boot == "" {
		return "", errors.New("boot id is empty")
	}
	return "linux:" + boot + ":" + fields[startTimeOffset], nil
}
