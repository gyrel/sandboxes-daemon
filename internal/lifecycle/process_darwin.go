//go:build darwin

package lifecycle

import (
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"
)

func startIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", ErrProcessNotFound
	}
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if errors.Is(err, unix.ESRCH) {
		return "", ErrProcessNotFound
	}
	if errors.Is(err, unix.EIO) {
		// Darwin reports EIO instead of ESRCH for some vanished PIDs. Only
		// classify it as gone when kill(2) independently confirms ESRCH; a
		// live but unreadable process still fails closed.
		if killErr := unix.Kill(pid, 0); errors.Is(killErr, unix.ESRCH) {
			return "", ErrProcessNotFound
		}
		return "", fmt.Errorf("kern.proc.pid: %w", err)
	}
	if err != nil {
		return "", err
	}
	if info == nil {
		return "", ErrProcessNotFound
	}
	start := info.Proc.P_starttime
	if start.Sec == 0 && start.Usec == 0 {
		return "", errors.New("process start time is unavailable")
	}
	return "darwin:" + strconv.FormatInt(start.Sec, 10) + ":" + strconv.FormatInt(int64(start.Usec), 10), nil
}
