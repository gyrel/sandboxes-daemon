//go:build windows

package lifecycle

import (
	"errors"
	"strconv"

	"golang.org/x/sys/windows"
)

func startIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", ErrProcessNotFound
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return "", ErrProcessNotFound
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return "", err
	}
	created := int64(creation.HighDateTime)<<32 | int64(creation.LowDateTime)
	return "windows:" + strconv.FormatInt(created, 10), nil
}
