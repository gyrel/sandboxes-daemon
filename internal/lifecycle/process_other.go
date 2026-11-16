//go:build !darwin && !linux && !windows

package lifecycle

import "errors"

func startIdentity(int) (string, error) {
	return "", errors.New("process identity is unsupported on this platform")
}
