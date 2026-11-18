package service

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const proxyHelperNamePrefix = "rheic-proxy-helper-linux-"

// resolveProxyHelperPath returns the guest proxy helper to mount into a
// sandbox. An explicit path always wins and must pass the existing helper
// validator. When it is empty, only deterministic locations next to the
// running daemon executable are considered; PATH is never consulted. Every
// existing candidate must validate, so a corrupt nearby file fails closed
// instead of silently falling back to another location.
func resolveProxyHelperPath(explicitPath, executablePath string) (string, error) {
	if explicitPath != "" {
		if err := validateProxyHelperBinary(explicitPath); err != nil {
			return "", fmt.Errorf("proxy helper %q is invalid: %w", explicitPath, err)
		}
		return explicitPath, nil
	}
	if executablePath == "" {
		executable, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("locate daemon executable for proxy helper discovery: %w", err)
		}
		executablePath = executable
	}
	if !filepath.IsAbs(executablePath) {
		return "", fmt.Errorf("daemon executable path %q must be absolute for proxy helper discovery", executablePath)
	}
	directory := filepath.Dir(executablePath)
	name := proxyHelperNamePrefix + runtime.GOARCH
	candidates := []string{
		filepath.Join(directory, name),
		filepath.Join(directory, "bin", name),
	}
	for _, candidate := range candidates {
		if _, err := os.Lstat(candidate); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", fmt.Errorf("inspect proxy helper candidate %q: %w; searched %s", candidate, err, quotedPaths(candidates))
		}
		if err := validateProxyHelperBinary(candidate); err != nil {
			return "", fmt.Errorf("proxy helper candidate %q is invalid: %w; searched %s", candidate, err, quotedPaths(candidates))
		}
		return candidate, nil
	}
	return "", fmt.Errorf(
		"proxy helper not found; searched %s; set --proxy-helper to an absolute static Linux %s helper path",
		quotedPaths(candidates), strings.ToUpper(runtime.GOARCH),
	)
}

func quotedPaths(paths []string) string {
	quoted := make([]string, len(paths))
	for index, path := range paths {
		quoted[index] = strconv.Quote(path)
	}
	return strings.Join(quoted, ", ")
}
