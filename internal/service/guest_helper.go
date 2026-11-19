package service

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// resolveGuestHelperPath implements deterministic next-to-executable helper
// discovery shared by the proxy and skills helpers. An explicit path wins and
// must pass validate; PATH is never consulted. Every existing candidate must
// validate, so a corrupt nearby file fails closed instead of falling back.
func resolveGuestHelperPath(explicitPath, executablePath, prefix, helperName, flagName, missingHint string, validate func(string) error) (string, error) {
	if explicitPath != "" {
		if err := validate(explicitPath); err != nil {
			return "", fmt.Errorf("%s %q is invalid: %w", helperName, explicitPath, err)
		}
		return explicitPath, nil
	}
	if executablePath == "" {
		executable, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("locate daemon executable for %s discovery: %w", helperName, err)
		}
		executablePath = executable
	}
	if !filepath.IsAbs(executablePath) {
		return "", fmt.Errorf("daemon executable path %q must be absolute for %s discovery", executablePath, helperName)
	}
	directory := filepath.Dir(executablePath)
	name := prefix + runtime.GOARCH
	candidates := []string{
		filepath.Join(directory, name),
		filepath.Join(directory, "bin", name),
	}
	for _, candidate := range candidates {
		if _, err := os.Lstat(candidate); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", fmt.Errorf("inspect %s candidate %q: %w; searched %s", helperName, candidate, err, quotedPaths(candidates))
		}
		if err := validate(candidate); err != nil {
			return "", fmt.Errorf("%s candidate %q is invalid: %w; searched %s", helperName, candidate, err, quotedPaths(candidates))
		}
		return candidate, nil
	}
	return "", fmt.Errorf(
		"%s not found; searched %s; set %s to an absolute static Linux %s %s",
		helperName, quotedPaths(candidates), flagName, strings.ToUpper(runtime.GOARCH), missingHint,
	)
}
