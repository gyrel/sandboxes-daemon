package service

import (
	"strconv"
	"strings"
)

const proxyHelperNamePrefix = "gyrel-proxy-helper-linux-"

// resolveProxyHelperPath returns the guest proxy helper to mount into a
// sandbox. An explicit path always wins and must pass the existing helper
// validator. When it is empty, only deterministic locations next to the
// running daemon executable are considered; PATH is never consulted. Every
// existing candidate must validate, so a corrupt nearby file fails closed
// instead of silently falling back to another location.
func resolveProxyHelperPath(explicitPath, executablePath string) (string, error) {
	return resolveGuestHelperPath(explicitPath, executablePath, proxyHelperNamePrefix, "proxy helper", "--proxy-helper", "helper path", validateProxyHelperBinary)
}

func quotedPaths(paths []string) string {
	quoted := make([]string, len(paths))
	for index, path := range paths {
		quoted[index] = strconv.Quote(path)
	}
	return strings.Join(quoted, ", ")
}
