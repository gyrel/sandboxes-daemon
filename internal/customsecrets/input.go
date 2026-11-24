package customsecrets

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
)

// MaxValueBytes matches the built-in service secret limit.
const MaxValueBytes = 8192

const maxSandboxNameLength = 63

// ErrInvalidInput reports scope, name, environment or value input outside the
// supported grammar. Messages never include the rejected value.
var ErrInvalidInput = errors.New("invalid custom secret input")

var (
	serviceNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._*-]{0,127}$`)
	envNamePattern     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// ValidateServiceName accepts an explicit custom service identity. Names that
// collide with built-in service secrets are rejected by the caller, which owns
// that list.
func ValidateServiceName(name string) error {
	if !serviceNamePattern.MatchString(name) {
		return fmt.Errorf("%w: service name must be 1 to 128 lowercase letters, digits, '.', '_', '-' or '*'", ErrInvalidInput)
	}
	return nil
}

// ValidateEnvName accepts a POSIX-style environment variable name. An empty
// name is valid and means the secret is only substituted, never exported.
func ValidateEnvName(name string) error {
	if name == "" || envNamePattern.MatchString(name) {
		return nil
	}
	return fmt.Errorf("%w: environment name must match [A-Za-z_][A-Za-z0-9_]*", ErrInvalidInput)
}

// ValidateScope checks the scope and sandbox pair with the same rules as
// service secrets: global scope takes no sandbox, sandbox scope requires one.
func ValidateScope(scope servicesecrets.Scope, sandboxName string) (servicesecrets.Scope, string, error) {
	if scope == "" {
		scope = servicesecrets.ScopeGlobal
	}
	sandboxName = strings.TrimSpace(sandboxName)
	switch scope {
	case servicesecrets.ScopeGlobal:
		if sandboxName != "" {
			return "", "", fmt.Errorf("%w: sandbox name requires sandbox scope", ErrInvalidInput)
		}
	case servicesecrets.ScopeSandbox:
		if sandboxName == "" || len(sandboxName) > maxSandboxNameLength || strings.ContainsAny(sandboxName, "/\\\x00\r\n") {
			return "", "", fmt.Errorf("%w: sandbox scope requires a valid sandbox name", ErrInvalidInput)
		}
	default:
		return "", "", fmt.Errorf("%w: scope must be global or sandbox", ErrInvalidInput)
	}
	return scope, sandboxName, nil
}

// ValidateValue checks the inline secret value. The message never includes it.
func ValidateValue(value []byte) error {
	if len(value) == 0 || len(value) > MaxValueBytes || !utf8.Valid(value) || strings.ContainsRune(string(value), '\x00') {
		return fmt.Errorf("%w: value must be valid UTF-8 and 1 to %d bytes", ErrInvalidInput, MaxValueBytes)
	}
	return nil
}
