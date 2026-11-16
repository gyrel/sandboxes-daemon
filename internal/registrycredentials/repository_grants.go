package registrycredentials

import (
	"errors"
	"net/http"
	"strings"
)

// ValidateRepositoryGrants validates exact host-configured repository scopes.
// Grants use the OCI form repository:NAME:pull,push, with no wildcards.
func ValidateRepositoryGrants(grants []string) error {
	_, err := compileRepositoryGrants(grants)
	return err
}

func compileRepositoryGrants(grants []string) (map[string]map[string]struct{}, error) {
	if len(grants) > 256 {
		return nil, errors.New("too many registry repository grants")
	}
	compiled := make(map[string]map[string]struct{}, len(grants))
	for _, grant := range grants {
		repository, actions, ok := parseRepositoryScope(grant)
		if !ok {
			return nil, errors.New("invalid registry repository grant")
		}
		if _, exists := compiled[repository]; exists {
			return nil, errors.New("duplicate registry repository grant")
		}
		compiled[repository] = actions
	}
	return compiled, nil
}

func (p *PullProxy) allowsRepository(repository string, actions map[string]struct{}) bool {
	allowed, ok := p.repositoryGrants[repository]
	if !ok || len(actions) == 0 {
		return false
	}
	for action := range actions {
		if _, ok := allowed[action]; !ok {
			return false
		}
	}
	return true
}

func denyRepository(w http.ResponseWriter) {
	http.Error(w, "registry authentication failed", http.StatusUnauthorized)
}

// ParseSandboxRepositoryGrants validates exact sandbox=repository:... entries.
// Entries bind authority to a sandbox name; no wildcard sandbox is accepted.
func ParseSandboxRepositoryGrants(entries []string) (map[string][]string, error) {
	if len(entries) > 256 {
		return nil, errors.New("too many sandbox registry grants")
	}
	result := make(map[string][]string)
	for _, entry := range entries {
		sandbox, scope, ok := strings.Cut(entry, "=")
		if !ok || !validGrantSandboxName(sandbox) {
			return nil, errors.New("invalid sandbox registry grant")
		}
		result[sandbox] = append(result[sandbox], scope)
	}
	for _, scopes := range result {
		if err := ValidateRepositoryGrants(scopes); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func validGrantSandboxName(name string) bool {
	if name == "" || len(name) > 63 || name == "." || name == ".." {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}
