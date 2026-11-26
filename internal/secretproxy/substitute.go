package secretproxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gyrel/slogx/events"
)

// Substitution replaces one guest-visible placeholder in request headers with a
// host-side value. The placeholder is not authority: it selects a host-vault
// entry that the resolver has already matched to this route's upstream.
type Substitution struct {
	Placeholder string
	Value       []byte
}

// SubstitutionResolver returns the substitutions that apply to one request on
// its route. It is evaluated per request, so a secret set or removed after the
// channel started takes effect without a restart. An error fails the request
// closed with no forwarding.
type SubstitutionResolver func(context.Context) ([]Substitution, error)

var errAmbiguousSubstitution = errors.New("ambiguous placeholder substitution")

// substituteRequest applies the route's substitutions before credential
// injection. It reports false after writing a 502 when substitution fails
// closed, so the request never reaches the upstream with a partial rewrite.
// Logs carry the route name and a count only, never placeholders or values.
func substituteRequest(w http.ResponseWriter, r *http.Request, service string, snapshot *proxySnapshot) bool {
	applied, err := applySubstitutions(r.Context(), r, snapshot.substitutions, snapshot.httpsUpstream, snapshot.upstreamHost)
	if err != nil {
		slog.Warn("custom secret substitution failed closed", "service", service)
		http.Error(w, "proxy credential unavailable", http.StatusBadGateway)
		return false
	}
	if applied > 0 {
		slog.Info("custom secret placeholder substituted", "service", service, "header_values", applied)
	}
	return true
}

// applySubstitutions replaces placeholders in the request headers. It is a
// no-op unless the route configured a resolver and dials an https upstream, so
// a plaintext route can never receive a substituted value. Replacement runs in
// a single pass, so a substituted value that happens to contain another
// placeholder is never rescanned. It returns the number of header values that
// contained a placeholder. Every refusal is recorded through the catalog:
// a configured resolver against a plaintext upstream is an InsecureScheme
// refusal, a failing host vault is VaultLocked, and a binding without a
// usable placeholder reference is RefMissing. Ambiguous overlapping bindings
// have no catalog reason and are not emitted.
func applySubstitutions(ctx context.Context, r *http.Request, resolve SubstitutionResolver, httpsUpstream bool, host string) (int, error) {
	if resolve == nil {
		return 0, nil
	}
	if !httpsUpstream {
		emitSecretSubstitute(ctx, host, "", events.SecretSubstituteDecisionRefused,
			events.SecretSubstituteReasonInsecurescheme, events.OutcomeDenied)
		return 0, nil
	}
	subs, err := resolve(ctx)
	defer clearSubstitutions(subs)
	if err != nil {
		emitSecretSubstitute(ctx, host, "", events.SecretSubstituteDecisionRefused,
			events.SecretSubstituteReasonVaultlocked, events.OutcomeFailed)
		return 0, err
	}
	if len(subs) == 0 {
		return 0, nil
	}
	if err := validateSubstitutions(subs); err != nil {
		if !errors.Is(err, errAmbiguousSubstitution) {
			emitSecretSubstitute(ctx, host, "", events.SecretSubstituteDecisionRefused,
				events.SecretSubstituteReasonRefmissing, events.OutcomeFailed)
		}
		return 0, err
	}
	return substituteHeaders(ctx, r, host, subs), nil
}

// substituteHeaders performs the single-pass replacement and records one
// substituted decision per placeholder that matched a header value.
func substituteHeaders(ctx context.Context, r *http.Request, host string, subs []Substitution) int {
	pairs := make([]string, 0, 2*len(subs))
	for _, sub := range subs {
		pairs = append(pairs, sub.Placeholder, string(sub.Value))
	}
	replacer := strings.NewReplacer(pairs...)
	applied := 0
	matched := make([]int, len(subs))
	for _, values := range r.Header {
		for i, value := range values {
			for j, sub := range subs {
				if strings.Contains(value, sub.Placeholder) {
					matched[j]++
					applied++
					break
				}
			}
			values[i] = replacer.Replace(value)
		}
	}
	for j, sub := range subs {
		if matched[j] > 0 {
			emitSecretSubstitute(ctx, host, sub.Placeholder, events.SecretSubstituteDecisionSubstituted, "", events.OutcomeOK)
		}
	}
	return applied
}

// validateSubstitutions fails closed on empty, duplicate or overlapping
// placeholders, which would make the replacement target ambiguous.
func validateSubstitutions(subs []Substitution) error {
	for i, sub := range subs {
		if sub.Placeholder == "" {
			return errors.New("empty placeholder substitution")
		}
		for _, other := range subs[i+1:] {
			if strings.Contains(sub.Placeholder, other.Placeholder) || strings.Contains(other.Placeholder, sub.Placeholder) {
				return errAmbiguousSubstitution
			}
		}
	}
	return nil
}

func clearSubstitutions(subs []Substitution) {
	for i := range subs {
		clear(subs[i].Value)
	}
}
