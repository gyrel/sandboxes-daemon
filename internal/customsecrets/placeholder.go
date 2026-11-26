package customsecrets

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// RandMarker is the template suffix replaced by random characters.
	RandMarker = "{rand}"
	// DefaultTemplate is used when a request leaves the placeholder empty.
	DefaultTemplate = "gyrel-" + RandMarker

	randLength           = 32
	randAlphabet         = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	maxPlaceholderLength = 256
	minPlaceholderLength = 8
	generateAttempts     = 16
	maskWidth            = 16
	maskRevealed         = 4
)

// ErrInvalidPlaceholder reports a placeholder that cannot be used. Messages
// never include the placeholder or the value, which may be secret.
var ErrInvalidPlaceholder = errors.New("invalid custom secret placeholder")

// ResolvePlaceholder returns the placeholder to use for a request. An empty
// request uses DefaultTemplate. A template ending in {rand} gets random
// characters from crypto/rand. Any other input is an explicit placeholder and
// is returned unchanged after validation against value. The random source is
// injectable for tests; production callers pass rand.Reader.
func ResolvePlaceholder(request string, value []byte, random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	template := request
	if template == "" {
		template = DefaultTemplate
	}
	if !strings.Contains(template, RandMarker) {
		if err := ValidatePlaceholder(template, value); err != nil {
			return "", err
		}
		return template, nil
	}
	if strings.Count(template, RandMarker) != 1 || !strings.HasSuffix(template, RandMarker) {
		return "", fmt.Errorf("%w: {rand} must appear once as the suffix", ErrInvalidPlaceholder)
	}
	prefix := strings.TrimSuffix(template, RandMarker)
	for attempt := 0; attempt < generateAttempts; attempt++ {
		suffix, err := randomSuffix(random, randLength)
		if err != nil {
			return "", fmt.Errorf("generate custom secret placeholder: %w", err)
		}
		candidate := prefix + suffix
		if ValidatePlaceholder(candidate, value) == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%w: could not generate a placeholder distinct from the value", ErrInvalidPlaceholder)
}

// ValidatePlaceholder checks the placeholder grammar and that it neither equals
// nor contains the secret value. Placeholders are printable ASCII without
// whitespace, must not use the ${...} reference syntax, and must be header-safe.
func ValidatePlaceholder(placeholder string, value []byte) error {
	if len(placeholder) < minPlaceholderLength || len(placeholder) > maxPlaceholderLength {
		return fmt.Errorf("%w: length must be %d to %d bytes", ErrInvalidPlaceholder, minPlaceholderLength, maxPlaceholderLength)
	}
	for i := 0; i < len(placeholder); i++ {
		if c := placeholder[i]; c < 0x21 || c > 0x7e {
			return fmt.Errorf("%w: only printable ASCII without spaces is allowed", ErrInvalidPlaceholder)
		}
	}
	if strings.Contains(placeholder, "${") || strings.Contains(placeholder, RandMarker) {
		return fmt.Errorf("%w: reserved syntax", ErrInvalidPlaceholder)
	}
	if len(value) > 0 && (placeholder == string(value) || strings.Contains(placeholder, string(value))) {
		return fmt.Errorf("%w: must not contain the secret value", ErrInvalidPlaceholder)
	}
	return nil
}

// MaskPlaceholder returns a fixed-width mask that reveals at most the last four
// characters. Inventories use it; the full placeholder is returned only on the
// write path.
func MaskPlaceholder(placeholder string) string {
	if placeholder == "" {
		return ""
	}
	revealed := placeholder
	if len(revealed) > maskRevealed {
		revealed = revealed[len(revealed)-maskRevealed:]
	}
	return strings.Repeat("*", maskWidth-len(revealed)) + revealed
}

// randomSuffix samples uniformly from randAlphabet using rejection sampling, so
// the modulo bias that a plain byte%62 would introduce is avoided.
func randomSuffix(random io.Reader, length int) (string, error) {
	const limit = 256 - 256%len(randAlphabet)
	const maxRounds = 64
	out := make([]byte, 0, length)
	buf := make([]byte, length)
	for round := 0; len(out) < length; round++ {
		if round == maxRounds {
			return "", errors.New("random source produced too few usable bytes")
		}
		if _, err := io.ReadFull(random, buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out = append(out, randAlphabet[int(b)%len(randAlphabet)])
			if len(out) == length {
				break
			}
		}
	}
	return string(out), nil
}
