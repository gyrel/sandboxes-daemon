package customsecrets

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestResolvePlaceholderGeneratesUniqueTemplatedValues(t *testing.T) {
	const value = "synthetic-secret-value-do-not-print"
	seen := make(map[string]struct{})
	for i := 0; i < 200; i++ {
		got, err := ResolvePlaceholder("", []byte(value), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(got, "rheic-") || len(got) != len("rheic-")+32 {
			t.Fatalf("default placeholder shape = %q", got)
		}
		if strings.Contains(got, value) {
			t.Fatal("generated placeholder contains the secret value")
		}
		if _, dup := seen[got]; dup {
			t.Fatalf("duplicate generated placeholder %q", got)
		}
		seen[got] = struct{}{}
	}
	got, err := ResolvePlaceholder("sk-{rand}", []byte(value), nil)
	if err != nil || !strings.HasPrefix(got, "sk-") || len(got) != len("sk-")+32 {
		t.Fatalf("suffix template = %q, %v", got, err)
	}
}

func TestResolvePlaceholderExplicitAndValidation(t *testing.T) {
	const value = "synthetic-secret-value-do-not-print"
	got, err := ResolvePlaceholder("sk-explicit-123", []byte(value), nil)
	if err != nil || got != "sk-explicit-123" {
		t.Fatalf("explicit placeholder = %q, %v", got, err)
	}
	for _, request := range []string{
		"short",
		"has space-placeholder",
		"${secret:openai}",
		"sk-" + value,
		value,
		"{rand}-prefix-marker",
		"a{rand}b",
		"sk-{rand}{rand}",
		"nul\x00placeholder",
		strings.Repeat("p", maxPlaceholderLength+1),
	} {
		if _, err := ResolvePlaceholder(request, []byte(value), nil); !errors.Is(err, ErrInvalidPlaceholder) {
			t.Errorf("ResolvePlaceholder(%q) err = %v, want ErrInvalidPlaceholder", request, err)
		}
	}
}

func TestPlaceholderErrorsDoNotEchoPlaceholderOrValue(t *testing.T) {
	const value = "synthetic-secret-value-do-not-print"
	_, err := ResolvePlaceholder("pre-"+value, []byte(value), nil)
	if err == nil || strings.Contains(err.Error(), value) {
		t.Fatalf("error echoed secret material: %v", err)
	}
}

func TestResolvePlaceholderRejectionSamplingAndBoundedRandomness(t *testing.T) {
	// 0xff is outside the unbiased range, so it is skipped; zeros map to 'a'.
	rejected := bytes.Repeat([]byte{0xff}, 32)
	zeros := make([]byte, 64)
	got, err := ResolvePlaceholder("x-{rand}", []byte("synthetic-value"), io.MultiReader(bytes.NewReader(rejected), bytes.NewReader(zeros)))
	if err != nil || got != "x-"+strings.Repeat("a", 32) {
		t.Fatalf("rejection sampling = %q, %v", got, err)
	}
	stuck := bytes.Repeat([]byte{0xff}, 4096)
	if _, err := ResolvePlaceholder("x-{rand}", []byte("synthetic-value"), bytes.NewReader(stuck)); err == nil {
		t.Fatal("random source that never yields usable bytes was accepted")
	}
}

func TestMaskPlaceholderRevealsAtMostFourCharacters(t *testing.T) {
	const placeholder = "sk-abcdefghijklmnop"
	masked := MaskPlaceholder(placeholder)
	if masked != strings.Repeat("*", 12)+"mnop" || len(masked) != 16 {
		t.Fatalf("mask = %q", masked)
	}
	if strings.Contains(masked, "sk-") || strings.Contains(masked, "abcdefgh") {
		t.Fatalf("mask leaked prefix or middle: %q", masked)
	}
	if short := MaskPlaceholder("abcdefgh"); short != strings.Repeat("*", 12)+"efgh" {
		t.Fatalf("short mask = %q", short)
	}
	if MaskPlaceholder("") != "" {
		t.Fatal("empty placeholder must mask to empty")
	}
}
