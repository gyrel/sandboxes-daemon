package settings

import (
	"strings"
	"testing"
)

func TestPublishAllowlistSettings(t *testing.T) {
	entries := "10.0.0.0/8,2001:db8::/32,127.0.0.1/32"
	for _, body := range []string{
		`network.publish.allowedCIDRs = ["10.0.0.0/8", "2001:db8::/32", "127.0.0.1/32"]`,
		`network.publish.allowedCIDRs = "[\"10.0.0.0/8\", \"2001:db8::/32\", \"127.0.0.1/32\"]"`,
		`network.publish.allowed_cidrs = ["10.0.0.0/8", "2001:db8::/32", "127.0.0.1/32"]`,
	} {
		t.Run(body, func(t *testing.T) {
			var values Values
			if err := parse(strings.NewReader(body), &values); err != nil {
				t.Fatal(err)
			}
			if err := validateValues(&values); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(values.NetworkPublishAllowedCIDRs, ","); got != entries {
				t.Fatalf("entries = %q, want %q", got, entries)
			}
		})
	}

	var empty Values
	if err := parse(strings.NewReader(`network.publish.allowedCIDRs = []`), &empty); err != nil {
		t.Fatal(err)
	}
	if len(empty.NetworkPublishAllowedCIDRs) != 0 {
		t.Fatalf("empty allowlist = %+v", empty.NetworkPublishAllowedCIDRs)
	}
}

func TestPublishAllowlistSettingsFailClosed(t *testing.T) {
	for name, body := range map[string]string{
		"garbage JSON":       `network.publish.allowedCIDRs = [10.0.0.0/8]`,
		"scalar":             `network.publish.allowedCIDRs = "10.0.0.0/8"`,
		"null":               `network.publish.allowedCIDRs = null`,
		"host bits":          `network.publish.allowedCIDRs = ["10.1.2.3/8"]`,
		"bad prefix length":  `network.publish.allowedCIDRs = ["10.0.0.0/33"]`,
		"bare address":       `network.publish.allowedCIDRs = ["10.0.0.0"]`,
		"duplicate":          `network.publish.allowedCIDRs = ["10.0.0.0/8", "10.0.0.0/8"]`,
		"empty entry":        `network.publish.allowedCIDRs = ["10.0.0.0/8", ""]`,
		"zone":               `network.publish.allowedCIDRs = ["fe80::1%eth0/64"]`,
		"unknown namespace":  `network.publish.allowedCidrs = ["10.0.0.0/8"]`,
		"unknown extra key":  `network.publish.allowedCIDRs = ["10.0.0.0/8"]` + "\n" + `network.publish.allowAll = true`,
		"non-array of CIDRs": `network.publish.allowedCIDRs = {"cidr":"10.0.0.0/8"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var values Values
			err := parse(strings.NewReader(body), &values)
			if err == nil {
				err = validateValues(&values)
			}
			if err == nil {
				t.Fatalf("accepted invalid allowlist: %s", body)
			}
		})
	}
}

func TestPublishAllowlistCatalogRequiresRestart(t *testing.T) {
	restart, known := RequiresRestart("network.publish.allowedCIDRs")
	if !known || !restart {
		t.Fatalf("network.publish.allowedCIDRs restart=%v known=%v", restart, known)
	}
	for _, key := range []string{"kit.allowedSources", "kit.allowLocalKits", "kit.requireSignature"} {
		restart, known := RequiresRestart(key)
		if !known || !restart {
			t.Fatalf("%s restart=%v known=%v; kit.* must mirror restart semantics", key, restart, known)
		}
	}
	if _, known := RequiresRestart("network.publish.unknown"); known {
		t.Fatal("unknown key reported as cataloged")
	}
	found := false
	for _, metadata := range Catalog() {
		if metadata.Key == "network.publish.allowedCIDRs" {
			found = metadata.Restart
		}
	}
	if !found {
		t.Fatal("catalog does not mark network.publish.allowedCIDRs as restart-required")
	}
}
