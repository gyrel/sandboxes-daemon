package redactcheck_test

import (
	"strings"
	"testing"

	"github.com/gyrel/sandboxes-daemon/internal/testsupport/redactcheck"
)

func TestRedactionHarnessScanRules(t *testing.T) {
	const root = "/var/folders/test/T/redactcheck-root"
	opts := redactcheck.Options{AllowRoot: root, HomeDir: "/Users/someone", GuestRoots: []string{"/workspace"}}
	cases := []struct {
		name string
		data string
		rule string
	}{
		{"user home", "open /Users/someone/.ssh/id_ed25519: denied", redactcheck.RuleUserHome},
		{"users path", "read /Users/other/private/key", redactcheck.RuleUsersPath},
		{"bare users root", "list /Users", redactcheck.RuleAbsolutePath},
		{"var folders", "temp /var/folders/ab/cdef/T/cache", redactcheck.RuleVarFoldersPath},
		{"gyrel temp", "socket /tmp/gyrel-sbx-1/state.sock", redactcheck.RuleGyrelTempPath},
		{"private", "volume /private/var/db/secret", redactcheck.RulePrivatePath},
		{"absolute", "config /opt/gyrel/secrets.json", redactcheck.RuleAbsolutePath},
		{"pem", "-----BEGIN PRIVATE KEY-----", redactcheck.RulePEMPrivateKey},
		{"openai", "sk-abcdefghijklmnop", redactcheck.RuleOpenAIKey},
		{"aws", "AKIAABCDEFGHIJKLMNOP", redactcheck.RuleAWSAccessKey},
		{"github", "ghp_abcdefghijklmnop", redactcheck.RuleGitHubToken},
		{"slack", "xoxb-1234567890-abcdefgh", redactcheck.RuleSlackToken},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.payload", redactcheck.RuleJWTPrefix},
		{"bearer", "Authorization: Bearer abcdefghijklmnop", redactcheck.RuleBearerToken},
		{"inline", "password=hunter2longvalue", redactcheck.RuleInlineSecret},
		{"base64", "blob QWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OTAx", redactcheck.RuleHighEntropyB64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := redactcheck.ScanString(tc.data, opts)
			if !hasRule(findings, tc.rule) {
				t.Fatalf("scan(%q) = %+v, want rule %s", tc.data, findings, tc.rule)
			}
			for _, finding := range findings {
				if strings.Contains(finding.String(), tc.data) {
					t.Fatalf("finding retained matched bytes: %s", finding)
				}
			}
		})
	}
}

func TestRedactionHarnessScanAllowlist(t *testing.T) {
	const root = "/var/folders/test/T/redactcheck-root"
	opts := redactcheck.Options{AllowRoot: root, HomeDir: "/Users/someone", GuestRoots: []string{"/workspace"}}
	for _, data := range []string{
		"database " + root,
		"workspace /workspace/project/file.go",
	} {
		if findings := redactcheck.ScanString(data, opts); len(findings) != 0 {
			t.Fatalf("allowlisted data %q produced %+v", data, findings)
		}
	}
	// Only the exact test root is allowlisted; descendants and unrelated
	// siblings remain findings.
	for _, data := range []string{
		root + "/daemon.sqlite",
		root + "-other/leak",
	} {
		if findings := redactcheck.ScanString(data, opts); len(findings) == 0 {
			t.Fatalf("path outside the exact allow root %q was not detected", data)
		}
	}
}

func hasRule(findings []redactcheck.Finding, rule string) bool {
	for _, finding := range findings {
		if finding.Rule == rule {
			return true
		}
	}
	return false
}
