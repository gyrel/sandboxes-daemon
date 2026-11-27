package redactcheck_test

import (
	"bytes"
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

// TestRedactionHarnessWindowsCoverage is platform independent: every fixture is
// a string, so it exercises the Windows coverage model on any host OS.
func TestRedactionHarnessWindowsCoverage(t *testing.T) {
	const windowsRoot = `C:\Users\runneradmin\AppData\Local\Temp\TestRedactionHarness_create-workspace-root1234567890\go-build1234567\T\x`
	const otherRoot = `C:\Users\runneradmin\AppData\Local\Temp\redactcheck-other-root`
	const unixRoot = "/var/folders/test/T/redactcheck-root"
	const plantedSecret = `sk-abcdefghijklmnopQWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OTAx`

	cases := []struct {
		name      string
		data      string
		allowRoot string
		wantRules []string
		wantClean bool
	}{
		{
			name:      "allow root span covers windows entropy",
			data:      `{"workspace":"` + windowsRoot + `"}`,
			allowRoot: windowsRoot,
			wantClean: true,
		},
		{
			name:      "windows host prefix outside allow root",
			data:      `{"workspace":"` + windowsRoot + `"}`,
			allowRoot: otherRoot,
			wantRules: []string{redactcheck.RuleUsersPath},
		},
		{
			name:      "windows drive letter prefix is case insensitive",
			data:      "workspace=" + strings.ToLower(windowsRoot),
			allowRoot: otherRoot,
			wantRules: []string{redactcheck.RuleUsersPath},
		},
		{
			name:      "secret outside allow root path token still detected",
			data:      "workspace=" + windowsRoot + "\nleak=" + plantedSecret,
			allowRoot: windowsRoot,
			wantRules: []string{redactcheck.RuleOpenAIKey, redactcheck.RuleHighEntropyB64},
		},
		{
			name:      "base64 run starting left of allow root token still detected",
			data:      plantedSecret + unixRoot,
			allowRoot: unixRoot,
			wantRules: []string{redactcheck.RuleHighEntropyB64},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := redactcheck.Options{AllowRoot: tc.allowRoot, HomeDir: "/Users/someone"}
			findings := redactcheck.ScanString(tc.data, opts)
			if tc.wantClean {
				if len(findings) != 0 {
					t.Fatalf("covered windows root produced %d findings: %+v", len(findings), findings)
				}
				return
			}
			for _, rule := range tc.wantRules {
				if !hasRule(findings, rule) {
					t.Fatalf("scan produced %+v, want rule %s", findings, rule)
				}
			}
			for _, finding := range findings {
				if strings.Contains(finding.String(), tc.data) {
					t.Fatalf("finding retained matched bytes: %s", finding)
				}
			}
		})
	}
}

// TestRedactionHarnessAllowRegionTokenExtension pins the allow-region rule that
// replaces full-containment suppression: an entropy or secret match is covered
// only when it STARTS inside the path token that begins at a known spelling of
// the test-owned root. Every fixture is a string, so this is platform
// independent and runs on darwin as the Windows evidence proxy.
func TestRedactionHarnessAllowRegionTokenExtension(t *testing.T) {
	const windowsRoot = `C:\Users\runneradmin\AppData\Local\Temp\TestRedactionHarness_create-workspace-root1234567890\go-build1234567\T\001`
	const escapedRoot = `C:\\Users\\runneradmin\\AppData\\Local\\Temp\\TestRedactionHarness_create-workspace-root1234567890\\go-build1234567\\T\\001`
	const unixRoot = "/var/folders/test/T/redactcheck-root"
	const entropyRun = "QWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OTAx"
	const plantedSecret = "sk-abcdefghijklmnop" + entropyRun

	cases := []struct {
		name       string
		data       string
		allowRoot  string
		wantClean  bool
		wantRules  []string
		wantAbsent []string
	}{
		{
			name:      "json escaped root covers entropy",
			data:      `{"workspace":"` + escapedRoot + `"}`,
			allowRoot: windowsRoot,
			wantClean: true,
		},
		{
			// The entropy run is a descendant of the root, not contained by the
			// root bytes. Token extension must cover it. The descendant path
			// itself stays a host-path finding: only entropy/secret suppression
			// is extended, by design.
			name:       "descendant path token covers entropy",
			data:       windowsRoot + `\work\dir\` + entropyRun,
			allowRoot:  windowsRoot,
			wantRules:  []string{redactcheck.RuleUsersPath},
			wantAbsent: []string{redactcheck.RuleHighEntropyB64},
		},
		{
			// Same descendant shape in JSON-escaped spelling: no known Windows
			// prefix matches the doubled separators, so the whole artifact is
			// clean and the entropy is proven covered by token extension.
			name:      "json escaped descendant is fully covered",
			data:      `{"workspace":"` + escapedRoot + `\\work\\dir\\` + entropyRun + `"}`,
			allowRoot: windowsRoot,
			wantClean: true,
		},
		{
			name:       "planted secret outside any path token is detected",
			data:       `{"workspace":"` + escapedRoot + `","leak":"` + plantedSecret + `"}`,
			allowRoot:  windowsRoot,
			wantRules:  []string{redactcheck.RuleOpenAIKey, redactcheck.RuleHighEntropyB64},
			wantAbsent: nil,
		},
		{
			// The run begins before the root token and crosses its start, so it
			// is not test-owned even though it intersects the region.
			name:       "run starting left of token still detected",
			data:       entropyRun + unixRoot,
			allowRoot:  unixRoot,
			wantRules:  []string{redactcheck.RuleHighEntropyB64},
			wantAbsent: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := redactcheck.Options{AllowRoot: tc.allowRoot, HomeDir: "/Users/someone"}
			findings := redactcheck.ScanString(tc.data, opts)
			for _, finding := range findings {
				t.Logf("finding: %s", finding)
			}
			if tc.wantClean {
				if len(findings) != 0 {
					t.Fatalf("covered artifact produced %d findings: %+v", len(findings), findings)
				}
				return
			}
			for _, rule := range tc.wantRules {
				if !hasRule(findings, rule) {
					t.Fatalf("scan produced %+v, want rule %s", findings, rule)
				}
			}
			for _, rule := range tc.wantAbsent {
				if hasRule(findings, rule) {
					t.Fatalf("scan produced %+v, want no rule %s", findings, rule)
				}
			}
			for _, finding := range findings {
				if strings.Contains(finding.String(), tc.data) {
					t.Fatalf("finding retained matched bytes: %s", finding)
				}
			}
		})
	}
}

// TestDiagnosticWindow pins the failure-output format: the slice starts at
// max(0, offset-64), ends at min(len, offset+128) and escapes non-printables.
func TestDiagnosticWindow(t *testing.T) {
	data := append(bytes.Repeat([]byte{'a'}, 64), []byte("C:\\Users\\x\x00y")...)
	data = append(data, bytes.Repeat([]byte{'z'}, 200)...)
	const offset = 64
	got := diagnosticWindow(data, offset)
	if !strings.HasPrefix(got, "bytes[0:192] offset=64 ") {
		t.Fatalf("diagnostic window = %q, want bytes[0:192] prefix", got)
	}
	if !strings.Contains(got, `C:\Users\x\x00y`) {
		t.Fatalf("diagnostic window did not escape NUL in place: %q", got)
	}
	short := diagnosticWindow([]byte("xyz"), 1)
	if short != "bytes[0:3] offset=1 xyz" {
		t.Fatalf("short diagnostic window = %q", short)
	}
	t.Logf("sample diagnostic: %s", got)
}

// TestFindingContextDiagnostics proves the harness failure helper attaches the
// escaped artifact slice for a finding produced through the real scan path.
func TestFindingContextDiagnostics(t *testing.T) {
	data := []byte(strings.Repeat("a", 80) + "\x00copy /Users/someone/secret.key failed" + strings.Repeat("z", 200))
	artifacts := []redactcheck.Artifact{{Name: "error:sample", Data: data}}
	findings := redactcheck.ScanArtifacts(artifacts, redactcheck.Options{HomeDir: "/Users/someone"})
	if len(findings) == 0 {
		t.Fatal("sample artifact was not detected")
	}
	context := findingContext(findings[0], artifacts)
	if !strings.Contains(context, "/Users/someone/secret.key") {
		t.Fatalf("diagnostic context omitted the matched path: %q", context)
	}
	if !strings.Contains(context, `\x00`) {
		t.Fatalf("diagnostic context did not escape NUL: %q", context)
	}
	t.Logf("sample finding context: %s", context)
}
