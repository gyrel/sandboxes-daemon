// Package redactcheck detects host-absolute paths and secret-shaped values in
// artifacts produced by daemon verb paths.
//
// The package is test support only. It never retains a matched value in a
// Finding, so a failing assertion cannot become a second leak. Detection is
// intentionally heuristic: a clean result is evidence that known patterns are
// absent, not proof that arbitrary data is safe to disclose.
package redactcheck

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Rule identifiers reported by Scan. They are stable so a failing gate names
// the class of leak rather than echoing the leaked bytes.
const (
	RuleUserHome       = "host_path_user_home"
	RuleUsersPath      = "host_path_users"
	RuleVarFoldersPath = "host_path_var_folders"
	RuleGyrelTempPath  = "host_path_gyrel_tmp"
	RulePrivatePath    = "host_path_private"
	RuleHomePath       = "host_path_home"
	RuleAbsolutePath   = "host_path_absolute"
	RulePEMPrivateKey  = "pem_private_key"
	RuleOpenAIKey      = "openai_key"
	RuleAWSAccessKey   = "aws_access_key"
	RuleGitHubToken    = "github_token"
	RuleSlackToken     = "slack_token"
	RuleJWTPrefix      = "jwt"
	RuleBearerToken    = "bearer"
	RuleInlineSecret   = "inline_secret"
	RuleHighEntropyB64 = "base64_high_entropy"
)

// Options controls one scan. AllowRoot is the exact test-owned temporary
// directory passed by the harness; the root string itself is allowed, while
// any other absolute path (including a descendant) is a finding. GuestRoots
// name guest-visible absolute path trees that are not host paths.
type Options struct {
	AllowRoot  string
	HomeDir    string
	GuestRoots []string
}

// Finding is one detected value. Artifact names the file, log stream, error
// string or SQLite row that contained it. The matched bytes are deliberately
// absent from the result.
type Finding struct {
	Artifact string
	Rule     string
	Line     int
	Offset   int64
}

// String renders a finding for a test log or report.
func (f Finding) String() string {
	artifact := f.Artifact
	if artifact == "" {
		artifact = "unattributed"
	}
	return fmt.Sprintf("%s:%d [%s] offset=%d", artifact, f.Line, f.Rule, f.Offset)
}

// Artifact is one named observable output: an error string, a log stream, an
// audit JSONL file, a SQLite row or a JSON snapshot.
type Artifact struct {
	Name string
	Data []byte
}

type secretRule struct {
	id string
	re *regexp.Regexp
}

// secretRules mirrors the shipped slogx/redact rule list and adds the
// abbreviated forms named by the X-3 brief. The copy is intentional: importing
// the production scanner would let a production redaction change alter the
// detection control. Keep this list cross-referenced with
// github.com/gyrel/slogx/redact.scan.go when that list changes.
var secretRules = []secretRule{
	{RulePEMPrivateKey, regexp.MustCompile(`-{5}BEGIN`)},
	{RuleOpenAIKey, regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}`)},
	{RuleAWSAccessKey, regexp.MustCompile(`\bAKIA[A-Z0-9]{8,}`)},
	{RuleGitHubToken, regexp.MustCompile(`\bghp_[A-Za-z0-9]{8,}`)},
	{RuleSlackToken, regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{8,}`)},
	{RuleJWTPrefix, regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}`)},
	{RuleBearerToken, regexp.MustCompile(`(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]{8,}`)},
	{RuleInlineSecret, regexp.MustCompile(`(?i)\b(?:password|api_key|secret)\s*=\s*[^\s&;,"']+`)},
}

var (
	// Padding is allowed only at the end so a key=value label in front of a
	// path does not become part of the base64 run. This keeps a path match
	// starting at the path itself, where allow-root offset coverage applies.
	base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`)
	absPath   = regexp.MustCompile(`(?:^|[\s"'` + "`" + `=:,;(\[{])((?:/[A-Za-z0-9._@+%-]+)+/?)`)
)

var knownHostPrefixes = []struct {
	rule   string
	prefix string
}{
	{RuleUsersPath, "/Users/"},
	{RuleVarFoldersPath, "/var/folders/"},
	{RuleGyrelTempPath, "/tmp/gyrel-"},
	{RulePrivatePath, "/private/"},
	{RuleHomePath, "/home/"},
	// Windows profile roots. The drive-letter comparison is folded so a path
	// produced with a lowercase drive (c:\users\...) is still recognized.
	{RuleUsersPath, `C:\Users\`},
}

type span struct {
	start int
	end   int
}

type scanner struct {
	data     []byte
	opts     Options
	findings []Finding
	spans    []span
	// allowRegions cover every representation of Options.AllowRoot, extended
	// along the path token that starts at each occurrence. Findings that are
	// not host-path rules are suppressed when their match starts inside one of
	// these regions; host-path findings keep the exact-root allowlist
	// semantics enforced by allowed.
	allowRegions []span
	seen         map[string]struct{}
}

// ScanString scans text. It is the string form of Scan.
func ScanString(s string, opts Options) []Finding {
	return Scan([]byte(s), opts)
}

// Scan returns every host-path and secret-shaped finding in data. The result
// is ordered by byte offset and then rule id.
func Scan(data []byte, opts Options) []Finding {
	if len(data) == 0 {
		return nil
	}
	s := &scanner{
		data: data,
		opts: normalizeOptions(opts),
		seen: make(map[string]struct{}),
	}
	s.markAllowRootSpans()
	s.findKnownHostPaths()
	s.findGenericHostPaths()
	s.findSecrets()
	sort.Slice(s.findings, func(i, j int) bool {
		if s.findings[i].Offset != s.findings[j].Offset {
			return s.findings[i].Offset < s.findings[j].Offset
		}
		return s.findings[i].Rule < s.findings[j].Rule
	})
	return s.findings
}

// ScanArtifacts scans every artifact and attributes each finding to its
// artifact name. The result is ordered by artifact, offset and rule id.
func ScanArtifacts(artifacts []Artifact, opts Options) []Finding {
	var out []Finding
	for _, artifact := range artifacts {
		for _, finding := range Scan(artifact.Data, opts) {
			finding.Artifact = artifact.Name
			out = append(out, finding)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Artifact != out[j].Artifact {
			return out[i].Artifact < out[j].Artifact
		}
		if out[i].Offset != out[j].Offset {
			return out[i].Offset < out[j].Offset
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

func normalizeOptions(opts Options) Options {
	opts.AllowRoot = trimRoot(opts.AllowRoot)
	for i := range opts.GuestRoots {
		opts.GuestRoots[i] = trimRoot(opts.GuestRoots[i])
	}
	if opts.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			opts.HomeDir = trimRoot(home)
		}
	} else {
		opts.HomeDir = trimRoot(opts.HomeDir)
	}
	return opts
}

func trimRoot(root string) string {
	root = strings.TrimSpace(root)
	if root == "" || root == "/" {
		return ""
	}
	return strings.TrimRight(root, "/")
}

// markAllowRootSpans records every occurrence of the test-owned allow root in
// each accepted spelling. Each occurrence is extended to the end of the
// maximal path token starting there: a run of path-grammar bytes. It runs
// before any detection rule so entropy and secret matches that start inside
// those bytes can be discarded instead of relying on a platform-specific
// prefix list.
//
// The extension is deliberately one-sided. The prose before the allow root is
// not test-owned, so a match that begins to the left of the token start is
// still reported even when it runs into the region; see allowRegionSuppressed.
func (s *scanner) markAllowRootSpans() {
	root := s.opts.AllowRoot
	if root == "" {
		return
	}
	for _, variant := range allowRootVariants(root) {
		needle := []byte(variant)
		for start := 0; start < len(s.data); {
			index := bytes.Index(s.data[start:], needle)
			if index < 0 {
				break
			}
			begin := start + index
			s.allowRegions = append(s.allowRegions, span{
				start: begin,
				end:   allowTokenEnd(s.data, begin),
			})
			start = begin + len(needle)
		}
	}
}

// allowRootVariants returns the spellings in which a test-owned root can reach
// an artifact: native, slash-normalized, backslash-normalized, JSON-escaped
// (each backslash doubled) and the same four with a lowercase drive letter.
func allowRootVariants(root string) []string {
	spellings := []string{
		root,
		filepath.ToSlash(root),
		filepath.FromSlash(root),
		strings.ReplaceAll(root, `\`, `\\`),
	}
	out := make([]string, 0, 2*len(spellings))
	seen := make(map[string]struct{}, 2*len(spellings))
	add := func(variant string) {
		if variant == "" {
			return
		}
		if _, ok := seen[variant]; ok {
			return
		}
		seen[variant] = struct{}{}
		out = append(out, variant)
	}
	for _, spelling := range spellings {
		add(spelling)
		add(lowercaseDrive(spelling))
	}
	return out
}

// lowercaseDrive folds an ASCII drive-letter prefix (C: -> c:) so a path
// rendered with a lowercase drive still matches an uppercase allow root.
func lowercaseDrive(value string) string {
	if len(value) < 2 || value[1] != ':' || !isASCIIAlpha(value[0]) {
		return value
	}
	return string(foldASCII(value[0])) + value[1:]
}

// allowTokenEnd returns the exclusive end of the maximal path token that
// begins at start. The class is the path grammar accepted by the harness:
// letters, digits, space, '.', '_', '@', '%', '+', '-', '/', '\', ':', '$',
// '{' and '}'. JSON-escaped backslashes are pairs of that same backslash byte.
func allowTokenEnd(data []byte, start int) int {
	end := start
	for end < len(data) && allowTokenByte(data[end]) {
		end++
	}
	return end
}

func allowTokenByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case ' ', '.', '_', '@', '%', '+', '-', '/', '\\', ':', '$', '{', '}', '~':
		return true
	default:
		return false
	}
}

// allowRegionSuppressed reports whether a match starting at offset belongs to
// a proven test-owned path token. The match must START inside the region, not
// merely intersect it: a run that begins before the token and crosses into it
// is still reported.
func (s *scanner) allowRegionSuppressed(offset int) bool {
	for _, region := range s.allowRegions {
		if offset >= region.start && offset < region.end {
			return true
		}
	}
	return false
}

func (s *scanner) findKnownHostPaths() {
	if s.opts.HomeDir != "" {
		s.findPrefix(RuleUserHome, s.opts.HomeDir)
	}
	for _, known := range knownHostPrefixes {
		s.findPrefix(known.rule, known.prefix)
	}
}

func (s *scanner) findPrefix(rule, prefix string) {
	if prefix == "" {
		return
	}
	needle := []byte(prefix)
	fold := driveLetterPrefix(prefix)
	for start := 0; start < len(s.data); {
		index := indexPrefix(s.data, needle, start, fold)
		if index < 0 {
			return
		}
		offset := index
		path, end := readPath(s.data, offset)
		if path == "" {
			start = offset + len(needle)
			continue
		}
		if !s.covered(offset, end) {
			s.spans = append(s.spans, span{start: offset, end: end})
			if !s.allowed(path) {
				s.add(rule, offset)
			}
		}
		if end <= offset {
			end = offset + len(needle)
		}
		start = end
	}
}

func indexPrefix(data, needle []byte, start int, fold bool) int {
	if !fold {
		index := bytes.Index(data[start:], needle)
		if index < 0 {
			return -1
		}
		return start + index
	}
	if len(needle) == 0 || start < 0 || start+len(needle) > len(data) {
		return -1
	}
	for i := start; i <= len(data)-len(needle); i++ {
		matched := true
		for j := range needle {
			if foldASCII(data[i+j]) != foldASCII(needle[j]) {
				matched = false
				break
			}
		}
		if matched {
			return i
		}
	}
	return -1
}

func driveLetterPrefix(prefix string) bool {
	return len(prefix) >= 2 && prefix[1] == ':' && isASCIIAlpha(prefix[0])
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func foldASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func (s *scanner) findGenericHostPaths() {
	for _, match := range absPath.FindAllSubmatchIndex(s.data, -1) {
		start, end := match[2], match[3]
		path := cleanPath(string(s.data[start:end]))
		if path == "" || s.covered(start, start+len(path)) {
			continue
		}
		s.spans = append(s.spans, span{start: start, end: start + len(path)})
		if !s.allowed(path) {
			s.add(RuleAbsolutePath, start)
		}
	}
}

func (s *scanner) findSecrets() {
	for _, rule := range secretRules {
		for _, match := range rule.re.FindAllIndex(s.data, -1) {
			s.add(rule.id, match[0])
		}
	}
	for _, match := range base64Run.FindAllIndex(s.data, -1) {
		if !mixedCaseAndDigits(s.data[match[0]:match[1]]) {
			continue
		}
		// Suppression is centralized in add: a run that starts inside an
		// extended test-owned path token is discarded, while a run that starts
		// to the left of the token is still reported.
		s.add(RuleHighEntropyB64, match[0])
	}
}

func (s *scanner) add(rule string, offset int) {
	// Secret-shaped matches inside the test-owned root's path token are false
	// positives produced by the root's own spelling (including JSON-escaped
	// descendants). Host-path rules keep allowed's exact-root semantics so a
	// descendant remains a finding.
	if !hostPathRule(rule) && s.allowRegionSuppressed(offset) {
		return
	}
	key := fmt.Sprintf("%s:%d", rule, offset)
	if _, exists := s.seen[key]; exists {
		return
	}
	s.seen[key] = struct{}{}
	s.findings = append(s.findings, Finding{
		Rule:   rule,
		Line:   1 + bytes.Count(s.data[:offset], []byte{'\n'}),
		Offset: int64(offset),
	})
}

func hostPathRule(rule string) bool {
	switch rule {
	case RuleUserHome, RuleUsersPath, RuleVarFoldersPath, RuleGyrelTempPath, RulePrivatePath, RuleHomePath, RuleAbsolutePath:
		return true
	default:
		return false
	}
}

func (s *scanner) allowed(path string) bool {
	path = cleanPath(path)
	if path == "" {
		return true
	}
	if path == s.opts.AllowRoot {
		return true
	}
	for _, root := range s.opts.GuestRoots {
		if underRoot(path, root) {
			return true
		}
	}
	return false
}

func (s *scanner) covered(start, end int) bool {
	for _, existing := range s.spans {
		if start < existing.end && end > existing.start {
			return true
		}
	}
	return false
}

func underRoot(path, root string) bool {
	if root == "" {
		return false
	}
	return path == root || strings.HasPrefix(path, root+"/")
}

func readPath(data []byte, start int) (string, int) {
	end := start
	for end < len(data) && !pathStop(data[end]) {
		end++
	}
	return cleanPath(string(data[start:end])), end
}

func cleanPath(path string) string {
	return strings.TrimRight(path, ".,;:!?)]}")
}

func pathStop(b byte) bool {
	switch b {
	// Backslash is a path separator on Windows, not a terminator. Treating it
	// as ordinary path data lets a C:\... path scan as one unit.
	case 0, ' ', '\t', '\n', '\r', '\v', '\f', '"', '\'', '`', '<', '>', '(', ')', '[', ']', '{', '}', ',', ';':
		return true
	default:
		return false
	}
}

func mixedCaseAndDigits(data []byte) bool {
	var upper, lower, digit bool
	for _, b := range data {
		switch {
		case b >= 'A' && b <= 'Z':
			upper = true
		case b >= 'a' && b <= 'z':
			lower = true
		case b >= '0' && b <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}
