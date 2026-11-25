package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	core "github.com/gyrel/sandboxes-core"
	sandbox "github.com/gyrel/sandboxes-core/sandbox"
)

func TestNormalizeRulesHTTPConditions(t *testing.T) {
	rules := []sandbox.NetworkRule{
		{Protocol: "tcp", Domain: "api.example.com", Port: 443, Methods: []string{"get", "GET", "post"}},
		{Protocol: "tcp", Domain: "api.example.com", Port: 443, Methods: []string{"GET", "POST"}},
		{Protocol: "tcp", Domain: "only-any.example.com", Methods: []string{"any"}},
		{Protocol: "tcp", Domain: "path-only.example.com", Path: "/v1/**"},
		{Protocol: "tcp", Domain: "query.example.com", Query: []sandbox.QueryCondition{{Name: "trace", Value: "*"}}},
		{Protocol: "tcp", Domain: "plain.example.com"},
	}
	out, err := normalizeRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
	// The first two canonicalize to one selector and deduplicate.
	if len(out) != 5 {
		t.Fatalf("normalized rules=%d want 5: %+v", len(out), out)
	}
	first := out[0]
	if strings.Join(first.Methods, ",") != "GET,POST" {
		t.Fatalf("methods not canonical: %+v", first.Methods)
	}
	if !strings.HasPrefix(first.RuleID, "rul_") {
		t.Fatalf("rule id missing: %+v", first)
	}
	if out[1].Methods[0] != "ANY" || out[1].Path != "/**" {
		t.Fatalf("ANY sentinel must survive and condition the rule: %+v", out[1])
	}
	if out[2].Path != "/v1/**" || len(out[2].Methods) != 0 {
		t.Fatalf("path condition lost: %+v", out[2])
	}
	if out[3].Query[0].Name != "trace" || out[3].Query[0].Value != "*" {
		t.Fatalf("query condition lost: %+v", out[3])
	}
	plain := out[4]
	if len(plain.Methods) != 0 || plain.Path != "" || len(plain.Query) != 0 {
		t.Fatalf("unconditioned rule gained HTTP fields: %+v", plain)
	}
}

func TestNormalizeRulesHTTPValidationFailsClosed(t *testing.T) {
	cases := [][]sandbox.NetworkRule{
		{{Protocol: "tcp", Domain: "a.example.com", Methods: []string{"WILD"}}},
		{{Protocol: "tcp", Domain: "a.example.com", Methods: []string{"*"}}},
		{{Protocol: "tcp", Domain: "a.example.com", Methods: []string{"GET", ""}}},
		{{Protocol: "tcp", Domain: "a.example.com", Path: "v1"}},
		{{Protocol: "tcp", Domain: "a.example.com", Path: "/../etc"}},
		{{Protocol: "tcp", Domain: "a.example.com", Path: "/a b"}},
		{{Protocol: "tcp", Domain: "a.example.com", Path: "/a?b=1"}},
		{{Protocol: "tcp", Domain: "a.example.com", Query: []sandbox.QueryCondition{{Name: "", Value: "x"}}}},
		{{Protocol: "tcp", Domain: "a.example.com", Query: []sandbox.QueryCondition{{Name: "a=b", Value: "x"}}}},
		{{Protocol: "tcp", Domain: "a.example.com", Query: []sandbox.QueryCondition{{Name: "a", Value: "with space"}}}},
	}
	for i, rules := range cases {
		if _, err := normalizeRules(rules, false); !errors.Is(err, core.ErrConflict) {
			t.Fatalf("case %d accepted invalid HTTP condition: %v", i, err)
		}
	}
}

func TestNetworkRuleIDChangesWithHTTPConditions(t *testing.T) {
	base := sandbox.NetworkRule{Protocol: "tcp", Domain: "api.example.com", Port: 443}
	out, err := normalizeRules([]sandbox.NetworkRule{base}, false)
	if err != nil {
		t.Fatal(err)
	}
	l4Only := out[0].RuleID
	// L4-only IDs must keep the historical derivation byte-for-byte.
	want := networkRuleIDForTest(base)
	if l4Only != want {
		t.Fatalf("L4 rule id changed compatibility hash: %s want %s", l4Only, want)
	}
	cond := base
	cond.Methods = []string{"GET"}
	out, err = normalizeRules([]sandbox.NetworkRule{cond}, false)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].RuleID == l4Only {
		t.Fatal("HTTP-conditioned rule must derive a different id")
	}
}

// networkRuleIDForTest recomputes the pre-P1.2 hash for L4-only rules.
func networkRuleIDForTest(rule sandbox.NetworkRule) string {
	sum := sha256.Sum256([]byte(rule.Protocol + "\x00" + rule.CIDR + "\x00" + rule.Domain + "\x00" + strconv.Itoa(int(rule.Port))))
	return "rul_" + hex.EncodeToString(sum[:8])
}

func TestPolicyRuleConflictRespectsHTTPConditions(t *testing.T) {
	allow := []sandbox.NetworkRule{{Protocol: "tcp", Domain: "api.example.com", Port: 443, Methods: []string{"GET"}, Path: "/**"}}
	deny := []sandbox.NetworkRule{{Protocol: "tcp", Domain: "api.example.com", Port: 443, Methods: []string{"POST"}, Path: "/**"}}
	if err := checkPolicyRuleConflict("sandbox:test", "allow", allow[0], allow, nil); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("identical conditioned allow must conflict with itself: %v", err)
	}
	// Incoming deny of the SAME conditioned selector as an existing allow is
	// an opposite-action conflict.
	if err := checkPolicyRuleConflict("sandbox:test", "deny", allow[0], allow, deny); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("same conditioned selector in opposite scope must conflict: %v", err)
	}
	// Incoming deny with a different method does not conflict with the
	// conditioned allow.
	if err := checkPolicyRuleConflict("sandbox:test", "deny", deny[0], allow, nil); err != nil {
		t.Fatalf("different methods must not conflict: %v", err)
	}
}

func TestPolicyCheckRequestURLTargets(t *testing.T) {
	req, err := policyCheckRequest("", "", "", 0, "http://api.example.com/v1/users?trace=on", "get")
	if err != nil {
		t.Fatal(err)
	}
	if req.Domain != "api.example.com" || req.Port != 80 || req.Path != "/v1/users" || req.Method != "GET" {
		t.Fatalf("url target parsed wrong: %+v", req)
	}
	if len(req.Query["trace"]) != 1 || req.Query["trace"][0] != "on" || req.RawQuery != "trace=on" {
		t.Fatalf("query lost: %+v", req)
	}
	if req.Protocol != "tcp" || req.Address != "" {
		t.Fatalf("protocol/address mismatch: %+v", req)
	}
	https, err := policyCheckRequest("", "", "", 0, "https://api.example.com/", "")
	if err != nil || https.Port != 443 || https.Path != "/" {
		t.Fatalf("https defaults wrong: %+v err=%v", https, err)
	}
	port, err := policyCheckRequest("", "", "", 0, "https://api.example.com:8443/x", "")
	if err != nil || port.Port != 8443 {
		t.Fatalf("explicit port wrong: %+v err=%v", port, err)
	}
	ipHost, err := policyCheckRequest("", "", "", 0, "http://192.0.2.10/x", "")
	if err != nil || ipHost.Address != "192.0.2.10" || ipHost.Domain != "" {
		t.Fatalf("IP host must land in address: %+v err=%v", ipHost, err)
	}
	bad := []struct {
		why      string
		url      string
		address  string
		method   string
		protocol string
	}{
		{"credentials", "http://u:p@host/x", "", "", ""},
		{"fragment", "http://host/x#frag", "", "", ""},
		{"scheme", "ftp://host/x", "", "", ""},
		{"missing host", "http:///x", "", "", ""},
		{"url+address", "http://host/x", "198.51.100.5", "", ""},
		{"wildcard method", "http://host/x", "", "*", ""},
		{"unknown method", "http://host/x", "", "WILD", ""},
		{"udp url", "http://host/x", "", "", "udp"},
	}
	for _, tc := range bad {
		if _, err := policyCheckRequest(tc.protocol, tc.address, "", 0, tc.url, tc.method); !errors.Is(err, core.ErrConflict) {
			t.Fatalf("%s: expected conflict, got %v", tc.why, err)
		}
	}
	if _, err := policyCheckRequest("tcp", "192.0.2.1", "", 443, "", ""); err != nil {
		t.Fatalf("url-less L4 call must still work: %v", err)
	}
	if _, err := policyCheckRequest("tcp", "", "", 0, "", ""); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("missing target must conflict: %v", err)
	}
}

func TestCheckPolicyHTTPDecisionRoundtrip(t *testing.T) {
	// Exercise the wire shape the server uses for conditioned rules and a URL
	// check through JSON encoding stability of the stored policy.
	rule := sandbox.NetworkRule{Protocol: "tcp", Domain: "api.example.com", Port: 443, Methods: []string{"GET"}, Path: "/v1/**", Query: []sandbox.QueryCondition{{Name: "trace", Value: "*"}}}
	out, err := normalizeRules([]sandbox.NetworkRule{rule}, false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []sandbox.NetworkRule
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !samePolicyRule(decoded[0], out[0]) {
		t.Fatalf("store round trip lost HTTP conditions: %+v vs %+v", decoded[0], out[0])
	}
}
