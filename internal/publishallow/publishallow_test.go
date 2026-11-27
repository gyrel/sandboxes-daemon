package publishallow

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseJSON(t *testing.T) {
	allow, err := ParseJSON(`["127.0.0.1/32","10.0.0.0/8","2001:db8::/32","0.0.0.0/0"]`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1/32", "10.0.0.0/8", "2001:db8::/32", "0.0.0.0/0"}
	if got := strings.Join(allow.Strings(), ","); got != strings.Join(want, ",") {
		t.Fatalf("entries = %q, want %q", got, strings.Join(want, ","))
	}
	empty, err := ParseJSON(`[]`)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty array = %+v, %v", empty, err)
	}
}

func TestParseJSONRejectsMalformedAndUnsafeEntries(t *testing.T) {
	for _, value := range []string{
		``,
		`null`,
		`{}`,
		`"10.0.0.0/8"`,
		`["10.0.0.0/8",]`,
		`["10.1.2.3/8"]`,
		`["10.0.0.0/33"]`,
		`["10.0.0.0"]`,
		`[""]`,
		`["  "]`,
		`["10.0.0.0/8","10.0.0.0/8"]`,
		`["fe80::1%eth0/64"]`,
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := ParseJSON(value); err == nil {
				t.Fatalf("accepted malformed allowlist %q", value)
			}
		})
	}
}

func TestMatchUsesFamilyAndFirstEntry(t *testing.T) {
	allow, err := Parse([]string{"10.0.0.0/8", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		addr string
		want string
	}{
		{"10.1.2.3", "10.0.0.0/8"},
		{"2001:db8::5", "2001:db8::/32"},
		{"192.0.2.1", ""},
		{"2001:db9::5", ""},
	} {
		entry, ok := allow.Match(netip.MustParseAddr(tc.addr))
		if tc.want == "" {
			if ok {
				t.Errorf("%s matched %q", tc.addr, entry.Text)
			}
			continue
		}
		if !ok || entry.Text != tc.want {
			t.Errorf("%s matched %q/%v, want %q", tc.addr, entry.Text, ok, tc.want)
		}
	}
}

func TestWildcardAllowMatchesConcreteAddressesOnly(t *testing.T) {
	allow, err := Parse([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := allow.Match(netip.MustParseAddr("203.0.113.9")); !ok {
		t.Fatal("0.0.0.0/0 did not match a concrete IPv4 address")
	}
	if _, ok := allow.Match(netip.MustParseAddr("2001:db8::1")); ok {
		t.Fatal("0.0.0.0/0 matched an IPv6 address")
	}
}

func TestCompileFailsClosed(t *testing.T) {
	if allow := Compile([]string{"10.0.0.0/8", "garbage"}); allow != nil {
		t.Fatalf("invalid raw list compiled to %+v", allow)
	}
	if allow := Compile(nil); allow != nil {
		t.Fatalf("absent list compiled to %+v", allow)
	}
	if allow := Compile([]string{"10.0.0.0/8"}); len(allow) != 1 {
		t.Fatalf("valid list compiled to %+v", allow)
	}
}
