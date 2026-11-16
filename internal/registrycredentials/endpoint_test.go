package registrycredentials

import (
	"errors"
	"testing"
)

func TestRegistryEndpointNormalization(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		want          string
		wantHostname  string
		wantPort      string
		wantPortIsSet bool
	}{
		{name: "default registry", input: "", want: "docker.io", wantHostname: "docker.io", wantPort: "443"},
		{name: "DNS", input: "Registry.Example.Test", want: "registry.example.test", wantHostname: "registry.example.test", wantPort: "443"},
		{name: "DNS trailing dot", input: "registry.example.test.:5000", want: "registry.example.test:5000", wantHostname: "registry.example.test", wantPort: "5000", wantPortIsSet: true},
		{name: "DNS custom port", input: "registry.example.test:5000", want: "registry.example.test:5000", wantHostname: "registry.example.test", wantPort: "5000", wantPortIsSet: true},
		{name: "DNS default port", input: "registry.example.test:443", want: "registry.example.test:443", wantHostname: "registry.example.test", wantPort: "443", wantPortIsSet: true},
		{name: "IPv4", input: "192.0.2.10", want: "192.0.2.10", wantHostname: "192.0.2.10", wantPort: "443"},
		{name: "IPv4 custom port", input: "192.0.2.10:5000", want: "192.0.2.10:5000", wantHostname: "192.0.2.10", wantPort: "5000", wantPortIsSet: true},
		{name: "bracketed IPv6", input: "[2001:DB8:0:0::1]", want: "[2001:db8::1]", wantHostname: "2001:db8::1", wantPort: "443"},
		{name: "bracketed IPv6 custom port", input: "[2001:DB8:0:0::1]:5000", want: "[2001:db8::1]:5000", wantHostname: "2001:db8::1", wantPort: "5000", wantPortIsSet: true},
		{name: "bare IPv6", input: "2001:db8::1", want: "[2001:db8::1]", wantHostname: "2001:db8::1", wantPort: "443"},
		{name: "bare IPv6 ending in decimal segment", input: "2001:db8::1:5000", want: "[2001:db8::1:5000]", wantHostname: "2001:db8::1:5000", wantPort: "443"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.input == "" {
				canonical, err := canonicalRegistry(test.input)
				if err != nil || canonical != test.want {
					t.Fatalf("canonicalRegistry(%q) = %q, %v; want %q", test.input, canonical, err, test.want)
				}
				return
			}
			endpoint, err := ParseRegistryEndpoint(test.input)
			if err != nil {
				t.Fatalf("ParseRegistryEndpoint(%q): %v", test.input, err)
			}
			if got := endpoint.Authority(); got != test.want {
				t.Fatalf("Authority() = %q, want %q", got, test.want)
			}
			if endpoint.Hostname != test.wantHostname || endpoint.PortString() != test.wantPort || endpoint.portSet != test.wantPortIsSet {
				t.Fatalf("endpoint = %#v, want host=%q port=%q portSet=%t", endpoint, test.wantHostname, test.wantPort, test.wantPortIsSet)
			}
			if test.input == "" {
				return
			}
			canonical, err := canonicalRegistry(test.input)
			if err != nil || canonical != test.want {
				t.Fatalf("canonicalRegistry(%q) = %q, %v; want %q", test.input, canonical, err, test.want)
			}
		})
	}
}

func TestRegistryEndpointRejectsAmbiguousOrUnsafeForms(t *testing.T) {
	for _, input := range []string{
		"https://registry.example.test",
		"registry.example.test/path",
		"user:pass@registry.example.test",
		"user@registry.example.test",
		"registry.example.test?query",
		"registry.example.test#fragment",
		"registry.example.test\\path",
		"registry.example.test :5000",
		"registry.example.test:",
		"registry.example.test:0",
		"registry.example.test:65536",
		"registry.example.test:abc",
		"registry.example.test:-1",
		"registry.example.test:80:90",
		"[2001:db8::1",
		"[2001:db8::1]x",
		"[192.0.2.10]:5000",
		"[]:5000",
		"*.example.test",
		"-registry.example.test",
		"registry_.example.test",
		"fe80::1%eth0",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseRegistryEndpoint(input); err == nil {
				t.Fatalf("ParseRegistryEndpoint(%q) accepted an invalid endpoint", input)
			}
			if _, err := canonicalRegistry(input); err == nil || !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("canonicalRegistry(%q) error = %v, want ErrInvalidCredential", input, err)
			}
		})
	}
}

func TestSameRegistryEndpointTreatsDefaultPortConsistently(t *testing.T) {
	for _, test := range []struct {
		first, second string
		want          bool
	}{
		{first: "registry.example.test", second: "registry.example.test:443", want: true},
		{first: "192.0.2.10", second: "192.0.2.10:443", want: true},
		{first: "[2001:db8::1]", second: "[2001:db8::1]:443", want: true},
		{first: "registry.example.test:5000", second: "registry.example.test:5001", want: false},
		{first: "registry.example.test", second: "registry.example.test:5000", want: false},
		{first: "192.0.2.10:5000", second: "192.0.2.11:5000", want: false},
		{first: "bad host", second: "bad host", want: false},
	} {
		if got := SameRegistryEndpoint(test.first, test.second); got != test.want {
			t.Errorf("SameRegistryEndpoint(%q, %q) = %t, want %t", test.first, test.second, got, test.want)
		}
	}
}
