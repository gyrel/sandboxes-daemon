package service

import "testing"

func TestSetPrivateRegistryAcceptsCustomPortsAndIPLiterals(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "DNS custom port", host: "Registry.Example.Test:5000", want: "registry.example.test:5000"},
		{name: "IPv4 custom port", host: "192.0.2.10:5000", want: "192.0.2.10:5000"},
		{name: "IPv6 custom port", host: "[2001:DB8::1]:5000", want: "[2001:db8::1]:5000"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			svc := &Service{}
			if err := svc.SetPrivateRegistry(test.host, "svc", []string{"auth.example.test:5000/token"}, []string{"cdn.example.test:5000"}, nil); err != nil {
				t.Fatal(err)
			}
			if svc.privateRegistryHost != test.want || svc.privateRegistryRealms[0].Host != "auth.example.test:5000" || svc.privateRegistryRedirects[0] != "cdn.example.test:5000" {
				t.Fatalf("private registry config = %+v", svc)
			}
		})
	}
	for _, invalid := range []string{"https://registry.example.test:5000", "user@registry.example.test:5000", "registry.example.test:5000/path", "registry.example.test:0", "[2001:db8::1"} {
		svc := &Service{}
		if err := svc.SetPrivateRegistry(invalid, "svc", []string{"auth.example.test/token"}, nil, nil); err == nil {
			t.Errorf("invalid private registry host %q was accepted", invalid)
		}
	}
}
