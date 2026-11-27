package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/gyrel/sandboxes-core/sandbox"

	"github.com/gyrel/sandboxes-daemon/internal/machinecode"
)

func TestCreateInputRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
	}{
		{"entry count", func() map[string]string {
			m := make(map[string]string)
			for i := range maxCreateEnvEntries + 1 {
				m[string(rune('a'+i))] = ""
			}
			return m
		}()},
		{"key", map[string]string{"1BAD": "value"}},
		{"credential", map[string]string{"A": secretRefPrefix + "token"}},
		{"nul", map[string]string{"A": "x\x00y"}},
		{"entry size", map[string]string{"A": strings.Repeat("x", maxCreateEnvEntry)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizeCreateEnv(tc.env)
			if code, ok := machinecode.Of(err); !ok || code != machinecode.EnvInvalid {
				t.Fatalf("error %v, reason %q", err, code)
			}
		})
	}
}

func TestPortRefusalReasons(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ports []sandbox.Port
		want  machinecode.Code
	}{
		{"count", make([]sandbox.Port, 65), machinecode.SpecInvalid},
		{"zero", []sandbox.Port{{}}, machinecode.SpecInvalid},
		{"duplicate", []sandbox.Port{{Host: 80, Guest: 80}, {Host: 80, Guest: 81}}, machinecode.SpecInvalid},
		{"protocol", []sandbox.Port{{Host: 80, Guest: 80, Protocol: "sctp"}}, machinecode.SpecInvalid},
		{"family", []sandbox.Port{{Host: 80, Guest: 80, Protocol: "tcp6", HostIP: "127.0.0.1"}}, machinecode.SpecInvalid},
		{"bind", []sandbox.Port{{Host: 80, Guest: 80, HostIP: "0.0.0.0"}}, machinecode.BindForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizePorts(tc.ports)
			if code, ok := machinecode.Of(err); !ok || code != tc.want {
				t.Fatalf("error %v, reason %q", err, code)
			}
		})
	}
	for _, tc := range []struct {
		message string
		want    machinecode.Code
	}{
		{"address already in use", machinecode.PortInUse}, {"permission denied", machinecode.ProbeUnavailable},
	} {
		err := hostPortProbeError(sandbox.Port{}, errors.New(tc.message))
		if code, ok := machinecode.Of(err); !ok || code != tc.want {
			t.Errorf("%v: reason %q", err, code)
		}
	}
}
