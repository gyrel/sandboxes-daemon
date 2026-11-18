package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/rheic/sandboxes-daemon/internal/settings"

	"github.com/rheic/slogx"
)

func TestApplyPolicyOverride(t *testing.T) {
	values := settings.Values{DefaultPolicyProfile: "deny-all"}
	if err := applyPolicyOverride(&values, ""); err != nil || values.DefaultPolicyProfile != "deny-all" {
		t.Fatalf("empty policy = %+v, %v", values, err)
	}
	if err := applyPolicyOverride(&values, "balanced"); err != nil || values.DefaultPolicyProfile != "balanced" {
		t.Fatalf("balanced policy = %+v, %v", values, err)
	}
	if err := applyPolicyOverride(&values, "allow-all"); err != nil || values.DefaultPolicyProfile != "allow-all" {
		t.Fatalf("allow-all policy = %+v, %v", values, err)
	}
	if err := applyPolicyOverride(&values, "sbx-compat"); err == nil {
		t.Fatal("unsupported policy override accepted")
	}
}

func TestIPv6RuleCapabilityRequiresFlagAndGateway(t *testing.T) {
	for _, test := range []struct {
		name string
		opts options
		want bool
	}{
		{name: "defaults off", opts: options{}, want: false},
		{name: "flag without gvproxy", opts: options{ipv6Experimental: true}, want: false},
		{name: "gvproxy without flag", opts: options{gvproxyPath: "/bin/gvproxy"}, want: false},
		{name: "flag and gvproxy", opts: options{ipv6Experimental: true, gvproxyPath: "/bin/gvproxy"}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ipv6RuleCapability(&test.opts); got != test.want {
				t.Fatalf("ipv6RuleCapability(%+v) = %v, want %v", test.opts, got, test.want)
			}
		})
	}
}

func TestConfigureExperimentalIPv6DisabledDoesNotRequireConfigurator(t *testing.T) {
	if err := configureExperimentalIPv6(false, nil); err != nil {
		t.Fatalf("configureExperimentalIPv6(false, nil) error = %v, want nil", err)
	}
}

func TestConfigureExperimentalIPv6Enabled(t *testing.T) {
	configurator := &testIPv6Configurator{}
	if err := configureExperimentalIPv6(true, configurator); err != nil {
		t.Fatalf("configureExperimentalIPv6(true, configurator) error = %v, want nil", err)
	}
	if configurator.calls != 1 {
		t.Fatalf("SetIPv6Enabled calls = %d, want 1", configurator.calls)
	}
	if !configurator.enabled {
		t.Fatal("SetIPv6Enabled argument = false, want true")
	}
}

func TestConfigureExperimentalIPv6UnsupportedFailsClosed(t *testing.T) {
	err := configureExperimentalIPv6(true, struct{}{})
	if err == nil {
		t.Fatal("configureExperimentalIPv6(true, unsupported) error = nil, want error")
	}
	if got, want := err.Error(), "configured gateway module does not support experimental IPv6"; got != want {
		t.Fatalf("configureExperimentalIPv6 error = %q, want %q", got, want)
	}
}

type testIPv6Configurator struct {
	calls   int
	enabled bool
}

func (configurator *testIPv6Configurator) SetIPv6Enabled(enabled bool) error {
	configurator.calls++
	configurator.enabled = enabled
	return nil
}

func TestConfigureExperimentalQUICDisabledDoesNotRequireConfigurator(t *testing.T) {
	if err := configureExperimentalQUIC(false, nil); err != nil {
		t.Fatalf("configureExperimentalQUIC(false, nil) error = %v, want nil", err)
	}
}

func TestConfigureExperimentalQUICEnabled(t *testing.T) {
	configurator := &testQUICConfigurator{}
	if err := configureExperimentalQUIC(true, configurator); err != nil {
		t.Fatalf("configureExperimentalQUIC(true, configurator) error = %v, want nil", err)
	}
	if configurator.calls != 1 {
		t.Fatalf("SetQUICEnabled calls = %d, want 1", configurator.calls)
	}
	if !configurator.enabled {
		t.Fatal("SetQUICEnabled argument = false, want true")
	}
}

func TestConfigureExperimentalQUICUnsupportedFailsClosed(t *testing.T) {
	err := configureExperimentalQUIC(true, struct{}{})
	if err == nil {
		t.Fatal("configureExperimentalQUIC(true, unsupported) error = nil, want error")
	}
	if got, want := err.Error(), "configured gateway module does not support experimental QUIC"; got != want {
		t.Fatalf("configureExperimentalQUIC error = %q, want %q", got, want)
	}
}

type testQUICConfigurator struct {
	calls   int
	enabled bool
}

func (configurator *testQUICConfigurator) SetQUICEnabled(enabled bool) error {
	configurator.calls++
	configurator.enabled = enabled
	return nil
}

func TestControlledHandlerFollowsLiveLevel(t *testing.T) {
	var out bytes.Buffer
	var level slog.LevelVar
	level.Set(slog.LevelInfo)

	logger := slogx.New(
		slogx.WithOutput(&out),
		slogx.WithFormat(slogx.FormatText),
		slogx.WithLevel(slog.LevelInfo),
	)
	log := slog.New(&controlledHandler{Handler: logger.Handler(), level: &level})

	log.Debug("hidden")
	if out.Len() != 0 {
		t.Fatalf("debug record passed the info threshold: %q", out.String())
	}

	level.Set(slog.LevelDebug)
	log.Debug("visible")
	if !strings.Contains(out.String(), "visible") {
		t.Fatalf("debug record missing after level change: %q", out.String())
	}
}

func TestRuntimeVerificationRequiresExplicitMode(t *testing.T) {
	if _, _, err := runtimeVerification(&options{}); err == nil {
		t.Fatal("unmanaged runtime was accepted without opt-in")
	}
	if _, _, err := runtimeVerification(&options{allowUnmanagedRuntime: true}); err != nil {
		t.Fatalf("explicit unmanaged runtime rejected: %v", err)
	}
	if _, _, err := runtimeVerification(&options{artifactDigests: "digests.yaml"}); err == nil {
		t.Fatal("digest file without artifacts was accepted")
	}
	if _, _, err := runtimeVerification(&options{runtimeArtifacts: artifactList{"gvproxy=/tmp/gvproxy"}}); err == nil {
		t.Fatal("artifact without digest file was accepted")
	}
	if _, _, err := runtimeVerification(&options{runtimeArtifacts: artifactList{"gvproxy=relative"}}); err == nil {
		t.Fatal("relative artifact path was accepted")
	}
	artifacts, digests, err := runtimeVerification(&options{
		artifactDigests:  "/tmp/digests.yaml",
		runtimeArtifacts: artifactList{"gvproxy=/tmp/gvproxy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if digests != "/tmp/digests.yaml" || artifacts["gvproxy"] != "/tmp/gvproxy" {
		t.Fatalf("artifacts=%v digests=%q", artifacts, digests)
	}
}
