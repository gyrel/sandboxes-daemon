package service

import (
	"context"
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

func TestCheckKitSourceDefaults(t *testing.T) {
	svc, _, _ := newCustomSecretTestService(t)
	ctx := context.Background()

	if reason, allowed, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY, "/home/u/kit", "", false); err != nil || !allowed || reason != localv1.CheckKitReason_CHECK_KIT_REASON_OK {
		t.Fatalf("directory default: reason=%v allowed=%t err=%v", reason, allowed, err)
	}
	if reason, allowed, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_GIT, "https://github.com/org/kit", "", false); err != nil || allowed || reason != localv1.CheckKitReason_CHECK_KIT_REASON_SOURCE_NOT_ALLOWED {
		t.Fatalf("git default: reason=%v allowed=%t err=%v", reason, allowed, err)
	}
	if reason, _, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_UNSPECIFIED, "x", "", false); err == nil {
		t.Fatalf("unspecified kind must error, reason=%v", reason)
	}
}

func TestCheckKitSourceReferenceRules(t *testing.T) {
	svc, _, _ := newCustomSecretTestService(t)
	ctx := context.Background()
	for _, ref := range []string{"", "https://user:[email protected]/kit", "oci://registry/kit?tag=v1", "git://host/repo#frag?x=1"} {
		reason, allowed, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_OCI, ref, "", false)
		if err != nil {
			t.Fatal(err)
		}
		if ref == "" || ref == "https://user:[email protected]/kit" || ref == "oci://registry/kit?tag=v1" {
			if allowed || reason != localv1.CheckKitReason_CHECK_KIT_REASON_INVALID_REFERENCE {
				t.Fatalf("ref %q: reason=%v allowed=%t", ref, reason, allowed)
			}
		}
	}
	// A fragment-only reference is not credential-bearing and passes the
	// reference gate (it is still source-denied for oci by default).
	if reason, _, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_OCI, "oci://registry/kit#frag", "", false); err != nil || reason != localv1.CheckKitReason_CHECK_KIT_REASON_SOURCE_NOT_ALLOWED {
		t.Fatalf("fragment ref routing: reason=%v err=%v", reason, err)
	}
}

func TestCheckKitSourceLocalDisabledAndSignature(t *testing.T) {
	svc, _, _ := newCustomSecretTestService(t)
	ctx := context.Background()

	svc.KitAllowLocalKits = false
	if reason, allowed, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_ZIP, "/tmp/kit.zip", "", false); err != nil || allowed || reason != localv1.CheckKitReason_CHECK_KIT_REASON_LOCAL_DISABLED {
		t.Fatalf("local disabled: reason=%v allowed=%t err=%v", reason, allowed, err)
	}

	svc.KitAllowLocalKits = true
	svc.KitAllowedSources = []string{kitSourceGit}
	svc.KitRequireSignature = true
	if reason, allowed, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_GIT, "https://git.example/kit", "", false); err != nil || allowed || reason != localv1.CheckKitReason_CHECK_KIT_REASON_SIGNATURE_REQUIRED {
		t.Fatalf("unsigned git: reason=%v allowed=%t err=%v", reason, allowed, err)
	}
	if reason, allowed, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_GIT, "https://git.example/kit", "", true); err != nil || !allowed || reason != localv1.CheckKitReason_CHECK_KIT_REASON_OK {
		t.Fatalf("signed git: reason=%v allowed=%t err=%v", reason, allowed, err)
	}
}

func TestCheckKitSourceStoreOverrides(t *testing.T) {
	svc, _, _ := newCustomSecretTestService(t)
	ctx := context.Background()

	if err := svc.store.SetSetting(ctx, kitAllowedSourcesSetting, `["git","oci"]`); err != nil {
		t.Fatal(err)
	}
	if reason, allowed, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY, "/home/u/kit", "", false); err != nil || allowed || reason != localv1.CheckKitReason_CHECK_KIT_REASON_SOURCE_NOT_ALLOWED {
		t.Fatalf("store override denies directory: reason=%v allowed=%t err=%v", reason, allowed, err)
	}
	if reason, allowed, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_OCI, "oci://reg/kit", "", false); err != nil || !allowed || reason != localv1.CheckKitReason_CHECK_KIT_REASON_OK {
		t.Fatalf("store override allows oci: reason=%v allowed=%t err=%v", reason, allowed, err)
	}

	// A present but invalid value fails closed to the most restrictive set.
	if err := svc.store.SetSetting(ctx, kitAllowedSourcesSetting, "not-json, not-a-kind"); err != nil {
		t.Fatal(err)
	}
	if reason, allowed, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY, "/home/u/kit", "", false); err != nil || allowed || reason != localv1.CheckKitReason_CHECK_KIT_REASON_SOURCE_NOT_ALLOWED {
		t.Fatalf("invalid store value must deny everything: reason=%v allowed=%t err=%v", reason, allowed, err)
	}
	if reason, allowed, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_GIT, "https://git.example/kit", "", false); err != nil || allowed || reason != localv1.CheckKitReason_CHECK_KIT_REASON_SOURCE_NOT_ALLOWED {
		t.Fatalf("invalid store value must deny git too: reason=%v allowed=%t err=%v", reason, allowed, err)
	}
}

func TestCheckKitSourceManagedFailClosed(t *testing.T) {
	svc, _, _ := newCustomSecretTestService(t)
	ctx := context.Background()
	svc.OrgPolicyEnforce = true
	svc.OrgPolicyOrg = "acme"

	// No bundle stored yet: managed checks fail closed as POLICY_UNAVAILABLE.
	if reason, allowed, err := svc.CheckKitSource(ctx, localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY, "/home/u/kit", "", false); err != nil || allowed || reason != localv1.CheckKitReason_CHECK_KIT_REASON_POLICY_UNAVAILABLE {
		t.Fatalf("managed without bundle: reason=%v allowed=%t err=%v", reason, allowed, err)
	}
	cfg, err := svc.GetKitPolicyConfig(ctx)
	if err != nil || !cfg.Managed {
		t.Fatalf("managed display with broken state: %+v err=%v", cfg, err)
	}
}

func TestGetKitPolicyConfigEffective(t *testing.T) {
	svc, _, _ := newCustomSecretTestService(t)
	ctx := context.Background()
	if err := svc.store.SetSetting(ctx, kitRequireSignatureSetting, "true"); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.SetSetting(ctx, kitAllowLocalKitsSetting, "false"); err != nil {
		t.Fatal(err)
	}
	cfg, err := svc.GetKitPolicyConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequireSignature || cfg.AllowLocalKits {
		t.Fatalf("store overrides not reflected: %+v", cfg)
	}
	if len(cfg.AllowedSources) != 2 || cfg.AllowedSources[0] != kitSourceDirectory || cfg.AllowedSources[1] != kitSourceZip {
		t.Fatalf("default sources = %v", cfg.AllowedSources)
	}
	if cfg.Managed {
		t.Fatal("unmanaged org reported as managed")
	}
}

func TestParseKitSourcesSettingFormats(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
		errs bool
	}{
		{raw: `["git","oci"]`, want: 2},
		{raw: "git,oci", want: 2},
		{raw: `["directory","directory"]`, want: 1},
		{raw: `["bogus"]`, errs: true},
		{raw: "git,,", errs: true},
		{raw: "", errs: true},
		{raw: `[]`, errs: true},
	} {
		got, err := parseKitSourcesSetting(tc.raw)
		if tc.errs {
			if err == nil {
				t.Fatalf("parseKitSourcesSetting(%q) accepted: %v", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseKitSourcesSetting(%q): %v", tc.raw, err)
		}
		if len(got) != tc.want {
			t.Fatalf("parseKitSourcesSetting(%q) = %v", tc.raw, got)
		}
	}
}
