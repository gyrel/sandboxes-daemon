package service

import "testing"

func TestRegistryGrantsBindToSandboxAndRegistry(t *testing.T) {
	svc := &Service{}
	docker := []string{"one=repository:team/a:pull", "two=repository:team/b:pull,push"}
	private := []string{"one=repository:private/a:pull"}
	if err := svc.SetRegistryRepositoryGrants(docker, private); err != nil {
		t.Fatal(err)
	}
	docker[0] = "one=repository:attacker/image:pull"
	if got := svc.registryDockerGrants["one"]; len(got) != 1 || got[0] != "repository:team/a:pull" {
		t.Fatalf("Docker grant changed: %v", got)
	}
	if len(svc.registryDockerGrants["three"]) != 0 || len(svc.registryPrivateGrants["two"]) != 0 {
		t.Fatal("unconfigured sandbox received a grant")
	}
	if err := svc.SetRegistryRepositoryGrants([]string{"*=repository:all:pull"}, nil); err == nil {
		t.Fatal("accepted wildcard sandbox")
	}
	if got := svc.registryDockerGrants["one"]; len(got) != 1 || got[0] != "repository:team/a:pull" {
		t.Fatal("invalid update changed existing policy")
	}
}
