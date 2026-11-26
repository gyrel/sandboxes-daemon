package registrycredentials

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gyrel/sandboxes-gateway/registryauth"
)

func fixtureRepositoryGrants() []string {
	return []string{"repository:demo:pull,push", "repository:library/test:pull,push", "repository:missing:pull,push", "repository:other:pull,push", "repository:other/image:pull,push", "repository:public:pull,push", "repository:public-gzip:pull,push", "repository:redirect:pull,push", "repository:repo:pull,push", "repository:team/app:pull,push", "repository:team/image:pull,push", "repository:truncated:pull,push"}
}

func TestRepositoryGrantsAreExactAndActionScoped(t *testing.T) {
	for _, scopes := range [][]string{{"repository:../private:pull"}, {"repository:team/image:delete"}, {"repository:team/*:pull"}, {"repository:team/image:pull", "repository:team/image:push"}} {
		if err := ValidateRepositoryGrants(scopes); err == nil {
			t.Errorf("accepted invalid grants %v", scopes)
		}
	}
	grants, err := compileRepositoryGrants([]string{"repository:team/image:pull"})
	if err != nil {
		t.Fatal(err)
	}
	p := &PullProxy{repositoryGrants: grants}
	if !p.allowsRepository("team/image", map[string]struct{}{"pull": {}}) {
		t.Fatal("allowed pull denied")
	}
	for _, test := range []struct{ repo, action string }{{"team/image", "push"}, {"other/image", "pull"}, {"team/Image", "pull"}} {
		if p.allowsRepository(test.repo, map[string]struct{}{test.action: {}}) {
			t.Fatalf("unauthorized operation allowed: %+v", test)
		}
	}
}

func TestRepositoryGrantDenialsDoNotReachUpstream(t *testing.T) {
	grants, err := compileRepositoryGrants([]string{"repository:team/image:pull"})
	if err != nil {
		t.Fatal(err)
	}
	p := &PullProxy{service: "registry.fixture", authority: "registry.example", repositoryGrants: grants}
	responses := make([]string, 0, 6)
	for _, repo := range []string{"other/image", "nonexistent/image"} {
		token := httptest.NewRequest(http.MethodGet, "https://registry.example/token?service=registry.fixture&scope=repository:"+repo+":pull", nil)
		w := httptest.NewRecorder()
		p.serveTokenRequest(w, token, registryauth.Realm{Path: "/token"})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("token for %s: %d", repo, w.Code)
		}
		responses = append(responses, w.Body.String())
		forward := httptest.NewRequest(http.MethodGet, "https://registry.example/v2/"+repo+"/manifests/latest", nil)
		w = httptest.NewRecorder()
		p.serveRegistryForward(w, forward, "registry.example")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("forward for %s: %d", repo, w.Code)
		}
		responses = append(responses, w.Body.String())
		mirror := httptest.NewRequest(http.MethodGet, "http://guest/v2/"+repo+"/manifests/latest", nil)
		w = httptest.NewRecorder()
		p.ServeHTTP(w, mirror)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("mirror for %s: %d", repo, w.Code)
		}
		responses = append(responses, w.Body.String())
	}
	for _, body := range responses {
		if body != responses[0] {
			t.Fatalf("denial responses differ: %q vs %q", responses[0], body)
		}
	}
	privateToken := httptest.NewRequest(http.MethodGet, "https://registry.example"+brokerTokenPath+"?service=registry.fixture&scope=repository:team/image:push", nil)
	w := httptest.NewRecorder()
	p.servePrivateTokenRequest(w, privateToken)
	if w.Code != http.StatusUnauthorized || w.Body.String() != responses[0] {
		t.Fatalf("push denial status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestSandboxRepositoryGrantsAreIsolated(t *testing.T) {
	grants, err := ParseSandboxRepositoryGrants([]string{"one=repository:team/a:pull", "two=repository:team/b:pull,push"})
	if err != nil {
		t.Fatal(err)
	}
	if len(grants["one"]) != 1 || grants["one"][0] != "repository:team/a:pull" || len(grants["two"]) != 1 {
		t.Fatalf("unexpected scoped grants: %v", grants)
	}
	for _, value := range []string{"*=repository:team/a:pull", "../one=repository:team/a:pull", "one=repository:team/*:pull", "one=repository:team/a:delete", "one=repository:team/a:pull;two=repository:team/b:pull"} {
		if _, err := ParseSandboxRepositoryGrants([]string{value}); err == nil {
			t.Errorf("accepted invalid grant %q", value)
		}
	}
	if _, err := ParseSandboxRepositoryGrants([]string{"one=repository:team/a:pull", "one=repository:team/a:push"}); err == nil {
		t.Fatal("accepted duplicate repository grants")
	}
}
