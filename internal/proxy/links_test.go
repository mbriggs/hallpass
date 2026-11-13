package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
)

// GitHub's pagination links on a repo's routes name the repo by ID. The
// broker rewrites them to the repo's name, so the next page goes with the
// token and the repo's policy like the first, and leaves other links alone.
func TestRepoLinks(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var seen []string
	// The API has a path prefix, as the verify fake's does.
	var api string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.RequestURI()+" auth="+r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		byID := `<` + api + `/repositories/42/pulls?state=open&page=2>; rel="next", <` + api + `/repositories/42/pulls?state=open&page=5>; rel="last"`
		switch r.URL.Path {
		case "/api/repos/acme/widgets/pulls":
			w.Header().Set("Link", byID+`, <https://evil.example/repositories/42/pulls?page=1>; rel="first", <`+api+`/repositories/42?page=1>; rel="prev"`)
		case "/api/repos/octo/public/pulls":
			w.Header().Set("Link", byID)
		case "/api/users/octocat/repos":
			w.Header().Set("Link", byID)
		case "/api/search/code":
			w.Header().Set("Link", `<`+api+`/search/code?q=x+repo%3Aacme%2Fwidgets&page=2>; rel="next"`)
			io.WriteString(w, `{"total_count":1,"items":[{"path":"main.go","repository":{"full_name":"acme/widgets"}}]}`)
			return
		}
		io.WriteString(w, `[]`)
	}))
	t.Cleanup(up.Close)
	api = up.URL + "/api"
	client := ghClient(t, api, config.Repo{Match: "acme/widgets"})
	get := func(uri string) http.Header {
		t.Helper()
		resp, err := client.Get("http://api.github.com" + uri)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", uri, resp.StatusCode, b)
		}
		return resp.Header
	}

	byName := `<` + api + `/repos/acme/widgets/pulls?state=open&page=2>; rel="next", <` + api + `/repos/acme/widgets/pulls?state=open&page=5>; rel="last"`
	got := get("/repos/acme/widgets/pulls?state=open").Get("Link")
	if want := byName + `, <https://evil.example/repositories/42/pulls?page=1>; rel="first", <` + api + `/repositories/42?page=1>; rel="prev"`; got != want {
		t.Errorf("repo route's Link:\n got %s\nwant %s", got, want)
	}
	// gh follows the next link through the broker, which sends it with the
	// token.
	next, _, _ := strings.Cut(strings.TrimPrefix(got, "<"+api), ">")
	get(next)
	mu.Lock()
	last := seen[len(seen)-1]
	mu.Unlock()
	if last != "/api/repos/acme/widgets/pulls?page=2&state=open auth=token "+testToken {
		t.Errorf("next page reached GitHub as %s", last)
	}

	// A repo outside the allowlist goes without the token, and its links
	// still name it.
	if got := get("/repos/octo/public/pulls").Get("Link"); !strings.Contains(got, api+"/repos/octo/public/pulls?state=open&page=2") {
		t.Errorf("anonymous repo route's Link: %s", got)
	}
	// Without a repo there is nothing to rewrite to.
	if got := get("/users/octocat/repos").Get("Link"); !strings.Contains(got, api+"/repositories/42/pulls") || strings.Contains(got, "/repos/") {
		t.Errorf("non-repo route's Link: %s", got)
	}
	if got, want := get("/search/code?q=x+repo:acme/widgets").Get("Link"), `<`+api+`/search/code?q=x+repo%3Aacme%2Fwidgets&page=2>; rel="next"`; got != want {
		t.Errorf("search's Link:\n got %s\nwant %s", got, want)
	}
}
