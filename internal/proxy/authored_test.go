package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
)

// GitHub serves PRs on the issues routes too, so editing one there needs
// pr.edit, as editing it on the pulls route does.
func TestIssueEditOfAPRNeedsPREdit(t *testing.T) {
	t.Parallel()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /repos/acme/widgets/issues/7":
			io.WriteString(w, `{"number":7,"user":{"login":"mbriggs"},"pull_request":{"url":"x"}}`)
		case "GET /repos/acme/widgets/issues/8":
			io.WriteString(w, `{"number":8,"user":{"login":"mbriggs"}}`)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(up.Close)
	client := ghClient(t, up.URL, config.Repo{Match: "acme/widgets", Deny: []config.Grant{"pr.edit"}})
	for n, want := range map[string]int{"7": 403, "8": 200} {
		req, _ := http.NewRequest(http.MethodPatch, "http://api.github.com/repos/acme/widgets/issues/"+n, strings.NewReader(`{"title":"changed"}`))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want || want == 403 && !strings.Contains(string(body), "policy allow pr.edit") {
			t.Errorf("PATCH issues/%s: %d %s", n, resp.StatusCode, body)
		}
	}
}
