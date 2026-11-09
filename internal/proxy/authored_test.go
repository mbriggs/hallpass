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
// pr.edit, as editing it on the pulls route does. Either way, agents may only
// edit what the token's user wrote.
func TestIssueEditOfAPRNeedsPREdit(t *testing.T) {
	t.Parallel()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /repos/acme/widgets/issues/7":
			io.WriteString(w, `{"number":7,"user":{"login":"mbriggs"},"pull_request":{"url":"x"}}`)
		case "GET /repos/acme/widgets/issues/8":
			io.WriteString(w, `{"number":8,"user":{"login":"mbriggs"}}`)
		case "GET /repos/acme/widgets/issues/9":
			io.WriteString(w, `{"number":9,"user":{"login":"someoneelse"}}`)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(up.Close)
	client := ghClient(t, up.URL, config.Repo{Match: "acme/widgets", Deny: []config.Grant{"pr.edit"}})
	for _, c := range []struct {
		n      string
		status int
		why    string
	}{
		{"7", 403, "policy allow pr.edit"},
		{"8", 200, ""},
		// Someone else's issue is refused whatever the policy says.
		{"9", 403, "you wrote"},
	} {
		req, _ := http.NewRequest(http.MethodPatch, "http://api.github.com/repos/acme/widgets/issues/"+c.n, strings.NewReader(`{"title":"changed"}`))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.status || !strings.Contains(string(body), c.why) {
			t.Errorf("PATCH issues/%s: %d %s", c.n, resp.StatusCode, body)
		}
	}
}
