package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
)

// A code search goes with the token only when it names one allowed repo,
// and comes back only when every result GitHub returns is in that repo.
func TestCodeSearch(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// A 304 would skip the answer check.
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		item := func(full string) string {
			return `{"path":"main.go","repository":{"full_name":"` + full + `","temp_clone_token":"T"}}`
		}
		w.Header().Set("X-RateLimit-Resource", "code_search")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "9999999999")
		w.Header().Set("Link", `<https://api.github.com/search/code?q=x&page=2>; rel="next"`)
		q := r.URL.Query().Get("q")
		switch {
		case strings.Contains(q, "throttled"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"message":"API rate limit exceeded"}`)
		case strings.Contains(q, "text"):
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "hello")
		case strings.Contains(q, "leak"):
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"total_count":2,"items":[`+item("acme/widgets")+`,`+item("acme/secret")+`]}`)
		default:
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"total_count":1,"items":[`+item("acme/widgets")+`]}`)
		}
	}))
	t.Cleanup(up.Close)
	client := ghClient(t, up.URL, config.Repo{Match: "acme/widgets", Access: "read"})
	get := func(q string) (int, http.Header, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "http://api.github.com/search/code?q="+url.QueryEscape(q), nil)
		req.Header.Set("If-None-Match", `"etag-guess"`)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}

	// Run twice: code search's own limit of 10 a minute mustn't make the
	// broker hold back the hourly reserve.
	for range 2 {
		status, h, body := get("widget repo:acme/widgets")
		if status != 200 || !strings.Contains(body, `"full_name":"acme/widgets"`) || strings.Contains(body, "temp_clone_token") || !strings.Contains(h.Get("Link"), "page=2") {
			t.Fatalf("allowed search: %d %v %s", status, h, body)
		}
	}
	n := calls.Load()
	for _, c := range []struct{ q, want string }{
		{"widget", "add repo:OWNER/NAME"},
		{"widget user:acme", "doesn't allow user:"},
		{"widget repo:acme/secret", "acme/secret isn't in hallpass's allowlist"},
		{"widget repo:octo/public", "octo/public isn't in hallpass's allowlist"},
	} {
		if status, _, body := get(c.q); status != http.StatusForbidden || !strings.Contains(body, c.want) {
			t.Errorf("%s: %d %s", c.q, status, body)
		}
	}
	if calls.Load() != n {
		t.Errorf("refused searches reached GitHub")
	}
	status, h, body := get("leak repo:acme/widgets")
	if status != http.StatusForbidden || !strings.Contains(body, "result from another repo") || strings.Contains(body, "acme/secret") || strings.Contains(body, "items") || h.Get("Link") != "" {
		t.Errorf("leaky answer: %d %v %s", status, h, body)
	}
	if status, _, body := get("text repo:acme/widgets"); status != http.StatusBadGateway || strings.Contains(body, "hello") {
		t.Errorf("text answer: %d %s", status, body)
	}
	// GitHub's own refusal reaches gh as GitHub wrote it.
	if status, h, body := get("throttled repo:acme/widgets"); status != http.StatusForbidden || !strings.Contains(body, "API rate limit exceeded") || h.Get("X-RateLimit-Resource") != "code_search" {
		t.Errorf("throttled: %d %v %s", status, h, body)
	}
}
