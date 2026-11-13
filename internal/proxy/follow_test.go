package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/peer"
)

// The broker follows a run log's redirect itself, only over HTTPS on port
// 443, and only to GitHub's storage hosts or its API.
func TestFollowsLogRedirects(t *testing.T) {
	t.Parallel()
	// The API is https://127.0.0.1, so a redirect within it is one the
	// broker follows. Nothing answers on port 443, so following it fails.
	const api = "https://127.0.0.1"
	locations := map[string]string{
		"2": "https://evil.example/log",
		"3": "http://evil.example/log",
		"4": "https://evil.example:8443/log",
		"5": api + "/log",
		// Hosts that start with the API's, but aren't it.
		"6": api + ".evil.example/log",
		"7": api + "@evil.example/log",
		// A host that ends in a storage host's name isn't one.
		"8": "https://xcodeload.github.com/archive.tar.gz",
	}
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		run := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/repos/acme/widgets/actions/runs/"), "/logs")
		if loc, ok := locations[run]; ok {
			w.Header().Set("Location", loc)
			w.WriteHeader(http.StatusFound)
			return
		}
		io.WriteString(w, "the log")
	}))
	t.Cleanup(up.Close)
	// Send the broker's requests for the API to the fake, whatever address
	// they name.
	tr := up.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	client := serveGH(t, "unix", &Server{
		Config:    &config.Config{Token: &config.Token{Login: "mbriggs"}, Repos: []config.Repo{{Match: "acme/widgets"}}, APIURL: api},
		Token:     testToken,
		Log:       slog.New(slog.DiscardHandler),
		Permitted: func(p peer.Peer) bool { return p.Known && p.UID == uint32(os.Getuid()) },
		Upstream: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	})

	for _, c := range []struct {
		run, want string
		status    int
	}{
		{"1", "the log", 200},
		{"2", "GitHub redirected to evil.example, which hallpass doesn't follow", 502},
		{"3", "GitHub redirected somewhere hallpass doesn't follow", 502},
		{"4", "GitHub redirected somewhere hallpass doesn't follow", 502},
		// Followed, so the error is the fetch's, which names the URL.
		{"5", `Get \"https://127.0.0.1/log\"`, 502},
		{"6", "GitHub redirected to 127.0.0.1.evil.example, which hallpass doesn't follow", 502},
		{"7", "GitHub redirected to evil.example, which hallpass doesn't follow", 502},
		{"8", "GitHub redirected to xcodeload.github.com, which hallpass doesn't follow", 502},
	} {
		resp, err := client.Get("http://api.github.com/repos/acme/widgets/actions/runs/" + c.run + "/logs")
		if err != nil {
			t.Errorf("run %s: %v", c.run, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.status || !strings.Contains(string(body), c.want) {
			t.Errorf("run %s: %d %s", c.run, resp.StatusCode, body)
		}
	}
}

// A storage host with a leading dot covers the hosts under it, and one
// without covers only itself.
func TestStorageHost(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{
		"release-assets.githubusercontent.com":       true,
		"objects.githubusercontent.com":              true,
		"codeload.github.com":                        true,
		"pipelines.actions.githubusercontent.com":    true,
		"productionresultssa0.blob.core.windows.net": true,
		"xcodeload.github.com":                       false,
		"evil-objects.githubusercontent.com":         false,
		"release-assets.githubusercontent.com.evil":  false,
		"githubusercontent.com":                      false,
	} {
		if got := storageHost(host); got != want {
			t.Errorf("storageHost(%q) = %v, want %v", host, got, want)
		}
	}
}
