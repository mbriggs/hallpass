package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mbriggs/hallpass/internal/audit"
	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/peer"
)

// lockedBuffer collects log lines from the handler goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Split(strings.TrimSuffix(l.b.String(), "\n"), "\n")
}

// A GraphQL request logs the repos it touches, whether it names them or
// names a node ID that resolves to one, so hallpass log --repo finds it and
// --summary files its refusals under the repo.
func TestGraphQLLogsRepos(t *testing.T) {
	t.Parallel()
	// The node IDs resolve to PRs in these repos.
	owners := map[string]string{"PR_W": "acme/widgets", "PR_G": "acme/gadgets", "PR_S": "acme/secret"}
	var resolves int
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			Query     string `json:"query"`
			Variables struct {
				IDs []string `json:"ids"`
			} `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !strings.Contains(req.Query, "nodes(ids") {
			io.WriteString(w, `{"data":{}}`)
			return
		}
		mu.Lock()
		resolves++
		mu.Unlock()
		var nodes []string
		for _, id := range req.Variables.IDs {
			nodes = append(nodes, fmt.Sprintf(`{"__typename":"PullRequest","repository":{"nameWithOwner":%q},"viewerDidAuthor":true}`, owners[id]))
		}
		io.WriteString(w, `{"data":{"nodes":[`+strings.Join(nodes, ",")+`]}}`)
	}))
	t.Cleanup(up.Close)
	logs := &lockedBuffer{}
	client := serveGH(t, "unix", &Server{
		Config: &config.Config{Token: &config.Token{Login: "mbriggs"}, APIURL: up.URL,
			Repos: []config.Repo{{Match: "acme/widgets"}, {Match: "acme/gadgets"}}},
		Token:     testToken,
		Log:       slog.New(slog.NewTextHandler(logs, nil)),
		Permitted: func(p peer.Peer) bool { return p.Known && p.UID == uint32(os.Getuid()) },
	})

	for i, c := range []struct {
		name, query string
		msg, repo   string
		resolved    bool
	}{
		{"node-ID mutation the policy refuses",
			`mutation{mergePullRequest(input:{pullRequestId:"PR_W"}){clientMutationId}}`, "refused", "acme/widgets", true},
		{"node-ID read",
			`query{node(id:"PR_W"){id}}`, "allowed", "acme/widgets", true},
		{"named repo and node IDs, each repo once",
			`query{repository(owner:"acme",name:"gadgets"){name} a:node(id:"PR_W"){id} b:node(id:"PR_G"){id}}`, "allowed", "acme/gadgets,acme/widgets", true},
		{"node ID outside the allowlist",
			`query{repository(owner:"acme",name:"widgets"){name} node(id:"PR_S"){id}}`, "refused", "acme/widgets,acme/secret", true},
		{"named repo outside the allowlist, refused before resolving",
			`query{repository(owner:"acme",name:"secret"){name} node(id:"PR_W"){id}}`, "refused", "acme/secret", false},
		{"unparseable document",
			`query{`, "refused", "", false},
	} {
		mu.Lock()
		before := resolves
		mu.Unlock()
		body, _ := json.Marshal(map[string]string{"query": c.query})
		resp, err := client.Post("http://api.github.com/graphql", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		// The broker logs an allowed request after it answers.
		var lines []string
		for range 200 {
			if lines = logs.lines(); len(lines) > i && lines[i] != "" {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if len(lines) <= i {
			t.Fatalf("%s: no log line", c.name)
		}
		rec, ok := audit.Parse(lines[i])
		if !ok {
			t.Fatalf("%s: unparseable log line %q", c.name, lines[i])
		}
		if rec.Msg != c.msg || rec.Get("repo") != c.repo {
			t.Errorf("%s: logged %s repo=%q, want %s repo=%q\n%s", c.name, rec.Msg, rec.Get("repo"), c.msg, c.repo, lines[i])
		}
		for repo := range strings.SplitSeq(c.repo, ",") {
			if repo != "" && !(audit.Filter{Repo: strings.ToUpper(repo)}).Match(rec) {
				t.Errorf("%s: --repo %s doesn't match %s", c.name, repo, lines[i])
			}
		}
		mu.Lock()
		if got := resolves - before; got != map[bool]int{true: 1, false: 0}[c.resolved] {
			t.Errorf("%s: %d resolve requests", c.name, got)
		}
		mu.Unlock()
	}

	// The refused merge files under its repo, with the command that allows it.
	rec, _ := audit.Parse(logs.lines()[0])
	g := audit.Summarize([]audit.Record{rec})
	if len(g) != 1 || g[0].Repo != "acme/widgets" || !strings.Contains(g[0].Reason, "policy allow pr.merge --repo acme/widgets") {
		t.Errorf("summary: %+v", g)
	}
}
