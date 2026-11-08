// Command fakegithub stands in for github.com and api.github.com while a
// scratch hallpass broker is driven for verification. It serves git smart
// HTTP from bare repos under -root through git http-backend, answers the
// REST and GraphQL calls gh and the broker make for acme/widgets, and
// refuses anything that doesn't carry the scratch token the broker should
// have added. Every request it sees goes to -log as one JSON line, so the
// log shows what actually reached "GitHub".
//
// Build it outside the module's package tree (the directory starts with a
// dot, so go vet ./... skips it):
//
//	go build -o "$S/bin/fakegithub" .claude/skills/verify-hallpass/scripts/fakegithub/main.go
package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// login is the account the scratch token belongs to. up.sh writes the same
// name into the scratch hallpass.toml.
const login = "verifier"

type entry struct {
	Time   string `json:"time"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Query  string `json:"query,omitempty"`
	Auth   string `json:"auth"` // "token-ok", "basic-ok", "wrong", or "none"
	Status int    `json:"status"`
	Body   string `json:"body,omitempty"`
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func main() {
	root := flag.String("root", "", "directory of bare repos, as OWNER/NAME.git")
	tokenFile := flag.String("token-file", "", "file holding the token the broker must send")
	logPath := flag.String("log", "", "JSONL request log")
	ready := flag.String("ready", "", "file to write the base URL to once listening")
	flag.Parse()
	if *root == "" || *tokenFile == "" || *logPath == "" || *ready == "" {
		log.Fatal("fakegithub: -root, -token-file, -log, and -ready are required")
	}
	tb, err := os.ReadFile(*tokenFile)
	if err != nil {
		log.Fatal(err)
	}
	token := strings.TrimSpace(string(tb))
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))

	gitExec, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		log.Fatal("fakegithub: git --exec-path: ", err)
	}
	backend := &cgi.Handler{
		Path: filepath.Join(strings.TrimSpace(string(gitExec)), "git-http-backend"),
		Env:  []string{"GIT_PROJECT_ROOT=" + *root, "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=agent"},
	}

	lf, err := os.OpenFile(*logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	record := func(e entry) {
		b, _ := json.Marshal(e)
		mu.Lock()
		lf.Write(append(b, '\n'))
		mu.Unlock()
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if strings.HasPrefix(r.URL.Path, "/api/") {
			body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		auth := "none"
		switch got := r.Header.Get("Authorization"); {
		case got == "token "+token:
			auth = "token-ok"
		case got == basic:
			auth = "basic-ok"
		case got != "":
			auth = "wrong"
		}
		rec := &recorder{ResponseWriter: w, status: 200}
		defer func() {
			b := string(body)
			if len(b) > 2000 {
				b = b[:2000] + "..."
			}
			record(entry{Time: time.Now().UTC().Format(time.RFC3339Nano), Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Auth: auth, Status: rec.status, Body: b})
		}()
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if auth != "token-ok" {
				rec.WriteHeader(401)
				io.WriteString(rec, `{"message":"Bad credentials"}`)
				return
			}
			api(rec, r, strings.TrimPrefix(r.URL.Path, "/api"), string(body))
			return
		}
		if auth != "basic-ok" {
			rec.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
			rec.WriteHeader(401)
			return
		}
		backend.ServeHTTP(rec, r)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	url := "http://" + ln.Addr().String()
	if err := os.WriteFile(*ready, []byte(url+"\n"), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Println("fakegithub listening on", url)
	log.Fatal(http.Serve(ln, h))
}

// api answers the calls gh and the broker make. acme/widgets exists, with
// PR and issue 1 written by the token's account and PR and issue 2 by a
// colleague; every other repo is a 404.
func api(w http.ResponseWriter, r *http.Request, path, body string) {
	w.Header().Set("Content-Type", "application/json")
	reply := func(code int, s string) {
		w.WriteHeader(code)
		io.WriteString(w, s)
	}
	repo := `{"id":1,"node_id":"R_1","name":"widgets","full_name":"acme/widgets","owner":{"login":"acme"},"default_branch":"main","private":true}`
	author := func(n string) string {
		if n == "1" {
			return login
		}
		return "colleague"
	}
	switch {
	case path == "/user":
		w.Header().Set("X-OAuth-Scopes", "repo")
		reply(200, `{"login":"`+login+`"}`)
	case path == "/graphql":
		graphql(reply, body)
	case path == "/repos/acme/widgets":
		reply(200, repo)
	case path == "/search/issues":
		reply(200, `{"total_count":0,"incomplete_results":false,"items":[]}`)
	case strings.HasPrefix(path, "/repos/acme/widgets/"):
		rest := strings.Split(strings.TrimPrefix(path, "/repos/acme/widgets/"), "/")
		if s, ok := actions(r.Method, rest); ok {
			reply(200, s)
			return
		}
		switch {
		case r.Method == "GET" && len(rest) == 2 && (rest[0] == "issues" || rest[0] == "pulls"):
			reply(200, fmt.Sprintf(`{"number":%s,"title":"fake %s %s","state":"open","user":{"login":"%s"}}`, rest[1], rest[0], rest[1], author(rest[1])))
		case r.Method == "GET" && len(rest) == 3 && rest[0] == "issues" && rest[1] == "comments":
			reply(200, fmt.Sprintf(`{"id":%s,"body":"fake comment","user":{"login":"%s"}}`, rest[2], author(rest[2])))
		case r.Method == "GET":
			reply(200, `[]`)
		case r.Method == "POST":
			reply(201, `{"id":101,"html_url":"https://github.com/acme/widgets/issues/1#issuecomment-101","user":{"login":"`+login+`"}}`)
		default:
			reply(200, `{"id":101,"user":{"login":"`+login+`"}}`)
		}
	default:
		reply(404, `{"message":"Not Found"}`)
	}
}

// actions answers the Actions, workflow, readme, and release reads gh makes,
// for run 5 (job 7) of workflow ci.yml and release v1.0.0, so gh gets past
// its first request.
func actions(method string, rest []string) (string, bool) {
	if method != "GET" {
		return "", false
	}
	const run = `{"id":5,"name":"ci","display_title":"fake run","status":"completed","conclusion":"success","head_branch":"main","head_sha":"abc","event":"push","workflow_id":9,"run_attempt":1,"html_url":"https://github.com/acme/widgets/actions/runs/5","jobs_url":"https://api.github.com/repos/acme/widgets/actions/runs/5/jobs","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}`
	const job = `{"id":7,"run_id":5,"name":"test","status":"completed","conclusion":"success","steps":[{"name":"build","status":"completed","conclusion":"success","number":1}],"html_url":"https://github.com/acme/widgets/actions/runs/5/job/7","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:00:00Z"}`
	const workflow = `{"id":9,"name":"ci","path":".github/workflows/ci.yml","state":"active","html_url":"https://github.com/acme/widgets/blob/main/.github/workflows/ci.yml"}`
	const release = `{"id":3,"tag_name":"v1.0.0","name":"v1.0.0","draft":false,"prerelease":false,"body":"","assets":[],"html_url":"https://github.com/acme/widgets/releases/tag/v1.0.0"}`
	p := strings.Join(rest, "/")
	switch {
	case p == "actions/runs" || (strings.HasPrefix(p, "actions/workflows/") && strings.HasSuffix(p, "/runs")):
		return `{"total_count":1,"workflow_runs":[` + run + `]}`, true
	case p == "actions/runs/5" || p == "actions/runs/5/attempts/1":
		return run, true
	case p == "actions/runs/5/jobs" || p == "actions/runs/5/attempts/1/jobs":
		return `{"total_count":1,"jobs":[` + job + `]}`, true
	case p == "actions/jobs/7":
		return job, true
	case p == "actions/jobs/7/logs":
		return "2026-01-01T00:00:00Z build ok\n", true
	case p == "actions/runs/5/logs" || p == "actions/runs/5/attempts/1/logs":
		return runLogs(), true
	case p == "actions/runs/5/artifacts" || p == "actions/artifacts":
		return `{"total_count":0,"artifacts":[]}`, true
	case p == "actions/workflows":
		return `{"total_count":1,"workflows":[` + workflow + `]}`, true
	case strings.HasPrefix(p, "actions/workflows/") && len(rest) == 3:
		return workflow, true
	case p == "readme":
		return `{"name":"README","path":"README","content":"","encoding":"base64","html_url":"https://github.com/acme/widgets/blob/main/README"}`, true
	case p == "releases/latest" || p == "releases/tags/v1.0.0":
		return release, true
	}
	return "", false
}

// runLogs is run 5's log archive, laid out as GitHub's: one file per job
// step under the job's name.
func runLogs() string {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, _ := z.Create("test/1_build.txt")
	io.WriteString(w, "2026-01-01T00:00:00Z build ok\n")
	z.Close()
	return b.String()
}

func graphql(reply func(int, string), q string) {
	switch {
	case strings.Contains(q, "nodes(ids"):
		// PR_1 and I_1 are the token user's, like PR and issue 1 over REST.
		mine := strings.Contains(q, `"PR_1"`) || strings.Contains(q, `"I_1"`)
		typ := "PullRequest"
		switch {
		case strings.Contains(q, `"I_`):
			typ = "Issue"
		case strings.Contains(q, `"R_`):
			typ = "Repository"
		}
		reply(200, fmt.Sprintf(`{"data":{"nodes":[{"__typename":"%s","repository":{"nameWithOwner":"acme/widgets"},"viewerDidAuthor":%t}]}}`, typ, mine))
	case strings.Contains(q, "IssueByNumber"):
		reply(200, `{"data":{"repository":{"hasIssuesEnabled":true,"issue":{"__typename":"Issue","id":"I_1","number":1,"url":"https://github.com/acme/widgets/issues/1","state":"OPEN","title":"fake issue","body":"","author":{"login":"verifier"},"comments":{"nodes":[],"totalCount":0},"assignees":{"nodes":[],"totalCount":0},"labels":{"nodes":[],"totalCount":0}}}}}`)
	case strings.Contains(q, "addComment"):
		reply(200, `{"data":{"addComment":{"commentEdge":{"node":{"url":"https://github.com/acme/widgets/pull/1#issuecomment-1"}}}}}`)
	case strings.Contains(q, "PullRequestByNumber"):
		reply(200, `{"data":{"repository":{"pullRequest":{"id":"PR_1","number":1,"url":"https://github.com/acme/widgets/pull/1","title":"fake pr","state":"OPEN","headRefName":"agent/x","headRepositoryOwner":{"id":"U","login":"acme"},"headRepository":{"id":"R_1","name":"widgets","nameWithOwner":"acme/widgets"},"isCrossRepository":false,"mergeStateStatus":"CLEAN","commits":{"nodes":[{"commit":{"oid":"abc"}}]},"baseRefName":"main"}}}}`)
	case strings.Contains(q, "RepositoryInfo"):
		reply(200, `{"data":{"repository":{"id":"R_1","name":"widgets","owner":{"login":"acme"},"defaultBranchRef":{"name":"main"},"isPrivate":true,"viewerPermission":"WRITE","hasIssuesEnabled":true}}}`)
	default:
		reply(200, `{"data":{}}`)
	}
}
