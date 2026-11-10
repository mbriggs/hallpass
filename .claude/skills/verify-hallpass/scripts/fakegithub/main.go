// Command fakegithub stands in for github.com and api.github.com while a
// scratch hallpass broker is driven for verification. It serves git over
// SSH from bare repos under -root, running real git-upload-pack and
// git-receive-pack for the one client key it accepts. It answers the REST
// and GraphQL calls gh and the broker make for acme/widgets, and refuses
// any that don't carry the scratch token the broker should have added.
// Every request it sees goes to -log as one JSON line, so the log shows
// what actually reached "GitHub".
//
// Build it outside the module's package tree (the directory starts with a
// dot, so go vet ./... skips it):
//
//	go build -o "$S/bin/fakegithub" .claude/skills/verify-hallpass/scripts/fakegithub/main.go
package main

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// login is the account the scratch token belongs to. up.sh writes the same
// name into the scratch hallpass.toml.
const login = "verifier"

type entry struct {
	Time   string `json:"time"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Query  string `json:"query,omitempty"`
	Auth   string `json:"auth"` // "token-ok", "key-ok", "wrong", or "none"
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
	clientKey := flag.String("ssh-client-key", "", "authorized_keys line of the one key git over SSH accepts")
	sshReady := flag.String("ssh-ready", "", "file to write the SSH address and host key to once listening")
	flag.Parse()
	if *root == "" || *tokenFile == "" || *logPath == "" || *ready == "" || *clientKey == "" || *sshReady == "" {
		log.Fatal("fakegithub: -root, -token-file, -log, -ready, -ssh-client-key, and -ssh-ready are required")
	}
	tb, err := os.ReadFile(*tokenFile)
	if err != nil {
		log.Fatal(err)
	}
	token := strings.TrimSpace(string(tb))

	lf, err := os.OpenFile(*logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	record := func(e entry) {
		b, _ := json.Marshal(e)
		mu.Lock()
		_, _ = lf.Write(append(b, '\n'))
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
		case got != "":
			auth = "wrong"
		}
		rec := &recorder{ResponseWriter: w, status: 200}
		defer func() {
			b := string(body)
			if len(b) > 2000 {
				b = b[:2000] + "..."
			}
			record(entry{Time: now(), Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Auth: auth, Status: rec.status, Body: b})
		}()
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			rec.WriteHeader(http.StatusNotFound)
			return
		}
		// octo/public is a public repo outside the allowlist: GitHub shows
		// it to anyone, token or not.
		if r.Method == http.MethodGet && r.URL.Path == "/api/repos/octo/public" && auth == "none" {
			rec.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(rec, `{"id":3,"name":"public","full_name":"octo/public","owner":{"login":"octo"},"default_branch":"main","private":false}`)
			return
		}
		if auth != "token-ok" {
			rec.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(rec, `{"message":"Bad credentials"}`)
			return
		}
		api(rec, r, strings.TrimPrefix(r.URL.Path, "/api"), string(body))
	})

	addr, hostKey, err := serveGitSSH(*root, *clientKey, record)
	if err != nil {
		log.Fatal("fakegithub: ssh: ", err)
	}
	if err := os.WriteFile(*sshReady, []byte(addr+"\n"+hostKey+"\n"), 0o644); err != nil {
		log.Fatal(err)
	}

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
// colleague. acme/readonly answers its repo lookup only. acme/gadgets
// redirects as a repo renamed to acme/widgets, and acme/gizmos as one
// renamed to acme/private. Every other repo is a 404.
func api(w http.ResponseWriter, r *http.Request, path, body string) {
	w.Header().Set("Content-Type", "application/json")
	reply := func(code int, s string) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, s)
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
	case path == "/repos/acme/widgets" || path == "/repositories/1":
		reply(200, repo)
	case path == "/repos/acme/readonly":
		reply(200, `{"id":2,"node_id":"R_2","name":"readonly","full_name":"acme/readonly","owner":{"login":"acme"},"default_branch":"main","private":true}`)
	case path == "/repos/acme/gadgets":
		// acme/gadgets was renamed to acme/widgets: GitHub redirects the old
		// name to the repo's ID, which the broker's current-name check follows.
		w.Header().Set("Location", "http://"+r.Host+"/api/repositories/1")
		reply(301, `{"message":"Moved Permanently"}`)
	case path == "/repos/acme/gizmos":
		// acme/gizmos was renamed to acme/private, which isn't allowlisted.
		w.Header().Set("Location", "http://"+r.Host+"/api/repositories/3")
		reply(301, `{"message":"Moved Permanently"}`)
	case path == "/repositories/3":
		reply(200, `{"id":3,"node_id":"R_3","name":"private","full_name":"acme/private","owner":{"login":"acme"},"default_branch":"main","private":true}`)
	case path == "/search/issues":
		reply(200, `{"total_count":0,"incomplete_results":false,"items":[]}`)
	case path == "/search/code":
		codeSearch(w, r, reply)
	case strings.HasPrefix(path, "/repos/acme/widgets/"):
		rest := strings.Split(strings.TrimPrefix(path, "/repos/acme/widgets/"), "/")
		if s, ok := actions(r.Method, rest); ok {
			reply(200, s)
			return
		}
		switch {
		case r.Method == http.MethodGet && len(rest) == 2 && (rest[0] == "issues" || rest[0] == "pulls"):
			reply(200, fmt.Sprintf(`{"number":%s,"title":"fake %s %s","state":"open","user":{"login":"%s"}}`, rest[1], rest[0], rest[1], author(rest[1])))
		case r.Method == http.MethodGet && len(rest) == 3 && rest[0] == "issues" && rest[1] == "comments":
			reply(200, fmt.Sprintf(`{"id":%s,"body":"fake comment","user":{"login":"%s"}}`, rest[2], author(rest[2])))
		case r.Method == http.MethodGet:
			reply(200, `[]`)
		case r.Method == http.MethodPost:
			reply(201, `{"id":101,"html_url":"https://github.com/acme/widgets/issues/1#issuecomment-101","user":{"login":"`+login+`"}}`)
		default:
			reply(200, `{"id":101,"user":{"login":"`+login+`"}}`)
		}
	default:
		reply(404, `{"message":"Not Found"}`)
	}
}

// codeSearch answers GET /search/code as GitHub does, with its own rate
// limit headers. It searches the repo a repo: qualifier names, and every
// repo the token sees when there's none, as GitHub would. A query holding
// "leak" also gets a result from acme/private, as if GitHub read the query
// differently from the broker, and one holding "throttled" gets GitHub's
// answer when the code search limit is used up. page 1 of 100 results
// links to a page 2.
func codeSearch(w http.ResponseWriter, r *http.Request, reply func(int, string)) {
	q := r.URL.Query()
	w.Header().Set("X-RateLimit-Resource", "code_search")
	w.Header().Set("X-RateLimit-Limit", "10")
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
	if strings.Contains(q.Get("q"), "throttled") {
		w.Header().Set("X-RateLimit-Remaining", "0")
		reply(403, `{"message":"API rate limit exceeded for user ID 1.","documentation_url":"https://docs.github.com/rest/overview/rate-limits-for-the-rest-api"}`)
		return
	}
	w.Header().Set("X-RateLimit-Remaining", "9")
	repos := []string{"acme/widgets", "acme/private"}
	for t := range strings.FieldsSeq(q.Get("q")) {
		if name, ok := strings.CutPrefix(strings.ToLower(t), "repo:"); ok {
			repos = []string{name}
		}
	}
	if strings.Contains(q.Get("q"), "leak") {
		repos = append(repos, "acme/private")
	}
	n, total := len(repos), len(repos)
	if q.Get("per_page") == "100" {
		total = 101
		switch q.Get("page") {
		case "1", "":
			n = 100
			next := url.Values{"q": {q.Get("q")}, "per_page": {"100"}, "page": {"2"}}
			w.Header().Set("Link", `<https://api.github.com/search/code?`+next.Encode()+`>; rel="next", <https://api.github.com/search/code?`+next.Encode()+`>; rel="last"`)
		default:
			n = 1
		}
	}
	items := make([]string, n)
	for i := range items {
		repo := repos[0]
		if i < len(repos) {
			repo = repos[i]
		}
		owner, name, _ := strings.Cut(repo, "/")
		file := fmt.Sprintf("src/widget%d.go", i)
		items[i] = fmt.Sprintf(`{"name":"widget%d.go","path":"%s","sha":"abc","url":"https://api.github.com/repos/%s/contents/%s","html_url":"https://github.com/%s/blob/main/%s","repository":{"id":1,"name":"%s","full_name":"%s","private":true,"owner":{"login":"%s"}},"score":1,"text_matches":[{"object_type":"FileContent","property":"content","fragment":"func widget() {}","matches":[{"text":"widget","indices":[5,11]}]}]}`,
			i, file, repo, file, repo, file, name, repo, owner)
	}
	reply(200, fmt.Sprintf(`{"total_count":%d,"incomplete_results":false,"items":[%s]}`, total, strings.Join(items, ",")))
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
	_, _ = io.WriteString(w, "2026-01-01T00:00:00Z build ok\n")
	_ = z.Close()
	return b.String()
}

func graphql(reply func(int, string), q string) {
	switch {
	case strings.Contains(q, "nodes(ids"):
		reply(200, nodes(q))
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

// nodes answers the broker's node lookup with one node per requested ID, in
// acme/widgets. IDs starting I_ are issues, R_ repos, and the rest PRs, and
// those ending _1 were written by the token's account, matching the REST
// fixture.
func nodes(body string) string {
	var req struct {
		Variables struct {
			IDs []string `json:"ids"`
		} `json:"variables"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return `{"errors":[{"message":"malformed body"}]}`
	}
	var out []map[string]any
	for _, id := range req.Variables.IDs {
		typ := "PullRequest"
		switch {
		case strings.HasPrefix(id, "I_"):
			typ = "Issue"
		case strings.HasPrefix(id, "R_"):
			typ = "Repository"
		}
		out = append(out, map[string]any{
			"__typename":      typ,
			"repository":      map[string]string{"nameWithOwner": "acme/widgets"},
			"viewerDidAuthor": strings.HasSuffix(id, "_1"),
		})
	}
	b, _ := json.Marshal(map[string]any{"data": map[string]any{"nodes": out}})
	return string(b)
}

// serveGitSSH listens on a local port and runs git-upload-pack and
// git-receive-pack over bare repos in root, as GitHub does, for the one
// client key it accepts. Each command goes to the request log.
func serveGitSSH(root, clientKey string, record func(entry)) (addr, hostKey string, err error) {
	want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(clientKey))
	if err != nil {
		return "", "", fmt.Errorf("-ssh-client-key: %w", err)
	}
	hk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	hs, err := ssh.NewSignerFromSigner(hk)
	if err != nil {
		return "", "", err
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(k.Marshal(), want.Marshal()) {
			record(entry{Time: now(), Method: "SSH", Path: "auth", Auth: "wrong", Status: 1})
			return nil, errors.New("unknown key")
		}
		return nil, nil
	}}
	cfg.AddHostKey(hs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSHConn(c, cfg, root, record)
		}
	}()
	return ln.Addr().String(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hs.PublicKey()))), nil
}

func serveSSHConn(c net.Conn, cfg *ssh.ServerConfig, root string, record func(entry)) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			var env []string
			for req := range creqs {
				switch req.Type {
				case "env":
					var kv struct{ K, V string }
					if ssh.Unmarshal(req.Payload, &kv) != nil {
						_ = req.Reply(false, nil)
						continue
					}
					env = append(env, kv.K+"="+kv.V)
					_ = req.Reply(true, nil)
				case "exec":
					var cmd struct{ C string }
					if ssh.Unmarshal(req.Payload, &cmd) != nil {
						_ = req.Reply(false, nil)
						continue
					}
					_ = req.Reply(true, nil)
					status := runGit(cmd.C, root, env, ch)
					record(entry{Time: now(), Method: "SSH", Path: cmd.C, Auth: "key-ok", Status: int(status)})
					var b [4]byte
					binary.BigEndian.PutUint32(b[:], status)
					_, _ = ch.SendRequest("exit-status", false, b[:])
					return
				case "shell":
					// What GitHub says to ssh -T, which status --check reads.
					_ = req.Reply(true, nil)
					_, _ = io.WriteString(ch.Stderr(), "Hi "+login+"! You've successfully authenticated, but GitHub does not provide shell access.\n")
					record(entry{Time: now(), Method: "SSH", Path: "shell", Auth: "key-ok", Status: 1})
					_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
					return
				default:
					_ = req.Reply(false, nil)
				}
			}
		}()
	}
}

// runGit runs "git-upload-pack 'owner/name.git'" or the receive-pack form
// against the bare repo in root, and returns its exit status.
func runGit(command, root string, env []string, ch ssh.Channel) uint32 {
	svc, arg, ok := strings.Cut(command, " ")
	if !ok || (svc != "git-upload-pack" && svc != "git-receive-pack") {
		return 1
	}
	path := strings.Trim(arg, "'")
	if strings.Contains(path, "..") || strings.Count(path, "/") != 1 {
		return 1
	}
	g := exec.Command("git", strings.TrimPrefix(svc, "git-"), filepath.Join(root, path))
	g.Env = append(os.Environ(), env...)
	g.Stdin, g.Stdout, g.Stderr = ch, ch, ch.Stderr()
	if g.Run() != nil {
		return 1
	}
	return 0
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
