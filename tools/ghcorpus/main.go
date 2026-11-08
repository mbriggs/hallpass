// Command ghcorpus records the HTTP requests a gh binary sends for the
// commands agents run, so the policy tests can check hallpass still allows
// them after a gh upgrade. It points gh at a stub Unix socket that answers
// every request with 200 and "{}" (repoAnswer has the one exception), runs each command against acme/widgets
// with no token and no network, and writes the requests to
// internal/policy/testdata/gh-<version>-capture.jsonl.
//
//	go run ./tools/ghcorpus -gh /path/to/gh
//
// gh gives up on many commands once it gets "{}" back, so a capture holds
// the requests up to that point, not a full session.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// commands are the gh invocations captured, in order. Keep them to what
// agents do in a repo with the default policy plus pr.merge and
// review.verdict, so every GraphQL request in a capture should classify.
var commands = [][]string{
	{"api", "user"},
	{"api", "repos/acme/widgets"},
	{"repo", "view", "acme/widgets"},
	{"pr", "view", "1", "-R", "acme/widgets"},
	{"pr", "view", "1", "-R", "acme/widgets", "--comments"},
	{"pr", "list", "-R", "acme/widgets"},
	{"pr", "list", "-R", "acme/widgets", "--search", "foo"},
	{"pr", "status", "-R", "acme/widgets"},
	{"pr", "diff", "1", "-R", "acme/widgets"},
	{"pr", "checks", "1", "-R", "acme/widgets"},
	{"pr", "create", "-R", "acme/widgets", "--head", "agent/x", "--base", "main", "--title", "t", "--body", "b"},
	{"pr", "edit", "1", "-R", "acme/widgets", "--title", "t", "--body", "b"},
	{"pr", "edit", "1", "-R", "acme/widgets", "--add-label", "bug"},
	{"pr", "ready", "1", "-R", "acme/widgets"},
	{"pr", "close", "1", "-R", "acme/widgets"},
	{"pr", "reopen", "1", "-R", "acme/widgets"},
	{"pr", "comment", "1", "-R", "acme/widgets", "-b", "looks fine"},
	{"pr", "review", "1", "-R", "acme/widgets", "--comment", "-b", "nit"},
	{"pr", "review", "1", "-R", "acme/widgets", "--approve"},
	{"pr", "merge", "1", "-R", "acme/widgets", "--squash"},
	{"pr", "merge", "1", "-R", "acme/widgets", "--auto", "--squash"},
	{"issue", "view", "1", "-R", "acme/widgets"},
	{"issue", "list", "-R", "acme/widgets"},
	{"issue", "create", "-R", "acme/widgets", "--title", "t", "--body", "b"},
	{"issue", "comment", "1", "-R", "acme/widgets", "-b", "hi"},
	{"issue", "edit", "1", "-R", "acme/widgets", "--title", "t"},
	{"issue", "close", "1", "-R", "acme/widgets"},
	{"run", "list", "-R", "acme/widgets"},
	{"run", "view", "99", "-R", "acme/widgets"},
	{"run", "view", "99", "-R", "acme/widgets", "--log-failed"},
	{"run", "rerun", "99", "-R", "acme/widgets", "--failed"},
	{"workflow", "list", "-R", "acme/widgets"},
	{"search", "prs", "foo", "--repo", "acme/widgets"},
	{"search", "issues", "foo", "--repo", "acme/widgets"},
}

type record struct {
	Cmd  string `json:"cmd"` // the gh command that sent it, for triage
	Head string `json:"head"`
	Body string `json:"body"`
}

func main() {
	gh := flag.String("gh", "gh", "gh binary to capture")
	out := flag.String("out", "internal/policy/testdata", "directory for the capture file")
	flag.Parse()

	version, err := ghVersion(*gh)
	if err != nil {
		log.Fatal(err)
	}
	tmp, err := os.MkdirTemp("", "ghcorpus")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	sock := filepath.Join(tmp, "gh.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	var recs []record
	go serve(ln, func(r record) {
		mu.Lock()
		recs = append(recs, r)
		mu.Unlock()
	})

	cfg := filepath.Join(tmp, "gh")
	os.MkdirAll(cfg, 0o755)
	os.WriteFile(filepath.Join(cfg, "config.yml"), []byte("version: \"1\"\nprompt: disabled\ntelemetry: disabled\nhttp_unix_socket: "+sock+"\n"), 0o644)
	os.WriteFile(filepath.Join(cfg, "hosts.yml"), []byte("github.com:\n    oauth_token: hallpass-dummy\n    user: hallpass\n    git_protocol: https\n"), 0o644)
	// A fixed environment keeps the capture the same whoever runs it, and
	// keeps the caller's tokens away from gh.
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + tmp,
		"TZ=UTC",
		"GH_CONFIG_DIR=" + cfg,
		"GH_NO_UPDATE_NOTIFIER=1",
		"GH_PROMPT_DISABLED=1",
		"NO_COLOR=1",
	}

	for _, args := range commands {
		mu.Lock()
		before := len(recs)
		mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, *gh, args...)
		cmd.Dir = tmp
		cmd.Env = env
		err := cmd.Run()
		cancel()
		mu.Lock()
		n := len(recs) - before
		for i := before; i < len(recs); i++ {
			recs[i].Cmd = "gh " + strings.Join(args, " ")
		}
		mu.Unlock()
		status := "ok"
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			status = fmt.Sprintf("exit %d", exit.ExitCode())
		} else if err != nil {
			log.Fatalf("gh %s: %v", strings.Join(args, " "), err)
		}
		fmt.Fprintf(os.Stderr, "%-3d requests  %-7s  gh %s\n", n, status, strings.Join(args, " "))
	}

	path := filepath.Join(*out, "gh-"+version+"-capture.jsonl")
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, r := range recs {
		enc.Encode(r)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %d requests to %s\n", len(recs), path)
}

var versionRE = regexp.MustCompile(`^gh version (\d+\.\d+\.\d+)`)

func ghVersion(gh string) (string, error) {
	out, err := exec.Command(gh, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("%s --version: %w", gh, err)
	}
	m := versionRE.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("can't read a version from %q", out)
	}
	return string(m[1]), nil
}

// repoAnswer answers gh's repository queries that check hasIssuesEnabled.
// With "{}" gh decides the repo has issues off and stops, so no issue
// mutation would reach the capture.
const repoAnswer = `{"data":{"repository":{"id":"R_x","name":"widgets","owner":{"login":"acme"},"hasIssuesEnabled":true,"viewerPermission":"WRITE","defaultBranchRef":{"name":"main"},` +
	`"issue":{"__typename":"Issue","id":"I_x","number":1,"title":"t","body":"b","url":"https://github.com/acme/widgets/issues/1","state":"OPEN"}}}}`

// serve answers each connection's one request with "{}" and records the
// head as gh sent it, headers in gh's order.
func serve(ln net.Listener, save func(record)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			br := bufio.NewReader(conn)
			var head bytes.Buffer
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				head.WriteString(line)
				if line == "\r\n" {
					break
				}
			}
			req, err := http.ReadRequest(bufio.NewReader(io.MultiReader(bytes.NewReader(head.Bytes()), br)))
			if err != nil {
				return
			}
			body, _ := io.ReadAll(req.Body)
			save(record{Head: strings.TrimSuffix(head.String(), "\r\n\r\n"), Body: string(body)})
			answer := "{}"
			if strings.Contains(string(body), "hasIssuesEnabled") {
				answer = repoAnswer
			}
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(answer), answer)
		}()
	}
}
