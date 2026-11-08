package policy

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/op"
)

// Each testdata/gh-<version>-capture.jsonl is one gh release's real traffic,
// recorded by verify-hallpass's gh-matrix.sh and appended with
// gh-matrix-corpus.py. hallpass must allow
// every request gh sends for the commands agents run, so a gh upgrade that
// changes them shows up here as a refusal.
func TestGHCorpus(t *testing.T) {
	files, err := filepath.Glob("testdata/gh-*-capture.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no gh captures in testdata")
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			t.Parallel()
			checkCapture(t, file)
		})
	}
}

var zeroID = regexp.MustCompile(`/0(/|\?|$)`)

// gh's requests that need an operation that's off by default.
var optIn = map[string]op.Op{
	"mergePullRequest(":           op.PRMerge,
	"enablePullRequestAutoMerge(": op.PRMerge,
	`"event":"APPROVE"`:           op.ReviewVerdict,
}

func checkCapture(t *testing.T, file string) {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	graphql := 0
	for sc.Scan() {
		var rec struct{ Cmd, Head, Body string }
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		method, rest, _ := strings.Cut(rec.Head, " ")
		target, _, _ := strings.Cut(rest, " ")
		if method == "POST" && target == "/graphql" {
			graphql++
			checkGraphQL(t, rec.Cmd, rec.Body)
			continue
		}
		// The stub answered {}, so gh followed an empty URL to "/". Real
		// GitHub would have given it one.
		if target == "/" || strings.HasPrefix(target, "/?") {
			continue
		}
		// gh read its PR and run numbers from the stub's {}, so they're 0.
		target = zeroID.ReplaceAllString(target, "/1$1")
		if _, err := ClassifyREST(method, target, []byte(rec.Body), nil); err != nil {
			t.Errorf("%s: refused %s %s: %v", rec.Cmd, method, target, err)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if graphql < 15 {
		t.Fatalf("only %d GraphQL requests in %s", graphql, file)
	}
}

func checkGraphQL(t *testing.T, cmd, body string) {
	t.Helper()
	// The stub answered {}, so gh sent empty IDs where real GitHub would
	// have given it some.
	body = strings.ReplaceAll(body, `"id":""`, `"id":"PR_x"`)
	g, err := ClassifyGraphQL([]byte(body), nil)
	if err != nil {
		t.Errorf("%s: refused: %v\n%.300s", cmd, err, body)
		return
	}
	for marker, want := range optIn {
		if strings.Contains(body, marker) && !slices.ContainsFunc(g.Nodes, func(n NodeUse) bool { return slices.Contains(n.Ops, want) }) {
			t.Errorf("%s: want %s among the ops, got %+v", cmd, want, g.Nodes)
		}
	}
	// What the broker forwards classifies the same way.
	if _, err := ClassifyGraphQL(g.Body, nil); err != nil {
		t.Errorf("%s: printed request no longer classifies: %v", cmd, err)
	}
}
