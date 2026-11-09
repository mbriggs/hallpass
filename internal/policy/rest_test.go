package policy

import (
	"bufio"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/op"
)

// refusedREST are corpus requests hallpass refuses, and why that's fine.
var refusedREST = map[string]string{
	"GET /?per_page=100": "in the original 2.98 capture, against a stub that answered {}; hallpass has always refused it and no gh command has needed it since",
}

// Every REST request gh sent in the corpus classifies, so a route gh
// depends on can't drop out of the tables unnoticed. Whether an operation
// is on is the config's call, checked later.
func TestRESTCorpus(t *testing.T) {
	t.Parallel()
	f, err := os.Open("testdata/gh-2.98.0-capture.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	n := 0
	for sc.Scan() {
		var rec struct{ Head, Body string }
		json.Unmarshal(sc.Bytes(), &rec)
		line, _, _ := strings.Cut(rec.Head, "\r\n")
		method, rest, _ := strings.Cut(line, " ")
		target, _, _ := strings.Cut(rest, " ")
		if target == "/graphql" {
			continue
		}
		// Some records were captured against a stub that answered {}, so gh
		// followed an empty URL to "/" and read its IDs as 0. Real GitHub
		// would have given it some, as TestGHCorpus also assumes.
		if target == "/" || strings.HasPrefix(target, "/?") {
			continue
		}
		target = zeroID.ReplaceAllString(target, "/1$1")
		n++
		_, err := ClassifyREST(method, target, []byte(rec.Body), nil)
		if why, ok := refusedREST[method+" "+target]; ok {
			if err == nil {
				t.Errorf("%s %s classifies now; drop it from refusedREST (%s)", method, target, why)
			}
			continue
		}
		if err != nil {
			t.Errorf("refused gh's own request %s %s: %v", method, target, err)
		}
	}
	if n < 20 {
		t.Fatalf("only %d REST requests in the corpus", n)
	}
}

// Each write names every operation the config must allow for it.
func TestRESTOps(t *testing.T) {
	cases := []struct {
		method, target, body string
		ops                  []op.Op
	}{
		{"POST", "/repos/acme/widgets/pulls", `{"title":"t","head":"x","base":"main"}`, []op.Op{op.PRCreate}},
		{"POST", "/repos/acme/widgets/issues", `{"title":"t"}`, []op.Op{op.IssueCreate}},
		{"POST", "/repos/acme/widgets/issues", `{"title":"t","labels":["automerge"],"assignees":["a"]}`, []op.Op{op.IssueCreate, op.Labels, op.Assign}},
		{"PATCH", "/repos/acme/widgets/issues/3", `{"labels":["bug"]}`, []op.Op{op.IssueEdit, op.Labels}},
		{"POST", "/repos/acme/widgets/issues/3/labels", `{"labels":["bug"]}`, []op.Op{op.Labels}},
		{"POST", "/repos/acme/widgets/pulls/3/reviews", `{"body":"nit","event":"COMMENT"}`, []op.Op{op.ReviewComment}},
		{"POST", "/repos/acme/widgets/pulls/3/reviews", `{"body":"nit"}`, []op.Op{op.ReviewComment}},
		{"POST", "/repos/acme/widgets/pulls/3/reviews", `{"event":"APPROVE"}`, []op.Op{op.ReviewComment, op.ReviewVerdict}},
		{"POST", "/repos/acme/widgets/pulls/3/reviews", `{"event":"REQUEST_CHANGES"}`, []op.Op{op.ReviewComment, op.ReviewVerdict}},
		{"POST", "/repos/acme/widgets/pulls/3/reviews/9/events", `{"event":"APPROVE"}`, []op.Op{op.ReviewComment, op.ReviewVerdict}},
		{"PUT", "/repos/acme/widgets/pulls/3/merge", `{"merge_method":"squash"}`, []op.Op{op.PRMerge}},
		{"PUT", "/repos/acme/widgets/pulls/3/merge", ``, []op.Op{op.PRMerge}},
		{"POST", "/repos/acme/widgets/actions/runs/1/rerun", ``, []op.Op{op.WorkflowRerun}},
		{"POST", "/repos/acme/widgets/actions/runs/1/rerun-failed-jobs", `{"enable_debug_logging":true}`, []op.Op{op.WorkflowRerun}},
		{"POST", "/repos/acme/widgets/actions/jobs/7/rerun", ``, []op.Op{op.WorkflowRerun}},
		{"POST", "/repos/acme/widgets/actions/workflows/deploy.yml/dispatches", `{"ref":"main","inputs":{"env":"prod"}}`, []op.Op{op.WorkflowDispatch}},
		{"POST", "/repos/acme/widgets/actions/workflows/42/dispatches", `{"ref":"main"}`, []op.Op{op.WorkflowDispatch}},
	}
	for _, c := range cases {
		r, err := ClassifyREST(c.method, c.target, []byte(c.body), nil)
		if err != nil {
			t.Errorf("%s %s %s: %v", c.method, c.target, c.body, err)
			continue
		}
		slices.Sort(r.Ops)
		slices.Sort(c.ops)
		if !r.Write || !slices.Equal(r.Ops, c.ops) {
			t.Errorf("%s %s %s: ops %v, want %v", c.method, c.target, c.body, r.Ops, c.ops)
		}
	}
}

func TestClassifyREST(t *testing.T) {
	ok := []struct {
		method, target, body string
		write, follow        bool
		authored, route      string
	}{
		{"GET", "/user", "", false, false, "", "GET /user"},
		{"GET", "/repos/acme/widgets", "", false, false, "", "GET repos/{repo}/"},
		{"GET", "/repos/acme/widgets/actions/runs/99?exclude_pull_requests=true", "", false, false, "", "GET repos/{repo}/actions/runs/#"},
		{"GET", "/repos/acme/widgets/actions/runs/99/logs", "", false, true, "", "GET repos/{repo}/actions/runs/#/logs"},
		{"GET", "/repos/acme/widgets/actions/jobs/5/logs", "", false, true, "", "GET repos/{repo}/actions/jobs/#/logs"},
		{"GET", "/search/issues?page=1&per_page=30&q=%28+foo+%29+repo%3Aacme%2Fwidgets+type%3Apr", "", false, false, "", "GET /search/issues"},
		{"POST", "/repos/acme/widgets/pulls", `{"title":"t","head":"agent/x","base":"main"}`, true, false, "", "POST pulls"},
		{"POST", "/repos/acme/widgets/issues/3/comments", `{"body":"hi"}`, true, false, "", "POST issues/#/comments"},
		{"POST", "/repos/acme/widgets/pulls/3/reviews", `{"body":"nit","event":"COMMENT"}`, true, false, "", "POST pulls/#/reviews"},
		{"PATCH", "/repos/acme/widgets/pulls/3", `{"title":"t"}`, true, false, "/repos/acme/widgets/pulls/3", "PATCH pulls/#"},
		{"PATCH", "/repos/acme/widgets/issues/comments/77", `{"body":"b"}`, true, false, "/repos/acme/widgets/issues/comments/77", "PATCH issues/comments/#"},
	}
	for _, c := range ok {
		r, err := ClassifyREST(c.method, c.target, []byte(c.body), nil)
		if err != nil {
			t.Errorf("%s %s: %v", c.method, c.target, err)
			continue
		}
		// Each target is already in the form the parse rebuilds, so the
		// upstream path is the target unchanged.
		if r.Write != c.write || r.Follow != c.follow || r.Authored != c.authored || r.Route != c.route || r.Path != c.target {
			t.Errorf("%s %s = %+v", c.method, c.target, r)
		}
	}
	bad := []struct{ method, target, body string }{
		{"POST", "/repos/acme/widgets/merges", `{"base":"main","head":"x"}`},
		{"POST", "/repos/acme/widgets/pulls/3/reviews", `{"event":"DISMISS"}`},
		{"POST", "/repos/acme/widgets/pulls/3", `{}`},
		{"POST", "/repos/acme/widgets/actions/workflows/../dispatches", `{"ref":"main"}`},
		{"POST", "/repos/acme/widgets/actions/runs/1/cancel", ``},
		{"POST", "/repos/acme/widgets/actions/runs/1/rerun", `{"x":1}`},
		{"DELETE", "/repos/acme/widgets/issues/3/labels/bug", ``},
		{"PUT", "/repos/acme/widgets/contents/x", `{}`},
		{"POST", "/repos/acme/widgets/git/refs", `{}`},
		{"DELETE", "/repos/acme/widgets/issues/comments/1", ``},
		{"GET", "/repos/acme/widgets/actions/secrets", ``},
		{"GET", "/repos/acme/widgets/environments/prod/secrets", ``},
		{"GET", "/repos/acme/widgets/hooks", ``},
		{"POST", "/repos/acme/widgets/issues/3/comments", `{"body":"/merge"}`},
		{"POST", "/repos/acme/widgets/pulls", `{"title":"t","head":"evil:x","base":"main"}`},
		{"POST", "/repos/acme/widgets/pulls/3/requested_reviewers", `{"team_reviewers":["core"]}`},
		{"POST", "/repos/acme/widgets/releases", `{}`},
		{"GET", "/repos/acme/%2e%2e/secret", ``},
		{"GET", "/repos/acme/widgets.git", ``},
		{"GET", "/repos/acme/widgets/../../user/repos", ``},
		{"GET", "/repositories/123/contents", ``},
		{"GET", "/orgs/acme/repos", ``},
		{"GET", "/search/code?q=org%3Aacme+password", ``},
		{"GET", "/search/issues?q=repo%3Aacme%2Fa+repo%3Aacme%2Fb", ``},
		// A second q would reach GitHub without the repo check.
		{"GET", "/search/issues?q=repo%3Aacme%2Fwidgets&q=repo%3Aacme%2Fsecret", ``},
		{"GET", "/repos/acme/widgets/pulls?state=open&state=closed", ``},
		{"GET", "/?per_page=100", ``},
		{"POST", "/repos/acme/widgets/issues/3/comments", `{"body":"a","body":"/merge"}`},
	}
	for _, c := range bad {
		if r, err := ClassifyREST(c.method, c.target, []byte(c.body), nil); err == nil {
			t.Errorf("%s %s %s: allowed (%+v)", c.method, c.target, c.body, r)
		}
	}
	// No read pattern can name Deployments, so the refusal offers no command.
	if _, err := ClassifyREST("GET", "/repos/acme/widgets/Deployments", nil, nil); err == nil || strings.Contains(err.Error(), "To allow it") {
		t.Errorf("GET Deployments: %v", err)
	}
}
