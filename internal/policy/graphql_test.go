package policy

import (
	"bufio"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
)

// The corpus is gh 2.98's real traffic, captured against a stub socket.
func TestGraphQLCorpus(t *testing.T) {
	t.Parallel()
	f, err := os.Open("testdata/gh-2.98.0-capture.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// gh's requests that need an operation that's off by default.
	optIn := map[string]op.Op{
		"mergePullRequest(":           op.PRMerge,
		"enablePullRequestAutoMerge(": op.PRAutoMerge,
		`"event":"APPROVE"`:           op.ReviewApprove,
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	n := 0
	for sc.Scan() {
		var rec struct{ Head, Body string }
		json.Unmarshal(sc.Bytes(), &rec)
		if !strings.HasPrefix(rec.Head, "POST /graphql") {
			continue
		}
		n++
		// The stub answered {}, so gh sent empty IDs where real GitHub would
		// have given it some.
		body := strings.ReplaceAll(rec.Body, `"id":""`, `"id":"PR_x"`)
		g, err := ClassifyGraphQL([]byte(body))
		if err != nil {
			t.Errorf("refused gh's own request: %v\n%.300s", err, rec.Body)
			continue
		}
		for marker, want := range optIn {
			if strings.Contains(rec.Body, marker) && !slices.ContainsFunc(g.Nodes, func(n NodeUse) bool { return slices.Contains(n.Ops, want) }) {
				t.Errorf("want %s among the ops, got %+v\n%.200s", want, g.Nodes, rec.Body)
			}
		}
		// What the broker forwards classifies the same way.
		if _, err := ClassifyGraphQL(g.Body); err != nil {
			t.Errorf("printed request no longer classifies: %v", err)
		}
	}
	if n < 15 {
		t.Fatalf("only %d GraphQL requests in the corpus", n)
	}
}

func gql(query string, vars map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	return b
}

func TestGraphQLRefusesEscapes(t *testing.T) {
	cases := map[string][]byte{
		"org repos through owner": gql(`{repository(owner:"acme",name:"widgets"){owner{... on Organization{repositories(first:5){nodes{name}}}}}}`, nil),
		"viewer repos":            gql(`{viewer{repositories(first:5){nodes{nameWithOwner}}}}`, nil),
		"fork contents":           gql(`{repository(owner:"acme",name:"widgets"){forks(first:1){nodes{object(expression:"HEAD:x"){id}}}}}`, nil),
		"cross reference body":    gql(`{repository(owner:"acme",name:"widgets"){issue(number:1){timelineItems(first:5){nodes{... on CrossReferencedEvent{source{... on Issue{body}}}}}}}}`, nil),
		"closing issue body":      gql(`{repository(owner:"acme",name:"widgets"){pullRequest(number:1){closingIssuesReferences(first:5){nodes{body}}}}}`, nil),
		"author's repos":          gql(`{repository(owner:"acme",name:"widgets"){pullRequest(number:1){author{... on User{repositories(first:1){nodes{name}}}}}}}`, nil),
		"organization root":       gql(`{organization(login:"acme"){repositories(first:1){nodes{name}}}}`, nil),
		"two operations":          gql(`query A{viewer{login}} query B{viewer{login}}`, nil),
		"subscription":            gql(`subscription{viewer{login}}`, nil),
		"unknown directive":       gql(`{viewer{login @defer}}`, nil),
		"search two repos":        gql(`query($q:String!){search(query:$q,type:ISSUE,first:5){issueCount}}`, map[string]any{"q": "repo:acme/widgets repo:acme/secret"}),
		"search or":               gql(`query($q:String!){search(query:$q,type:ISSUE,first:5){issueCount}}`, map[string]any{"q": "repo:acme/widgets OR repo:acme/secret"}),
		"search org":              gql(`query($q:String!){search(query:$q,type:ISSUE,first:5){issueCount}}`, map[string]any{"q": "org:acme bug"}),
		"dismiss event":           gql(`mutation{addPullRequestReview(input:{pullRequestId:"X",event:DISMISS}){clientMutationId}}`, nil),
		"jump the merge queue":    gql(`mutation{enqueuePullRequest(input:{pullRequestId:"X",jump:true}){clientMutationId}}`, nil),
		"labels by name":          gql(`mutation{addLabelsToLabelable(input:{labelableId:"X",labels:["automerge"]}){clientMutationId}}`, nil),
		"fork PR":                 gql(`mutation{createPullRequest(input:{repositoryId:"R",headRepositoryId:"F",baseRefName:"main",headRefName:"x",title:"t"}){clientMutationId}}`, nil),
		"chatops":                 gql(`mutation{addComment(input:{subjectId:"X",body:"looks good\n/merge"}){clientMutationId}}`, nil),
		"bors":                    gql(`mutation{addComment(input:{subjectId:"X",body:"bors r+"}){clientMutationId}}`, nil),
		"commit on branch":        gql(`mutation{createCommitOnBranch(input:{branch:{branchName:"main",repositoryNameWithOwner:"acme/widgets"},expectedHeadOid:"0",message:{headline:"x"}}){clientMutationId}}`, nil),
		"batch":                   []byte(`[{"query":"{viewer{login}}"}]`),
		"duplicate key":           []byte(`{"query":"{viewer{login}}","query":"{viewer{login}}"}`),
		"trailing data":           []byte(`{"query":"{viewer{login}}"}{"query":"x"}`),
		"unknown field":           gql(`{repository(owner:"acme",name:"widgets"){secretSauce}}`, nil),
	}
	for name, body := range cases {
		if g, err := ClassifyGraphQL(body); err == nil {
			t.Errorf("%s: allowed (%+v)", name, g)
		}
	}
}

func TestGraphQLUses(t *testing.T) {
	g, err := ClassifyGraphQL(gql(`query($o:String!,$n:String!){repository(owner:$o,name:$n){pullRequest(number:1){title headRepository{nameWithOwner} author{login}}}}`, map[string]any{"o": "acme", "n": "widgets"}))
	if err != nil || len(g.Repos) != 1 || g.Repos[0].Repo.String() != "acme/widgets" || g.Mutation {
		t.Fatalf("%+v %v", g, err)
	}
	g, err = ClassifyGraphQL(gql(`mutation{updatePullRequest(input:{pullRequestId:"PR_1",title:"t"}){pullRequest{url}}}`, nil))
	if err != nil || len(g.Nodes) != 1 || !g.Nodes[0].Authored || !g.Nodes[0].Write || g.Nodes[0].ID != "PR_1" {
		t.Fatalf("%+v %v", g, err)
	}
}

// Each mutation names every operation the config must allow, on every node
// it changes, so an alias can't slip one past.
func TestGraphQLOps(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		ops  []op.Op
	}{
		{"comment", gql(`mutation{addComment(input:{subjectId:"X",body:"hi"}){clientMutationId}}`, nil), []op.Op{op.Comment}},
		{"aliased merge", gql(`mutation{ok:addComment(input:{subjectId:"X",body:"hi"}){clientMutationId} m:mergePullRequest(input:{pullRequestId:"X"}){clientMutationId}}`, nil), []op.Op{op.Comment, op.PRMerge}},
		{"approve in variables", gql(`mutation($i:AddPullRequestReviewInput!){addPullRequestReview(input:$i){clientMutationId}}`, map[string]any{"i": map[string]any{"pullRequestId": "X", "event": "APPROVE"}}), []op.Op{op.ReviewComment, op.ReviewApprove}},
		{"request changes", gql(`mutation{addPullRequestReview(input:{pullRequestId:"X",event:REQUEST_CHANGES}){clientMutationId}}`, nil), []op.Op{op.ReviewComment, op.ReviewChanges}},
		{"submit approve", gql(`mutation{submitPullRequestReview(input:{pullRequestReviewId:"X",event:APPROVE}){clientMutationId}}`, nil), []op.Op{op.ReviewComment, op.ReviewApprove}},
		{"labels on create", gql(`mutation{createIssue(input:{repositoryId:"R",title:"t",labelIds:["L"]}){clientMutationId}}`, nil), []op.Op{op.IssueCreate, op.Labels}},
		{"assign on edit", gql(`mutation{updatePullRequest(input:{pullRequestId:"X",assigneeIds:["U"]}){clientMutationId}}`, nil), []op.Op{op.PREdit, op.Assign}},
		{"auto-merge", gql(`mutation{enablePullRequestAutoMerge(input:{pullRequestId:"X",mergeMethod:SQUASH}){clientMutationId}}`, nil), []op.Op{op.PRAutoMerge}},
		{"merge queue", gql(`mutation{enqueuePullRequest(input:{pullRequestId:"X"}){clientMutationId}}`, nil), []op.Op{op.PRMerge}},
		{"add labels", gql(`mutation{addLabelsToLabelable(input:{labelableId:"X",labelIds:["L"]}){clientMutationId}}`, nil), []op.Op{op.Labels}},
	}
	for _, c := range cases {
		g, err := ClassifyGraphQL(c.body)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		var got []op.Op
		for _, n := range g.Nodes {
			if !n.Write {
				t.Errorf("%s: %s isn't a write", c.name, n.Where)
			}
			got = append(got, n.Ops...)
		}
		slices.Sort(got)
		got = slices.Compact(got)
		slices.Sort(c.ops)
		if !slices.Equal(got, c.ops) {
			t.Errorf("%s: ops %v, want %v", c.name, got, c.ops)
		}
	}

	// CheckOps names the operation and how to allow it.
	r := github.Repo{Owner: "acme", Name: "widgets"}
	err := CheckOps([]op.Op{op.Comment, op.PRMerge}, op.Defaults(), r)
	if err == nil || !strings.Contains(err.Error(), "policy allow pr.merge --repo acme/widgets") {
		t.Errorf("CheckOps = %v", err)
	}
	if err := CheckOps([]op.Op{op.Comment}, op.Defaults(), r); err != nil {
		t.Errorf("CheckOps refused a default: %v", err)
	}
}
