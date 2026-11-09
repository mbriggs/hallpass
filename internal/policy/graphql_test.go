package policy

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
)

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
		"parent branch target":    gql(`{repository(owner:"acme",name:"widgets"){parent{defaultBranchRef{target{oid}}}}}`, nil),
		"parent branch prefix":    gql(`{repository(owner:"acme",name:"widgets"){parent{defaultBranchRef{prefix}}}}`, nil),
		"parent issues":           gql(`{repository(owner:"acme",name:"widgets"){parent{issues(first:1){nodes{title}}}}}`, nil),
		"parent readme":           gql(`{repository(owner:"acme",name:"widgets"){parent{object(expression:"HEAD:README"){id}}}}`, nil),
		"org description":         gql(`{repository(owner:"acme",name:"widgets"){owner{... on Organization{description}}}}`, nil),
		"viewer branch":           gql(`{viewer{repository(name:"secret"){defaultBranchRef{name}}}}`, nil),
		"viewer repo by name":     gql(`{viewer{repository(name:"secret"){nameWithOwner}}}`, nil),
		"viewer org by login":     gql(`{viewer{organization(login:"acme"){name}}}`, nil),
		"parent repo's issues":    gql(`{repository(owner:"acme",name:"widgets"){issue(number:1){parent{repository{issues(first:1){nodes{title}}}}}}}`, nil),
		"parent repo's readme":    gql(`{repository(owner:"acme",name:"widgets"){issue(number:1){parent{repository{object(expression:"HEAD:README"){id}}}}}}`, nil),
		"parent body":             gql(`{repository(owner:"acme",name:"widgets"){issue(number:1){parent{body}}}}`, nil),
	}
	for name, body := range cases {
		if g, err := ClassifyGraphQL(body, nil); err == nil {
			t.Errorf("%s: allowed (%+v)", name, g)
		}
	}
}

// gh issue view reads each sub-issue link's repo name, and gh release reads
// a repo's releases.
func TestGraphQLAllowsGhReads(t *testing.T) {
	for name, body := range map[string][]byte{
		"sub-issue parent's repo": gql(`{repository(owner:"acme",name:"widgets"){issue(number:1){parent{number title repository{nameWithOwner}} subIssues(first:5){nodes{number repository{nameWithOwner}}}}}}`, nil),
		"releases":                gql(`{repository(owner:"acme",name:"widgets"){releases(first:5){nodes{name tagName isDraft description}} latestRelease{tagName} release(tagName:"v1"){databaseId}}}`, nil),
	} {
		if _, err := ClassifyGraphQL(body, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGraphQLUses(t *testing.T) {
	g, err := ClassifyGraphQL(gql(`query($o:String!,$n:String!){repository(owner:$o,name:$n){pullRequest(number:1){title headRepository{nameWithOwner} author{login}}}}`, map[string]any{"o": "acme", "n": "widgets"}), nil)
	if err != nil || len(g.Repos) != 1 || g.Repos[0].String() != "acme/widgets" || g.Mutation {
		t.Fatalf("%+v %v", g, err)
	}
	g, err = ClassifyGraphQL(gql(`mutation{updatePullRequest(input:{pullRequestId:"PR_1",title:"t"}){pullRequest{url}}}`, nil), nil)
	if err != nil || len(g.Nodes) != 1 || !g.Nodes[0].Authored || !g.Nodes[0].Write || g.Nodes[0].ID != "PR_1" {
		t.Fatalf("%+v %v", g, err)
	}

	// A node read may resolve to a repo or to something in one, but not to
	// a team, which isn't in any repo, or a user, whose repository(name:)
	// looks one up.
	g, err = ClassifyGraphQL(gql(`{node(id:"X"){id}}`, nil), nil)
	if err != nil || len(g.Nodes) != 1 {
		t.Fatalf("%+v %v", g, err)
	}
	r := github.Repo{Owner: "acme", Name: "widgets"}
	reads := func(github.Repo) (bool, op.Set, bool) { return false, op.Defaults(), true }
	for typ, want := range map[string]bool{"Repository": true, "Issue": true, "Team": false, "User": false} {
		if err := CheckNode(g.Nodes[0], Node{Type: typ, Repo: r}, reads); (err == nil) != want {
			t.Errorf("node read of a %s: %v", typ, err)
		}
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
		{"approve in variables", gql(`mutation($i:AddPullRequestReviewInput!){addPullRequestReview(input:$i){clientMutationId}}`, map[string]any{"i": map[string]any{"pullRequestId": "X", "event": "APPROVE"}}), []op.Op{op.ReviewComment, op.ReviewVerdict}},
		{"request changes", gql(`mutation{addPullRequestReview(input:{pullRequestId:"X",event:REQUEST_CHANGES}){clientMutationId}}`, nil), []op.Op{op.ReviewComment, op.ReviewVerdict}},
		{"submit approve", gql(`mutation{submitPullRequestReview(input:{pullRequestReviewId:"X",event:APPROVE}){clientMutationId}}`, nil), []op.Op{op.ReviewComment, op.ReviewVerdict}},
		{"labels on create", gql(`mutation{createIssue(input:{repositoryId:"R",title:"t",labelIds:["L"]}){clientMutationId}}`, nil), []op.Op{op.IssueCreate, op.Labels}},
		{"assign on edit", gql(`mutation{updatePullRequest(input:{pullRequestId:"X",assigneeIds:["U"]}){clientMutationId}}`, nil), []op.Op{op.PREdit, op.Assign}},
		{"assign and label on edit", gql(`mutation{updateIssue(input:{id:"X",assigneeIds:["U"],labelIds:["L"]}){clientMutationId}}`, nil), []op.Op{op.IssueEdit, op.Assign, op.Labels}},
		{"auto-merge", gql(`mutation{enablePullRequestAutoMerge(input:{pullRequestId:"X",mergeMethod:SQUASH}){clientMutationId}}`, nil), []op.Op{op.PRMerge}},
		{"merge queue", gql(`mutation{enqueuePullRequest(input:{pullRequestId:"X"}){clientMutationId}}`, nil), []op.Op{op.PRMerge}},
		{"add labels", gql(`mutation{addLabelsToLabelable(input:{labelableId:"X",labelIds:["L"]}){clientMutationId}}`, nil), []op.Op{op.Labels}},
	}
	for _, c := range cases {
		g, err := ClassifyGraphQL(c.body, nil)
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

	// Assigning people needs assign, which is off by default, because
	// GitHub notifies each person assigned.
	g, err := ClassifyGraphQL(gql(`mutation{addAssigneesToAssignable(input:{assignableId:"X",assigneeIds:["U"]}){clientMutationId}}`, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	r0 := github.Repo{Owner: "acme", Name: "widgets"}
	defaults := func(github.Repo) (bool, op.Set, bool) { return true, op.Defaults(), true }
	if err := CheckNode(g.Nodes[0], Node{Type: "Issue", Repo: r0, Authored: true}, defaults); err == nil || !strings.Contains(err.Error(), "policy allow assign") {
		t.Errorf("assigning with the defaults: %v", err)
	}

	// CheckOps names the operation and how to allow it.
	r := r0
	err = CheckOps([]op.Op{op.Comment, op.PRMerge}, op.Defaults(), r)
	if err == nil || !strings.Contains(err.Error(), "policy allow pr.merge --repo acme/widgets") {
		t.Errorf("CheckOps = %v", err)
	}
	if err := CheckOps([]op.Op{op.Comment}, op.Defaults(), r); err != nil {
		t.Errorf("CheckOps refused a default: %v", err)
	}
}
