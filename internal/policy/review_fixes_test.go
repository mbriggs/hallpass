package policy

import "testing"

// Cases from the interrogate review.
func TestReviewFindings(t *testing.T) {
	refusedREST := []struct{ method, target, body string }{
		{"GET", "/repos/acme/widgets/secret-scanning/alerts", ``},
		{"GET", "/repos/acme/widgets/actions/organization-variables", ``},
		{"GET", "/repos/acme/widgets/actions/organization-secrets", ``},
		{"GET", "/repos/acme/widgets/HOOKS", ``},
		{"GET", "/repos/acme/widgets/Actions/Variables", ``},
		{"GET", "/repos/acme/widgets/environments/x/Secrets", ``},
		{"GET", "/repos/acme/widgets/collaborators", ``},
		{"GET", "/repos/acme/widgets/", ``},
		{"GET", `/search/issues?q=label%3A%22x+repo%3Aacme%2Fwidgets+y%22`, ``},
		{"POST", "/repos/acme/widgets/pulls/3/reviews", `{"event":"COMMENT","comments":[{"path":"a","line":1,"body":"/merge"}]}`},
		{"POST", "/repos/acme/widgets/issues/3/comments", `{"body":"fine\r/merge"}`},
	}
	for _, c := range refusedREST {
		if r, err := ClassifyREST(c.method, c.target, []byte(c.body), nil); withToken(r, err) {
			t.Errorf("%s %s %s: allowed (%+v)", c.method, c.target, c.body, r)
		}
	}
	allowedREST := []string{
		"/repos/acme/widgets", "/repos/acme/widgets/pulls/3/files", "/repos/acme/widgets/contents/src/main.go?ref=x",
		"/repos/acme/widgets/branches/feature/x", "/repos/acme/widgets/commits/abc/check-runs",
		"/repos/acme/widgets/actions/workflows/ci.yml/runs", "/repos/acme/widgets/git/trees/main?recursive=1",
	}
	for _, target := range allowedREST {
		if _, err := ClassifyREST("GET", target, nil, nil); err != nil {
			t.Errorf("GET %s: %v", target, err)
		}
	}
	if r, _ := ClassifyREST("GET", "/repos/acme/widgets", nil, nil); len(r.Strip) == 0 {
		t.Error("repo response keeps temp_clone_token")
	}

	refusedGQL := map[string][]byte{
		"temp clone token": gql(`{repository(owner:"acme",name:"widgets"){tempCloneToken}}`, nil),
		"quoted search":    gql(`query($q:String!){search(query:$q,type:ISSUE,first:5){issueCount}}`, map[string]any{"q": `label:"x repo:acme/widgets y"`}),
		"thread body":      gql(`mutation($i:AddPullRequestReviewInput!){addPullRequestReview(input:$i){clientMutationId}}`, map[string]any{"i": map[string]any{"pullRequestId": "X", "event": "COMMENT", "threads": []any{map[string]any{"path": "a", "line": 1, "body": "/merge"}}}}),
		"fork head":        gql(`mutation{createPullRequest(input:{repositoryId:"R",baseRefName:"main",headRefName:"evil:x",title:"t"}){clientMutationId}}`, nil),
		"pr's upstream":    gql(`{repository(owner:"acme",name:"widgets"){ref(qualifiedName:"x"){associatedPullRequests(first:1){nodes{body}}}}}`, nil),
	}
	for name, body := range refusedGQL {
		if g, err := ClassifyGraphQL(body, nil); err == nil {
			t.Errorf("%s: allowed (%+v)", name, g)
		}
	}
}
