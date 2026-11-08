// Package op names the operations agents may do through the broker, so the
// config can turn each one on or off, for every repo or for one.
//
// Each name covers every way of doing the operation: a REST route, a
// GraphQL mutation, or a git push. Denying pr.merge refuses the merge
// endpoint and the mergePullRequest mutation alike.
//
// Hard denies, like secrets, settings, and workflow edits, have no name
// here, so no config can turn them on.
package op

import "slices"

// Op is one operation's config name.
type Op string

const (
	PRCreate         Op = "pr.create"
	PREdit           Op = "pr.edit"
	PRReviewers      Op = "pr.request-review"
	IssueCreate      Op = "issue.create"
	IssueEdit        Op = "issue.edit"
	Assign           Op = "assign"
	Comment          Op = "comment"
	ReviewComment    Op = "review.comment"
	PushDefault      Op = "push.default"
	ReviewApprove    Op = "review.approve"
	ReviewChanges    Op = "review.request-changes"
	PRMerge          Op = "pr.merge"
	PRAutoMerge      Op = "pr.automerge"
	Labels           Op = "labels"
	WorkflowRerun    Op = "workflow.rerun"
	WorkflowDispatch Op = "workflow.dispatch"
)

// Info describes an operation.
type Info struct {
	Op Op
	// On reports whether agents may do it when the config doesn't say.
	On bool
	// Does completes "agents may not ...", as in "agents may not merge PRs".
	Does string
	// Warn, when set, is what the user should know before allowing it.
	Warn string
}

// All lists every operation, the ones on by default first.
var All = []Info{
	{Op: PRCreate, On: true, Does: "open PRs"},
	{Op: PREdit, On: true, Does: "edit, close, reopen, or change the draft state of your PRs"},
	{Op: PRReviewers, On: true, Does: "request reviews on your PRs"},
	{Op: IssueEdit, On: true, Does: "edit, close, or reopen your issues"},
	{Op: Comment, On: true, Does: "comment on PRs and issues, or edit your comments"},
	{Op: ReviewComment, On: true, Does: "leave comment-only reviews and review comments"},

	{Op: IssueCreate, Does: "open issues",
		Warn: "Issues show as yours, and in a public repo anyone can read them."},
	{Op: Assign, Does: "assign people to your PRs and issues",
		Warn: "GitHub notifies each person assigned."},
	{Op: PushDefault, Does: "push the default branch",
		Warn: "Agents can also force-push it. hallpass can't tell a force push from a fast-forward, so turn on GitHub's branch protection if its history matters."},
	{Op: ReviewApprove, Does: "approve PRs",
		Warn: "An approval through hallpass counts as yours. GitHub doesn't let you approve your own PRs, so this approves other people's."},
	{Op: ReviewChanges, Does: "request changes in reviews",
		Warn: "A change request through hallpass counts as yours, and can block a PR until you dismiss it."},
	{Op: PRMerge, Does: "merge PRs or add them to the merge queue",
		Warn: "Agents can merge any PR GitHub lets you merge, including their own, with nobody reviewing it."},
	{Op: PRAutoMerge, Does: "turn auto-merge on or off",
		Warn: "With auto-merge on, a PR merges once its checks pass, with nobody reviewing it."},
	{Op: Labels, Does: "add or remove labels",
		Warn: "Some repos treat labels like automerge or safe-to-test as approvals."},
	{Op: WorkflowRerun, Does: "rerun workflow runs and jobs",
		Warn: "A rerun gets the same secrets the run had."},
	{Op: WorkflowDispatch, Does: "dispatch workflows",
		Warn: "Agents choose the ref and inputs. A dispatched workflow, often a deploy, runs that ref's code with the workflow's secrets."},
}

// Lookup finds an operation by name.
func Lookup(name string) (Info, bool) {
	i := slices.IndexFunc(All, func(i Info) bool { return string(i.Op) == name })
	if i < 0 {
		return Info{}, false
	}
	return All[i], true
}

// Set is the operations agents may do in one repo.
type Set map[Op]bool

// Defaults is the set when the config says nothing.
func Defaults() Set {
	s := Set{}
	for _, i := range All {
		if i.On {
			s[i.Op] = true
		}
	}
	return s
}

func (s Set) Has(o Op) bool { return s[o] }
