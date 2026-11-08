# gh PR commands and GraphQL

`gh pr` and `gh issue` mostly use GraphQL. The broker parses each document
against GitHub's schema, refuses mutations it doesn't allow, resolves node
IDs to repos, and filters text that bots would treat as a command.

## Sub-features

- `gql-comment` posts a PR comment.
- `gql-merge` refuses `gh pr merge`.
- `gql-approve` refuses `gh pr review --approve`.
- `gql-chatops` refuses a comment with a bot command line like `/merge`.

## Driving it with gh

Preconditions: `cd /tmp`.

- **Comment.** `gh pr comment 1 -R acme/widgets -b "looks fine"` exits 0 and
  prints `https://github.com/acme/widgets/pull/1#issuecomment-1`. The fake
  log has a `POST /api/graphql` whose body contains `addComment` and `looks fine`.
- **Merge.** `gh pr merge 1 -R acme/widgets --squash` exits 1 with
  `GraphQL: hallpass: agents may not merge PRs, add them to the merge queue, or turn auto-merge on or off in acme/widgets. To allow it: sudo /opt/hallpass/bin/hallpass policy allow pr.merge --repo acme/widgets`.
  No fake log entry contains `mergePullRequest`.
- **Approve.** `gh pr review 1 -R acme/widgets --approve` exits 1 with
  `hallpass: agents may not approve PRs or request changes in acme/widgets. To allow it: sudo /opt/hallpass/bin/hallpass policy allow review.verdict --repo acme/widgets`.
  No fake log body contains `APPROVE`.
- **Allowlist.** `gh pr comment 1 -R acme/secret -b hi` exits 1 with
  `GraphQL: hallpass: acme/secret isn't in hallpass's allowlist`. No fake log
  entry names `acme/secret`. (Feature ID `gql-allowlist`.)
- **ChatOps.** `gh pr comment 1 -R acme/widgets -b "/merge"` exits 1 with
  `hallpass: hallpass doesn't post text with the line "/merge", because bots act on lines like it as your command. Rephrase it`.
  No fake log body contains `/merge`.

## Gotchas

- Each `gh pr` command first runs a `PullRequestByNumber` query, which the
  broker allows, so the fake log always has reads before the refused
  mutation. Look for the mutation's name, not for an empty log.
- The fake's GraphQL answers are canned for gh 2.98.0. When a gh upgrade
  changes a query, the fake falls back to `{"data":{}}` and gh fails with a
  parse or "not found" error that isn't from hallpass. Extend
  `scripts/fakegithub/main.go` instead of reading that as a broker failure.
  `internal/policy/testdata/gh-<version>-capture.jsonl` (from `make corpus`)
  has the new gh's exact queries, tagged by command, to copy from.
