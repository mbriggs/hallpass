# gh PR commands and GraphQL

`gh pr` and `gh issue` mostly use GraphQL. The broker parses each document
against GitHub's schema, refuses mutations it doesn't allow, resolves node
IDs to repos, and filters text that bots would treat as a command.

## Sub-features

- `gql-comment` posts a PR comment.
- `gql-merge` refuses `gh pr merge`.
- `gql-approve` refuses `gh pr review --approve`.
- `gql-allowlist` refuses a repo outside the allowlist.
- `gql-author` refuses a mutation on a colleague's PR.
- `gql-chatops` refuses a comment with a bot command line like `/merge`.
- `gql-renames` adds `followRenames: false` to every `repository(...)` the
  broker forwards, so an old name can't reach a renamed repo.

## Driving it

`scripts/drive.sh "$S" graphql` runs these cases from
`scripts/cases/gh-graphql.sh`:

- `gql-comment`: `gh pr comment` posts, the fake sees `addComment`, and
  the `PullRequestByNumber` query before it has `followRenames: false`.
- `gql-merge`: `gh pr merge` is refused with `GraphQL: hallpass: agents may
  not merge PRs`, and no `mergePullRequest` reaches the fake.
- `gql-approve`: `gh pr review --approve` is refused with `agents may not
  approve PRs or request changes`.
- `gql-allowlist`: a comment on `acme/secret` is refused, and the fake never
  sees `acme/secret`.
- `gql-author`: closing colleague's PR 2 by node ID is refused with
  `agents may only change PRs, issues, and comments you wrote`. The fake
  sees the broker's `nodes(ids` lookup and no `closePullRequest`. It names
  the node directly, because the fake answers every `PullRequestByNumber`
  with PR 1.
- `gql-chatops`: a `/merge` comment is refused with `hallpass doesn't post
  text with the line "/merge"`.

## Gotchas

- Each `gh pr` command first runs a `PullRequestByNumber` query, which the
  broker allows, and the broker sends its own `nodes(ids` query to resolve
  the PR's repo and author before a mutation. So the fake log always has
  reads before the refused mutation. Look for the mutation's name, not for
  an empty log.
- The fake's `nodes` answer puts every ID in `acme/widgets`. So a GraphQL
  write to `acme/readonly` would be allowed here, unlike on GitHub. Extend
  the fake before adding a read-only GraphQL journey.
- The fake's GraphQL answers are canned for gh 2.98.0. When a gh upgrade
  changes a query, the fake falls back to `{"data":{}}` and gh fails with a
  parse or "not found" error that isn't from hallpass. Extend
  `scripts/fakegithub/main.go` instead of reading that as a broker failure.
  `make GH=<new gh> corpus` writes
  `internal/policy/testdata/gh-<version>-capture.jsonl` with the new gh's
  exact queries, each tagged with its command, to copy from. It overwrites
  that file, so don't rerun it on a version whose file also has
  `gh-matrix-corpus.py` lines.
