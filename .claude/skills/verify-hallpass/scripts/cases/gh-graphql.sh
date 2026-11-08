# gh PR commands and GraphQL cases. See features/gh-graphql.md.
feature_graphql() {
  case_ gql-comment
  check 0 'https://github.com/acme/widgets/pull/1#issuecomment-1' 'gh pr comment 1 -R acme/widgets -b "looks fine"'
  fake_has addComment
  fake_has 'looks fine'
  fake_has 'followRenames: false'

  case_ gql-merge
  check fail 'GraphQL: hallpass: agents may not merge PRs' 'gh pr merge 1 -R acme/widgets --squash'
  fake_lacks mergePullRequest

  case_ gql-approve
  check fail 'agents may not approve PRs or request changes in acme/widgets' 'gh pr review 1 -R acme/widgets --approve'
  fake_lacks APPROVE

  case_ gql-allowlist
  check fail "acme/secret isn't in hallpass's allowlist" 'gh pr comment 1 -R acme/secret -b hi'
  fake_lacks acme/secret

  # gh pr can't reach PR 2, because the fake answers every
  # PullRequestByNumber with PR 1, so name the node directly.
  case_ gql-author
  check fail 'agents may only change PRs, issues, and comments you wrote' "gh api graphql -f query='mutation{closePullRequest(input:{pullRequestId:\"PR_2\"}){clientMutationId}}'"
  fake_has 'nodes(ids'
  fake_lacks closePullRequest

  case_ gql-chatops
  check fail "hallpass doesn't post text with the line \"/merge\"" 'gh pr comment 1 -R acme/widgets -b "/merge"'
  fake_lacks '/merge'
}
