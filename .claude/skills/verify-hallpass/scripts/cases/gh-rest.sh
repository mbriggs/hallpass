# gh REST cases. See features/gh-rest.md.
feature_rest() {
  case_ rest-read
  check 0 acme/widgets 'gh api repos/acme/widgets --jq .full_name'
  fake_has '"path":"/api/repos/acme/widgets","auth":"token-ok"'

  case_ rest-allowlist
  check fail "acme/secret isn't in hallpass's allowlist" 'gh api repos/acme/secret'
  fake_lacks acme/secret

  case_ rest-readonly
  check fail 'agents may only read acme/readonly' 'gh api -X POST repos/acme/readonly/issues -f title=x'
  fake_lacks '"method":"POST"'

  case_ rest-op
  check fail 'agents may not merge PRs' 'gh api -X PUT repos/acme/widgets/pulls/1/merge'
  fake_lacks '"method":"PUT"'
  check fail 'agents may not open issues in acme/widgets' 'gh api -X POST repos/acme/widgets/issues -f title=x'
  fake_lacks '"method":"POST"'

  case_ rest-route
  check fail 'hallpass never allows reading repos/{repo}/actions/secrets' 'gh api repos/acme/widgets/actions/secrets'
  fake_lacks actions/secrets

  case_ rest-read-off
  check fail 'policy allow read:actions/variables --repo acme/widgets' 'gh api repos/acme/widgets/actions/variables'
  fake_lacks actions/

  case_ rest-author-colleague
  check fail 'agents may only change PRs, issues, and comments you wrote' 'gh api -X PATCH repos/acme/widgets/issues/2 -f title=x'
  fake_has '"method":"GET","path":"/api/repos/acme/widgets/issues/2"'
  fake_lacks '"method":"PATCH"'

  case_ rest-author-own
  check 0 '"id":101' 'gh api -X PATCH repos/acme/widgets/issues/1 -f title=x'
  fake_has '"method":"PATCH","path":"/api/repos/acme/widgets/issues/1"'

  case_ rest-short-sha
  check fail 'hallpass needs the full SHA, not "abc1234"' 'gh api repos/acme/widgets/commits/abc1234'
  fake_lacks commits/

  case_ rest-token
  check 0 hallpass-brokered "grep oauth_token \"$S/gh/hosts.yml\""
  check fail '' "grep oauth_token \"$S/gh/hosts.yml\" | grep -v hallpass-brokered"
}
