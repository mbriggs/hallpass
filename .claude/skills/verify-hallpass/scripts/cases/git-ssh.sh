# git over SSH cases, as one journey. See features/git-ssh.md. Pushes go
# to the fake's bare repo under $S, never to github.com.
feature_ssh() {
  local before; before=$(refs)
  rm -rf "$S/work" "$S/work2" "$S/work3"

  case_ git-clone
  check 0 '' "git clone -q git@github.com:acme/widgets.git \"$S/work\""
  # The broker asks GitHub for the repo's current name before running git.
  fake_has '"path":"/api/repos/acme/widgets","auth":"token-ok"'
  fake_has "\"method\":\"SSH\",\"path\":\"git-upload-pack 'acme/widgets.git'\",\"auth\":\"key-ok\""
  check 0 '' "git clone -q https://github.com/acme/widgets \"$S/work2\""
  check 0 '' "git clone -q ssh://git@github.com/acme/widgets \"$S/work3\""
  cd "$S/work" || { fail "no clone"; return; }
  check 0 '' 'echo change >> README && git commit -qam "agent work"'

  case_ git-push-new
  check 0 '[new branch]      HEAD -> agent/fix' 'git push origin HEAD:agent/fix'
  fake_has "git-receive-pack 'acme/widgets.git'"
  broker_has 'refs=[refs/heads/agent/fix]'
  if refs | grep -q 'refs/heads/agent/fix '; then ok "the fake has agent/fix"; else fail "the fake lacks agent/fix"; fi

  case_ git-push-own
  check 0 '(forced update)' 'git commit -q --amend -m "agent work, amended" && git push --force origin HEAD:agent/fix'

  case_ git-push-default
  check fail 'main is the default branch' 'git push origin HEAD:main'
  case_ git-push-protected
  check fail 'release/1 is protected' 'git push origin HEAD:release/1'
  case_ git-push-colleague
  check fail 'agents can only update branches they created' 'git push --force origin HEAD:colleague'
  check fail 'agents can only delete branches they created' 'git push origin :colleague'
  case_ git-push-tag
  check fail "agents can't push tags" 'git push origin HEAD:refs/tags/v1'

  case_ git-push-workflow
  check fail "agents can't change .github/workflows" "printf 'on: push\njobs: {x: {}}\n' > .github/workflows/ci.yml && git commit -qam wf && git push origin HEAD:agent/fix"
  check 0 '' 'git reset -q --hard HEAD~1'

  case_ git-allowlist
  check fail "isn't in hallpass's allowlist" 'git ls-remote https://github.com/acme/secret'
  fake_lacks acme/secret

  case_ git-readonly
  check 0 refs/heads/colleague 'git ls-remote git@github.com:acme/readonly'
  check fail 'agents may only read acme/readonly' 'git push git@github.com:acme/readonly HEAD:agent/ro'
  fake_lacks "git-receive-pack 'acme/readonly.git'"

  case_ git-renamed
  check fail 'acme/gadgets is now acme/widgets on GitHub' 'git ls-remote git@github.com:acme/gadgets'
  fake_has '"path":"/api/repos/acme/gadgets"'
  fake_has '"path":"/api/repositories/1"'
  fake_lacks "acme/gadgets.git"

  case_ git-delete-own
  check 0 '[deleted]         agent/fix' 'git push origin :agent/fix'

  case_ git-refs-unchanged
  if [ "$(refs)" = "$before" ]; then ok "the fake's refs match the start: main and colleague unchanged, no release/1, v1, or agent/fix"
  else fail "the fake's refs changed:"; diff <(echo "$before") <(refs) | sed 's/^/  /'; fi
}
