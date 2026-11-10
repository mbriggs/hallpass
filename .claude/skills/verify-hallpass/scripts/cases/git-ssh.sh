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

  case_ git-push-after-restart
  # The ledger in $S/state is what lets the agent update agent/fix after
  # the broker restarts.
  if grep -qF '"branch":"agent/fix"' "$S/state/branches.jsonl" 2>/dev/null; then ok "\$S/state/branches.jsonl records agent/fix"; else fail "\$S/state/branches.jsonl doesn't record agent/fix"; fi
  restart_broker || return
  check 0 '(forced update)' 'git commit -q --amend -m "agent work, after a restart" && git push --force origin HEAD:agent/fix'

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

  case_ git-push-protected-path
  # protected_paths has scripts/deploy.sh for every repo and .github/actions
  # on acme/widgets. Neither exists on the fake, so adding one is a change.
  check fail "agents can't change scripts/deploy.sh, which protected_paths in hallpass's config names" "mkdir -p scripts && echo evil > scripts/deploy.sh && git add scripts && git commit -qm deploy && git push origin HEAD:agent/fix"
  check 0 '' 'git reset -q --hard HEAD~1'
  check fail "agents can't change .github/actions" "mkdir -p .github/actions/x && echo 'runs: {using: composite}' > .github/actions/x/action.yml && git add .github && git commit -qm action && git push origin HEAD:agent/fix"
  check 0 '' 'git reset -q --hard HEAD~1'
  check 0 'HEAD -> agent/fix' "mkdir -p scripts && echo lint > scripts/lint.sh && git add scripts && git commit -qm lint && git push origin HEAD:agent/fix"

  case_ git-allowlist
  # A repo outside the allowlist goes to GitHub's smart HTTP with no
  # credential. The fake answers acme/secret, which it doesn't have, as
  # GitHub does: a 401.
  check fail "hallpass: Without a token, GitHub answered 401 Unauthorized. acme/secret isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow acme/secret" 'git ls-remote https://github.com/acme/secret'
  fake_has '"method":"GET","path":"/acme/secret.git/info/refs","query":"service=git-upload-pack","auth":"none","status":401'
  fake_lacks "acme/secret.git'"
  broker_has 'repo=acme/secret op=upload-pack anonymous=true reason="Without a token'

  case_ git-anonymous-private
  # acme/private is private: the fake's SSH would serve it to the broker's
  # key, and its HTTP refuses it without one. Nothing of it reaches git.
  check fail 'Without a token, GitHub answered 401 Unauthorized. acme/private' "git clone -q https://github.com/acme/private \"$S/private\""
  if [ -e "$S/private/README" ]; then fail "the private repo's README reached the clone"; else ok "no private README in the clone"; fi
  fake_lacks "git-upload-pack 'acme/private.git'"
  fake_lacks '"path":"/acme/private.git/git-upload-pack"'

  case_ git-anonymous-clone
  rm -rf "$S/public" "$S/public-shallow" "$S/public-partial"
  check 0 '' "git clone -q https://github.com/octo/public \"$S/public\""
  check 0 public "cat \"$S/public/README\""
  fake_has '"method":"GET","path":"/octo/public.git/info/refs","query":"service=git-upload-pack","auth":"none","status":200'
  fake_has '"method":"POST","path":"/octo/public.git/git-upload-pack","auth":"none","status":200'
  fake_lacks "octo/public.git'"
  fake_lacks '"auth":"wrong"'
  broker_has 'repo=octo/public op=upload-pack anonymous=true exit=0'
  check 0 '' "git -C \"$S/public\" fetch -q"
  check 0 '' "git clone -q --depth 1 https://github.com/octo/public \"$S/public-shallow\""
  check 0 1 "git -C \"$S/public-shallow\" rev-list --count HEAD"
  check 0 '' "git clone -q --filter=blob:none https://github.com/octo/public \"$S/public-partial\""
  check 0 two "cat \"$S/public-partial/second\""

  case_ git-anonymous-push
  check fail "octo/public isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow octo/public" "git -C \"$S/public\" push origin HEAD:agent/x"
  fake_lacks receive-pack

  case_ git-anonymous-renamed
  check 0 refs/heads/main 'git ls-remote https://github.com/octo/old'
  fake_has '"path":"/octo/old.git/info/refs"'
  fake_has '"path":"/octo/public.git/git-upload-pack"'
  broker_has 'repo=octo/old op=upload-pack anonymous=true now=octo/public exit=0'

  case_ git-anonymous-other-host
  check fail "GitHub redirected somewhere hallpass doesn't follow. octo/away isn't in hallpass's allowlist" 'git ls-remote https://github.com/octo/away'
  fake_lacks away-target

  case_ git-anonymous-throttled
  check fail "GitHub is limiting git without a token from this machine's address (429 Too Many Requests); try again later." 'git ls-remote https://github.com/octo/busy'

  case_ git-anonymous-v0
  check fail 'only over git protocol v2' 'git -c protocol.version=0 ls-remote https://github.com/octo/public'
  fake_lacks /octo/public.git/

  case_ git-anonymous-denied
  cp "$S/hallpass.toml" "$S/hallpass.toml.orig"
  { echo 'deny = ["anonymous"]'; cat "$S/hallpass.toml.orig"; } > "$S/hallpass.toml"
  restart_broker || return
  check fail "hallpass: octo/public isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow octo/public" 'git ls-remote https://github.com/octo/public'
  fake_lacks /octo/public.git/
  check 0 refs/heads/main 'git ls-remote https://github.com/acme/widgets'
  fake_has "git-upload-pack 'acme/widgets.git'\",\"auth\":\"key-ok\""
  mv "$S/hallpass.toml.orig" "$S/hallpass.toml"
  restart_broker || return

  case_ git-readonly
  check 0 refs/heads/colleague 'git ls-remote git@github.com:acme/readonly'
  check fail 'agents may only read acme/readonly' 'git push git@github.com:acme/readonly HEAD:agent/ro'
  fake_lacks "git-receive-pack 'acme/readonly.git'"

  case_ git-renamed
  check fail "acme/gizmos is now acme/private on GitHub, and hallpass checks both names: acme/private isn't in hallpass's allowlist" 'git ls-remote git@github.com:acme/gizmos'
  fake_has '"path":"/api/repos/acme/gizmos"'
  fake_has '"path":"/api/repositories/3"'
  fake_lacks "acme/gizmos.git"
  fake_lacks "acme/private.git"

  case_ git-renamed-allowed
  check 0 refs/heads/main 'git ls-remote git@github.com:acme/gadgets'
  fake_has '"path":"/api/repos/acme/gadgets"'
  fake_has "git-upload-pack 'acme/widgets.git'"
  fake_lacks "acme/gadgets.git"

  case_ git-push-github-rejects-some
  # An update hook on the fake stands in for a GitHub ruleset: it declines
  # agent/declined. The broker logs both sets, and the ledger takes only
  # the ref GitHub accepted.
  local hook="$S/gh-root/acme/widgets.git/hooks/update"
  printf '#!/bin/sh\ntest "$1" != refs/heads/agent/declined\n' > "$hook" && chmod +x "$hook"
  check fail 'hook declined' 'git push origin HEAD:agent/taken HEAD:agent/declined'
  broker_has 'level=WARN msg=pushed'
  broker_has 'refs=[refs/heads/agent/taken] rejected="[{\"ref\":\"refs/heads/agent/declined\",\"reason\":\"hook declined\"}]"'
  broker_lacks 'msg=refused'
  if grep -qF '"branch":"agent/taken"' "$S/state/branches.jsonl" && ! grep -qF '"branch":"agent/declined"' "$S/state/branches.jsonl"; then
    ok "the ledger records agent/taken and not agent/declined"
  else fail "the ledger after a partly rejected push:"; sed 's/^/  /' "$S/state/branches.jsonl"; fi

  case_ git-push-github-rejects-all
  check fail 'hook declined' 'git push origin HEAD:agent/declined'
  broker_has 'level=WARN msg=rejected'
  broker_has 'refs=[] rejected="[{\"ref\":\"refs/heads/agent/declined\",\"reason\":\"hook declined\"}]"'
  broker_lacks 'msg=refused'
  if grep -qF '"branch":"agent/declined"' "$S/state/branches.jsonl"; then fail "the ledger records agent/declined"; else ok "the ledger doesn't record agent/declined"; fi
  rm -f "$hook"
  check 0 '[deleted]         agent/taken' 'git push origin :agent/taken'

  case_ git-delete-own
  check 0 '[deleted]         agent/fix' 'git push origin :agent/fix'

  case_ git-refs-unchanged
  if [ "$(refs)" = "$before" ]; then ok "the fake's refs match the start: main and colleague unchanged, no release/1, v1, or agent/fix"
  else fail "the fake's refs changed:"; diff <(echo "$before") <(refs) | sed 's/^/  /'; fi
}
