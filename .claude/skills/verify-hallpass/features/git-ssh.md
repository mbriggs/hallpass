# git over SSH

git reaches github.com through `hallpass ssh`, which hands the git command
to the broker's SSH socket. The broker checks the repo against the
allowlist and each pushed ref against its rules, reads every pushed pack
for workflow changes, and runs the command on GitHub with its own key.
Agents can push branches they create. They can't push the default branch,
protected branches, colleagues' branches, tags, or commits that change
`.github/workflows`.

## Sub-features

- `git-clone` clones in every URL form.
- `git-push-new` pushes a new agent branch, and the broker records it in its ledger.
- `git-push-own` force-pushes and deletes a branch the agent created.
- `git-push-default` refuses pushes to `main`.
- `git-push-protected` refuses pushes to `release/*`.
- `git-push-colleague` refuses updating or deleting `colleague`.
- `git-push-tag` refuses tag pushes.
- `git-push-workflow` refuses a push whose commits change `.github/workflows`.
- `git-allowlist` refuses `ls-remote` on `acme/secret`.

## Driving it with git

Preconditions: refs recorded with
`GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -C "$S/gh-root/acme/widgets.git" for-each-ref > "$S/evidence/refs-before.txt"`.

- **Clone.** `git clone -q git@github.com:acme/widgets.git "$S/work" && cd "$S/work"`
  exits 0. The fake log has `SSH git-upload-pack 'acme/widgets.git'` with `key-ok`.
- **Commit.** `echo change >> README && git commit -qam "agent work"`.
- **New branch.** `git push origin HEAD:agent/fix` exits 0. The fake log has
  `SSH git-receive-pack 'acme/widgets.git'`, and the fake's refs gain
  `refs/heads/agent/fix`.
- **Own branch.** `git commit -q --amend -m "agent work, amended" && git push --force origin HEAD:agent/fix`
  exits 0.
- **Refusals.** Each exits non-zero with `hallpass: ` and this reason:
  `git push origin HEAD:main` gives `main is the default branch`,
  `git push origin HEAD:release/1` gives `release/1 is protected`,
  `git push --force origin HEAD:colleague` gives `agents can only update branches they created`,
  `git push origin :colleague` gives `agents can only delete branches they created`,
  `git push origin HEAD:refs/tags/v1` gives `agents can't push tags`.
- **Workflow.** `printf 'on: push\njobs: {x: {}}\n' > .github/workflows/ci.yml && git commit -qam wf && git push origin HEAD:agent/fix`
  exits non-zero with `agents can't change .github/workflows`. Then
  `git reset -q --hard HEAD~1`.
- **Allowlist.** `git ls-remote https://github.com/acme/secret` fails with
  `isn't in hallpass's allowlist`.
- **Delete own.** `git push origin :agent/fix` exits 0.
- **Proof.** Diff the fake's refs against `refs-before.txt`. `main` and
  `colleague` are unchanged, and there's no `release/1`, no `refs/tags/v1`,
  and no `agent/fix` left. A refused push still logs
  `SSH git-receive-pack` in the fake, since the broker opens the session to
  read GitHub's refs, but the refs don't move.

## push.default

To check `push.default`, stop the broker (its pid is in `$S/broker.pid`;
check that `/proc/PID/cmdline` names `$S` first), add
`allow = ["push.default"]` under the `acme/widgets` entry in
`$S/hallpass.toml`, and start it again with the `nohup` line from `up.sh`.
Then `git push origin HEAD:main` exits 0 and the fake's `main` moves, and
`git push origin :main` gives `agents can't delete the default branch`.

## Gotchas

- Not yet run end to end from this skill. The agent permission check
  blocks the push batch, because it can't tell the fake from real GitHub
  when it sees `git push --force` and pushes to `main`. Ask the user to
  approve these commands, and say they go to the fake under `$S`.
  `TestGitOverSSHThroughBroker` in `cmd/hallpass/ssh_test.go` drives the
  same journey against an SSH fake in `go test`.
- The ledger file is fixed at `/var/lib/hallpass/branches.jsonl`, which the
  scratch broker can't write. The broker records each push in memory and
  logs `msg="ledger write failed; after a restart agents can't update this branch"`
  at `level=ERROR`. Own-branch updates work until the broker restarts, and
  doctor's `level=ERROR` check fails from then on.
- Without `GIT_CONFIG_NOSYSTEM=1`, the system config's include of
  `/etc/hallpass/gitconfig` wins and git goes to the live broker. `$S/env`
  sets it. If the URLs look wrong, check
  `git config --show-origin --get-regexp '^(url\..*\.insteadof|core\.sshcommand)$'`.
- The fake's repo sets `uploadpack.allowFilter` and
  `uploadpack.allowAnySHA1InWant`, as GitHub does. The workflow check
  fetches trees blobless, and fails without them.
