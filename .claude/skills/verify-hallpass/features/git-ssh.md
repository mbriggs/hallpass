# git over SSH

git reaches github.com through `hallpass ssh`, which hands the git command
to the broker's SSH socket. The broker checks the repo against the
allowlist, asks GitHub for the repo's current name, checks each pushed ref
against its rules, reads every pushed pack for workflow changes, and runs
the command on GitHub with its own key. Agents can push branches they
create. They can't push the default branch, protected branches,
colleagues' branches, tags, or commits that change `.github/workflows`.

## Sub-features

- `git-clone` clones with `git@github.com:`, `https://github.com/`, and
  `ssh://git@github.com/` URLs.
- `git-push-new` pushes a new agent branch, and the broker records it in its ledger.
- `git-push-own` force-pushes and deletes a branch the agent created.
- `git-push-default` refuses pushes to `main`.
- `git-push-protected` refuses pushes to `release/*`.
- `git-push-colleague` refuses updating or deleting `colleague`.
- `git-push-tag` refuses tag pushes.
- `git-push-workflow` refuses a push whose commits change `.github/workflows`.
- `git-allowlist` refuses `ls-remote` on `acme/secret`.
- `git-readonly` fetches `acme/readonly` and refuses pushes to it.
- `git-renamed` refuses a repo's old name after a rename or transfer.
- `git-push-default-allowed` pushes `main` once `push.default` is on.

## Driving it with git

Preconditions: `cd /tmp`, and the fake's refs recorded with
`GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -C "$S/gh-root/acme/widgets.git" for-each-ref > "$S/evidence/refs-before.txt"`.

- **Clone.** `git clone -q git@github.com:acme/widgets.git "$S/work" && cd "$S/work"`
  exits 0. `git clone -q https://github.com/acme/widgets "$S/work2"` and
  `git clone -q ssh://git@github.com/acme/widgets "$S/work3"` also exit 0.
  The fake log has a `GET /api/repos/acme/widgets` with `token-ok` (the
  current-name check) and a line with `"method":"SSH"`,
  `"path":"git-upload-pack 'acme/widgets.git'"`, and `"auth":"key-ok"`.
- **Commit.** `echo change >> README && git commit -qam "agent work"`.
- **New branch.** `git push origin HEAD:agent/fix` exits 0 and prints
  `* [new branch]      HEAD -> agent/fix`. The fake log has
  `git-receive-pack 'acme/widgets.git'`, and the fake's refs gain
  `refs/heads/agent/fix`. `broker.log` has `msg=pushed ... refs=[refs/heads/agent/fix]`.
- **Own branch.** `git commit -q --amend -m "agent work, amended" && git push --force origin HEAD:agent/fix`
  exits 0 and prints `(forced update)`.
- **Refusals.** Each exits 1 with `! [remote rejected]` and
  `(hallpass: <reason>)`:
  - `git push origin HEAD:main`: `main is the default branch; push another branch and open a PR. agents may not push the default branch in acme/widgets. To allow it: sudo /opt/hallpass/bin/hallpass policy allow push.default --repo acme/widgets`
  - `git push origin HEAD:release/1`: `release/1 is protected in hallpass's config`
  - `git push --force origin HEAD:colleague`: `agents can only update branches they created. To let agents update it as it is: sudo /opt/hallpass/bin/hallpass ledger add acme/widgets colleague <sha>`
  - `git push origin :colleague`: `agents can only delete branches they created. To let agents delete it as it is: sudo /opt/hallpass/bin/hallpass ledger add acme/widgets colleague <sha>`
  - `git push origin HEAD:refs/tags/v1`: `agents can't push tags`
- **Workflow.** `printf 'on: push\njobs: {x: {}}\n' > .github/workflows/ci.yml && git commit -qam wf && git push origin HEAD:agent/fix`
  exits 1 with `hallpass: agents can't change .github/workflows. Push that change yourself with git personal push`.
  Then `git reset -q --hard HEAD~1`.
- **Allowlist.** `git ls-remote https://github.com/acme/secret` exits 128
  with `hallpass: acme/secret isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow acme/secret`.
  No fake log line names `acme/secret`.
- **Read-only.** `git ls-remote git@github.com:acme/readonly` lists `main`
  and `colleague`. `git push git@github.com:acme/readonly HEAD:agent/ro`
  exits 128 with `hallpass: agents may only read acme/readonly`, and the
  fake log has no `git-receive-pack 'acme/readonly.git'`.
- **Renamed.** `git ls-remote git@github.com:acme/gadgets` exits 128 with
  `hallpass: acme/gadgets is now acme/widgets on GitHub. Use the new name, which hallpass checks against its allowlist`.
  The fake log has `GET /api/repos/acme/gadgets` and then
  `GET /api/repositories/1`, which is the broker following the redirect,
  and no SSH line for it.
- **Delete own.** `git push origin :agent/fix` exits 0 and prints `- [deleted]         agent/fix`.
- **Proof.** Diff the fake's refs against `refs-before.txt`: nothing changed.
  `main` and `colleague` didn't move, and there's no `release/1`, no
  `refs/tags/v1`, and no `agent/fix` left. Each refused push still logs
  `git-receive-pack` in the fake, because the broker opens the session to
  read GitHub's refs before it checks. The refs don't move.

## push.default

To check `push.default`, stop the broker (its pid is in `$S/broker.pid`;
check that `ps -ww -o command= -p PID` names `$S` first), add
`allow = ["push.default"]` on the line after `match = "acme/widgets"` in
`$S/hallpass.toml`, and start it again with the `nohup` line from `up.sh`,
appending (`>>`) to `broker.log`. `hallpass status` then shows
`acme/widgets (+push.default)`. From `$S/work`,
`echo d >> README && git commit -qam "default push" && git push origin HEAD:main`
exits 0, and the fake's `main` moves to your `HEAD`. `git push origin :main`
still exits 1 with `hallpass: agents can't delete the default branch`.
Run this last: it leaves the fake's `main` moved.

## Gotchas

- Match the fake log with `jq`, not a literal grep. Each line is JSON, such
  as `{"method":"SSH","path":"git-upload-pack 'acme/widgets.git'","auth":"key-ok",...}`.
  A push also logs one or two extra `git-upload-pack` lines: the broker
  reads the default branch, and the workflow check fetches trees.
- The current-name check hits `GET /api/repos/OWNER/REPO` at most once per
  10 minutes per repo, so later git commands don't repeat it.
- The ledger file is fixed at `branches.jsonl` in the state dir
  (`/var/lib/hallpass` on Linux, `/var/db/hallpass` on macOS), which the
  scratch broker can't write. The broker records each push in memory and
  logs `msg="ledger write failed; after a restart agents can't update this branch"`
  at `level=ERROR` with `err="open <state dir>/branches.jsonl: permission denied"`.
  Own-branch updates work until the broker restarts, and doctor's
  `level=ERROR` check fails from then on. The push.default restart loses
  the record of `agent/fix`, so run push.default after the main journey.
- An agent may update a branch only from the tip it last pushed. If
  anything else moves the branch, the push is refused with
  `<branch> has changed since an agent last pushed it`. The fix it names,
  `sudo hallpass ledger add`, needs root and writes the live ledger, so
  don't run it against the scratch broker.
- Without `GIT_CONFIG_NOSYSTEM=1`, the system config's include of
  `/etc/hallpass/gitconfig` wins and git goes to the live broker. `$S/env`
  sets it. If the URLs look wrong, check
  `git config --show-origin --get-regexp '^(url\..*\.insteadof|core\.sshcommand)$'`.
- The fake's repos set `uploadpack.allowFilter` and
  `uploadpack.allowAnySHA1InWant`, as GitHub does. The workflow check
  fetches trees blobless, and fails without them.
- The agent permission check may block the push batch, because it can't
  tell the fake from real GitHub when it sees `git push --force` and pushes
  to `main`. Ask the user to approve these commands, and say they go to the
  fake under `$S`. `TestGitOverSSHThroughBroker` in
  `cmd/hallpass/ssh_test.go` drives the same journey in `go test`.
