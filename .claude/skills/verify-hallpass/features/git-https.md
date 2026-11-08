# git over HTTPS

git reaches github.com through the broker's SOCKS socket as plain HTTP. The
broker checks the repo against the allowlist and each pushed ref against
its rules, adds the token, and talks to GitHub. Agents can push branches
they create. They can't push the default branch, protected branches,
colleagues' branches, or tags.

## Sub-features

- `git-clone` clones in every URL form.
- `git-push-new` pushes a new agent branch, and the broker records it in its ledger.
- `git-push-own` force-pushes and deletes a branch the agent created.
- `git-push-default` refuses pushes to `main`.
- `git-push-protected` refuses pushes to `release/*`.
- `git-push-colleague` refuses updating or deleting `colleague`.
- `git-push-tag` refuses tag pushes.
- `git-allowlist` refuses `ls-remote` on `acme/secret`.

## Driving it with git

Preconditions: refs recorded with
`GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -C "$S/gh-root/acme/widgets.git" for-each-ref > "$S/evidence/refs-before.txt"`.

- **Clone.** `git clone -q git@github.com:acme/widgets.git "$S/work" && cd "$S/work"`
  exits 0. The fake log has `GET /acme/widgets.git/info/refs` with `basic-ok`.
- **Commit.** `echo change >> README && git commit -qam "agent work"`.
- **New branch.** `git push origin HEAD:agent/fix` exits 0. The fake's refs
  gain `refs/heads/agent/fix`.
- **Own branch.** `git commit -q --amend -m "agent work, amended" && git push --force origin HEAD:agent/fix`
  exits 0.
- **Refusals.** Each exits non-zero with `hallpass: ` and this reason:
  `git push origin HEAD:main` gives `main is the default branch`,
  `git push origin HEAD:release/1` gives `release/1 is protected`,
  `git push --force origin HEAD:colleague` gives `agents can only update branches they created`,
  `git push origin :colleague` gives `agents can only delete branches they created`,
  `git push origin HEAD:refs/tags/v1` gives `agents can't push tags`.
- **Allowlist.** `git ls-remote https://github.com/acme/secret` fails with
  `isn't in hallpass's allowlist`.
- **Delete own.** `git push origin :agent/fix` exits 0.
- **Proof.** Diff the fake's refs against `refs-before.txt`. `main` and
  `colleague` are unchanged, and there's no `release/1`, no `refs/tags/v1`,
  and no `agent/fix` left.

## Gotchas

- Not yet run end to end from this skill. The agent permission check
  blocked the first attempt, because it can't tell the fake from real
  GitHub when it sees `git push --force` and pushes to `main`. Ask the user
  to approve these commands, and say they go to the fake under `$S`.
- The ledger file is fixed at `/var/lib/hallpass/branches.jsonl`, which the
  scratch broker can't write. The broker records new branches in memory and
  logs `msg="ledger write failed; agents can't update this branch later"`
  at `level=ERROR`. Despite the message, own-branch updates work until the
  broker restarts, and doctor's `level=ERROR` check fails from then on.
- Without `GIT_CONFIG_NOSYSTEM=1`, the system config's include of
  `/etc/hallpass/gitconfig` wins and git goes to the live broker. `$S/env`
  sets it, so check `git config --show-origin --get-regexp '^http\.'` if
  the URLs look wrong.
- Workflow-file pushes over HTTPS pass the broker and are left for GitHub to
  refuse (the token lacks `workflow` scope). The fake doesn't model that, so
  a workflow push succeeding here proves nothing either way.
