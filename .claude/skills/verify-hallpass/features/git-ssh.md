# git over SSH

git reaches github.com through `hallpass ssh`, which hands the git command
to the broker's SSH socket. The broker checks the repo against the
allowlist, asks GitHub for the repo's current name, checks each pushed ref
against its rules, reads every pushed pack for workflow changes, and runs
the command on GitHub with its own key. Agents can push branches they
create. They can't push the default branch, protected branches,
colleagues' branches, tags, or commits that change `.github/workflows` or
`.github/dependabot.yml`.

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

## Driving it

`scripts/drive.sh "$S" ssh` runs these cases from `scripts/cases/git-ssh.sh`,
in order, as one journey in `$S/work`:

- `git-clone`: clones over `git@github.com:`, `https://github.com/`, and
  `ssh://git@github.com/`. The fake sees the broker's current-name check,
  `GET /api/repos/acme/widgets` with `token-ok`, and `git-upload-pack
  'acme/widgets.git'` with `key-ok`.
- `git-push-new`: pushes `agent/fix` as a new branch, `broker.log` records
  `refs=[refs/heads/agent/fix]`, and the fake gains the branch.
- `git-push-own`: amends and force-pushes `agent/fix`.
- `git-push-default`, `git-push-protected`, `git-push-colleague`,
  `git-push-tag`: refused with `main is the default branch`, `release/1 is
  protected`, `agents can only update branches they created` and `agents
  can only delete branches they created`, and `agents can't push tags`.
- `git-push-workflow`: a commit that changes `.github/workflows` is refused
  with `agents can't change .github/workflows`.
- `git-allowlist`: `ls-remote` on `acme/secret` is refused with `isn't in
  hallpass's allowlist`, and the fake never sees it.
- `git-readonly`: `ls-remote` on `acme/readonly` lists its branches, and a
  push there is refused with `agents may only read acme/readonly`.
- `git-renamed`: `acme/gadgets` is refused with `acme/gadgets is now
  acme/widgets on GitHub`. The fake sees `GET /api/repos/acme/gadgets` and
  the redirect's `GET /api/repositories/1`, and no SSH for it.
- `git-delete-own`: deletes `agent/fix`.
- `git-refs-unchanged`: the fake's refs match the start. A refused push
  still logs `git-receive-pack`, because the broker reads GitHub's refs
  before it checks, but no ref moves.

## push.default

`scripts/drive.sh "$S" push-default`, after `ssh`, adds
`allow = ["push.default"]` to the `acme/widgets` entry and restarts the
broker. `push-default-allowed` checks that `hallpass status` shows
`acme/widgets (+push.default)` and that a push to `main` moves the fake's
`main`. `push-default-delete` checks that deleting `main` is still refused
with `agents can't delete the default branch`. It then restores the config
and restarts the broker. It leaves the fake's `main` moved, so start over
with `up.sh` before running `ssh` again.

## Gotchas

- Match the fake log with `jq`, not a literal grep. Each line is JSON, such
  as `{"method":"SSH","path":"git-upload-pack 'acme/widgets.git'","auth":"key-ok",...}`.
  A push with a pack usually logs three extra `git-upload-pack` lines: the
  broker reads the default branch, the workflow check fetches trees, and
  the broker reads the default branch again before it forwards. A
  delete-only push logs one.
- The current-name check sends `GET /api/repos/OWNER/REPO` on every git
  command, uncached, so the fake logs one per clone, `ls-remote`, and push.
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
- Typed by hand, the push batch trips the agent permission check, which
  can't tell the fake from real GitHub when it sees `git push --force` and
  pushes to `main`. `drive.sh` runs it as one committed script instead.
  `TestGitOverSSHThroughBroker` in `cmd/hallpass/ssh_test.go` drives the
  same journey in `go test`.
