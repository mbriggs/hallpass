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
- `git-push-after-restart` force-pushes that branch again after a broker
  restart, from the ledger in `$S/state`.
- `git-push-default` refuses pushes to `main`.
- `git-push-protected` refuses pushes to `release/*`.
- `git-push-colleague` refuses updating or deleting `colleague`.
- `git-push-tag` refuses tag pushes.
- `git-push-workflow` refuses a push whose commits change `.github/workflows`.
- `git-push-protected-path` refuses a push that adds a path the config's
  `protected_paths` names, globally or on the repo's entry.
- `git-allowlist` refuses `ls-remote` on `acme/secret`, after GitHub's
  smart HTTP answers it 401 without a credential.
- `git-anonymous-private` refuses a clone of `acme/private`, and nothing
  of it reaches git.
- `git-anonymous-clone` clones, fetches, shallow-clones, and partially
  clones `octo/public` without a credential.
- `git-anonymous-push` refuses a push to `octo/public`.
- `git-anonymous-renamed` follows `octo/old`'s redirect to `octo/public`.
- `git-anonymous-other-host` doesn't follow `octo/away`'s redirect.
- `git-anonymous-throttled` says when GitHub rate limits.
- `git-anonymous-v0` refuses a fetch outside the allowlist over protocol v0.
- `git-anonymous-denied` refuses `octo/public` when the policy denies
  `anonymous`, and still fetches `acme/widgets` with the key.
- `git-readonly` fetches `acme/readonly` and refuses pushes to it.
- `git-renamed` refuses a repo's old name when the allowlist doesn't cover
  the new one.
- `git-renamed-allowed` follows an old name when the allowlist covers both
  names.
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
- `git-push-after-restart`: `$S/state/branches.jsonl` records `agent/fix`,
  the broker restarts, and another amend and force-push of `agent/fix`
  succeeds.
- `git-push-default`, `git-push-protected`, `git-push-colleague`,
  `git-push-tag`: refused with `main is the default branch`, `release/1 is
  protected`, `agents can only update branches they created` and `agents
  can only delete branches they created`, and `agents can't push tags`.
- `git-push-workflow`: a commit that changes `.github/workflows` is refused
  with `agents can't change .github/workflows`.
- `git-push-protected-path`: the scratch config protects
  `scripts/deploy.sh` globally and `.github/actions` on `acme/widgets`.
  Adding either is refused with `agents can't change PATH, which
  protected_paths in hallpass's config names`, and a push adding
  `scripts/lint.sh` beside it goes through.
- `git-allowlist`: `ls-remote` on `acme/secret` is refused with `Without a
  token, GitHub answered 401 Unauthorized. acme/secret isn't in hallpass's
  allowlist`. The fake sees `GET /acme/secret.git/info/refs` with auth
  `none` and status 401, and no SSH for it. `broker.log` has
  `anonymous=true`.
- `git-anonymous-private`: a clone of `acme/private` is refused with the
  same 401, no `README` reaches the clone, and the fake sees neither SSH
  for `acme/private.git` nor a POST to its `git-upload-pack`.
- `git-anonymous-clone`: `octo/public` clones, and its `README` says
  `public`. The fake sees `GET /octo/public.git/info/refs` and `POST
  /octo/public.git/git-upload-pack` with auth `none`, no SSH for the repo,
  and no `wrong` auth. `broker.log` has `repo=octo/public op=upload-pack
  anonymous=true exit=0`. A fetch in the clone works, a `--depth 1` clone
  has one commit, and a `--filter=blob:none` clone checks out `second`,
  which needs the lazy fetch of its blob to go through too.
- `git-anonymous-push`: a push from that clone is refused with `octo/public
  isn't in hallpass's allowlist`, and the fake sees no `receive-pack`.
- `git-anonymous-renamed`: `ls-remote` on `octo/old` lists `main`, the fake
  sees the POST under `octo/public`, and `broker.log` has `anonymous=true
  now=octo/public`.
- `git-anonymous-other-host`: `octo/away` is refused with `GitHub
  redirected somewhere hallpass doesn't follow`, and the fake never sees
  the redirect's target, `/away-target`.
- `git-anonymous-throttled`: `octo/busy` is refused with `GitHub is
  limiting git without a token from this machine's address (429 Too Many
  Requests); try again later.`
- `git-anonymous-v0`: `git -c protocol.version=0 ls-remote` on `octo/public`
  is refused with `only over git protocol v2`, before the fake sees it.
- `git-anonymous-denied`: with `deny = ["anonymous"]` in the config and the
  broker restarted, `octo/public` gets the plain allowlist refusal and the
  fake never sees it, while `acme/widgets` still lists over SSH with
  `key-ok`. The case puts the config back and restarts the broker.
- `git-readonly`: `ls-remote` on `acme/readonly` lists its branches, and a
  push there is refused with `agents may only read acme/readonly`.
- `git-renamed`: `acme/gizmos` is refused with `acme/gizmos is now
  acme/private on GitHub, and hallpass checks both names: acme/private
  isn't in hallpass's allowlist`. The fake sees `GET
  /api/repos/acme/gizmos` and the redirect's `GET /api/repositories/3`,
  and no SSH for either name.
- `git-renamed-allowed`: `ls-remote` on `acme/gadgets` lists widgets's
  `main`. The fake sees `GET /api/repos/acme/gadgets` and
  `git-upload-pack 'acme/widgets.git'`, never `acme/gadgets.git`.
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
- The scratch broker keeps its state in `$S/state`, from `serve
  --state-dir`: the ledger in `branches.jsonl` and pushed packs in
  `spool/`. Without the flag it would use the live state dir
  (`/var/lib/hallpass` on Linux, `/var/db/hallpass` on macOS), fail to
  write it, and log `msg="ledger write failed; after a restart agents
  can't update this branch"`. `drive.sh` fails any run whose `broker.log`
  has that line.
- A pushed pack waits in the spool while the broker checks it. The broker
  unlinks each file as soon as it makes it, so the directory looks empty
  even mid-push. A broker that can't open the spool logs `msg="push spool
  didn't open; pushes that carry commits will be refused"` and refuses
  every push with a pack.
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
