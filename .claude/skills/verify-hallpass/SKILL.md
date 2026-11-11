---
name: verify-hallpass
description: End-to-end check of hallpass through real gh and git, against a scratch broker and fake GitHub. Use to prove a policy, proxy, signing, or status change, or whether hallpass allows a request.
---

# Verify hallpass

hallpass is a credential broker. Clients reach it three ways: `gh` through
the gh socket, `git` through the SSH socket, and `hallpass status` /
`hallpass-sign` through the control socket.

Verification runs a second broker, not the installed one:

- `serve --config FILE` reads a config you write, `HALLPASS_RUN_DIR`
  moves all three sockets, and `--state-dir $S/state` holds the branch
  ledger and the push spool, so the scratch broker never opens the live state dir. The broker
  runs as you, with no root.
- The config's `api_url`, `git_url`, `ssh_addr`, and `ssh_host_keys` point
  it at `scripts/fakegithub`, a local server with canned REST/GraphQL
  answers for `acme/widgets`, an SSH server that runs real
  `git-upload-pack` and `git-receive-pack`, and git's smart HTTP for the
  public `octo/public`, through real `git http-backend`. The API returns
  401 to any request without the scratch token, and SSH accepts only the
  broker's key, so a success there shows the broker added its credential.
  Smart HTTP serves only `octo/public`, and only to a request with no
  credential.
- The token, SSH key, and signing key are scratch credentials in
  `$S/keys/broker`, made by `scripts/scratchcreds` with the platform's
  backend: `sealed:` on macOS, `file:` elsewhere. That's what the installed
  broker uses, except on Linux with a TPM, which gets `file:` because the
  scratch broker runs as you. Set `HALLPASS_VERIFY_BACKEND=file`, `sealed`,
  or `tpm` before `up.sh` to pick another. The fake reads the plain token in
  `$S/keys/token`.

The installed broker belongs to the user. It runs under systemd with its
sockets in `/run/hallpass` on Linux, or under launchd with them in
`/var/db/hallpass/run` on macOS, and it holds the real GitHub token. Never
restart it, rewrite its config, or send mutating requests through it. Two scratch brokers can run side by side;
each gets its own dir.

**This machine aliases `gh` to `/opt/hallpass/bin/hallpass gh`, the live
broker.** `$S/env` removes the alias. If `type gh` doesn't print a real
binary path after you source it, stop: your gh calls are reaching the live
broker and real GitHub.

## The all run: the landing check

Every lane passes this before `bin/worktree land`:

```sh
.claude/skills/verify-hallpass/scripts/all.sh
```

It refuses to start with anything uncommitted, because its stamp names
the committed tree. Then it runs `up.sh`, `doctor.sh`, `drive.sh S all`,
and `down.sh` in a new scratch dir, and prints the failed checks under
their case names if any fail. When every check passes, and the broker was
built from the tree the run started on, it writes `$S/evidence/verified`
holding `HEAD^{tree}` and prints that path. `land` refuses a tree with no
stamp, unless the change is Markdown only. Commit, rebase if `land` asks,
then run it, since either changes the tree.

It runs under `env -i`: `HOME`, `USER`, `TMPDIR`, and a `PATH` of the
system dirs plus the directories of `go` and `gh`, found through
`mise which` or the caller's `PATH`. So a login shell's PATH, the gh
alias, `GH_*` and `GIT_*` variables, and Go's env file can't change the
result. In a lane, `up.sh` reads the scratch-dir prefix from
`worktree.env`. The evidence stays in `$S/evidence/` either way.

This is the end-to-end check. The TLA+ model in `verify/` is separate,
and `land` doesn't ask for it. To check one feature while you work, use
the steps below by hand.

## Launch

Run `up.sh`, `doctor.sh`, `drive.sh`, and `down.sh` from the repo root:

```sh
.claude/skills/verify-hallpass/scripts/up.sh
```

It prints the scratch dir, `$S`, on its last line. Pass that path literally
to the other scripts. In a lane, the harness refuses `S=$(...)`.

`up.sh [DIR]` builds `bin/hallpass` with `make build`, copies it to `$S/bin`,
builds the fake, makes a token and P-256 SSH and signing keys, seeds the
bare repo `acme/widgets` (branches `main` and `colleague`, and
`.github/workflows/ci.yml`), copies of it as `acme/readonly` and the
unallowlisted `acme/private`, and the public `octo/public`, and starts
both processes. It prints the scratch dir once the broker logs
`msg=serving` with `token=true ssh=true signing=true`, and fails loudly
otherwise. The allowlist is `acme/widgets` (write), `acme/readonly` (read),
and `acme/gadgets`, which the fake answers as widgets's old name. The config
also sets `protected_branches = ["release/*"]`, and `protected_paths`:
`scripts/deploy.sh` globally and `.github/actions` on `acme/widgets`.

`$S/env` is what points git and gh at the scratch broker. It sets
`HALLPASS_RUN_DIR`, puts `$S/bin` first on PATH, sets
`GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL=$S/gitconfig` (the system git
config routes github.com to the live broker), sets `GH_CONFIG_DIR=$S/gh`
(`http_unix_socket` is the scratch gh socket), and unsets `GH_TOKEN`,
`GITHUB_TOKEN`, and `SSH_AUTH_SOCK`. `drive.sh` sources it. Don't source it
in a Bash call yourself: in a lane the harness refuses that.

After rebuilding, run `down.sh` and then `up.sh` again. The broker runs the
copy in `$S/bin`, and doctor flags it when that copy differs from the
checkout.

## Doctor

```sh
.claude/skills/verify-hallpass/scripts/doctor.sh "$S"
```

Read-only. It checks that both pids are alive and that their command lines
name `$S`, that all three sockets exist, that the broker binary matches
`bin/hallpass`, and that the fake refuses requests without the token. It
then runs `hallpass status --check` and checks `broker.log` for
`level=ERROR`. Exit 0 means it's worth driving. Run it first whenever
anything looks off.

To check the live install without changing it: `/opt/hallpass/bin/hallpass
status` (no `--check` unless the user asks; `--check` calls real GitHub).

## Drive

```sh
.claude/skills/verify-hallpass/scripts/drive.sh S all
.claude/skills/verify-hallpass/scripts/drive.sh S rest graphql signing status
```

`drive.sh S FEATURE...` runs the committed cases in `scripts/cases/` for
`rest`, `graphql`, `ssh`, `push-default`, `signing`, `status`, or `all`.
Each case prints its command, output, and exit, then `ok` or `FAIL` against
the expected exit and text, and against the fake's request log and
`broker.log` where that matters. It writes everything to
`$S/evidence/transcript.txt`, ends with `#### N failed`, and exits 1 if any
check failed. Every run also checks that `broker.log` has no `ledger write
failed` line. It refuses to run unless gh is the plain binary pointed at
`$S/gh`. `features/README.md` maps each feature to a file that says what
each case proves.

To check something no case covers, add a case to the feature's file in
`scripts/cases/` and run it with `drive.sh`. Don't type git and gh commands
against the scratch broker by hand. In a lane, the harness refuses sourcing
`$S/env`, env-prefixed git, compound commands, and arguments that look like
git, and the permission check refuses force pushes and pushes to `main`
even when they go to the fake. Agents who type them end up improvising
scripts in `tmp/` or skipping the check. A committed case gets reviewed
with the change and runs as one plain command.

How each client reaches the scratch broker, for writing a case:

- gh: plain `gh ...` after sourcing `$S/env`. Don't use `hallpass gh`: it
  sets `GH_CONFIG_DIR=/etc/hallpass/gh`, which points at the live broker.
- git: plain `git` with any github.com URL form (`git@github.com:acme/widgets`,
  `https://github.com/acme/widgets`). `$S/gitconfig` rewrites them to
  `ssh://git@github.com/` and sets `core.sshCommand` to `$S/bin/hallpass ssh`,
  which reaches the scratch SSH socket through `HALLPASS_RUN_DIR`.
- Signing: `git commit -S`. `$S/gitconfig` sets `gpg.format=ssh`,
  `gpg.ssh.program=$S/bin/hallpass-sign`, and `user.signingKey=$S/keys/signing.pub`.
- Status: `hallpass status`, `hallpass status --check`, `hallpass status --json`.

## Evidence

Everything goes in `$S/evidence/`. `down.sh` keeps that directory and
deletes the rest of `$S`.

- `broker.log`: the broker's slog output, one `msg=allowed`, `msg=refused`,
  or `msg=pushed` line per request (`msg=signed` for a signature), with uid,
  pid, and process chain first and then the request's own fields, as in
  `msg=refused via=gh uid=1000 pid=... procs=... reason=...`. Match on
  `msg=refused` and the reason separately. A push where GitHub rejected
  some refs logs `level=WARN msg=pushed`, and one where it rejected every
  ref logs `msg=rejected`. Both carry `rejected=`, JSON listing each ref
  and GitHub's reason. A push that fails before the checks, as when GitHub
  sends no ref list, logs `level=WARN msg=failed reason=...`. These are the lines
  the live broker writes to `journalctl -u hallpass` on Linux and
  `/var/log/hallpass.log` on macOS.
- `github-requests.jsonl`: every request that reached the fake, with
  method, path, body, and `auth` (`token-ok`, `key-ok`, `wrong`, `none`). git
  shows up as method `SSH` with the git command as the path. This is the
  side-effect record.
- `github-refs-at-teardown.txt`: the refs on the fake's `acme/widgets` when
  `down.sh` ran.
- `transcript.txt`: every case `drive.sh` ran, with its command, output,
  exit, and checks.

Cite the case names from the transcript as the evidence. A new case should
check what the existing ones do. An allowed API write shows up in
`github-requests.jsonl` with `token-ok`. A refused API write doesn't show
up there at all, though some refusals need a read first (the author check
GETs the issue), and that read does appear. A refused push does show up,
so compare the fake's refs instead, as `scripts/cases/git-ssh.sh` does.

The fake stands in for GitHub only. Policy, proxies, signing, and sockets
are the real binary. What GitHub itself enforces (branch protection,
rulesets) isn't modeled, so don't claim it.

## The gh matrix

To find what real gh commands hallpass refuses, or to refresh the corpus
for a new gh release, run the matrix against a scratch broker:

```sh
.claude/skills/verify-hallpass/scripts/gh-matrix.sh "$S" tmp/matrix.jsonl
python3 -I .claude/skills/verify-hallpass/scripts/gh-matrix-report.py tmp/matrix.jsonl
```

`gh-matrix.sh` runs the gh commands agents use most, plus reads the floor
must refuse, through `scripts/capture`, which records each request with the
broker's verdict. The report lists each command's refusals and exit. A
failure with no refusal is usually the fake's canned data, not hallpass:
gh got an answer it didn't expect after the broker allowed the request.
Extend `fakegithub` when a command stops before its main request, then
run `make lint`. It is the only check that covers `scripts/fakegithub`
and `scripts/capture`: `go vet ./...` and `go test ./...` skip them
because `.claude` starts with a dot.

Sort each refusal: a bug (a read gh needs, refused), an operation that's
off by default, or a refusal by design. After fixing the bugs, append the
run to the corpus, which keeps allowed requests and operation refusals and
skips refusals by design:

```sh
python3 -I .claude/skills/verify-hallpass/scripts/gh-matrix-corpus.py tmp/matrix.jsonl internal/policy/testdata/gh-2.98.0-capture.jsonl
```

`TestGHCorpus` and `TestRESTCorpus`, both in `make test`, then require every
one to classify. The matrix runs the `gh` on `PATH`, so for a new gh version,
put that gh first on `PATH` and start a new corpus file named for it.

## Cleanup

```sh
.claude/skills/verify-hallpass/scripts/down.sh "$S"
```

It kills only the pids in `$S/*.pid`, and only if their command lines
still name `$S`. Then it records the fake's refs and deletes everything in
`$S` except `evidence/`. `pkill hallpass` would also hit the live broker.

## Not covered by the scratch broker

- **Real GitHub's SSH addresses.** The scratch broker dials the fake through
  `ssh_addr` alone, so GitHub's real host keys, its network path, and the
  fallback from `github.com:22` to `ssh.github.com:443` aren't exercised.
  The sshgate unit tests cover the fallback.
- **Root setup and maintenance commands** (`install`, `login`,
  `install-pat`, `ssh-key`, `signing-key`, `allow`, `disallow`, `policy`, `ledger`,
  `logout`, `uninstall`). They write `/etc/hallpass` and the live install.
  Ask the user before running any of them.
- **The TPM backend**, unless you run `up.sh` with
  `HALLPASS_VERIFY_BACKEND=tpm` and can open `/dev/tpmrm0`.
