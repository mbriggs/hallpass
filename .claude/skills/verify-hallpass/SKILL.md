---
name: verify-hallpass
description: End-to-end check of hallpass through real gh and git, against a scratch broker and fake GitHub. Use to prove a policy, proxy, signing, or status change, or whether hallpass allows a request.
---

# Verify hallpass

hallpass is a credential broker. Clients reach it three ways: `gh` through
the gh socket, `git` through the SOCKS git socket, and `hallpass status` /
`hallpass-sign` through the control socket.

Verification runs a second broker, not the installed one:

- `serve --config FILE` reads a config you write, and `HALLPASS_RUN_DIR`
  moves all four sockets. The broker runs as you, with no root.
- The config's `api_url` and `git_url` point it at `scripts/fakegithub`, a
  local server that serves git smart HTTP via `git http-backend` and canned
  REST/GraphQL answers for `acme/widgets`. It returns 401 to any request
  that lacks the scratch token, so a 200 there shows the broker added the
  token.
- The token and signing key are scratch files (`file:` backend). No TPM.

The installed broker (`/run/hallpass`, systemd `hallpass.service`, real
GitHub token) belongs to the user. Never restart it, rewrite its config, or
send mutating requests through it. Two scratch brokers can run side by side;
each gets its own dir.

**This machine aliases `gh` to `/opt/hallpass/bin/hallpass gh`, the live
broker.** `$S/env` removes the alias. If `type gh` doesn't print a real
binary path after you source it, stop: your gh calls are reaching the live
broker and real GitHub.

## Launch

Run `up.sh`, `doctor.sh`, and `down.sh` from the repo root, and drive from
anywhere else (see `features/README.md`):

```sh
S=$(.claude/skills/verify-hallpass/scripts/up.sh | tail -1)
```

`up.sh [DIR]` builds `bin/hallpass` with `make build`, copies it to `$S/bin`,
builds the fake, makes a token and a P-256 signing key, seeds the bare repo
`acme/widgets` (branches `main` and `colleague`), and starts both processes.
It prints the scratch dir once the broker logs `msg=serving` with
`token=true ssh=false signing=true`, and fails loudly otherwise. The
allowlist is `acme/widgets` (write) and `acme/readonly` (read), and
`protected_branches = ["release/*"]`.

Each shell that drives it needs:

```sh
. "$S/env"
```

That sets `HALLPASS_RUN_DIR`, puts `$S/bin` first on PATH, sets
`GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL=$S/gitconfig` (the system git
config routes github.com to the live broker), sets `GH_CONFIG_DIR=$S/gh`
(`http_unix_socket` is the scratch gh socket), and unsets `GH_TOKEN`,
`GITHUB_TOKEN`, and `SSH_AUTH_SOCK`. Bash tool calls don't keep shell
state, so source it at the start of each call.

After rebuilding, run `down.sh` and then `up.sh` again. The broker runs the
copy in `$S/bin`, and doctor flags it when that copy differs from the
checkout.

## Doctor

```sh
.claude/skills/verify-hallpass/scripts/doctor.sh "$S"
```

Read-only. It checks that both pids are alive and that their command lines
name `$S`, that all four sockets exist, that the broker binary matches
`bin/hallpass`, and that the fake refuses requests without the token. It
then runs `hallpass status --check` and checks `broker.log` for
`level=ERROR`. Exit 0 means it's worth driving. Run it first whenever
anything looks off. After an agent branch push it fails on `level=ERROR`
because the scratch broker can't write the branch ledger. That failure
alone isn't a fault; see `features/git-https.md`.

To check the live install without changing it: `/opt/hallpass/bin/hallpass
status` (no `--check` unless the user asks; `--check` calls real GitHub).

## Drive

`features/README.md` maps each feature to a file with its exact commands
and expected output. How each client reaches the scratch broker:

- gh: plain `gh ...` after sourcing `$S/env`. Don't use `hallpass gh`: it
  sets `GH_CONFIG_DIR=/etc/hallpass/gh`, which points at the live broker.
- git: plain `git` with any github.com URL form (`git@github.com:acme/widgets`,
  `https://github.com/acme/widgets`). `$S/gitconfig` rewrites them to
  `http://github.com/` through `socks5h://localhost$S/run/git.sock`.
- Signing: `git commit -S`. `$S/gitconfig` sets `gpg.format=ssh`,
  `gpg.ssh.program=$S/bin/hallpass-sign`, and `user.signingKey=$S/keys/signing.pub`.
- Status: `hallpass status`, `hallpass status --check`, `hallpass status --json`.

## Evidence

Everything goes in `$S/evidence/`. `down.sh` keeps that directory and
deletes the rest of `$S`.

- `broker.log`: the broker's slog output, one `msg=allowed` or
  `msg=refused reason=...` line per request (`msg=signed` for a signature)
  with uid, pid, and process chain. These are the lines
  `journalctl -u hallpass` shows for the live broker.
- `github-requests.jsonl`: every request that reached the fake, with
  method, path, body, and `auth` (`token-ok`, `basic-ok`, `wrong`, `none`).
  This is the side-effect record.
- `github-refs-at-teardown.txt`: the refs on the fake's `acme/widgets` when
  `down.sh` ran.
- Your transcript: tee each driven command and its output to
  `$S/evidence/transcript.txt`, e.g.
  `{ echo '$ gh api repos/acme/secret'; gh api repos/acme/secret; echo "exit=$?"; } >> "$S/evidence/transcript.txt" 2>&1`.

For each case, capture the command, its output and exit code, the broker's
log line, and the fake's request log, and name the feature ID beside them.
An allowed write shows up in `github-requests.jsonl` with `token-ok` (API)
or `basic-ok` (git). A refused write doesn't show up there at all. Some
refusals need a read first (the author check GETs the issue), and that
read does appear. For pushes, also compare the fake's refs before and
after with
`GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -C "$S/gh-root/acme/widgets.git" for-each-ref`.

The fake stands in for GitHub only. Policy, proxies, signing, and sockets
are the real binary. What GitHub itself enforces (the `workflow` scope over
HTTPS, branch protection, rulesets) isn't modeled, so don't claim it.

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
Extend `fakegithub` when a command stops before its main request.

Sort each refusal: a bug (a read gh needs, refused), an operation that's
off by default, or a refusal by design. After fixing the bugs, append the
run to the corpus, which keeps allowed requests and operation refusals and
skips refusals by design:

```sh
python3 -I .claude/skills/verify-hallpass/scripts/gh-matrix-corpus.py tmp/matrix.jsonl internal/policy/testdata/gh-2.98.0-capture.jsonl
```

`TestGraphQLCorpus` and `TestRESTCorpus` then require every one to
classify. For a new gh version, start a new corpus file named for it.

## Cleanup

```sh
.claude/skills/verify-hallpass/scripts/down.sh "$S"
```

It kills only the pids in `$S/*.pid`, and only if their command lines
still name `$S`. Then it records the fake's refs and deletes everything in
`$S` except `evidence/`. `pkill hallpass` would also hit the live broker.

## Not covered by the scratch broker

- **git over SSH** (`ssh.sock`, `hallpass ssh`, the pack workflow check).
  The sshgate dials real github.com with GitHub's published host keys, and
  `git_url` doesn't redirect it. The tests in `internal/sshgate` and
  `internal/policy/workflows_test.go` cover the pieces. An end-to-end check
  needs the live broker and a real repo the user names.
- **Root setup and maintenance commands** (`install`, `login`,
  `install-pat`, `ssh-key`, `signing-key`, `allow`, `disallow`, `policy`, `ledger`,
  `logout`, `uninstall`). They write `/etc/hallpass` and the live install.
  Ask the user before running any of them.
- **The TPM backend.** Scratch keys are `file:`.
