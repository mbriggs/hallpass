---
name: hallpass-setup
description: Set up hallpass on a machine with the user, or repair a setup that `hallpass status --check` reports broken.
disable-model-invocation: true
---

# Set up hallpass

You and the user take turns. The user runs every step that needs sudo or a
browser, since you can't type their password or approve anything on GitHub.
In Claude Code they can run a command in this session by typing
`! <command>`. Outside it, they run commands in their own terminal and tell
you when each finishes.

Run hallpass as `/opt/hallpass/bin/hallpass` throughout, including in
commands you give the user. A `hallpass` found on PATH may be a copy that code
running as the user could replace.

## Find where setup stands

You may arrive partway through. If `/opt/hallpass/bin/hallpass` doesn't
exist, start at Install. Otherwise
`/opt/hallpass/bin/hallpass status --check --json` tells you what's done:

- **"can't reach the hallpass broker".** Install didn't finish. Rerun it.
- **`token`, `ssh`, or `signing` missing.** That credential isn't set up.
  If the user hasn't said whether they want it, go to Choose the
  credentials. One they declined is fine.
- **A credential with `problem` or `check_error` set.** A `check_error` can
  be a network failure, so rerun the check once. If it stays broken, set
  the token up again, which replaces the old one. For a key, the user runs
  `sudo /opt/hallpass/bin/hallpass ssh-key remove` or `signing-key remove`,
  then creates it again.
- **No `repos`.** Go to Allow repos.
- **Repos, but no `policy` and no entry in `repos` with changes like
  `(+pr.merge)`.** Ask whether the user has chosen what agents may do. If
  not, go to Choose what agents may do.
- **Every credential the user wants is set and checked.** Go to Check git
  and gh.

## Install

Prefer a release binary. Download the one for the machine,
`hallpass-<linux|darwin>-<amd64|arm64>`, from
https://github.com/mbriggs/hallpass/releases, and verify it before it runs as
root:

```sh
gh attestation verify hallpass-linux-amd64 --repo mbriggs/hallpass
chmod +x hallpass-linux-amd64
sudo ./hallpass-linux-amd64 install
```

From a checkout, `make build && sudo ./bin/hallpass install` works too.
Rerunning install upgrades in place. It refuses to run if a directory above
`/opt/hallpass/bin` is writable by anyone but root. It skips the
`/usr/local/bin/hallpass` link when that directory fails the same check,
which is common with Homebrew; then tell the user to add `/opt/hallpass/bin`
to their PATH.

## Choose the credentials

Each is optional:

- **The token** turns on gh. Most users want it.
- **The SSH key** turns on git, which goes through hallpass over SSH only.
  Most users want it too. With a token and no SSH key, git still goes to
  the broker, which refuses it and says to create a key. Only Linux has a
  TPM backend. On macOS hallpass keeps keys in a file only its service user
  can read, encrypted under a key tied to the Mac. If `doctor` warns that a
  credential is a plain file, it predates sealing; offer to set it up again.
  The broker dials `github.com:22`, so a network that blocks port
  22 can't use git through hallpass.
- **The signing key** signs commits and tags, which then show as Verified.

Tell the user that every credential acts as them on GitHub, so agent PRs,
comments, and pushes show as theirs.

### The token

Two ways, and both store the token the same way:

- **Device login.** The user runs `sudo /opt/hallpass/bin/hallpass login`,
  opens the printed link in any browser, and enters the code. GitHub shows
  it as GitHub CLI asking for the `repo` scope. The token goes straight from
  GitHub into storage. It doesn't expire, so they should run `login` again
  every few months, which revokes the old one. Orgs that restrict OAuth
  apps and haven't approved GitHub CLI reject it.
- **A classic PAT.** For those orgs. The user runs
  `sudo /opt/hallpass/bin/hallpass install-pat` in their own terminal, not
  through `!`, since the hidden prompt needs a real terminal. They open the
  printed link, create a token with only `repo` and an expiry of 90 days,
  and paste it at the hidden prompt. For orgs with SAML SSO they click
  Configure SSO next to the token and authorize each org.

### The SSH key

The user runs `sudo /opt/hallpass/bin/hallpass ssh-key create` and adds the
printed key at https://github.com/settings/ssh/new as an **Authentication**
key, then authorizes it for any SSO orgs. From then on git works through
hallpass for every allowed repo.

### The signing key

The user runs `sudo /opt/hallpass/bin/hallpass signing-key create` and adds
the printed key at https://github.com/settings/ssh/new as a **Signing** key.
Tell them Verified will mean "made on this machine through hallpass", not
"you reviewed it".

A global `user.signingkey` or `gpg.ssh.program` overrides hallpass's system
config, so agent commits would still go to the user's own signer, often a
password manager prompt. `doctor`, under Check git and gh, reports it. Offer to move those settings into a file that only
`git personal` loads, with an alias in their global config:

```ini
[alias]
  personal = "!GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=include.path GIT_CONFIG_VALUE_0=$HOME/.config/git/personal-signing.inc git"
```

Show them the change and wait for a yes before you make it.

## Allow repos

Agents reach only allowed repos. Ask which. Before the first `allow`, warn
the user: with a token or SSH key, every github.com remote goes through the
broker, and repos not allowed are refused. Pushing to the default branch is
refused too, so the user pushes their own commits with `git personal push`.
Then have the user run, for each:

```sh
sudo /opt/hallpass/bin/hallpass allow OWNER/REPO
```

`'OWNER/*'` covers every current and future repo of an owner. Quote it, or
zsh fails the glob before hallpass runs. `--read` lets agents read but not
write. For an org repo, suggest the user run `/hallpass-repo` instead, which checks what
an agent's branch could trigger there before suggesting any policy change.

## Choose what agents may do

Interview the user about the work their agents do, repo by repo, before
anyone runs `policy allow`. Ask about the work, not the operation names:
does an agent open issues when it finds a bug, merge its own PR once CI
passes, rerun a flaky job, push straight to the default branch, debug
deploys? Map each answer to operations, and show the user each one's
default and warning from `/opt/hallpass/bin/hallpass policy show` before
they choose it. The defaults let agents open and edit their own PRs,
comment, and review without approving. Everything else is off.

Settle with the user, for each operation they want:

- **Where.** Everywhere, one owner (`--repo 'OWNER/*'`), or one repo. Merge,
  rerun, and pushing the default branch usually belong on one repo whose
  CI and deploys the user knows, not everywhere.
- **What it triggers.** `workflow.rerun` and `workflow.dispatch` run
  workflows with their secrets, and a deploy workflow deploys. `pr.merge`
  with a release-on-merge workflow ships with nobody reviewing.
- **Reads beyond the defaults.** Agents debugging deploys or CI may need
  `read:environments`, `read:deployments`, `read:actions/variables`, or
  `read:rulesets`. These are reads, so the risk is what they reveal.
  Actions logs are on by default, and can show secrets that masking missed.

Then give the user one `sudo /opt/hallpass/bin/hallpass policy allow ...`
line per scope, and run `policy show OWNER/REPO` with them afterward to
confirm. Tell them they can start narrow: every refusal prints the exact
`policy allow` command that would permit it.

## Check git and gh

Run `/opt/hallpass/bin/hallpass doctor`. It checks that every git on the
machine includes hallpass's config and is new enough, that nothing in the
user's own config overrides the broker's routing, credential helper, ssh
command, or signing, that gh can run through the broker, and that the running
broker is the installed build. Each FAIL line carries its fix; walk the user
through them and rerun until it exits 0. Its warn lines name other
credentials agents could reach, like an SSH agent or a gh login; hiding those
is a sandbox's job, not hallpass's.

For gh, add `alias gh='/opt/hallpass/bin/hallpass gh'` to the user's shell
config. Agents that run non-interactive shells don't expand aliases, so tell
the user to have those agents call `/opt/hallpass/bin/hallpass gh` directly,
or set `GH_CONFIG_DIR=/etc/hallpass/gh` in their environment.

Tell the user how to do what hallpass refuses: `git personal <command>` runs
git with their own credentials, and `command gh`, which skips the alias,
uses their own login.

## Confirm it works

Setup is done when all of these hold, for the credentials the user chose:

- `/opt/hallpass/bin/hallpass status --check` and
  `/opt/hallpass/bin/hallpass doctor` exit 0.
- `git ls-remote https://github.com/OWNER/REPO` succeeds for an allowed
  private repo, and fails with `isn't in hallpass's allowlist` for one that
  isn't.
- `/opt/hallpass/bin/hallpass gh api repos/OWNER/REPO --jq .full_name`
  prints the allowed repo.
- With the signing key, a commit in a scratch repo passes
  `git verify-commit HEAD`.
- `journalctl -u hallpass -n 20` on Linux, or `/var/log/hallpass.log` on
  macOS, shows each of those requests.

Finish by suggesting `sudo -k`, so the user's cached sudo doesn't outlive
setup.
