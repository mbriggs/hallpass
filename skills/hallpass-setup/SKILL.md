---
name: hallpass-setup
description: Set up hallpass on a machine, so coding agents use git and gh through a broker that holds the credentials. Use when installing hallpass, or when `hallpass status` fails.
disable-model-invocation: true
---

# Set up hallpass

You and the user take turns. The user runs every step that needs sudo or a
browser, since you can't type their password or approve anything on GitHub.
In Claude Code they can run a command in this session by typing
`! <command>`. Outside it, they run commands in their own terminal and tell
you when each finishes. You check the state between steps and explain what
each one did.

Run hallpass as `/opt/hallpass/bin/hallpass` throughout, including in
commands you give the user. A `hallpass` found on PATH may be a copy that code
running as the user could replace.

## Find where setup stands

You may arrive partway through. If `/opt/hallpass/bin/hallpass` doesn't
exist, start at Install. Otherwise
`/opt/hallpass/bin/hallpass status --check --json` tells you what's done:

- **"can't reach the hallpass broker".** Install didn't finish. Rerun it.
- **`token`, `ssh`, or `signing` missing.** That credential isn't set up.
  Ask the user which ones they want before setting any up.
- **A credential with `problem` or `check_error` set.** It's broken. Remove
  it and set it up again, under its section below.
- **No `repos`.** Go to Allow repos.
- **Everything set and checked.** Go to Check git and gh.

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

Each is optional. Explain what each turns on and let the user pick:

- **The token** turns on git over HTTPS and gh. Most users want it.
- **The SSH key** turns on git over SSH. It's only needed for orgs that
  block both classic PATs and GitHub CLI's OAuth app but accept SSH keys,
  or when the user wants a credential that can't leave the TPM.
- **The signing key** signs commits and tags, which then show as Verified.

Tell the user that every credential acts as them on GitHub, so agent PRs,
comments, and pushes show as theirs.

### The token

Two ways, and both store the token the same way:

- **Device login.** The user runs `sudo /opt/hallpass/bin/hallpass login`,
  opens the printed link in any browser, and enters the code. GitHub shows
  it as GitHub CLI asking for the `repo` scope. The token goes straight from
  GitHub into storage. It doesn't expire, so they should run `login` again
  every few months. Orgs that restrict OAuth apps and haven't approved
  GitHub CLI reject it.
- **A classic PAT.** For those orgs. The user runs
  `sudo /opt/hallpass/bin/hallpass install-pat` in their own terminal, not
  through `!`, opens the printed link, creates a token with only `repo` and
  an expiry of 90 days, and pastes it at the hidden prompt. For orgs with
  SAML SSO they click Configure SSO next to the token and authorize each
  org.

### The SSH key

The user runs `sudo /opt/hallpass/bin/hallpass ssh-key create` and adds the
printed key at https://github.com/settings/ssh/new as an **Authentication**
key, then authorizes it for any SSO orgs. git over SSH also needs repos
allowed with `--via ssh` when there's a token, since HTTPS is the default.

### The signing key

The user runs `sudo /opt/hallpass/bin/hallpass signing-key create` and adds
the printed key at https://github.com/settings/ssh/new as a **Signing** key.
Tell them Verified will mean "made on this machine through hallpass", not
"you reviewed it".

Then check the user's own git config, because a global setting overrides
hallpass's system config:

```sh
git config --show-origin --get-all user.signingkey
git config --show-origin --get-all gpg.ssh.program
```

If either comes from a file other than `/etc/hallpass/gitconfig`, the user's
own signing wins and agent commits would still go to it, often a password
manager prompt. Offer to move those settings into a file that only
`git personal` loads, with an alias in their global config:

```ini
[alias]
  personal = "!GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=include.path GIT_CONFIG_VALUE_0=$HOME/.config/git/personal-signing.inc git"
```

Show them the change before you make it.

## Allow repos

Agents reach only allowed repos. Ask which, then have the user run, for
each:

```sh
sudo /opt/hallpass/bin/hallpass allow OWNER/REPO
```

`OWNER/*` covers every current and future repo of an owner. `--read` lets
agents read but not write. `--via ssh` sends the owner's git over SSH.
`hallpass policy` turns operations like `pr.merge` or `push.default` on or
off, everywhere or for one repo. For
each org repo, the hallpass-repo skill checks what an agent's branch could
trigger there.

Warn the user before the first `allow` takes effect: with a token, every
github.com remote goes through the broker, and repos not allowed are refused.
Pushing to the default branch is refused too, so the user pushes their own
commits with `git personal push`, or allows it for one repo with
`sudo /opt/hallpass/bin/hallpass policy allow push.default --repo OWNER/REPO`.

## Check git and gh

Confirm the user's git reads the include, since on macOS a Homebrew git has a
different system config from Apple's:

```sh
type -a git
git config --show-origin --get-all include.path
```

Every git listed should show `/etc/hallpass/gitconfig`. If one doesn't, have
the user run `sudo <that git> config --system --add include.path /etc/hallpass/gitconfig`.
For the token, each git must be 2.47 or later; install prints a warning for
older ones. Apple's git on Xcode 16 and Ubuntu 24.04's git are too old.

For gh, add `alias gh='/opt/hallpass/bin/hallpass gh'` to the user's shell
config. Agents that run non-interactive shells don't expand aliases, so tell
the user to have those agents call `/opt/hallpass/bin/hallpass gh` directly,
or set `GH_CONFIG_DIR=/etc/hallpass/gh` in their environment.

Tell the user how to do what hallpass refuses: `git personal <command>` runs
git with their own credentials, and gh run directly uses their own login.

Name any other credentials you find that agents could reach, such as an SSH
agent socket, a logged-in gh config, or keyring tokens. Hiding those is a
sandbox's job, not hallpass's.

## Confirm it works

Setup is done when all of these hold, for the credentials the user chose:

- `/opt/hallpass/bin/hallpass status --check` exits 0.
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
