# hallpass

hallpass lets coding agents use git and gh on GitHub without holding a
credential. A broker runs as its own user and holds up to three: a GitHub
token, an SSH key, and a signing key. git and gh send their requests through
the broker's Unix sockets. The broker checks each request against a policy,
uses the credential itself, and logs the request. Nothing an agent can read holds a
secret, so code that goes around the broker reaches GitHub with no
credential.

Each credential is optional and turns on its own features:

| Credential | Kept in | Turns on |
| --- | --- | --- |
| Token: a device login or a classic PAT, `repo` scope only | sealed to the TPM where there is one, otherwise a file only the broker user reads | git over HTTPS, and gh |
| SSH key, ECDSA P-256 | generated inside the TPM where there is one, otherwise a file | git over SSH |
| Signing key, ECDSA P-256 | generated inside the TPM where there is one, otherwise a file | signed commits and tags |

Every credential acts as you on GitHub, so it works in your repos and your
orgs' repos without any org approving it. The allowlist in `/etc/hallpass/hallpass.toml` decides which repos
agents reach.

## What it prevents and mitigates

hallpass assumes code running as you is hostile: a malicious npm
`postinstall` script, a poisoned dependency, or an agent that was talked into
something. It aims to keep that code from taking a GitHub credential, and to
limit what it can do through the broker.

It prevents these:

- **Theft of a credential by code running as you.** The broker runs as its
  own user (`hallpass`, or `_hallpass` on macOS). Its files are mode 0600 and
  its state directory is closed to others, so your processes can't read them
  or attach a debugger to the broker. git and gh never see a token or key.
- **Copying the keys off the machine, even as root.** On Linux with a TPM, the
  SSH and signing keys are generated inside it and never exist anywhere
  else. The token is sealed to it, so a copied disk yields nothing.
- **Reaching repos you didn't allow.** The broker refuses any repo the
  allowlist doesn't cover, for git, gh, and GraphQL node IDs. GraphQL
  reads that walk from an allowed repo into another one, through an owner,
  an author, a fork, or a cross-reference, see only names, IDs, numbers,
  titles, and states, never bodies, code, or comments. Of a repo reached
  that way, like a fork's parent, they also see its description, its
  default branch's name, your permission there, and whether it has issues
  and a wiki, which `gh pr create` reads.
- **Merging, approving, and pushing to protected branches.** By default,
  agents can't merge or approve PRs, push the default branch, add labels,
  or rerun or dispatch workflows. You can allow each of these everywhere or
  in one repo. See [Policy](#policy). Whatever the policy says, agents can't
  push a tag or a protected branch other than the default, or update or
  delete branches they didn't create.
- **Workflow injection.** Shai-Hulud committed a workflow to send repo
  secrets out. Over HTTPS, GitHub refuses workflow changes from a token
  without `workflow` scope, and `login` and `install-pat` refuse tokens that have it. Over
  SSH, GitHub doesn't check, so the broker refuses a pushed branch whose new
  commit changes `.github/workflows`.
- **Settings, secrets, and admin.** The broker refuses repo settings,
  rulesets, hooks, deploy keys, secrets and their names, release changes, and
  deletes, and no policy can allow them. Any request not on its lists is
  refused, including whatever GitHub adds later.
- **Commands for bots.** PR and issue text with lines like `/merge` or
  `bors r+` is refused, because bots would take them as your command.
- **Silent fallback to your credentials.** The git config clears every
  other credential helper for github.com, so a request that goes around the
  broker stops instead of falling through to a keyring token or a prompt.

It mitigates these:

- **Agent work looks like yours.** PRs, comments, and pushes show as you,
  so nobody needs to approve anything. Edits are limited to PRs,
  issues, and comments you wrote, so agents can't rewrite a colleague's.
- **A stolen token.** A PAT expires within a year, and `status` warns from
  14 days out. A device-login token doesn't expire. Run `login` again every
  few months, which revokes the old one.
- **Not knowing what happened.** The broker logs every request it allows or
  refuses, with the client's uid and process chain, for example
  `git push origin fix < claude`. Read the log with `journalctl -u hallpass`
  on Linux, or `/var/log/hallpass.log` on macOS. The client controls its
  command line, so treat the chain as a lead, not proof.
- **Signed commits.** With the signing key, commits made through hallpass
  show as Verified on GitHub. That means "made on this machine through
  hallpass", not "you reviewed it". Anything running as you can get a commit
  signed.

It doesn't protect against these:

- **Hostile code using the broker.** Anything running as you
  can ask the broker for whatever its policy allows, in every allowed repo.
  Keep the allowlist to the repos agents need.
- **Your own credentials.** If agents can reach your SSH agent, your
  password manager, or a logged-in gh, they can go around hallpass.
  `git personal` and your own gh are reachable that way too, gated only by
  whatever prompt guards them. Run agents in a sandbox that hides those if
  you need that boundary.
- **Root.** Root can unseal the token on the running machine and use it
  until it's revoked or expires. On macOS, root can read every credential.
- **A compromised setup session.** Setup runs `sudo` from your shell. If code
  running as you replaced `sudo` on your PATH, or edited the checkout you
  build from, it gets root. Install from an attested release binary, from a
  shell you trust, and run `sudo -k` afterward.
- **Code that agents push.** An agent can push a malicious change to a
  branch and open a PR for it. Review PRs before you merge them.
- **Secrets in existing workflows.** Agents can't edit workflows, but a
  workflow that runs on `push` or `pull_request` runs the agent's branch code
  with the secrets it references.
- **Bots the filter doesn't know.** The filter covers common
  triggers, not every bot's grammar.
- **Composite actions.** Like GitHub's, the workflow check covers
  `.github/workflows`, not actions elsewhere in the repo that workflows use.

## How it works

`install` writes `/etc/hallpass/gitconfig` for the credentials that exist and
includes it from each git's system config:

- **git over HTTPS.** github.com remotes, in every form, are rewritten to
  `http://github.com/`, and git reaches them through
  `socks5h://localhost/run/hallpass/git.sock`. HTTPS through hallpass needs
  git 2.47 or later. The tunnel carries plain HTTP, so the broker
  reads each request, rebuilds it, adds the token, and sends it to GitHub over
  TLS. There's no CA and no TCP port.
- **git over SSH.** `core.sshCommand` is `hallpass ssh`. For github.com it
  sends the git command to the broker's socket and relays the data. The
  broker connects to GitHub with its key, checking GitHub's published host
  keys, and runs only `git-upload-pack` and `git-receive-pack`. For any other
  host, `hallpass ssh` runs the real ssh.
- **gh.** `hallpass gh` runs gh with `GH_CONFIG_DIR=/etc/hallpass/gh`, whose
  `http_unix_socket` setting sends gh's requests as plain HTTP to the broker.
  The broker classifies each REST route and GraphQL document against
  GitHub's schema, resolves node IDs to repos, and adds the token.
- **Signing.** `gpg.ssh.program` is `hallpass-sign`, which takes
  `ssh-keygen -Y sign` arguments. For the broker's key it asks the broker,
  which signs only git commits and tags. Everything else goes to the real
  `ssh-keygen`.

When both the token and the SSH key exist, git uses HTTPS, because GitHub
enforces the workflow block there. An allowlist entry can route an owner over
SSH with `--via ssh`, for orgs that block classic PATs but accept SSH keys.

## Policy

Each thing agents may do has a name, like `pr.merge` or `push.default`. A
name covers every way of doing it: the REST route, the GraphQL mutation, and
the git push. Denying `pr.merge` refuses `gh pr merge` and
`gh api -X PUT .../merge` alike. `hallpass policy show` lists them:

| On by default | Off by default |
| --- | --- |
| `pr.create`, `pr.edit`, `pr.request-review`, `issue.create`, `issue.edit`, `assign`, `comment`, `review.comment` | `push.default`, `review.approve`, `review.request-changes`, `pr.merge`, `pr.automerge`, `labels`, `workflow.rerun`, `workflow.dispatch` |

Change them for every repo, or for one allowlist entry:

```sh
sudo /opt/hallpass/bin/hallpass policy allow workflow.rerun
sudo /opt/hallpass/bin/hallpass policy allow push.default pr.merge --repo mbriggs/dots
sudo /opt/hallpass/bin/hallpass policy deny labels --repo acme/*
sudo /opt/hallpass/bin/hallpass policy reset pr.merge --repo mbriggs/dots
hallpass policy show mbriggs/dots     # what's in effect there, and which layer set it
```

The layers apply in order: the defaults, then the global lists, then the
`OWNER/*` entry, then the exact entry. The most specific layer that names an
operation decides it. `allow` prints a warning for the risky operations, among them:

- An approval or change request through hallpass counts as yours.
- `pr.merge` and `pr.automerge` let agents merge with nobody reviewing.
- `workflow.dispatch` lets agents pick the ref and inputs of a workflow
  that often deploys with real secrets.
- `push.default` passes even when `protected_branches` names the default
  branch. Agents still can't delete it, but they can force-push it, because
  the broker can't tell a force push from a fast-forward. Turn on GitHub's
  branch protection if its history matters.

A refusal names the operation and the command that would allow it:

```text
GraphQL: hallpass: agents may not merge PRs or add them to the merge queue in acme/widgets. To allow it: sudo /opt/hallpass/bin/hallpass policy allow pr.merge --repo acme/widgets
```

The settings live in `/etc/hallpass/hallpass.toml` as `allow` and `deny`
lists, at the top level and on each `[[repo]]`.

The broker checks each client's uid against `uids` in the config, from the
kernel's peer credentials. The git config applies to everyone on the machine,
so hallpass suits a machine with one user.

## Use your own credentials

For anything the policy refuses, use your own credentials:

```sh
git personal push            # git without hallpass's config
```

`git personal` runs git with `GIT_CONFIG_NOSYSTEM=1`, so remotes stay as
written and your own SSH key and helpers answer. Plain gh, without
`hallpass gh` or its config dir, uses your own login.

## Set up a machine

The `skills/hallpass-setup` skill walks an agent through setup with you. The
core steps:

```sh
sudo ./hallpass-linux-amd64 install                 # or ./bin/hallpass from make build
sudo /opt/hallpass/bin/hallpass login               # token by device login
sudo /opt/hallpass/bin/hallpass ssh-key create      # optional: add the key on GitHub
sudo /opt/hallpass/bin/hallpass signing-key create  # optional: add as a signing key
sudo /opt/hallpass/bin/hallpass allow 'you/*'
hallpass status --check    # the broker's credentials, checked with GitHub
hallpass doctor            # this machine's git, gh, and signing setup
```

`login` runs GitHub's device flow as root, with GitHub CLI's client ID and
the `repo` scope, so the token goes straight from GitHub into storage. Orgs
that restrict OAuth apps and haven't approved GitHub CLI reject it. For those,
paste a classic PAT with `install-pat` instead.

Release binaries for Linux and macOS, amd64 and arm64, are on the
[releases page](https://github.com/mbriggs/hallpass/releases) with build
provenance. Verify a download before running it as root:

```sh
gh attestation verify hallpass-linux-amd64 --repo mbriggs/hallpass
```

## Commands

Run `hallpass help` for the full list. Root commands go through
`/opt/hallpass/bin/hallpass`, not a copy on your PATH.

| Command | Runs as | Does |
| --- | --- | --- |
| `install` | root | Installs the binary, service, and git and gh config, or upgrades them |
| `login` | root | Gets a token by device login |
| `install-pat` | root | Stores a classic PAT you paste |
| `logout` | root | Removes and revokes the token |
| `ssh-key create\|remove\|show` | root | Manages the SSH key |
| `signing-key create\|remove\|show` | root | Manages the signing key |
| `allow OWNER/REPO [--read] [--via ssh]` | root | Lets agents use a repo, or `OWNER/*` |
| `disallow OWNER/REPO` | root | Removes an allowlist entry |
| `policy allow\|deny\|reset OP... [--repo OWNER/REPO]` | root | Changes what agents may do, everywhere or in one entry |
| `policy show [OWNER/REPO]` | you | Lists the operations, or what's in effect in one repo |
| `uninstall [--purge]` | root | Removes what `install` added. `--purge` also revokes the token and deletes the credentials and config |
| `status [--check]` | you | Reports the broker's state. `--check` also asks GitHub |
| `doctor` | you | Checks this machine's git, gh, and signing setup against the broker |
| `ledger add OWNER/REPO BRANCH` | root | Lets agents update a branch they didn't create |
| `gh ARGS` | you | Runs gh through the broker |

## License

MIT. See [LICENSE](LICENSE).
