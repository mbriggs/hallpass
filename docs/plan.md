# Plan: brokered GitHub credentials

Status: accepted 2026-11-08. Replaces the GitHub App design. Built from a
five-way arena; see "Where this came from" at the end.

## As built

Built on 2026-11-08 and run against real GitHub on Linux. Where this
document and the code in `cmd/` and `internal/` disagree, the code wins.

Planned but not built: the `X-OAuth-Scopes` re-check on
responses, expiry warnings from `hallpass gh` and on pushes, the corpus
capture command, and `hallpass why`.

## Goal

Coding agents work unattended on the user's GitHub repos, including repos in
orgs the user belongs to, without anyone in those orgs approving anything.
Agents run ordinary `git` and `gh`. No credential reaches an agent: the
broker holds every one, uses it itself, and applies one policy to every
request.

The GitHub App goes away entirely: `create-app`, the manifest flow,
`install-key`, JWT signing, token minting, the token-returning credential
helper, `hallpass token`, and the rulesets and CODEOWNERS steps in the repo
skill.

## Three optional credentials

The broker can hold up to three credentials. Each one is optional and turns
on its own features. A machine can have any one, any two, or all three.

| Credential | Lives in | Turns on |
| --- | --- | --- |
| **PAT**: a classic PAT with `repo` scope only and a 90-day expiry, or a `repo`-scoped token from `hallpass login` | TPM-sealed blob on Linux, sealed file on macOS | gh through the broker |
| **SSH key**: ECDSA P-256 generated in the TPM, added to the user's GitHub account as an authentication key | TPM on Linux, sealed file on macOS | git through the broker |
| **Signing key**: ECDSA P-256 generated in the TPM, added as a signing key | TPM on Linux, sealed file on macOS | signed commits and tags, shown as Verified on GitHub |

What each combination gives:

| PAT | SSH | Signing | git | gh | Commits |
| --- | --- | --- | --- | --- | --- |
| yes | | | refused, with a pointer to `ssh-key create` | yes | unsigned |
| | yes | | yes | no | unsigned |
| yes | yes | | yes | yes | unsigned |
| any | any | yes | as above | as above | signed |
| | | yes | not brokered | no | signed |

git goes over SSH only. With the PAT and no SSH key, the git config still
sends github.com to the broker, which refuses git and says to create a key,
so git can't fall through to the user's own credentials. See "Decisions"
for why HTTPS git went away.

Each credential gets its own root command that creates or installs it and
prints what the user adds on GitHub:

- `sudo hallpass login` (device login, like `gh auth login`) or
  `sudo hallpass install-pat` (paste a classic PAT)
- `sudo hallpass ssh-key create`, which prints the public key to add under
  SSH and GPG keys as an **authentication** key
- `sudo hallpass signing-key create`, which prints the public key to add as a
  **signing** key

The keys also have `remove`, and the PAT has `logout`. `install` writes git and gh config for whatever is
present, and the commands above rerun that step.

## Trade-offs of dropping the App

- **Only the broker limits scope.** The PAT and SSH key reach every repo the
  user can reach. The allowlist in `/etc/hallpass/hallpass.toml` is the only
  limit on which repos agents use, so a bug there exposes all of them.
- **Agents act as the user everywhere.** On personal repos too, so the user
  can't approve agent PRs. The broker refuses approvals and merges unless
  `hallpass policy` turns them on, and the user merges with their own
  credentials.
- **The PAT is weaker against root than a key.** Root on the running machine
  can unseal it and use it elsewhere until it expires. The SSH and signing
  keys are generated in the TPM and can't leave it, even for root.

## How it works

The broker listens on two Unix sockets beside `hallpass.sock`, all behind
the peer-uid check. Only the sockets for credentials that are present serve
anything; the others answer with "this machine has no <credential>".

- **gh** uses its own `http_unix_socket` config key, which sends plain
  HTTP/1.1 over the socket even for `https://` URLs. go-gh sets both
  `DialContext` and `DialTLSContext` to the same Unix dial. Verified by
  running gh 2.98 against a capture listener.
- **git** goes over SSH only. Every github.com remote form is rewritten to
  `ssh://git@github.com/`, and git uses `core.sshCommand = /opt/hallpass/bin/hallpass ssh`.
  For github.com, the wrapper sends the service and repo from the remote
  command (`git-upload-pack 'acme/widgets.git'`) to the broker and relays
  stdin and stdout. The broker opens the SSH connection to GitHub with its
  own key, runs exactly that command, and sees the git protocol in the clear.
  For any other host the wrapper runs the real `ssh` unchanged.
- **Signing** uses `gpg.format = ssh` and
  `gpg.ssh.program = /opt/hallpass/bin/hallpass-sign`, a link to the binary,
  because git runs that program without arguments of its own. git calls it
  with the same arguments as `ssh-keygen -Y sign`. The wrapper sends the
  buffer to the broker and writes back the signature.

For gh, the broker parses each request strictly, classifies it,
checks policy, builds a fresh upstream request from what it parsed, adds the
PAT, and sends it to GitHub over TLS with system roots. There's no CA, no
keychain trust, no TCP port, and no per-run secret, on either platform.

```
agent ── gh ────(http_unix_socket, plain HTTP)──────────▶ gh.sock   ─┐
agent ── git ───(hallpass ssh: command + stdio)─────────▶ ssh.sock  ─┤
agent ── git ───(hallpass-sign: buffer)──────────────────▶ hallpass.sock (JSON, also status)
                                                                     ▼
          broker: peer uid → parse → classify → resolve → decide → audit
                  → PAT over HTTPS for gh, or the TPM SSH key over SSH for git
```

If a client skips the routing, its request reaches GitHub with no credential.
That's the property everything else rests on: client config only routes, and
policy lives in the broker.

### Sockets

Separate sockets rather than one that sniffs the first byte, so each listener
rejects everything that isn't its one protocol.

| Socket | Linux | macOS | Speaks |
| --- | --- | --- | --- |
| `hallpass.sock` (exists) | `/run/hallpass/hallpass.sock` | `/var/db/hallpass/run/hallpass.sock` | one JSON request: `status` or `sign` |
| `gh.sock` | `/run/hallpass/gh.sock` | `/var/db/hallpass/run/gh.sock` | HTTP/1.1, `Host: api.github.com` only |
| `ssh.sock` | `/run/hallpass/ssh.sock` | `/var/db/hallpass/run/ssh.sock` | one JSON header line, then git's stdin. Back: framed stdout, stderr, and exit status |

On Linux they're socket units with `FileDescriptorName=` and
`Service=hallpass.service`. `install` removes `hallpass-git.socket`, which
earlier versions used for HTTPS git. `Listen` picks fds by `LISTEN_FDNAMES`. On macOS
the broker binds them itself.

### Config

```toml
uids = [1000]
protected_branches = ["main", "master", "release/*", "production"]
allow = ["workflow.rerun"]   # operations, for every repo; see Policy
deny = ["labels"]

[token]
secret = "tpm:/var/lib/hallpass/token-1762600000.tpm"   # or "file:..."
source = "pat"          # or "login"
login = "mbriggs"
created = 2026-11-08T00:00:00Z
expires = 2027-02-06T00:00:00Z   # absent for device-login tokens

[ssh]
key = "tpm:/var/lib/hallpass/ssh-1762600000.tpm"
public = "ecdsa-sha2-nistp256 AAAA... hallpass@kant"

[signing]
key = "tpm:/var/lib/hallpass/signing-1762600000.tpm"
public = "ecdsa-sha2-nistp256 AAAA... hallpass-signing@kant"

# Repos agents may use. Most specific match wins.
[[repo]]
match = "mbriggs/*"

[[repo]]
match = "mbriggs/dots"
allow = ["push.default", "pr.merge"]   # overrides mbriggs/* and global

[[repo]]
match = "acme/*"

[[repo]]
match = "acme/payments"
access = "read"
```

Only root edits it, through `allow`, `disallow`, `policy`, and the credential
commands.
Matching ignores case. With no `[[repo]]` entries, nothing is reachable.

### Routing

`install` generates `/etc/hallpass/gitconfig` from the config. With the PAT
or the SSH key:

```ini
[url "ssh://git@github.com/"]
	insteadOf = https://github.com/
	insteadOf = git@github.com:
	insteadOf = ssh://git@github.com/
[core]
	sshCommand = /opt/hallpass/bin/hallpass ssh
[ssh]
	variant = ssh
[credential "https://github.com"]
	helper =
	helper = /opt/hallpass/bin/hallpass credential
[credential "http://github.com"]
	helper =
	helper = /opt/hallpass/bin/hallpass credential
[alias]
	personal = "!GIT_CONFIG_NOSYSTEM=1 git"
```

The wrapper passes non-GitHub hosts to the real `ssh`. `ssh.variant = ssh`
makes git pass `-p` and `GIT_PROTOCOL` to the wrapper. gh's remote parsing
ignores the scheme, so `ssh://` remotes resolve for `gh pr create`. The credential helper answers every github.com
request with `quit=1` and "it went around the hallpass broker", so a
bypassed request fails instead of prompting.
`git personal` skips the system config, as today.

With the PAT, gh runs with `GH_CONFIG_DIR=/etc/hallpass/gh`: root-owned,
`config.yml` with `version: "1"`, `http_unix_socket: <gh.sock>`,
`git_protocol: https`, `prompt: disabled`, `telemetry: disabled`, and a
`hosts.yml` with a placeholder token so gh thinks it's logged in.
`version: "1"` matters: without it gh tries to migrate the read-only file and
exits. `hallpass gh ARGS` is a thin wrapper that sets that, unsets
`GH_TOKEN`, `GITHUB_TOKEN`, `GH_HOST`, and the other token variables, and
runs gh. Agents can also get brokered plain `gh` with
`GH_CONFIG_DIR=/etc/hallpass/gh` in their environment. Without the PAT,
`hallpass gh` refuses: "gh through hallpass needs a token".

Routing everything costs two things: a network that blocks port 22 can't
reach GitHub through the broker, and git LFS doesn't work through it. Use
`git personal` for LFS repos.

## Policy

One policy covers every brokered request, whatever credential carries it.

Hard denies are Go code that no config can lift. The rest is a Go rules table,
keyed on GitHub's schema names (mutation and root field names, types), not on
gh's query text. gh produced four different `PullRequestByNumber` documents in
one capture session, so query-text allowlists would break every release.

### What agents may do in an allowed repo

Always, in a repo with write access:

- Read code, PRs, issues, comments, reviews, checks, statuses, Actions runs,
  jobs, and logs.
- Clone and fetch.
- Create branches, except `protected_branches`. Update, force-push, or
  delete only branches the broker saw this machine create (the branch
  ledger, below).

Everything else agents write is an operation with a name, which the config
turns on or off (`internal/op`). One name covers every way of doing the
operation: the REST route, the GraphQL mutation, and the git push. A request
names every operation it does, and the repo's config must allow each one.
`createIssue` with `labelIds` needs both `issue.create` and `labels`.

On by default:

| Operation | Covers |
| --- | --- |
| `pr.create` | PRs from a branch in the same repo |
| `pr.edit` | edit, close, reopen, ready, draft, on PRs the user authored |
| `pr.request-review` | review requests on PRs the user authored |
| `issue.edit` | edit, close, reopen, on issues the user authored |
| `comment` | comments on any PR or issue, edits of the user's own |
| `review.comment` | comment-only and pending reviews, review comments, thread resolution |

Off by default:

| Operation | Covers | Why it's off |
| --- | --- | --- |
| `issue.create` | open issues | issues show as the user's, and in a public repo anyone can read them |
| `assign` | assign people to PRs and issues the user authored, and `assignees`/`assigneeIds` on create and edit | GitHub notifies each person assigned |
| `push.default` | create or update the default branch, even if `protected_branches` names it; never delete | force pushes look like fast-forwards to the broker |
| `review.verdict` | approve or request changes | they count as the user's |
| `pr.merge` | merge, merge queue (no `jump`), auto-merge on or off | merges with nobody reviewing |
| `labels` | add or remove labels, `labels`/`labelIds` on create and edit | many orgs use labels like `automerge` or `safe-to-test` as approvals |
| `workflow.rerun` | rerun a run, its failed jobs, or a job | reruns get the run's secrets |
| `workflow.dispatch` | dispatch a workflow by id or file name | agents pick the ref and inputs of what is often a deploy |

The config has `allow` and `deny` lists at the top level and on each
`[[repo]]` entry. The layers apply in order: defaults, global, `owner/*`,
exact. The last layer that names an operation decides it. One layer can't
both allow and deny an operation, and an unknown name fails validation, so a
typo in `deny` can't quietly deny nothing. `access` still comes from the
most specific entry alone.

`hallpass policy allow|deny|reset OP... [--repo MATCH]` edits a layer, and
prints a warning when it allows a risky one. Naming a repo that only
`OWNER/*` covers adds an exact entry with the wildcard's access, and a
`reset` that leaves that entry with no policy offers to remove it. `hallpass policy show [OWNER/REPO]`
prints what's in effect and which layer decided each operation, which is
also how to see whether a narrower entry overrides a change. Refusals
name the operation and the command that would allow it.

### Hard denies

These have no operation name, so no config can lift them.

- Dismissing reviews, and review events GitHub may add.
- `update-branch`, revert, jumping the merge queue.
- Ref writes outside a checked push: `createCommitOnBranch`, `createRef`,
  `updateRef(s)`, `deleteRef`, REST `git/refs`, contents `PUT`/`DELETE`.
- Deleting the default branch. Pushes to `protected_branches` other than
  the default branch, tags, anything outside `refs/heads/`, signed pushes,
  push options.
- Settings, rulesets, protections, collaborators, teams, hooks, deploy keys,
  environments, secrets and variables (names included), releases, uploads,
  workflow cancels, deletes, transfers, projects, discussions.
- Lines that work as ChatOps commands from the user: lines starting
  with `/` or `bors`, and mentions of bots like `@mergifyio` and
  `@dependabot`. This list can't be complete.

git pushes don't use the PAT, so its missing `workflow` scope doesn't stop
workflow changes. The broker's pack check over SSH does (see "Workflow
check over SSH").

### Classifying REST

Reads match an allowlist of path patterns under `/repos/{owner}/{repo}`,
plus `/user`, `/rate_limit`, and search. Writes match a table of method and
path, each naming its operation. Everything else is refused, including
routes GitHub adds later. The broker reads the raw request target and
rejects `%`, `\`, `;`, `#`, `//`, dot segments, spaces, control bytes, and
non-ASCII before matching. `{owner}/{repo}` goes through `github.ParseRepo`.
Reads pass their query string re-encoded from the parse. Writes refuse one.
Write bodies are decoded strictly (no duplicate or unknown keys) and
re-encoded.

Search (`GET /search/issues`) is allowed only with exactly one `repo:`
qualifier naming a reachable repo, no `org:`, `user:`, or `owner:`, no
quotes, and no boolean operators.

Run logs and artifacts (`.../actions/runs/{id}/logs`,
`.../actions/jobs/{id}/logs`, `.../artifacts/{id}/zip`): the broker follows
GitHub's 302 itself, once, without the PAT, only to hosts ending in
`.actions.githubusercontent.com`, `.blob.core.windows.net`, or
`objects.githubusercontent.com`, and streams the body back. gh never reaches a
non-GitHub host through the socket.

### Classifying GraphQL

This is the largest piece.

1. **Parse and validate.** One JSON object with `query`, `variables`,
   `operationName`. Parse with `github.com/vektah/gqlparser/v2` and validate
   against GitHub's public schema, embedded and refreshed with `make schema`
   (see "When gh or GitHub changes").
   Validation skips gqlparser's overlapping-fields rule, because gh sends
   queries GitHub accepts that fail it. Refuse arrays (batches), more than
   one operation, subscriptions, directives other than `@include`/`@skip`
   (both branches get checked), and anything that fails validation,
   including fields hallpass's schema copy lacks.
2. **Limit.** Coerce the variables, walk fragments where they're spread, and
   refuse more than 25 levels or 5,000 fields.
3. **Roots.** Allowed: `repository(owner, name)` for a reachable repo;
   `node`/`nodes` whose IDs resolve into one; `viewer` (identity only);
   `search` under the REST search rule; `rateLimit`; `__typename`; and
   introspection (`__type`, `__schema`). gh sends `__type` probes at runtime
   to pick fields, so refusing introspection breaks `gh pr view`. The schema
   is public, so allowing it leaks nothing.
4. **Walk with views.** Under an allowed root the view is `Full`. Edges to
   repos, accounts, teams, and projects (`owner`, `author`,
   `headRepository`, `forks`) drop to `Identity`. Edges to repo content
   (types with a `repository` field) keep `Full` only in a mutation's
   payload or when a hand-written table says GitHub keeps them in the same
   repo, like `PullRequest.comments`. Others drop to `Identity`, so new
   GitHub fields can't open a path to other repos. That catches
   cross-references a rule on repo types alone would miss:
   `CrossReferencedEvent.source` is an `Issue`. `Identity` allows identity
   scalars (`id`, `login`, `nameWithOwner`, `url`, `number`, `title`,
   `state`, counts, pagination), an `owner` hop, and the members of a
   connection it was given, but no new connection.
5. **Mutations.** Every root field must be in the mutation table, with an
   allowlist of input fields. Each table entry names the input fields that
   bind it to a repo (`repositoryId`, `pullRequestId`, `subjectId`, ...) and
   any extra rule (a review event other than `COMMENT` needs its operation,
   author must be the user, `headRepositoryId` must equal `repositoryId`).
   gh passes every mutation as `input: $input`.
6. **Resolve node IDs.** One batched `nodes(ids:)` query with the PAT asks
   each ID's `__typename`, repo, and `viewerDidAuthor` (`resolveQuery` in
   `internal/proxy/gh.go`). The type must match what the mutation expects.
   Null, error, or timeout means deny. Cache results for an hour. Don't
   decode IDs locally; the format is undocumented.
7. **Forward what was checked.** Print the parsed document back to text and
   re-encode the coerced variables. GitHub receives the document the broker printed,
   so parser differences can't change its meaning.

Refusals come back as HTTP 200 with
`{"errors":[{"type":"FORBIDDEN","message":"hallpass: ..."}]}`, which gh
prints as `GraphQL: hallpass: ...`.

### Checking pushes

git reaches the broker only over SSH (see "The SSH key"). For receive-pack,
the broker reads the client's pkt-lines up to the first flush through a
64 KiB bounded reader. It refuses `push-cert`, push options, shallow
pushes, and unknown capabilities. Each `<old> <new> <ref>`:

- must be `refs/heads/<name>`, with `<name>` passing `check-ref-format` rules
- the default branch (read from HEAD in a second upload-pack session over
  the same connection; a failed lookup denies): only with `push.default`,
  and never deleted
- any other branch in `protected_branches`: refused
- `old` all zeros (create): allowed
- otherwise (update, force, or delete): only a ledger branch, and only
  when `old` is the commit the ledger has for it
- a ref named twice in one push: refused

If any command fails, nothing goes upstream. The broker answers with a
synthesized report-status, side-band framed when negotiated, so git prints
`! [remote rejected] main -> main (hallpass: main is the default branch)`.

If every command passes, the broker sends its re-encoded commands, then
the pack. It reads GitHub's report-status as it relays it
and, for each `ok` ref other than the default branch, records the new
commit in the ledger, or removes the branch for a delete.

The branch ledger is `<StateDir>/branches.jsonl`, append-only, written only
after GitHub confirms, and the last line for a branch wins. Each line holds
the commit an agent last pushed. GitHub applies a ref update only if the ref
still has `old`, so a branch the user pushed to, or deleted and made again
at another commit, no longer matches, and agents can't overwrite it. The
broker sees only commits, not who made a ref. A branch the user recreates
at the agent's last commit still matches and stays the agent's, which
loses no work of the user's. Lines written before
commits were recorded match no push. `sudo hallpass ledger add OWNER/REPO
BRANCH COMMIT` lets agents push to a branch while it points at COMMIT, and
the push refusal prints that command with the commit filled in. The model
in `verify/branch-ledger` checks this.

### Upstream

- Inbound headers pass a short allowlist, such as `Accept` and
  `User-Agent`. Client `Authorization` and `Cookie` never pass.
- API calls get `Authorization: token <PAT>`. The upstream client never
  follows redirects.
- Response headers pass an allowlist too, which leaves out `Set-Cookie` and
  `X-OAuth-Scopes`. The broker strips `temp_clone_token` from REST and
  refuses it in GraphQL.
- GitHub 401 becomes 403 "GitHub rejected hallpass's token. It expired or
  was revoked. Run sudo /opt/hallpass/bin/hallpass login, or install-pat."
- A response with `X-GitHub-SSO: required; url=...` becomes "this org
  requires SAML SSO authorization for hallpass's token. Open <url>".
- The PAT shares the user's 5,000 requests an hour. The broker refuses gh
  requests with 429 when `X-RateLimit-Remaining` drops below 1,000, so the
  user's own gh keeps working.
- One audit line per request: decision, reason, socket, method, repo, REST
  route or GraphQL root and mutation names, refs for pushes, upstream status,
  uid, pid, process chain. Bodies and the PAT never reach the log.

## The PAT

There are two ways to get the token into the broker. Both store it the same
way and turn on the same features.

### `hallpass login`: brokered device login

`sudo /opt/hallpass/bin/hallpass login` runs GitHub's OAuth device flow as
root, the way `gh auth login` does, using GitHub CLI's public client ID and
asking for scope `repo` only:

1. `POST https://github.com/login/device/code` with the client ID and
   `scope=repo`.
2. Print the one-time code and https://github.com/login/device. The user
   opens it in any browser, on any machine, and approves.
3. Poll `POST https://github.com/login/oauth/access_token` at the interval
   GitHub gives, until it returns the token or the code expires.
4. Check and store it exactly as `install-pat` does (steps 3 and 4 below),
   except that an OAuth token (`gho_`) has no expiry header.

The token goes from GitHub's API into the TPM inside one root process. It
never touches the clipboard, a file, or a process the user owns.

The costs:

- **It borrows GitHub CLI's identity.** The authorization shows as GitHub CLI
  under the user's authorized OAuth apps and in org audit logs, which is why
  orgs that approved GitHub CLI accept it without asking anyone. An org that
  restricts OAuth apps and hasn't approved GitHub CLI rejects it. Classic PATs
  aren't subject to that restriction, so `install-pat` still works there.
  GitHub could also object to a tool reusing another app's client ID.
- **It doesn't expire.** OAuth app tokens have no expiry. `status` shows its
  age and suggests `login` again after 90 days.
- **Revoking it is coarse.** Per-token revocation needs GitHub CLI's client
  secret, which hallpass doesn't have. Revoking the GitHub CLI authorization
  on github.com also logs the user's own gh out. `POST /credentials/revoke`
  takes the token value and works, so `login` again and `uninstall --purge`
  use that for the old token.

### `install-pat`: a token the user creates

`sudo /opt/hallpass/bin/hallpass install-pat`, run in the user's own
terminal or piped from `op read`:

1. Prints a prefilled creation link
   (`https://github.com/settings/tokens/new?scopes=repo&description=hallpass-<host>`)
   and the SSO step.
2. Reads the token from the tty with echo off, or from stdin. Never argv or
   env.
3. Calls `GET /user` with it and refuses unless: the prefix is `ghp_` (or
   `gho_` from `login`);
   `X-OAuth-Scopes` is exactly `repo`; `GitHub-Authentication-Token-Expiration`
   is present and at most 366 days out (warn past 90); the login matches the
   previous PAT's, unless `--new-login`.
4. Stores it. On Linux with a TPM, sealed under the SRK, so a copied disk
   blob is useless. On macOS, AES-256-GCM-encrypted under a key derived
   from a random machine secret, the serial number, the hardware UUID, and
   the data volume UUID (`internal/keys/sealed.go`). Otherwise a 0600 file
   owned by the service user. The
   config points at the new one only after it's stored.
5. Revokes the old PAT with `POST /credentials/revoke`, unless `--keep-old`.

`status` shows login and days left, and warns from 14 days. `status --check`
fails when GitHub rejects the PAT or its scopes aren't exactly `repo`.

## The SSH key

`sudo hallpass ssh-key create` generates an ECDSA P-256 key inside the TPM
(`go-tpm-keyfiles` under the SRK, saved as a TSS2 key file, like
`ssh-tpm-agent`), prints the public key with a title, and links to
https://github.com/settings/ssh/new. For SSO orgs the user authorizes the
key on GitHub. On macOS it's a sealed file owned by the service user,
encrypted the same way as the PAT.
`status --check` runs the `ssh -T` equivalent against GitHub and reports the
login.

### The wrapper

git runs `hallpass ssh [options] git@github.com git-upload-pack 'acme/widgets.git'`
(`-o SendEnv=GIT_PROTOCOL` and `-p` appear too). The wrapper:

- For a host other than `github.com`, runs the real `ssh` with the same
  arguments.
- For `github.com`, accepts only user `git` and a command of
  `git-upload-pack '<path>'` or `git-receive-pack '<path>'`, connects to
  `ssh.sock`, and sends `{"service": ..., "repo": ..., "git_protocol": ...}`.
  It then copies stdin to the broker and the broker's frames to stdout,
  stderr, and its exit status. It never holds a key.

### In the broker

1. Peer uid check, then parse the repo name. The repo must be allowed, with
   `access = "write"` for receive-pack.
2. Open an SSH connection to `github.com:22` with `golang.org/x/crypto/ssh`,
   signing with the TPM key through `crypto.Signer`. GitHub's published host
   keys are embedded in the binary; a mismatch refuses.
3. Run exactly the parsed command, with `GIT_PROTOCOL` set only to
   `version=2` or nothing.
4. upload-pack: relay both directions.
5. receive-pack: relay GitHub's ref advertisement, adding `no-thin` to its
   capabilities so the pack the client sends is self-contained. Read the
   client's commands with the same pkt-line reader and `CheckPush`, taking
   the default branch from HEAD in a second upload-pack session. Then read
   the pack and check it for workflow changes (below). If anything is
   refused, discard the rest of the pack and answer with a synthesized
   report-status. A push of only deletes carries no pack, so there's
   nothing to discard: git waits for the answer with stdin still open.
   Until 2026-11-08 the gate drained anyway, and every refused delete over
   SSH hung. Otherwise forward the commands and the pack, and relay
   GitHub's report-status, recording ledger entries.

### Workflow check over SSH

GitHub doesn't refuse workflow changes over SSH, and git pushes never use
the PAT, whose missing `workflow` scope would stop them over HTTPS. So the
broker's own check is the only guard:

1. Index the pack: parse every object, resolving deltas, and keep commits
   and trees. `no-thin` means every delta base is inside the pack.
2. GitHub runs a push's workflows from the commit the ref ends at, so check
   that commit, whether it's in the pack or already on GitHub. Its
   `.github/workflows` entry (mode and ID) must match the entry at the ref's
   old commit or at the default branch's head. The second covers rebasing
   onto a main whose workflows someone else changed.
3. Objects the comparison needs that aren't in the pack come from a blobless
   fetch: upload-pack v2 `fetch` with `want <commit>`, `deepen 1`,
   `filter blob:none`, over the same SSH key.
4. Commit headers are read like git: tree first, parents right after. A
   tree or parent line anywhere else refuses the push.
5. A mismatch refuses the push: "agents can't change .github/workflows. Push
   that change yourself with git personal push". The pack is capped at
   512 MiB; a bigger push can't be checked and is refused.

This is the most delicate code in the broker, and every push runs it.

## Signing

`sudo hallpass signing-key create` generates a second TPM key, prints the
public key, and links to https://github.com/settings/ssh/new with the key
type set to Signing. It's separate from the SSH key so each can be revoked
alone.

`install` adds to the generated gitconfig:

```ini
[gpg]
	format = ssh
[gpg "ssh"]
	program = /opt/hallpass/bin/hallpass-sign
	allowedSignersFile = /etc/hallpass/allowed_signers
[user]
	signingkey = /etc/hallpass/signing.pub
[commit]
	gpgsign = true
[tag]
	gpgsign = true
```

git calls `hallpass-sign -Y sign -n git -f /etc/hallpass/signing.pub <file>`
and expects `<file>.sig`. The wrapper:

- For `-Y sign` with namespace `git` and a key file holding the broker's
  public key, sends the buffer to the
  broker's `sign` op and writes the armored SSHSIG it gets back.
- For anything else (`-Y verify`, `-Y find-principals`,
  `-Y check-novalidate`, or another key), runs the real `ssh-keygen` with the
  same arguments, so verification and the user's own keys work as before.

The broker signs only namespace `git`, and only a buffer that parses as a
commit or tag object. It logs the object's kind, first message line, uid,
and process chain. Anything running as the user can get commits signed this way,
so Verified means "made on this machine through hallpass", not "the user
reviewed it". The README says so.

The user's global config wins over the system config, so a global
`gpg.ssh.program` (here, `op-ssh-sign` in dots `dev/.gitconfig`) would
override hallpass's. The setup skill moves the user's own signing settings
into a file the `git personal` alias includes, so personal commits still
sign with 1Password and everything else signs through hallpass.

## Linux and macOS

| | Linux | macOS |
| --- | --- | --- |
| Sockets | socket units with `LISTEN_FDNAMES` | broker binds under `/var/db/hallpass/run` |
| PAT at rest | TPM-sealed, or 0600 file without a TPM | sealed 0600 file. A launchd daemon can't use the Secure Enclave, so root can decrypt it. Excluded from Time Machine. |
| SSH and signing keys | generated in the TPM | sealed 0600 files. Root can decrypt them. |
| git | any distro git | Apple git or Homebrew git. Homebrew git reads its own `$(brew --prefix)/etc/gitconfig`. |
| Include | `git config --system` with root's git | every git found: the one on `PATH`, `/usr/bin/git` only if `xcode-select -p` succeeds (otherwise it opens the CLT installer), `/opt/homebrew/bin/git`, `/usr/local/bin/git` |
| Logs | journald | `/var/log/hallpass.log`, plus `/etc/newsyslog.d/hallpass.conf`, since per-request lines grow faster |

SSH routing works with any git.

## Failure modes

| Failure | Result |
| --- | --- |
| Broker down | git can't reach the SSH socket, and gh can't dial. Neither holds a credential, so nothing falls back. |
| Client skips routing (`-c core.sshCommand=ssh`, own `GH_CONFIG_DIR`, `curl`) | The request reaches GitHub with no hallpass credential. Over SSH it may reach the user's own ssh-agent, which is outside hallpass's scope, as today. |
| Credential missing | Its socket refuses with "this machine has no <credential>; run sudo hallpass <command>". git with only a PAT is refused this way, with `ssh-key create`. |
| Repo not allowed | Refused, naming the repo and `sudo hallpass allow`. |
| Unknown route, mutation, edge, or schema field | Deny, naming what was missing. |
| Node ID or default-branch lookup fails | Deny. |
| Malformed pkt-line, odd encoding, push-cert | Deny. |
| GitHub host key mismatch | SSH refused, logged as an error. |
| Pack can't be indexed, or a parent fetch fails | Push refused. |
| Ledger write fails after a push | Memory has the new commit until the broker restarts. After that the ledger has the previous one, and updates are refused with `ledger add` in the message. |
| PAT expired, revoked, or SSO missing | The messages in "Upstream". No fallback. |
| Signing request isn't a commit or tag | Refused, and git reports the signing failure. |
| Another local uid | Refused by the uid check. |

## Changes to hallpass

| Area | Change |
| --- | --- |
| delete | `internal/appflow`, `create-app`, `install-key`, App JWT and `Mint` in `internal/github`, the `token` op, `hallpass token`, `client.Token`, `RepoFromRemote`, the App-key import in `internal/keys` |
| `internal/config` | `[token]`, `[ssh]`, `[signing]`, `[[repo]]`, `protected_branches`, the `allow` and `deny` layers, validation, `Allowed(repo)` with access and operations |
| new `internal/peer` | peer credentials and the process chain, moved out of `internal/broker` |
| `internal/broker` | `status` lists credentials and their state; new `sign` op; `LISTEN_FDNAMES` in `Listen` |
| new `internal/op` | operation names, defaults, and warnings |
| new `internal/policy` | pure classification: REST table, GraphQL walk and tables, embedded schema, pkt-line and receive-pack parsing, report-status synthesis, hard denies |
| new `internal/proxy` | gh: listener, HTTP framing rules, header filters, upstream client, error mapping, redirect follow, rate reserve, audit |
| new `internal/sshgate` | git over SSH: the branch ledger, command parse, GitHub host-key pinning, session relay, `no-thin`, pack indexing, workflow check, blobless fetch |
| new `internal/sign` | SSHSIG signing, commit and tag object check |
| `internal/keys` | TPM: generate P-256 keys, seal and unseal the PAT; sealed backend for macOS; file backend for Linux without a TPM |
| `internal/client` | `Credential` always answers `quit=1` with a hint |
| `internal/system` | generated gitconfig per credential, `/etc/hallpass/gh`, socket units, `allowed_signers`, multi-git include and `xcode-select` guard on macOS, newsyslog, uninstall |
| `cmd/hallpass` | `login`, `install-pat`, `logout`, `ssh-key` and `signing-key` `create/remove/show`, `allow [--read]`, `disallow`, `policy`, `ledger add/list`, `ssh`, `sign` and the `hallpass-sign` link; `gh` becomes the env wrapper; `status` lines |
| `go.mod` | add `github.com/vektah/gqlparser/v2`, `golang.org/x/crypto`, `golang.org/x/term`, `github.com/foxboron/go-tpm-keyfiles` |

## Skills and README

- `hallpass-setup` asks which credentials the user wants and walks through
  each: the PAT from the link with only `repo` and 90 days, run in their own
  terminal; the SSH key added as an authentication key; the signing key added
  as a signing key; SSO authorization per org for the PAT and SSH key. It
  checks every git with `type -a git`, and moves the user's own signing
  config into `git personal` when they choose hallpass signing.
- `hallpass-repo` becomes short: `allow` the repo or owner, choose `--read`, list workflows that run agent branches with secrets, and
  list bot configs (`.mergify.yml`, `bors.toml`, Prow `OWNERS`, workflows on
  `issue_comment`), since hallpass's ChatOps list is fixed. No App install, no
  rulesets, no CODEOWNERS.
- README: rewrite "What it prevents and mitigates" for the brokered design.
  Agent work shows as the user; the allowlist is the scope; same-uid code can
  do what the policy allows; existing workflows run agent branches with
  secrets; ChatOps blocking is incomplete; Verified means "made here"; root
  can read the PAT, and on macOS the keys.

## Verification

**Done.** gh over `http_unix_socket` sends plain HTTP.

**Corpus, offline, in CI.** `make corpus GH=<gh>` runs `tools/ghcorpus`,
which runs about 35 gh commands against a stub socket that answers `{}`, with
no token and no network. It writes
`internal/policy/testdata/gh-<version>-capture.jsonl`, each request tagged
with the command that sent it. `TestGHCorpus` replays every capture file and
fails on any request hallpass refuses, so CI checks them without gh
installed. gh stops early on some commands once it reads `{}`, so a capture
covers the requests up to that point.

**When gh or GitHub changes.** hallpass refuses what it doesn't recognize,
so API changes break commands rather than open holes. Two things drift:

- gh releases change the queries and routes gh sends. For each gh release
  agents use, run `make corpus GH=<new gh>` and commit the new capture. A
  failure names the gh command and the field or route refused. Decide
  whether the policy should allow it, or whether the refusal is right and
  the command stays unsupported. Delete a capture once no machine runs that
  gh version.
- GitHub's schema gains fields gh starts asking for, which fail validation
  until the embedded copy has them. `make schema` fetches GitHub's
  published schema, writes it over the embedded copy, and lists new fields
  by kind. Read the new scalar and object fields before committing: agents
  can read them in an allowed repo, so a new secret belongs in
  `deniedFields`. `TestTablesMatchSchema` fails if a policy table names a
  type or field GitHub removed.

After either, extend the verify-hallpass fake for the commands that
changed (see its `gh-graphql.md`).

**Attack tests.** Literal requests for each known attack: GraphQL aliasing,
batching, fragments under `viewer`, variables hiding `APPROVE`, node IDs from
another repo, nested traversal through `owner`, `author`, `forks`, and
cross-references; REST encoding, case, and `/repositories/{id}` paths;
smuggling and h2c; pkt-line push-cert, push options, deletes, tags; SSH
commands other than the
two git ones, quoted paths with `'`, thin packs, packs with a workflow change
hidden in a delta, a revert of a workflow file to an older blob; signing
requests that aren't commits. Fuzz the pkt-line parser, ref-name validator,
raw-path parser, pack indexer, and GraphQL normalizer.

**Integration, in CI on Linux and macOS, no credentials.**

- git: the upstream is a local `golang.org/x/crypto/ssh` server running real
  `git-upload-pack` and `git-receive-pack` over bare repos, with its host key
  pinned in the test. Real git clones, fetches, pushes a branch, and
  force-pushes it. It's refused on the default branch, a tag, a delete, a
  colleague's branch, and a workflow change, asserting the
  `! [remote rejected]` text and that the bare repo didn't change. A second
  repo with `push.default` takes a push to a protected `main` and refuses
  deleting it.
- gh: real gh runs the corpus commands against canned GraphQL and REST.
- Signing: real git commits with `commit.gpgsign`, and `git verify-commit`
  passes against `allowed_signers`.
- Bypass: broker stopped, `GIT_TERMINAL_PROMPT=0` shows nothing prompted.

**Live, run by the user.** A scratch org the user owns, with an allowed
private repo (`target`, with a protected `main` and a workflow) and one that
isn't (`canary`):

1. `install-pat` refuses a token with `workflow`, then accepts a `repo` one.
2. Clone, push a branch, force-push it.
   Default-branch push, tag push, delete, and a workflow-file push are each
   refused.
3. `hallpass gh pr create`, `pr view`, `pr list`, `pr comment`,
   `pr review --comment`, `pr checks`, `run view --log`, `issue create`
   work. `pr review --approve`, `pr merge`, `pr merge --auto`,
   `pr comment --body '/merge'`, and any write to `canary` are refused.
4. A GraphQL query reaching `canary` through nesting is refused.
5. A commit pushed through hallpass shows Verified on GitHub.
6. `canary` is unchanged afterward, and no review in `target` is approved.
7. `grep -r ghp_` across `~`, `/tmp`, agent transcripts, and `ps eww` during
   a push finds nothing.
8. Repeat 2 and 3 on macOS with Apple git and Homebrew git.

## Build order

| # | Piece | Size |
| --- | --- | --- |
| 1 | Delete the App code; `internal/peer`; config with the three credentials and `[[repo]]`; `status` | −900, +350 |
| 2 | `internal/keys` TPM key generation and PAT sealing; `install-pat`, `ssh-key`, `signing-key` commands | 600 |
| 3 | `internal/policy` git parsing and push checks (started), corpus harness | 600 |
| 4 | `internal/proxy` for HTTPS git (removed 2026-11-08), generated gitconfig, credential helper change | 900 |
| 5 | Signing: `internal/sign`, `hallpass sign`, gitconfig, integration test | 400 |
| 6 | REST table, search rule, redirect follow, `hallpass gh`, `/etc/hallpass/gh` | 700 |
| 7 | GraphQL: validate, normalize, roots, edge table, mutation table, resolver, print | 1,200 |
| 8 | `internal/sshgate`: wrapper, relay, host keys, push checks; SSH integration test | 700 |
| 9 | Pack indexing, workflow check, blobless parent fetch | 800 |
| 10 | Skills, README, macOS multi-git include, live verification on both platforms | docs |

About 6,000 lines including tests. Each step after 2 ships a working
feature on its own. Most of the risk is in steps 7 and 9.

## Decisions

The user decided these on 2026-11-08:

- The GitHub App is removed, not kept alongside.
- The PAT, SSH key, and signing key are each optional. Any combination works.
- Branch creation: any name that isn't the default branch or protected. The
  ledger keeps agents off branches they didn't create.
- ChatOps body filtering is on by default.
- The PAT has `repo` scope only, no `read:org`.
- Labels are off by default.
- No marker on agent content.
- LFS isn't supported through the broker in v1.

Left open, then built as recommended:

- Commits and tags made under hallpass's config are signed when the signing
  key exists.

Changed after the first build, on 2026-11-08:

- git over HTTPS is removed, and with it per-entry `via`. git goes over SSH
  only, and the PAT is for gh. SSH works in orgs that block classic PATs,
  its key stays in the TPM, and one transport halves the git code and the
  credential matrix. `via` was per entry while git's routing was per owner,
  so an exact entry without it was refused over SSH. The costs: GitHub's own
  workflow-scope refusal no longer sits behind the broker's pack check, so
  that check is the only guard; and the gate dials `github.com:22`, so a
  network that blocks port 22 can't reach GitHub. `ssh.github.com:443`
  isn't supported yet.
- Operations replace the fixed rules for merges, approvals, labels, reruns,
  dispatches, and default-branch pushes. See "Policy".

## Where this came from

Five candidate plans for the org-repo proxy, each from a different direction
(smallest build, adversary first, question the mechanism, maintenance over
years, both platforms and operations). All five found gh's
`http_unix_socket` on their own, and three found the plaintext git path. The
base is the maintenance plan: rules keyed on schema names, the corpus
harness, refusal messages, the branch ledger for pushes, and
`viewerDidAuthor` for edits. Grafted in:

- From adversary first: separate sockets, rebuilding every request from its
  parsed form and reprinting GraphQL, the typed edge table with `Full` and
  `Identity` views, ChatOps filtering, labels off, the rate reserve, strict
  framing, the attack test suite.
- From question the mechanism: plaintext git with `followRedirects = false`,
  the `install-pat` scope checks, and TPM sealing.
- From both platforms: synthesized report-status, SSO and 401 mapping, PAT
  revocation on rotation, read-only entries, the multi-git include on macOS,
  the `git http-backend` integration test.
- From smallest build: gh config `version: "1"`, and gh passing every
  mutation as `input: $input`.

After the arena, the user moved personal repos onto the broker, removed the
App, and added the SSH and signing keys as optional credentials. The
plaintext HTTPS git path and its `git http-backend` test were later removed;
see "Decisions".
