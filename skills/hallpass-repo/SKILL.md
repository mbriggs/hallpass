---
name: hallpass-repo
description: Let hallpass agents use a GitHub repo, or stop them, and report what an agent's branch could trigger there. Run it for every repo or owner agents use.
disable-model-invocation: true
---

# Add a repo to hallpass

Settle the plan with the user, then run it: the repo or `OWNER/*`, read or
write, and HTTPS or SSH. After that, run to the end and report.

## Allow it

The user runs, since it needs sudo:

```sh
sudo /opt/hallpass/bin/hallpass allow OWNER/REPO [--read] [--via ssh]
```

`OWNER/*` covers every current and future repo of the owner. To stop agents,
`sudo /opt/hallpass/bin/hallpass disallow OWNER/REPO`, and stop there. A
broader entry like `OWNER/*` may still cover a repo after its own entry goes.

Nothing on GitHub changes. By default the broker refuses merges, approvals,
labels, workflow reruns and dispatches, and pushes to the default branch.
The user can allow any of them for this repo:

```sh
sudo /opt/hallpass/bin/hallpass policy allow OP... --repo OWNER/REPO
```

`hallpass policy show OWNER/REPO` lists the operations and what's in
effect. Tag pushes, protected branches, and branches agents didn't create
stay refused whatever the policy says. Before suggesting `push.default`,
`pr.merge`, or `workflow.dispatch`, check the branch protection and the
dispatchable workflows below. GitHub's branch protection and rulesets still
apply on top, unless the user is an admin who bypasses them.

## Check what an agent's branch could trigger

Use the user's own gh for these reads: run gh directly, not through
`hallpass gh`, which refuses some of them on purpose.

**Workflows that run agent code with secrets.** Agents can't edit workflows,
but a workflow on `push` or `pull_request` runs their branch with whatever
secrets it references:

```sh
gh api repos/OWNER/REPO/contents/.github/workflows --jq '.[].name'
gh api repos/OWNER/REPO/contents/.github/workflows/NAME --jq .content | base64 -d
```

For each workflow that does, tell the user which secrets an agent's branch
could read. If those matter and the user can't change the workflow, suggest
`--read` for this repo.

**Bots that act on comments.** hallpass posts as the user, and its filter
covers common commands like `/merge` and `bors r+`, not every bot. Look for
`.mergify.yml`, `bors.toml`, `.github/dependabot.yml`, Prow `OWNERS`, and
workflows on `issue_comment`. Name each bot and the commands it accepts,
so the user knows what an agent's comment could set off.

**Branch protection.** Check whether the default branch has protection or
rulesets:

```sh
gh api repos/OWNER/REPO/rules/branches/DEFAULT_BRANCH --jq '.[].type'
```

If it has none, say so: the broker's refusal is the only thing stopping a
push to it.

## Confirm it works

- `git ls-remote https://github.com/OWNER/REPO` succeeds. With `--via ssh`,
  `git ls-remote git@github.com:OWNER/REPO` does.
- `/opt/hallpass/bin/hallpass gh api repos/OWNER/REPO --jq .full_name`
  prints the repo.
- `/opt/hallpass/bin/hallpass status` lists the entry.

Report the entry, the workflows that expose secrets to agent branches, the
bots that act on comments, and whether the default branch is protected.
