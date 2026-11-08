---
name: hallpass-repo
description: Let hallpass agents use a GitHub repo, or stop them, and report what an agent's branch could trigger there.
disable-model-invocation: true
---

# Add a repo to hallpass

Run the checks below, then settle the plan with the user: the repo or
`'OWNER/*'`, read or write, and any policy changes. After that, run to the
end and report.

To stop agents instead, the user runs
`sudo /opt/hallpass/bin/hallpass disallow OWNER/REPO`, and you stop there. A
broader entry like `'OWNER/*'` may still cover a repo after its own entry
goes; `/opt/hallpass/bin/hallpass status` shows the entries left.

## Check what an agent's branch could trigger

Use the user's own gh for these reads: run `command gh`, which skips a `gh`
alias, not `hallpass gh`, which refuses some of them on purpose. If that gh
isn't logged in, ask the user to run the reads.

**Workflows that run agent code with secrets.** Agents can't edit workflows,
but a workflow on `push` or `pull_request` runs their branch with whatever
secrets it references. For each workflow that does, tell the user which
secrets an agent's branch could read. If those matter and the user can't
change the workflow, suggest `--read` for this repo. Also list the workflows
on `workflow_dispatch` and what each deploys.

**Bots that act on comments.** hallpass posts as the user, and its filter
covers common commands like `/merge` and `bors r+`, not every bot. Look for
`.mergify.yml`, `bors.toml`, `.github/dependabot.yml`, Prow `OWNERS`, and
workflows on `issue_comment`. Name each bot and the commands it accepts,
so the user knows what an agent's comment could set off.

**Branch protection.** Check whether the default branch has protection or
rulesets. If it has none, say so: the broker's refusal is the only thing
stopping a push to it.

## Allow it

The user runs, since it needs sudo:

```sh
sudo /opt/hallpass/bin/hallpass allow OWNER/REPO [--read]
```

`allow` changes nothing on GitHub. By default the broker refuses merges and
auto-merge (`pr.merge`), approvals and change requests (`review.verdict`),
labels, workflow reruns and dispatches, and pushes to the default branch
(`push.default`).
`/opt/hallpass/bin/hallpass policy show OWNER/REPO` lists each operation's
name and what's in effect, and the user can allow any of them for this repo:

```sh
sudo /opt/hallpass/bin/hallpass policy allow OP... --repo OWNER/REPO
```

Tag pushes, the branches `protected_branches` names in
`/etc/hallpass/hallpass.toml`, and updates to branches agents didn't create
stay refused whatever the policy says. Suggest `push.default`, `pr.merge`,
or `workflow.dispatch` only in light of the branch protection and
dispatchable workflows you found. GitHub's branch protection and rulesets
still apply on top, unless the user is an admin who bypasses them.

## Confirm it works

For `'OWNER/*'`, pick one repo it covers.

- `git ls-remote https://github.com/OWNER/REPO` succeeds.
- `/opt/hallpass/bin/hallpass gh api repos/OWNER/REPO --jq .full_name`
  prints the repo.
- `/opt/hallpass/bin/hallpass status` lists the entry.

Report the entry, the workflows that expose secrets to agent branches, the
bots that act on comments, and whether the default branch is protected.
