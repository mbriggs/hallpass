---
name: verify-branch-ledger
description: TLA+ check that agents update or delete only branches they made. Use when a diff touches internal/proxy/ledger.go, CheckPush or checkUpdate, or push checks or ledger writes in serveGit or relayPush.
---

# Verify the branch ledger

**Property.** GitHub never applies an agent's update or delete to a branch that the user created.
**Harm if broken.** An agent force-pushes over or deletes the user's own work, which hallpass promises can't happen ("Agents can't ... update or delete branches they didn't create", README).

The model is `verify/branch-ledger/BranchLedger.tla`. It covers one repo with two branch names, two agent pushes in flight at once, up to four new commits, ledger file writes that fail, broker restarts, and the user creating, pushing, and deleting branches with their own credentials.

## Does the change touch it

Check the model when a diff changes any of these:

| Code | Model action |
| --- | --- |
| `policy.ReadPush`, `RefUpdate.Create`, `RefUpdate.Delete` in `internal/policy/git.go` | `AgentSendsPush`, `IsCreate`, `IsDelete` |
| `CheckPush`, `checkUpdate`, `Branches.Ours` in `internal/policy/git.go` | `BrokerChecksPush` |
| `policy.ReportStatus` in `internal/policy/git.go` | `BrokerRecords` (which refs count as accepted) |
| `serveGit` in `internal/proxy/git.go`: the `CheckPush` call, the forward to GitHub, the `Ledger.Add` loop | `BrokerChecksPush`, `GitHubApplies`, `BrokerRecords` |
| `relayPush` in `internal/sshgate/gate.go`: the same three places | the same actions |
| `Ledger.Has`, `Ledger.Add`, `OpenLedger` in `internal/proxy/ledger.go` | `BrokerChecksPush`, `BrokerRecords`, `LedgerWriteSucceeds`, `LedgerWriteFails`, `BrokerRestarts` |
| the `OpenLedger` call in `cmd/hallpass/main.go` | `BrokerRestarts` |

A change elsewhere in those files, such as path parsing or the workflow check, doesn't touch the model. `check.sh` flags any edit to the four hashed files anyway. Read the diff and decide.

Each action in the `.tla` file names its code in a comment. The model treats these as one atomic step each, because each is one in the code: one `Ledger.Has` call (it holds the ledger mutex), GitHub's compare-and-swap on one ref, and `Ledger.Add`'s update of the in-memory set. If a change splits one of these, or merges two of them, change the model to match.

## Make the model describe the change first

`check.sh` checks the model as written, not the code. When a diff changes a step in the table above, edit `BranchLedger.tla` to describe the code after the diff, and then run it. Do this whether the change is meant to alter behavior or you suspect it is a bug. If you are only reviewing a change that won't land, model it in a copy of the directory outside the repo.

A new call site of a mapped function is a new step. For example, a second `Ledger.Add` call before the forward to GitHub becomes its own action between `BrokerChecksPush` and `GitHubApplies`, with `pc` values for the new position.

## Run

```sh
verify/branch-ledger/check.sh
```

It takes about 5 seconds and needs Java 11 or later. The first run downloads tla2tools 1.7.4 to `~/.cache/hallpass/` and checks its hash. To use a copy you already have, set `TLA2TOOLS_JAR`. TLC's output for each config goes to `verify/branch-ledger/out/`.

| Config | Expected | Means |
| --- | --- | --- |
| `Full.cfg` | `NoClobber` violated | finding F1, below |
| `NoReuse.cfg` | pass | with F1's path closed, every other ordering keeps both properties |
| `Sanity.cfg` | `AgentNeverUpdatesOwnBranch` violated | an agent can update its own branch, so the passes aren't from a model that refuses everything |

Exit 0 means every config gave its expected result and the covered files match `covered.sha256`. While F1 is open, report it alongside an exit 0. Exit 1 means a config gave something else. Exit 3 means the results were as expected but covered code changed since the last sync. It lists the changed files. Read their diffs against the table above before you trust the results.

Read every TLC result, pass or fail, with the `/statechart` skill. It gives each violation as its shortest path in plain words and draws how the pushes, the ledger, and GitHub move between states.

## Read a failure

Tell TLC's trace as a story in the code's words, for example "an agent creates `fix`, the user deletes it and pushes their own `fix`, an agent force-pushes `fix`". Then follow the story through the real code.

- **Real bug.** Each step is something the code allows, and each step that the model treats as atomic is atomic in the code. Report it with the story and leave the property alone. Leave product code alone too: the fix is the user's call unless they asked you to make it. To confirm a bug against the real broker, write a throwaway test in `internal/proxy` that drives `fakeGitHub` from `git_test.go`, and delete it afterwards.
- **Modeling error.** A step can't happen in the code: an ordering the code prevents, an action that is two steps in the model but one in the code, or the reverse. Fix the model, and name the code that rules the path out in the action's comment.

`LedgerOnlyAgentBranches` breaking means the ledger names a branch that GitHub never accepted from an agent. That is the precondition for a clobber, and it usually shows up a few steps before `NoClobber` does. To get the clobber path as well, run a copy of the config with `LedgerOnlyAgentBranches` removed from `INVARIANTS`.

## Finding F1: a reused branch name

Open as of the last sync. The ledger is a set of branch names (`ledgerKey` in `internal/proxy/ledger.go`). Nothing removes an entry, and `Has` can't tell this life of a branch from an earlier one with the same name. The shortest path:

1. An agent creates `docs`. GitHub accepts, and `Ledger.Add` records it.
2. The user deletes `docs` on GitHub. Merging a PR with "Automatically delete head branches" on does the same.
3. The user later pushes their own branch named `docs`.
4. An agent force-pushes or deletes `docs`. `Ledger.Has` says yes, and GitHub applies it.

An agent deleting its own branch before step 3 leads to the same result. A throwaway test against the real broker over HTTPS reproduced step 4 as a forced update on 2026-11-08. One fix is to record the tip the agent last pushed and refuse an update whose old commit differs from that tip. It is unbuilt and unchecked.

When F1 is fixed, `Full.cfg` should pass. Change its line in `expect=` in `check.sh` to `Full:pass`, delete this section, and change the `Full.cfg` row above.

## Scope

The model covers the ledger rule for creates, updates, and deletes of branches under `refs/heads/`, over HTTPS and SSH alike. It leaves these out:

- The default-branch, protected-pattern, tag, and ref-name rules in `checkUpdate`, which don't depend on the ledger. With the `push.default` operation allowed, agents may update the default branch without the ledger, which is intended.
- The default branch cache in `Server.defaultBranch` (`internal/proxy/server.go`), which can be up to 10 minutes stale.
- Pushes with several ref commands, `atomic`, and the workflow check in `relayPush`.
- Other machines' brokers. Each machine has its own ledger.
- Repos are one repo. Renames and transfers aren't modeled.

A pass covers the model at these bounds: names `{"fix", "docs"}`, pushes `{"p1", "p2"}`, `MaxCommit = 4`. Raising the bounds in the `.cfg` files costs time: three pushes with four commits passes `NoReuse.cfg` in about 25 seconds on 24 cores, and three pushes with five commits ran past two minutes without finishing.

## Change the properties

If a property no longer says what hallpass promises, take that to the user. Don't loosen it to get a pass.

## Coverage and sync

- Covered files and their hashes: `verify/branch-ledger/covered.sha256`, written by `check.sh --resync`.
- Last confirmed: 2026-11-08, before the first commit, so the hashes are the only record. `internal/proxy/git.go` and `internal/sshgate/gate.go` changed between that sync and commit `0714438`, so `check.sh` exits 3 until someone checks the model against them.

Run `check.sh --resync` and move the date forward only after you've read the covered code at the new state and confirmed that every action still describes it. Write the commit you confirmed against here, so `git diff <commit> -- <covered files>` shows what changed since the model was last true.
