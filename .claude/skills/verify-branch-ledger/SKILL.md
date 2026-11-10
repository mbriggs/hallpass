---
name: verify-branch-ledger
description: TLA+ check that agents update or delete only branches they made. Use when a diff touches a ledger.go, CheckPush, checkUpdate, or relayPush's push checks or ledger writes.
---

# Verify the branch ledger

**Property.** GitHub applies an agent's update or delete to a branch only when the branch points at a commit an agent put on that branch, or one the user handed over with `sudo hallpass ledger add`.
**Harm if broken.** An agent force-pushes over or deletes the user's own work: a branch the user made, a name they reused, or commits they added to an agent's branch. The README promises agents can't "update or delete branches they didn't create".

The ledger (`internal/sshgate/ledger.go`) holds, for each branch, the commit an agent last pushed to it. `checkUpdate` lets an update or delete through only when its old commit is that one. GitHub applies a ref command only if the ref still has the old commit, so a branch the user changed stops matching.

The model is `verify/branch-ledger/BranchLedger.tla`. Its configs cover:
- two pushes in flight at once on one branch
- pushes of two refs, atomic or not
- ledger writes that fail, and broker restarts
- the user setting a branch to a new commit or any commit GitHub has (which covers restoring a deleted branch), deleting it, and running `ledger add`
- agents pushing a fresh commit, or one of theirs that GitHub doesn't have yet, such as one from a rejected push

## Does the change touch it

Check the model when a diff changes any of these:

| Code | Model action |
| --- | --- |
| `policy.ReadPush`, `RefUpdate.Create`, `RefUpdate.Delete` in `internal/policy/git.go` | `AgentSendsPush`, `IsCreate`, `IsDelete` |
| `CheckPush` (including its refusal of a ref named twice), `checkUpdate`, `Branches.Tip` in `internal/policy/git.go` | `BrokerChecksPush`, `Allowed` |
| `policy.ReportStatus` in `internal/policy/git.go` | `GitHubAnswers` (which refs count as accepted) |
| `relayPush` in `internal/sshgate/gate.go`: the `CheckPush` call, the forward to GitHub, the `Ledger.Record` loop | `BrokerChecksPush`, `GitHubAnswers`, `BrokerRecords` |
| `Ledger.Tip`, `Ledger.Record`, `OpenLedger` in `internal/sshgate/ledger.go` | `Allowed`, `BrokerRecords`, `BrokerRestarts` |
| the `OpenLedger` call in `serve`, `cmd/hallpass/main.go` | `BrokerRestarts` |
| `ledger add` in `cmd/hallpass/ledger.go`, and the `system.Restart` it calls in `internal/system/system_linux.go` and `system_darwin.go` | `UserAddsLedgerEntry`, then `BrokerRestarts` |

A change elsewhere in those files, such as path parsing, the default-branch rule, the workflow check, or most of `serve` and the install code, doesn't touch the model. `check.sh` flags any edit to the hashed files anyway. Read the diff and decide.

Each action in the `.tla` file names its code in a comment. The model treats these as one atomic step each, because each is one in the code:
- GitHub's answer to one push, with a compare-and-swap on each ref
- one `Ledger.Record` call, which holds the ledger mutex while it sets memory and appends the line, so a failed append leaves memory changed and the file as it was
- one `ledger add`, which appends from a separate process

`CheckPush` calls `Tip` once per command, each under the mutex, and the model reads them all in one step. That's sound because GitHub's compare-and-swap decides what lands, not the check. If a change splits or merges any of these steps, change the model to match.

## Make the model describe the change first

`check.sh` checks the model as written, not the code. When a diff changes a step in the table above, edit `BranchLedger.tla` to describe the code after the diff, and then run it. Until you do, a green run says nothing about the change. Do this whether the change is meant to alter behavior or you suspect it is a bug. If you are only reviewing a change that won't land, model it in a copy of the directory outside the repo.

A new call site of a mapped function is a new step. For example, a second `Ledger.Record` call before the forward to GitHub becomes its own action between `BrokerChecksPush` and `GitHubAnswers`, with `pc` values for the new position.

## Run

```sh
verify/branch-ledger/check.sh          # about 35 seconds for the whole run
verify/branch-ledger/check.sh --deep   # adds ConcurrentDeep.cfg, about 11 minutes more
```

It needs Java 11 or later. The first run downloads tla2tools 1.7.4 to `~/.cache/hallpass/` and checks its hash. To use a copy you already have, set `TLA2TOOLS_JAR`. TLC's output for each config goes to `verify/branch-ledger/out/`. Run `--deep` before landing a change to the ledger's write or restart path. It explores about 225 million states, and TLC keeps its state files in a temporary directory under `/tmp` until it finishes.

| Config | Bounds | Expected | Catches changes to |
| --- | --- | --- | --- |
| `Concurrent.cfg` | 1 branch, 2 pushes of 1 ref, 3 commits, restarts on | pass | the check, races between pushes, `Record`'s write and failure, restarts, `ledger add` |
| `MultiRef.cfg` | 2 branches, 1 push of up to 2 refs, 4 commits, restarts off | pass | the check, which refs get recorded, `atomic`, a commit moving to a second branch |
| `SanityOwn.cfg` | 1 branch, 1 push, 3 commits | `AgentNeverUpdatesOwnBranch` violated | a model that refuses agents' own updates |
| `SanityHanded.cfg` | the same | `AgentNeverUpdatesHandedBranch` violated | a model where `ledger add` does nothing |
| `ConcurrentDeep.cfg` (`--deep`) | as `Concurrent.cfg` with 4 commits | pass |

The sanity configs show that an agent can go on updating its own branch, and can update one the user handed over, so the passes aren't from a model that refuses everything. `Restarts = FALSE` turns off restarts, failed writes, and `ledger add` to keep `MultiRef.cfg` small; `Concurrent.cfg` covers them. Bigger bounds grow fast. In an earlier draft of this model without symmetry, two pushes of two refs each with 4 commits ran 4.5 minutes, past 195 million states, without finishing, and left 19 GB of TLC state in `/tmp`.

Exit 0 means every config gave its expected result and the covered files match `covered.sha256`. Exit 1 means a config gave something else. Exit 3 means the results were as expected but covered code changed since the last sync. It lists the changed files. Read their diffs against the table above before you trust the results.

Read every TLC result, pass or fail, with the `/statechart` skill. It gives each violation as its shortest path in plain words and draws how the pushes, the ledger, and GitHub move between states.

## Read a failure

Tell TLC's trace as a story in the code's words, for example "an agent creates `fix`, the user deletes it and pushes their own `fix`, an agent force-pushes `fix`". Then follow the story through the real code.

- **Real bug.** Each step is something the code allows, and each step that the model treats as atomic is atomic in the code. Report it with the story and leave the property alone. Leave product code alone too: the fix is the user's call unless they asked you to make it. To confirm it against the real broker, add a case to `TestGitOverSSHThroughBroker` in `cmd/hallpass/ssh_test.go`. Its last block already drives a reused name, a user push to an agent's branch, and a handover. Changes the user makes go straight to the bare repo with the `plain` env.
- **Modeling error.** A step can't happen in the code: an ordering the code prevents, an action that is two steps in the model but one in the code, or the reverse. Fix the model, and name the code that rules the path out in the action's comment.

`LedgerSound` breaking means the ledger holds a commit that no agent put on that branch and the user didn't hand over. That is the precondition for an overwrite, and it usually shows up a few steps before `NoOverwrite` does. To get the overwrite path as well, run a copy of the config with `LedgerSound` removed from `INVARIANTS`.

These broken variants of the model must fail. If a change makes one pass, the model has lost its grip on that path:
- The name-only check from before the fix. Both configs break `NoOverwrite`.
- Recording every ref in a push, or every ref once any is accepted, not just the ones GitHub accepted. `MultiRef.cfg` breaks `NoOverwrite`, and `Concurrent.cfg` breaks `LedgerSound`.
- Recording a create before GitHub confirms it. Same as the previous variant.

`Concurrent.cfg` can't show the overwrite for the recording bugs. With one branch, the wrongly recorded commit never reaches GitHub, so the user never has it.

## Scope

The model covers creates, updates, and deletes of branches under `refs/heads/`, over SSH, the only way agents push. It leaves these out:

- The default branch. The ledger doesn't record it, and with the `push.default` operation agents may update it without the ledger, which is intended. In an empty repo (`headBranch` in `gate.go` returns no default), `checkUpdate` lets only a create through by that rule. Updates and deletes still meet the ledger, which `TestCheckPushEmptyRepo` pins. Protected-pattern, tag, and ref-name rules don't depend on the ledger either.
- Pushes that name a ref twice. `CheckPush` refuses them, and `TestCheckPush` checks that.
- Lines in `branches.jsonl` from before commits were recorded. `OpenLedger` keeps them with no commit, which matches no push, as `TestLedgerReplaysTips` checks.
- The workflow check in `relayPush`.
- Other machines' brokers. Each machine has its own ledger, and another machine's push moves the branch off this one's commit.
- Repos are one repo. Renames and transfers aren't modeled.

The property allows one case the old wording didn't. If the user deletes an agent's branch and restores it at the agent's commit, agents may update it again. Nothing of the user's is lost, because the branch holds only what an agent put there.

## Change the properties

If a property no longer says what hallpass promises, take that to the user. Don't loosen it to get a pass.

## Coverage and sync

- Covered files and their hashes: `verify/branch-ledger/covered.sha256`, written by `check.sh --resync`.
- Last confirmed: 2026-11-10, on `add3f67` plus the change that logs the refs GitHub rejected. `ReportStatus` now returns a `Report` that also holds GitHub's `ng` lines, and `relayPush` takes `Accepted` from it into the same `Record` loop. `FuzzReportStatus` checks that `Accepted` matches the old return for every input, so `GitHubAnswers` counts the same refs as accepted. The two early returns that answered git without a log line now log `msg=failed` and return false at the same points, and the final log line moved into `logReport`. No action changes. Before that, on `47eb3cd` plus the change that fetches repos outside the allowlist without a credential. `handle` now sends a read of an unlisted repo to `serveAnonymous` before the SSH key is used, and `serve` sets the gate's `GitURL` (`47eb3cd` changed only `main.go's usage text). That path never pushes, never calls `relayPush`, and never touches the ledger; a push to an unlisted repo is refused before it as before. No action changes. Before that, on `d90791e` plus the change that adds `protected_paths`. `relayPush` now takes the repo's whole `config.Rule`, passes `rule.Ops` to `CheckPush` as before, and hands `rule.Paths` to the pack check, which only refuses more. No action changes. Before that, on `75f6cbe` plus the change that adds `serve --state-dir`. The flag sets the directory `OpenLedger` and `OpenSpool` get, and it defaults to the state dir as before. A restart starts `serve` with the same command line, so it reopens the same ledger and `BrokerRestarts` still describes it. Before that, on `5dfd1ad` plus the change that spools pushed packs to disk. Between `7b61582` and `5dfd1ad`, the port 443 fallback changed how `dial` picks an address and `serve` sets `Addrs`, and `hallpass log` added `OpenLog` beside `Restart` in the two `internal/system` files. Neither touches an action. `relayPush` now copies the pack to a spool file, checks it from there, and streams it to GitHub, and `serve` opens the spool. `CheckPush` still runs first, the forward still happens only after every check passes, and the `Record` loop is unchanged, so no action changes. Before that, on 2026-11-09, on `7b61582`. No covered file changed since `b730153`. That commit's `ParseRepo` change refuses a repo name that still ends in `.git`. The ledger is keyed by the parsed repo, which the model treats as one repo, and the change only refuses more names, so no action changes. Before that, on 2026-11-08, on `5d252dc` plus the golangci-lint change (`b730153`), which marks ignored writes in `relayPush` with `_ =` and swaps `strings.Split` for `SplitSeq` in `git.go`, with the same steps in the same order. Before that, on `00ff1a4` plus the change that refuses an empty repo's first push when it names more than one ref. That refusal is in `CheckPush`, applies only when there's no default branch, which the model leaves out, and only refuses more, so `BrokerChecksPush` still describes it. Before that, on `ae3599b` plus the change that checks the default branch again after the pack. When the default changed, `relayPush` runs `CheckPush` a second time before the forward. A push goes upstream only when every check passed, and the second check's `Tip` reads are later reads of the same ledger, so `BrokerChecksPush` still describes it. `ae3599b` was confirmed with `--deep` and started hashing `cmd/hallpass/main.go` and the two `internal/system` files that define `Restart`.

Run `check.sh --resync` and move the date forward only after you've read the covered code at the new state and confirmed that every action still describes it. Write the commit you confirmed against here, so `git diff <commit> -- <covered files>` shows what changed since the model was last true.
