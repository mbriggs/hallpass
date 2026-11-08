---
name: worktree
description: Work in a hallpass lane, a linked git worktree with its own build and scratch brokers. Use before the first write in the primary checkout, when the user asks for a parallel session, or when the working directory is under .claude/worktrees/.
---

# Work in a lane

Every change to hallpass happens in a lane: a linked git worktree that
`bin/worktree` has provisioned. The primary checkout, which `bin/worktree info` names, stays
on `main`. Its build is the one `make install` puts in
`/opt/hallpass/bin`, and the live broker runs it. Don't edit files there.

A lane has an index `n` from 0 to 99. It gets its own `bin/hallpass` and
`verify/branch-ledger/out/`, and its verify-hallpass scratch brokers live in
`/tmp/hallpass-verify-lane<n>.XXXXXX`. The lane shares the Go caches, the
TLA+ jar in `~/.cache/hallpass`, and the live broker with the primary. Real
git and gh go through the live broker from every checkout.

## Create a lane

- In this session, call `EnterWorktree`.
- For a subagent, pass `isolation: "worktree"`. It branches from the
  current commit (`worktree.baseRef: "head"`).
- From a terminal, run `claude --worktree NAME`.
- Anything else: `git worktree add .claude/worktrees/NAME -b NAME`, then
  `bin/worktree setup` in it.

The first Bash command in a new worktree provisions it: setup claims an
index, runs `go mod download` and `make build` from the lane's source, and
writes `worktree.env`. The hook then reports what `bin/worktree info` prints.
If setup fails, that one command is blocked, and the log is in
`tmp/worktree-setup.failed`. Read it, fix the cause, and run
`bin/worktree setup`. Until then, `up.sh` refuses to start.

## Commands in a lane

| Command | In a lane |
| --- | --- |
| `make build`, `make test` | the lane's source and `bin/hallpass` |
| verify-hallpass `up.sh` | a scratch broker in `/tmp/hallpass-verify-lane<n>.XXXXXX`. Stop it with `down.sh`; teardown also stops and deletes any that are left |
| `verify/branch-ledger/check.sh` | the lane's `out/`, the shared jar |
| `make install` | refuses, exit 3. The primary runs it after a PR merges, through `bin/worktree sync` |
| `sudo hallpass install`, `login`, `policy allow`, and the other root commands | never from an agent. Tell the user the command to run from the primary |

The env hook picks the checkout from the directory each command starts in.
`cd <lane> && cmd` run from the primary gets the primary's env, so run lane
commands with the lane as the working directory.

To run git against the primary from an isolated session, call
`ExitWorktree` with `action: "keep"`, run the command from the primary,
then call `EnterWorktree` with the lane's `path` to go back.

## Land

A lane lands as one commit, through a PR that you squash-merge once CI
passes. The user asked for that in this repo. Merging to `main` cuts a
release, and the broker allows it only because the user ran
`policy allow pr.merge --repo mbriggs/hallpass`.

1. Commit, then write the commit message you want on `main` to a file
   (subject line, blank line, body, and the attribution lines).
2. Write the PR description to a second file, outside the checkout. Use
   the `prose` skill for it, with the reviewer as the reader, and the
   `show-me` skill for the views that make the change clear, such as a
   file tree of what moved or a Mermaid sequence of a new flow. End it with
   the PR attribution line.
3. From the lane: `bin/worktree land --message MSG --body DESC`. It squashes
   the branch onto `origin/main`, force-pushes with a lease, and opens the
   PR or rewrites its title (the commit subject) and description (DESC).
   It prints the PR URL. Rebase onto `origin/main` first if it says the
   branch is behind. Pass `--body` every time you land: without it, the
   description becomes the commit body.
4. Own the PR until it merges. Watch it with
   `/opt/hallpass/bin/hallpass gh pr checks BRANCH --watch` (run it in the
   background), and check `gh pr view BRANCH --json state,reviews,comments`
   for merges and review comments.
   - If CI fails, read `gh run view RUN --log-failed`, fix the cause in the
     lane, and land again with `--message` and `--body`, updating the
     description if the change grew. Then watch again. If you can't fix
     it, tell the user what failed and why.
   - Answer review comments the same way: fix, re-land, and reply.
5. When every check passes and no review asks for changes, merge it:
   `/opt/hallpass/bin/hallpass gh pr merge BRANCH --squash`. Leave out
   `--delete-branch`: teardown deletes the branch. If hallpass refuses the
   merge, show the user its message, which names the command that allows
   it, and stop there.
6. Once the PR is merged, call `ExitWorktree` with `keep`, and run
   `bin/worktree sync` in the primary. It fast-forwards `main` and runs
   `make install` so the live broker runs what merged. If it prints
   `NOT INSTALLED`, sudo needed a password: ask the user to run
   `make install` in the primary.

To keep working in the lane after a squash merge, run
`git rebase --onto origin/main <merged PR head>`. A plain rebase replays the
squashed commits.

## Clean up

Ask the user before you remove a lane. Then:

1. Call `ExitWorktree` with `action: "keep"`, never `remove`. `remove`
   refuses any worktree with commits since it was created, even landed ones.
2. From the primary: `bin/worktree teardown NAME`. It runs `sync`, then
   removes the worktree, deletes its branch, stops the lane's scratch
   brokers, and frees the index. It refuses uncommitted or untracked files,
   and a HEAD that's neither on `main` nor the head of a merged PR. Pass
   `--discard` only after the user agrees the work can go.

Teardown run from inside the lane leaves the directory behind, and the next
command provisions the lane again. Lanes whose directory is gone, like a
finished subagent's, are swept at session start, after `ExitWorktree`, and
30 seconds after a subagent stops.

## Change this tooling

`bin/worktree`, `bin/worktree-env.sh`, `.claude/hooks/`, and
`.claude/settings.json` make up the lane tooling. After changing them, run
`.claude/skills/worktree/scripts/test.sh`. It works in a temporary repo with
lanes 90-92 and a stub gh.
