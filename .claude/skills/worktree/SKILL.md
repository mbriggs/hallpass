---
name: worktree
description: Work in a hallpass lane, a git worktree with its own build and scratch brokers. Use before the first write in the primary checkout, when the user asks for a parallel session, or when the working directory is under .claude/worktrees/.
---

# Work in a lane

Every change to hallpass happens in a lane: a linked git worktree that
`bin/worktree` has provisioned. The primary checkout, which `bin/worktree info`
names, stays on `main`. Its build is the one `make install` puts in
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
| verify-hallpass `all.sh` | the landing check: a whole run in a new scratch dir, which keeps the stamp in its `evidence/` |
| verify-hallpass `up.sh` | a scratch broker in `/tmp/hallpass-verify-lane<n>.XXXXXX`. Stop it with `down.sh`; teardown also stops and deletes any that are left |
| `verify/branch-ledger/check.sh` | the lane's `out/`, the shared jar |
| `bin/worktree info` | the lane's index, scratch prefix, and binary |
| `bin/worktree land` | pushes the lane's one commit and opens or updates its PR |
| `make install` | refuses, exit 3. The primary runs it after a PR merges, through `bin/worktree merge` or `sync` |
| `bin/worktree merge`, `sync`, `teardown NAME` | refuse; they run in the primary |
| `sudo hallpass install`, `login`, `policy allow`, and the other root commands | never from an agent. Tell the user the command to run from the primary |

The env hook picks the checkout from the directory each command starts in.
`cd <lane> && cmd` run from the primary gets the primary's env, so run lane
commands with the lane as the working directory.

## Commands that run in the primary

`merge`, `sync`, and `teardown NAME` run in the primary, and a session
isolated to a worktree can't run git against the primary. In a session that
entered the lane with `EnterWorktree`, call `ExitWorktree` with
`action: "keep"`, run the command from the primary, then call
`EnterWorktree` with the lane's `path` to go back. A subagent returns the
command to its parent to run. A session started with `claude --worktree`
asks the user to run it from the primary.

## Land

A lane lands as one commit, through a PR that is squash-merged. Merging to
`main` cuts a release.

1. Commit. If an earlier `land` said the branch lacks commits from
   `origin/main`, run `git rebase origin/main` first. If it also said `main`
   changed the lane tooling, reread this skill before going on.
2. Verify the commit: from the lane, with nothing uncommitted, run
   `.claude/skills/verify-hallpass/scripts/all.sh`. It runs every
   verify-hallpass check against a scratch broker and, only when all of
   them pass, stamps the commit's tree in
   `/tmp/hallpass-verify-lane<n>.XXXXXX/evidence/verified`. `land` refuses
   a branch whose tree has no stamp, unless it changes only Markdown. A
   failure is a finding: fix it in the lane, commit, and run it again.
   Rebasing changes the tree, so rebase first, then verify. If the change
   can't affect the broker, pass `--no-verify REASON` to `land`, and the
   reason goes in the PR description.
3. Write the commit message you want on `main` to a file outside the
   checkout: subject line, blank line, body, and the attribution lines.
4. Write the PR description to a second file outside the checkout. Use the
   prose skill for it, with the reviewer as the reader, and the show-me
   skill for the views that make the change clear, such as a file tree of
   what moved or a Mermaid sequence of a new flow. End it with the PR
   attribution line.
5. From the lane: `bin/worktree land --message MSG --body DESC`. It squashes
   the branch onto `origin/main`, force-pushes with a lease, and opens the
   PR or rewrites its title (the commit subject) and description (DESC).
   It prints the PR URL. Pass `--body` every time you land: without it, the
   description becomes the commit body.
6. Own the PR until it merges. Watch it with
   `/opt/hallpass/bin/hallpass gh pr checks BRANCH --watch`, run in the
   background, and check `gh pr view BRANCH --json state,reviews,comments`
   for review comments.
   - If CI fails, read `gh run view RUN --log-failed`, fix the cause in the
     lane, and land again from step 1, updating the description if the
     change grew. If you can't fix it, tell the user what failed and why.
   - Answer review comments the same way: fix, land again, and reply.
7. Merge it once every check passes and no review asks for changes. In this
   repo you merge every lane's PR that gets there; the user asked for that.
   That rule, not the words "land it", is what asks for the merge. Merge only
   through `bin/worktree merge NAME`, run in the primary (see above), never
   with `gh pr merge`. It checks that the PR is open, green, and at the
   lane's HEAD, squash-merges it, then runs `sync`. If hallpass refuses the
   merge, show the user its message, which names the command that allows
   it, and stop there.
8. If the user merged the PR instead, run `bin/worktree sync` in the
   primary yourself. It fast-forwards `main` and runs `make install`, so the
   live broker runs what merged.

If `merge` or `sync` prints `NOT INSTALLED`, sudo needed a password: tell
the user to run the command it names in the primary, `make install` with
plain sudo, which prompts. Until then the live broker runs the previous build.

To keep working in the lane after a squash merge, run
`git rebase --onto origin/main <merged PR head>`. A plain rebase replays the
squashed commits.

## Clean up

Ask the user before you remove a lane. Then:

1. In a session that entered the lane with `EnterWorktree`, call
   `ExitWorktree` with `action: "keep"`, never `remove`. `remove` refuses
   any worktree with commits since it was created, even landed ones.
2. From the primary: `bin/worktree teardown NAME`. It removes the
   worktree, deletes its branch, stops the lane's scratch brokers, deletes
   their dirs, and frees the index. It refuses uncommitted or untracked
   files, and a HEAD that's neither on `main` nor the head of a merged PR.
   Pass `--discard` only after the user agrees the work can go.
3. Teardown never syncs. If it says `main` is behind `origin/main`, run
   `bin/worktree sync`.

Teardown run from inside the lane leaves the directory behind, and the next
command provisions the lane again. Lanes whose directory is gone, like a
finished subagent's, are swept at session start, after `ExitWorktree`, and
30 seconds after a subagent stops.

## Change this tooling

`bin/worktree` and `bin/worktree-env.sh` are the shared lane script and
loader from the create-worktree-lanes skill, copied unchanged. Don't edit
them here: tell the user what they get wrong, so the fix goes into that
skill. What hallpass isolates lives in `bin/worktree.lane`. After changing
it, `.claude/hooks/`, or `.claude/settings.json`, run
`.claude/skills/worktree/scripts/test.sh`. It works in a temporary repo with
lanes 90-92 and a stub gh.
