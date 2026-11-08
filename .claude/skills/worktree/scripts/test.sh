#!/usr/bin/env bash
# Tests bin/worktree in a temporary repo with a bare remote and a stub gh.
# Uses lanes 90-92 only, so live lanes are never touched.
#
#   .claude/skills/worktree/scripts/test.sh     exit 0 when every check passes
#   KEEP=1 .../test.sh                          keep /tmp/worktree-test.* to debug
set -uo pipefail

src=$(cd "$(dirname "$0")/../../../.." && pwd -P)
T=$(cd "$(mktemp -d /tmp/worktree-test.XXXXXX)" && pwd -P)
fail=0
ok()  { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fail=1; }
check() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }

export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com
export WORKTREE_LANES=90-92
export WORKTREE_GH=$T/gh-stub
export WORKTREE_INSTALL='env > "$T/installed"'
export T
unset WORKTREE_LANE WORKTREE_PRIMARY HALLPASS_VERIFY_PREFIX

cleanup() {
  local d
  for d in /tmp/hallpass-verify-lane9[0-2].*; do
    [ -d "$d" ] || continue
    [ -f "$d/broker.pid" ] && kill -9 "$(cat "$d/broker.pid")" 2>/dev/null
    rm -rf "$d"
  done
  rm -rf "$T"
}
trap cleanup EXIT
[ -n "${KEEP:-}" ] && trap - EXIT
# Leftovers from an earlier run would change allocation.
cleanup; mkdir -p "$T"

# --- the stub gh --------------------------------------------------------------
mkdir -p "$T/gh"
cat > "$T/gh-stub" <<'EOF'
#!/usr/bin/env bash
# pr list --head B --state S ...  prints $T/gh/S-B; pr create makes an open PR.
echo "$*" >> "$T/gh/calls"
head= state= ; args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[i]}" in --head) head=${args[i+1]} ;; --state) state=${args[i+1]} ;; esac
done
case "$1 $2" in
  "pr list") cat "$T/gh/$state-$head" 2>/dev/null; exit 0 ;;
  "pr create") echo 7 > "$T/gh/open-$head" ;;
  "api -X") ;;
  "pr view") echo "https://example.com/pull/7" ;;
esac
EOF
chmod +x "$T/gh-stub"

# --- the temp repo ------------------------------------------------------------
git init -q --bare -b main "$T/origin.git"
git init -q -b main "$T/primary"
P=$T/primary
mkdir -p "$P/bin" "$P/.claude/skills/verify-hallpass/scripts"
cp "$src/bin/worktree" "$src/bin/worktree-env.sh" "$P/bin/"
cp "$src/.claude/skills/verify-hallpass/scripts/down.sh" "$P/.claude/skills/verify-hallpass/scripts/"
cp "$src/.gitignore" "$P/"
printf 'module example.com/t\n\ngo 1.22\n' > "$P/go.mod"
cat > "$P/Makefile" <<'EOF'
WORKTREE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))bin/worktree
build:
	mkdir -p bin && echo built > bin/hallpass
install:
	@$(WORKTREE) guard --deny "make install"
	echo installed
EOF
git -C "$P" add -A
git -C "$P" add -f .claude
git -C "$P" commit -q -m init
git -C "$P" remote add origin "$T/origin.git"
git -C "$P" push -q -u origin main

wt() { git -C "$P" worktree add -q -b "$1" "$P/.claude/worktrees/$1" main; echo "$P/.claude/worktrees/$1"; }
lane_of() { sed -n 's/^WORKTREE_LANE=//p' "$1/worktree.env"; }

# --- the primary --------------------------------------------------------------
check "setup refuses in the primary" bash -c "! (cd '$P' && bin/worktree setup) 2>/dev/null"
check "info in the primary reports the primary" bash -c "(cd '$P' && bin/worktree info) | grep -q 'checkout: primary'"
check "guard passes in the primary" bash -c "cd '$P' && bin/worktree guard --deny x"
check "make install passes the guard in the primary" bash -c "make -s -C '$P' install | grep -q installed"

# --- setup: two racing setups in one worktree ---------------------------------
A=$(wt a)
(cd "$A" && bin/worktree setup > "$T/a1.log" 2>&1; echo $? > "$T/a1.rc") &
(cd "$A" && bin/worktree setup > "$T/a2.log" 2>&1; echo $? > "$T/a2.rc") &
wait
check "both racing setups succeed" bash -c "[ \"\$(cat '$T/a1.rc' '$T/a2.rc')\" = \"0
0\" ]"
check "the race registers one lane" bash -c "[ \$(grep -lx '$A' '$P'/tmp/worktrees/[0-9]* | wc -l) -eq 1 ]"
check "lane a got 90" [ "$(lane_of "$A")" = 90 ]
check "setup built the lane's own binary" [ -f "$A/bin/hallpass" ]
check "info in the lane reports lane 90" bash -c "(cd '$A' && bin/worktree info) | grep -q 'checkout: lane 90'"
check "a second setup is a no-op" bash -c "(cd '$A' && bin/worktree setup) | grep -q 'already provisioned'"

# --- a killed lock holder -----------------------------------------------------
B=$(wt b)
perl -MFcntl=:flock -e 'open(my $f, ">>", shift) or die; flock($f, LOCK_EX); sleep 300' "$P/tmp/worktrees/.lock" &
holder=$!
sleep 0.3
(cd "$B" && bin/worktree setup > "$T/b.log" 2>&1; echo $? > "$T/b.rc") &
setup=$!
sleep 1
check "setup waits while the registry lock is held" [ ! -f "$T/b.rc" ]
kill -9 "$holder"
wait "$setup"
check "setup proceeds after the holder is killed" [ "$(cat "$T/b.rc")" = 0 ]
check "lane b got 91" [ "$(lane_of "$B")" = 91 ]

# --- the loader and guard -----------------------------------------------------
C=$(wt c)
check "the loader refuses a linked worktree without worktree.env" \
  bash -c "! (cd '$C' && sh -c '. bin/worktree-env.sh; worktree_load .') 2>/dev/null"
check "the loader names bin/worktree setup" \
  bash -c "(cd '$C' && sh -c '. bin/worktree-env.sh; worktree_load .') 2>&1 | grep -q 'bin/worktree setup'"
check "the loader overrides inherited values" \
  bash -c "cd '$A' && WORKTREE_LANE=5 HALLPASS_VERIFY_PREFIX=/nope sh -c '. bin/worktree-env.sh; worktree_load .; echo \$HALLPASS_VERIFY_PREFIX' | grep -qx /tmp/hallpass-verify-lane90"
check "the loader keeps a parent's values for the same lane" \
  bash -c "cd '$A' && WORKTREE_LANE=90 HALLPASS_VERIFY_PREFIX=/scratch sh -c '. bin/worktree-env.sh; worktree_load .; echo \$HALLPASS_VERIFY_PREFIX \$WORKTREE_PRIMARY' | grep -qx '/scratch $P'"
check "guard --deny exits 3 in a lane" bash -c "cd '$A'; bin/worktree guard --deny x 2>/dev/null; [ \$? -eq 3 ]"
check "guard checks its own checkout, not the cwd" bash -c "cd '$P'; '$A/bin/worktree' guard --deny x 2>/dev/null; [ \$? -eq 3 ]"
check "make install refuses in a lane" bash -c "! make -s -C '$A' install 2>&1 | grep -q installed && make -s -C '$A' install 2>&1 | grep -q 'refuses to run in a lane'"
check "guard --warn continues in a lane" bash -c "cd '$A' && bin/worktree guard --warn x 2>/dev/null"
if (: </dev/tty) 2>/dev/null; then
  echo "skip  guard --confirm without a terminal (this run has one)"
else
  check "guard --confirm refuses without a terminal" bash -c "cd '$A'; bin/worktree guard --confirm x 2>/dev/null; [ \$? -eq 3 ]"
fi

# --- the hook: a failed setup -------------------------------------------------
hook=$src/.claude/hooks/worktree-bash.sh
mv "$C/Makefile" "$C/Makefile.ok"; printf 'build:\n\tfalse\n' > "$C/Makefile"
printf '{"cwd":"%s"}' "$C" | "$hook" >/dev/null 2>&1; rc=$?
check "a failed setup blocks the command (exit 2)" [ "$rc" = 2 ]
check "a failed setup leaves the marker" [ -f "$C/tmp/worktree-setup.failed" ]
check "a failed setup writes no worktree.env" [ ! -f "$C/worktree.env" ]
printf '{"cwd":"%s"}' "$C" | "$hook" >/dev/null 2>&1; rc=$?
check "the next command runs past the marker" [ "$rc" = 0 ]
check "guarded entry points refuse while setup is broken" \
  bash -c "! (cd '$C' && sh -c '. bin/worktree-env.sh; worktree_load .') 2>/dev/null"
mv "$C/Makefile.ok" "$C/Makefile"
check "a fixed setup succeeds" bash -c "cd '$C' && bin/worktree setup >/dev/null 2>&1"
check "a fixed setup clears the marker" [ ! -f "$C/tmp/worktree-setup.failed" ]
check "lane c reused the entry its failed setup wrote" [ "$(lane_of "$C")" = 92 ]
out=$(printf '{"cwd":"%s"}' "$P" | "$hook" 2>&1); rc=$?
check "the hook does nothing in the primary" [ "$rc" = 0 -a -z "$out" ]

# --- teardown --stale ---------------------------------------------------------
S=$(mktemp -d /tmp/hallpass-verify-lane91.XXXXXX)
mkdir -p "$S/bin"; cp /bin/sleep "$S/bin/hallpass"; touch "$S/hallpass.toml"
"$S/bin/hallpass" 300 & echo $! > "$S/broker.pid"
broker=$(cat "$S/broker.pid")
rm -rf "$B"
echo /nonexistent > "$P/tmp/worktrees/95"
(cd "$A" && bin/worktree teardown --stale) > "$T/sweep.log" 2>&1
check "the sweep stops the gone lane's scratch broker" bash -c "! kill -0 $broker 2>/dev/null"
check "the sweep deletes the gone lane's scratch dir" [ ! -e "$S" ]
check "the sweep deletes the gone lane's entry" [ ! -e "$P/tmp/worktrees/91" ]
check "the sweep leaves live lanes" [ -f "$P/tmp/worktrees/90" -a -f "$P/tmp/worktrees/92" -a -f "$A/worktree.env" ]
check "the sweep leaves lanes outside the range" [ -f "$P/tmp/worktrees/95" ]
rm -f "$P/tmp/worktrees/95"
W=$(mktemp -d /tmp/hallpass-verify-lane91.XXXXXX)
D=$(wt d)
# 90 and 92 are live, and 91 has a scratch dir but no entry: nothing is free.
check "allocation skips an index whose scratch dir exists without an entry" \
  bash -c "(cd '$D' && bin/worktree setup 2>&1) | grep -q 'every lane in 90-92 is taken'"
check "a setup that found no lane writes no worktree.env or entry" \
  bash -c "[ ! -f '$D/worktree.env' ] && ! grep -qx '$D' '$P'/tmp/worktrees/[0-9]*"
(cd "$P" && bin/worktree teardown --stale) >/dev/null 2>&1
check "the sweep leaves a scratch dir with no entry" [ -d "$W" ]
rm -rf "$W"
git -C "$P" worktree remove --force "$D"

# --- land ---------------------------------------------------------------------
cd "$A"
echo one > one; git add one; git commit -q -m "one"
echo two > two; git add two; git commit -q -m "two"
check "land refuses several commits" bash -c "bin/worktree land 2>&1 | grep -q 'has 2 commits'"
echo dirty >> one
check "land refuses tracked changes" bash -c "! bin/worktree land >/dev/null 2>&1"
git checkout -q one
printf 'Add one and two\n\nThe body.\n' > "$T/msg"
check "land --message squashes and opens a PR" bash -c "bin/worktree land --message '$T/msg' | grep -q example.com/pull/7"
check "the branch lands as one commit" [ "$(git rev-list --count origin/main..HEAD)" = 1 ]
check "land pushed the branch" [ "$(git -C "$T/origin.git" rev-parse a)" = "$(git rev-parse HEAD)" ]
check "land created the PR with the commit's title" grep -q 'pr create --base main --head a --title Add one and two --body The body.' "$T/gh/calls"
printf 'Add one and two, reworded\n\nNew body.\n' > "$T/msg"
check "land on an open PR rewrites it" bash -c "bin/worktree land --message '$T/msg' >/dev/null && grep -q 'api -X PATCH repos/{owner}/{repo}/pulls/7 -f title=Add one and two, reworded -f body=New body.' '$T/gh/calls'"
printf '## Summary\n\nWritten for reviewers.\n' > "$T/body"
check "land --body sets the PR description from its own file" \
  bash -c "bin/worktree land --message '$T/msg' --body '$T/body' >/dev/null && grep -q 'api -X PATCH repos/{owner}/{repo}/pulls/7 -f title=Add one and two, reworded -f body=## Summary' '$T/gh/calls'"
check "land refuses an unknown option" bash -c "bin/worktree land --bogus 2>&1 | grep -q usage"
check "the force-pushed branch matches" [ "$(git -C "$T/origin.git" rev-parse a)" = "$(git rev-parse HEAD)" ]
git checkout -q --detach
check "land refuses a detached HEAD" bash -c "bin/worktree land 2>&1 | grep -q detached"
git checkout -q a
# Someone else's commit lands on main first.
other=$(mktemp -d "$T/other.XXXX"); git clone -q "$T/origin.git" "$other/c"
(cd "$other/c" && echo x > x && git add x && git commit -q -m other && git push -q origin main)
check "land refuses a branch behind origin/main" bash -c "bin/worktree land 2>&1 | grep -q 'lacks commits from origin/main'"
git rebase -q origin/main
bin/worktree land >/dev/null || bad "land after rebase"
landed=$(git rev-parse HEAD)

# --- sync ---------------------------------------------------------------------
# The squash merge: GitHub writes a new commit on main.
(cd "$other/c" && git pull -q && git merge -q --squash origin/a && git commit -q -m "Add one and two (#7)" && git push -q origin main)
echo "$landed" > "$T/gh/merged-a"
rm -f "$T/gh/open-a"
check "sync refuses in a lane" bash -c "! bin/worktree sync >/dev/null 2>&1"
cd "$P"
check "sync fast-forwards main" bash -c "WORKTREE_LANE=90 HALLPASS_VERIFY_PREFIX=/tmp/x bin/worktree sync | grep -q 'fast-forwarded'"
check "sync matches origin/main" [ "$(git rev-parse main)" = "$(git rev-parse origin/main)" ]
check "sync installs after main moves" [ -f "$T/installed" ]
check "install runs without the lane's variables" bash -c "! grep -q '^WORKTREE_LANE=\|^HALLPASS_VERIFY_PREFIX=' '$T/installed'"
rm -f "$T/installed"
check "sync with nothing new skips install" bash -c "bin/worktree sync | grep -q 'up to date' && [ ! -f '$T/installed' ]"
echo local > local; git add local; git commit -q -m local
check "sync refuses local commits" bash -c "bin/worktree sync 2>&1 | grep -q 'need a PR'"
git reset -q --hard origin/main

# --- teardown NAME ------------------------------------------------------------
echo late > "$A/late"
check "teardown refuses untracked files" bash -c "bin/worktree teardown a 2>&1 | grep -q 'uncommitted changes'"
(cd "$A" && git add late && git commit -q -m late)
check "teardown refuses commits made after the merge" bash -c "bin/worktree teardown a 2>&1 | grep -q 'merged PR'"
(cd "$A" && git reset -q --hard "$landed")
check "teardown refuses inside a lane" bash -c "cd '$A' && ! bin/worktree teardown a >/dev/null 2>&1"
check "teardown accepts the head of a merged PR" bash -c "bin/worktree teardown a >/dev/null 2>&1"
check "teardown removed the worktree" [ ! -e "$A" ]
check "teardown deleted the squash-merged branch" bash -c "! git show-ref -q refs/heads/a"
check "teardown dropped lane 90" [ ! -e "$P/tmp/worktrees/90" ]
check "teardown left lane 92" [ -f "$P/tmp/worktrees/92" ]
(cd "$C" && echo wip > wip && git add wip && git commit -q -m wip)
check "teardown refuses unlanded work" bash -c "bin/worktree teardown c 2>&1 | grep -q \"isn't on main\""
check "teardown --discard removes it anyway" bash -c "bin/worktree teardown c --discard >/dev/null 2>&1 && [ ! -e '$C' ] && [ ! -e '$P/tmp/worktrees/92' ]"
E=$(mktemp -d "$T/outside.XXXX")/e
git worktree add -q -b e "$E" main
(cd "$E" && bin/worktree setup >/dev/null 2>&1)
check "teardown takes a path outside .claude/worktrees" bash -c "bin/worktree teardown '$E' >/dev/null 2>&1 && [ ! -e '$E' ]"
check "no lanes remain" bash -c "! ls '$P'/tmp/worktrees/[0-9]* >/dev/null 2>&1"

cd /
[ "$fail" = 0 ] && echo "all checks passed" || echo "some checks FAILED"
exit "$fail"
