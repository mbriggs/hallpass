#!/usr/bin/env bash
# Tests what hallpass adds to the shared bin/worktree: bin/worktree.lane, the
# make install guard and marker, and up.sh's loader, in a temporary repo with
# a bare remote and a stub gh. The shared script itself is tested in the
# create-worktree-lanes skill. Uses lanes 90-92 only, so live lanes are never
# touched.
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
export WORKTREE_LANE_RANGE=90-92
export WORKTREE_GH=$T/gh-stub
export WORKTREE_INSTALL='env > "$T/installed"'
export T
unset WORKTREE_LANE WORKTREE_PRIMARY WORKTREE_KEYS HALLPASS_VERIFY_PREFIX WORKTREE_STAMPS

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
cp "$src/bin/worktree" "$src/bin/worktree.lane" "$src/bin/worktree-env.sh" "$P/bin/"
cp "$src/.claude/skills/verify-hallpass/scripts/down.sh" "$src/.claude/skills/verify-hallpass/scripts/all.sh" "$P/.claude/skills/verify-hallpass/scripts/"
cp "$src/.gitignore" "$P/"
printf 'module example.com/t\n\ngo 1.22\n' > "$P/go.mod"
# The real install target's guard and marker lines, with the build and the
# sudo step stubbed.
{
  printf 'WORKTREE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))bin/worktree\n'
  printf 'build:\n\tmkdir -p bin && echo built > bin/hallpass\n'
  printf 'install:\n'
  sed -n '/^install:/,/^$/p' "$src/Makefile" | grep -e 'guard' -e 'installed"$'
  printf '\techo installed\n'
} > "$P/Makefile"
git -C "$P" add -A
git -C "$P" add -f .claude
git -C "$P" commit -q -m init
git -C "$P" remote add origin "$T/origin.git"
git -C "$P" push -q -u origin main

wt() { git -C "$P" worktree add -q -b "$1" "$P/.claude/worktrees/$1" main; echo "$P/.claude/worktrees/$1"; }
lane_of() { sed -n 's/^WORKTREE_LANE=//p' "$1/worktree.env"; }

check "the lane file isn't gitignored" bash -c "! git -C '$P' check-ignore -q bin/worktree.lane"

# --- the primary --------------------------------------------------------------
check "info in the primary names the primary's scratch dirs" bash -c "(cd '$P' && bin/worktree info) | grep '/tmp/hallpass-verify.XXXXXX' >/dev/null"
check "make install passes the guard in the primary" bash -c "make -s -C '$P' install | grep -qx installed"
check "make install marks the commit installed" \
  [ "$(cat "$P/.git/worktree-installed" 2>/dev/null)" = "$(git -C "$P" rev-parse HEAD)" ]
check "sync skips the install that make install marked" \
  bash -c "cd '$P' && bin/worktree sync | grep -qx installed && [ ! -f '$T/installed' ]"

# --- setup --------------------------------------------------------------------
A=$(wt a)
check "setup succeeds" bash -c "cd '$A' && bin/worktree setup >/dev/null 2>&1"
check "lane a got 90" [ "$(lane_of "$A")" = 90 ]
check "setup built the lane's own binary" [ -f "$A/bin/hallpass" ]
check "worktree.env names the lane's verify prefix" grep -qx 'HALLPASS_VERIFY_PREFIX=/tmp/hallpass-verify-lane90' "$A/worktree.env"
check "info in the lane names its scratch dirs" bash -c "(cd '$A' && bin/worktree info) | grep '/tmp/hallpass-verify-lane90.XXXXXX' >/dev/null"
check "info in the primary lists lane 90" bash -c "(cd '$P' && bin/worktree info) | grep 'lane 90 .*$A' >/dev/null"

# --- the loader and guard -----------------------------------------------------
B=$(wt b)
# up.sh loads the lane this way before it picks a scratch dir.
check "up.sh's loader refuses a linked worktree without worktree.env" \
  bash -c "! (cd '$B' && sh -c '. bin/worktree-env.sh; worktree_load .') 2>/dev/null"
check "up.sh's loader gives a lane its verify prefix" \
  bash -c "cd '$A' && sh -c '. bin/worktree-env.sh; worktree_load .; echo \$HALLPASS_VERIFY_PREFIX' | grep -qx /tmp/hallpass-verify-lane90"
check "make install refuses in a lane" \
  bash -c "out=\$(make -s -C '$A' install 2>&1); ! printf '%s\n' \"\$out\" | grep -qx installed && printf '%s' \"\$out\" | grep -q 'refuses to run in a lane'"

# --- the hook: a failed setup -------------------------------------------------
hook=$src/.claude/hooks/worktree-bash.sh
mv "$B/Makefile" "$B/Makefile.ok"; printf 'build:\n\tfalse\n' > "$B/Makefile"
# The hook acts only on worktrees of the project Claude Code opened.
printf '{"cwd":"%s"}' "$B" | CLAUDE_PROJECT_DIR=$T/origin.git "$hook" >/dev/null 2>&1; rc=$?
check "the hook ignores another project's worktree" [ "$rc" = 0 -a ! -f "$B/tmp/worktree-setup.failed" ]
printf '{"cwd":"%s"}' "$B" | CLAUDE_PROJECT_DIR=$P "$hook" >/dev/null 2>&1; rc=$?
check "a failed build blocks the command (exit 2)" [ "$rc" = 2 ]
check "a failed build leaves the marker and no worktree.env" [ -f "$B/tmp/worktree-setup.failed" -a ! -f "$B/worktree.env" ]
mv "$B/Makefile.ok" "$B/Makefile"
check "a fixed setup succeeds" bash -c "cd '$B' && bin/worktree setup >/dev/null 2>&1 && [ ! -f '$B/tmp/worktree-setup.failed' ]"
check "lane b got 91" [ "$(lane_of "$B")" = 91 ]

# --- teardown --stale ---------------------------------------------------------
S=$(mktemp -d /tmp/hallpass-verify-lane91.XXXXXX)
mkdir -p "$S/bin" "$S/evidence"; cp /bin/sleep "$S/bin/hallpass"; touch "$S/hallpass.toml"
"$S/bin/hallpass" 300 & broker=$!
echo "$broker" > "$S/broker.pid"
S2=$(mktemp -d /tmp/hallpass-verify-lane91.XXXXXX)
rm -rf "$B"
(cd "$A" && bin/worktree teardown --stale) > "$T/sweep.log" 2>&1
wait "$broker" 2>/dev/null
check "the sweep stops the gone lane's scratch broker" bash -c "! kill -0 $broker 2>/dev/null"
check "the sweep deletes every scratch dir of the gone lane" [ ! -e "$S" -a ! -e "$S2" ]
check "the sweep deletes the gone lane's entry" [ ! -e "$P/tmp/worktrees/91" ]
check "the sweep leaves the live lane" [ -f "$P/tmp/worktrees/90" -a -f "$A/worktree.env" ]
# The entry back with its scratch dirs already gone: the drop still succeeds.
echo "$T/gone" > "$P/tmp/worktrees/91"
(cd "$P" && bin/worktree teardown --stale) >/dev/null 2>&1
check "the sweep drops a lane whose scratch dirs are already gone" [ ! -e "$P/tmp/worktrees/91" ]
W=$(mktemp -d /tmp/hallpass-verify-lane91.XXXXXX)
W2=$(mktemp -d /tmp/hallpass-verify-lane92.XXXXXX)
D=$(wt d)
# 90 is live, and 91 and 92 have scratch dirs but no entry: nothing is free.
check "allocation skips an index whose scratch dir exists without an entry" \
  bash -c "(cd '$D' && bin/worktree setup 2>&1) | grep -q 'no free lane in 90-92'"
(cd "$P" && bin/worktree teardown --stale) >/dev/null 2>&1
check "the sweep leaves a scratch dir with no entry" [ -d "$W" -a -d "$W2" ]
rm -rf "$W" "$W2"
check "a freed index is allocated again" \
  bash -c "cd '$D' && bin/worktree setup >/dev/null 2>&1 && [ \"\$(sed -n 's/^WORKTREE_LANE=//p' '$D/worktree.env')\" = 91 ]"

# --- land: the verify-hallpass stamp ------------------------------------------
cd "$A"
vprefix=/tmp/hallpass-verify-lane90
# stamp records a passing all.sh run for HEAD's tree, as drive.sh does.
stamp() { mkdir -p "$vprefix.test/evidence"; git -C "$A" rev-parse 'HEAD^{tree}' > "$vprefix.test/evidence/verified"; }
echo code > gate.go
check "the all run refuses uncommitted changes" \
  bash -c "out=\$(.claude/skills/verify-hallpass/scripts/all.sh 2>&1); [ \$? = 1 ] && printf '%s' \"\$out\" | grep -q 'commit or drop these changes first' && ! ls -d $vprefix.* >/dev/null 2>&1"
git add gate.go; git commit -q -m "gate"
check "land refuses a tree no all.sh run stamped" bash -c "bin/worktree land 2>&1 | grep -q 'no passing .*all.sh run stamped'"
mkdir -p "$vprefix.old/evidence"; echo 0000 > "$vprefix.old/evidence/verified"
check "land ignores a stamp for another tree" bash -c "bin/worktree land 2>&1 | grep -q 'no passing'"
mkdir -p /tmp/hallpass-verify-lane91.other/evidence
git rev-parse 'HEAD^{tree}' > /tmp/hallpass-verify-lane91.other/evidence/verified
check "land ignores another lane's stamp" bash -c "bin/worktree land 2>&1 | grep -q 'no passing'"
rm -rf /tmp/hallpass-verify-lane91.other
check "land --no-verify says why in the PR" \
  bash -c "bin/worktree land --no-verify 'only a comment changed' >/dev/null && grep -q 'Not verified with .*all.sh.: only a comment changed' '$T/gh/calls'"
echo more > gate.go; git commit -q -am "gate 2"
printf 'Gate\n\nBody.\n' > "$T/msg"
stamp
check "land accepts the stamp in the lane's scratch dir" \
  bash -c "bin/worktree land --message '$T/msg' 2>&1 | grep -q 'verified: $vprefix.test/evidence/verified'"

# --- teardown NAME ------------------------------------------------------------
cd "$P"
check "teardown refuses unlanded work" bash -c "bin/worktree teardown a 2>&1 | grep -q \"isn't on main\""
check "teardown --discard drops lane 90 and its scratch dirs" \
  bash -c "bin/worktree teardown a --discard >/dev/null 2>&1 && [ ! -e '$A' ] && [ ! -e '$P/tmp/worktrees/90' ] && ! ls -d $vprefix.* >/dev/null 2>&1"
git worktree remove --force "$D"
(cd "$P" && bin/worktree teardown --stale) >/dev/null 2>&1
check "no lanes remain" bash -c "! ls '$P'/tmp/worktrees/[0-9]* >/dev/null 2>&1"

cd /
[ "$fail" = 0 ] && echo "all checks passed" || echo "some checks FAILED"
exit "$fail"
