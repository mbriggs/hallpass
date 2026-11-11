#!/usr/bin/env bash
# The landing check: verify the committed tree end to end, and stamp it.
#
#   .claude/skills/verify-hallpass/scripts/all.sh
#
# Refuses to start with anything uncommitted, since the stamp names the
# committed tree. Then, in a new scratch dir, it runs up.sh, doctor.sh,
# drive.sh S all, and down.sh, and exits 0 only when every check passed. Only
# then does it write $S/evidence/verified, holding HEAD^{tree}, which
# bin/worktree land looks for (STAMPS in bin/worktree.lane). down.sh keeps
# evidence/, so the stamp and the transcript outlive the broker.
#
# Everything runs under env -i, with HOME, USER, TMPDIR, and a PATH of the
# system dirs plus the directories of go and gh. A login shell's PATH, gh
# aliases, GH_* and GIT_* variables, and Go's env file then can't make the
# run pass or fail. A lane's values come from its worktree.env, through
# up.sh's loader.
set -euo pipefail

repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
here=$(cd "$(dirname "$0")" && pwd)

if [ -z "${HALLPASS_VERIFY_CLEAN:-}" ]; then
  # Resolve the two tools that live outside the system dirs to real
  # binaries, not shims that read this machine's tool config.
  tool() { mise which "$1" 2>/dev/null || type -P "$1" || { echo "all.sh: $1 not found on PATH or through mise" >&2; exit 2; }; }
  go=$(tool go)
  gh=$(tool gh)
  exec env -i HOME="$HOME" USER="${USER:-$(id -un)}" TMPDIR="${TMPDIR:-/tmp}" \
    PATH="$(dirname "$go"):$(dirname "$gh"):/usr/bin:/bin:/usr/sbin:/sbin" \
    GOENV=off HALLPASS_VERIFY_CLEAN=1 "$0" "$@"
fi
[ $# -eq 0 ] || { echo "usage: all.sh" >&2; exit 2; }

if [ -n "$(git -C "$repo" status --porcelain)" ]; then
  git -C "$repo" status --short >&2
  echo "all.sh: commit or drop these changes first; the stamp names the committed tree" >&2
  exit 1
fi
tree=$(git -C "$repo" rev-parse 'HEAD^{tree}')

S=$("$here/up.sh" | tail -1)
[ -d "$S/evidence" ] || { echo "all.sh: up.sh printed no scratch dir" >&2; exit 1; }
trap '"$here/down.sh" "$S" >/dev/null 2>&1 || true' EXIT
echo "scratch dir: $S"

"$here/doctor.sh" "$S"
if ! "$here/drive.sh" "$S" all >/dev/null; then
  # Each failed check, under the name of its case.
  grep -e '^== ' -e '^FAIL' "$S/evidence/transcript.txt" | grep -B1 '^FAIL' >&2 || true
  echo "all.sh: checks failed; see $S/evidence/transcript.txt" >&2
  exit 1
fi
tail -1 "$S/evidence/transcript.txt"

# The broker ran the tree this run started from, and nothing changed it.
if [ "$(cat "$S/built-from")" != "$tree" ] || [ "$(git -C "$repo" rev-parse 'HEAD^{tree}')" != "$tree" ] || [ -n "$(git -C "$repo" status --porcelain)" ]; then
  echo "all.sh: the checkout changed during the run; nothing stamped" >&2
  exit 1
fi
"$here/down.sh" "$S" >/dev/null
trap - EXIT
echo "$tree" > "$S/evidence/verified"
echo "stamped tree $tree as verified: $S/evidence/verified"
