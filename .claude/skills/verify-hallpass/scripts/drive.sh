#!/usr/bin/env bash
# Drive a scratch broker through committed cases, so nobody has to type
# git and gh commands by hand against it.
#
#   drive.sh S FEATURE...    FEATURE is rest, graphql, ssh,
#                            push-default, signing, status, or all
#
# Each feature runs its cases in order. Every case prints the command, its
# output, and ok or FAIL against the expected exit and text, and checks the
# fake's request log and broker.log where the feature file says to. Output
# also goes to $S/evidence/transcript.txt. Exits 1 if any check failed.
#
# The expectations are in features/*.md, keyed by the case names printed
# here. When a refusal's wording changed but the request is still refused
# and absent from the fake's log, update the case and the feature file.
set -uo pipefail

[ $# -ge 2 ] || { echo "usage: drive.sh S FEATURE..." >&2; exit 2; }
S=$1; shift
[ -s "$S/env" ] && [ -s "$S/broker.pid" ] || { echo "drive.sh: $S isn't a running scratch dir; run up.sh first" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)

# shellcheck source=/dev/null
. "$S/env"
# The guard against reaching the live broker: plain gh must be the real
# binary, pointed at the scratch config.
case "$(type -t gh)" in file) ;; *) echo "drive.sh: gh isn't a plain binary here; refusing" >&2; exit 2;; esac
[ "$GH_CONFIG_DIR" = "$S/gh" ] || { echo "drive.sh: GH_CONFIG_DIR isn't the scratch one" >&2; exit 2; }

. "$here/cases/lib.sh"
for f in gh-rest gh-graphql git-ssh push-default signing status; do . "$here/cases/$f.sh"; done

FAILS=0
rm -f "$S/.drive-fails"
whole=
[ "$1" = all ] && { whole=1; set -- rest graphql ssh push-default signing status; }
{
  for feature in "$@"; do
    fn="feature_${feature//-/_}"
    if ! declare -F "$fn" >/dev/null; then echo "drive.sh: no feature $feature" >&2; FAILS=$((FAILS+1)); continue; fi
    echo "#### $feature"
    (cd /tmp && "$fn")
    FAILS=$((FAILS + $(cat "$S/.drive-fails" 2>/dev/null || echo 0)))
    rm -f "$S/.drive-fails"
  done
  echo "#### $FAILS failed"
} 2>&1 | tee -a "$S/evidence/transcript.txt"
[ "$(tail -1 "$S/evidence/transcript.txt")" = "#### 0 failed" ] || exit 1
# A whole passing run stamps the tree the broker was built from, which
# bin/worktree land looks for. down.sh keeps evidence/, so the stamp
# outlives the broker.
if [ -n "$whole" ] && [ -s "$S/built-from" ] && [ "$(cat "$S/built-from")" != dirty ]; then
  cp "$S/built-from" "$S/evidence/verified"
  echo "stamped $(cat "$S/evidence/verified") as verified"
fi
