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
# all.sh, not this, stamps a tree for bin/worktree land.
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
[ "$1" = all ] && set -- rest graphql ssh push-default signing status
{
  for feature in "$@"; do
    fn="feature_${feature//-/_}"
    if ! declare -F "$fn" >/dev/null; then echo "drive.sh: no feature $feature" >&2; FAILS=$((FAILS+1)); continue; fi
    echo "#### $feature"
    (cd /tmp && "$fn")
    FAILS=$((FAILS + $(cat "$S/.drive-fails" 2>/dev/null || echo 0)))
    rm -f "$S/.drive-fails"
  done
  # Every run, whatever the features: the broker wrote its ledger. Its
  # state dir is $S/state, so a failure here means it looked elsewhere.
  echo
  echo "== ledger-writes"
  if grep -qF 'ledger write failed' "$S/evidence/broker.log"; then
    echo "FAIL  broker.log has: ledger write failed"; FAILS=$((FAILS+1))
  else
    echo "ok    broker.log lacks: ledger write failed"
  fi
  echo "#### $FAILS failed"
} 2>&1 | tee -a "$S/evidence/transcript.txt"
[ "$(tail -1 "$S/evidence/transcript.txt")" = "#### 0 failed" ] || exit 1
