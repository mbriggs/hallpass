#!/usr/bin/env bash
# Read-only: is the scratch broker in SCRATCH_DIR worth driving?
#   doctor.sh SCRATCH_DIR
# Exits 0 when every check passes. Changes nothing.
set -uo pipefail
S=${1:?usage: doctor.sh SCRATCH_DIR}
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
fail=0
ok()  { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fail=1; }

# A pid counts only if it is alive and its command line names this scratch
# dir, so a recycled pid or someone else's broker never passes.
ours() {
  local pid; pid=$(cat "$S/$1.pid" 2>/dev/null) || return 1
  ps -ww -o command= -p "$pid" 2>/dev/null | grep -qF "$S/"
}
ours fake   && ok "fakegithub pid $(cat "$S/fake.pid") is ours" || bad "fakegithub isn't running from $S"
ours broker && ok "broker pid $(cat "$S/broker.pid") is ours"   || bad "broker isn't running from $S"

for s in hallpass git gh ssh; do
  [ -S "$S/run/$s.sock" ] && ok "socket $s.sock" || bad "no socket $S/run/$s.sock"
done

if cmp -s "$S/bin/hallpass" "$repo/bin/hallpass"; then ok "broker binary matches the checkout's bin/hallpass"
else bad "broker binary differs from $repo/bin/hallpass (rebuilt since up.sh? run down.sh, then up.sh)"; fi

url=$(cat "$S/fake.url" 2>/dev/null)
code=$(curl -s -o /dev/null -w '%{http_code}' "$url/api/user")
[ "$code" = 401 ] && ok "fakegithub at $url refuses requests without the token" || bad "fakegithub at $url answered $code without a token"

st=$(HALLPASS_RUN_DIR="$S/run" "$S/bin/hallpass" status --check 2>&1)
if echo "$st" | grep -q "^token:    classic PAT for verifier" && ! echo "$st" | grep -q "FAILED\|BROKEN"; then
  ok "status --check: token confirmed with the fake, signing key loaded"
else bad "status --check:"; echo "$st" | sed 's/^/      /'; fi

grep -q 'level=ERROR' "$S/evidence/broker.log" && bad "broker.log has errors: $(grep level=ERROR "$S/evidence/broker.log" | tail -1)" || ok "broker.log has no errors"
exit $fail
