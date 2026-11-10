# Helpers for drive.sh's cases. Sourced after $S/env, so commands reach the
# scratch broker. Each feature runs in a subshell, which counts its
# failures in $S/.drive-fails.

_fails=0
_fake_mark=0
_broker_mark=0

ok()   { echo "ok    $*"; }
fail() { echo "FAIL  $*"; _fails=$((_fails+1)); echo "$_fails" > "$S/.drive-fails"; }

# case NAME starts a case: it names it in the output, and marks the logs so
# the log checks see only what this case sent.
case_() {
  echo
  echo "== $1"
  _fake_mark=$(wc -l < "$S/evidence/github-requests.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
  _broker_mark=$(wc -l < "$S/evidence/broker.log" | tr -d ' ')
}

# check WANT TEXT CMD runs CMD with bash and prints it with its output.
# WANT is 0, or fail for any non-zero exit. TEXT, if set, must appear in
# the output.
check() {
  local want=$1 text=$2 cmd=$3 out rc
  echo "\$ $cmd"
  out=$(bash -c "$cmd" 2>&1); rc=$?
  [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/  /'
  echo "  exit=$rc"
  if [ "$want" = fail ] && [ "$rc" = 0 ]; then fail "wanted a non-zero exit"; return; fi
  if [ "$want" != fail ] && [ "$rc" != "$want" ]; then fail "wanted exit $want"; return; fi
  if [ -n "$text" ] && ! grep -qF -- "$text" <<<"$out"; then fail "output lacks: $text"; return; fi
  ok "${text:-exit $rc}"
}

_since() { tail -n +$(( $2 + 1 )) "$1" 2>/dev/null; }
fake_has()    { if _since "$S/evidence/github-requests.jsonl" "$_fake_mark" | grep -qF -- "$1"; then ok "fake saw: $1"; else fail "fake didn't see: $1"; fi; }
fake_lacks()  { if _since "$S/evidence/github-requests.jsonl" "$_fake_mark" | grep -qF -- "$1"; then fail "fake saw: $1"; else ok "fake didn't see: $1"; fi; }
broker_has()  { if _since "$S/evidence/broker.log" "$_broker_mark" | grep -qF -- "$1"; then ok "broker.log has: $1"; else fail "broker.log lacks: $1"; fi; }
broker_lacks(){ if _since "$S/evidence/broker.log" "$_broker_mark" | grep -qF -- "$1"; then fail "broker.log has: $1"; else ok "broker.log lacks: $1"; fi; }

# refs prints the fake's refs for acme/widgets.
refs() { GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -C "$S/gh-root/acme/widgets.git" for-each-ref --format='%(refname) %(objectname)'; }

# restart_broker stops the scratch broker, after checking its command line
# names $S, and starts it again on $S/hallpass.toml and $S/state.
restart_broker() {
  local pid; pid=$(cat "$S/broker.pid")
  case "$(ps -o command= -p "$pid")" in *"$S"*) kill "$pid" ;; *) fail "pid $pid isn't this scratch broker"; return 1 ;; esac
  while kill -0 "$pid" 2>/dev/null; do sleep 0.1; done
  local before; before=$(grep -c 'msg=serving' "$S/evidence/broker.log")
  nohup env HALLPASS_RUN_DIR="$S/run" "$S/bin/hallpass" serve --config "$S/hallpass.toml" --state-dir "$S/state" >> "$S/evidence/broker.log" 2>&1 &
  echo $! > "$S/broker.pid"
  for _ in $(seq 50); do [ "$(grep -c 'msg=serving' "$S/evidence/broker.log")" -gt "$before" ] && return 0; sleep 0.1; done
  fail "the broker didn't come back"; return 1
}
