#!/usr/bin/env bash
# Model-checks hallpass's branch ledger with TLC and compares each config's
# result with what's expected. See .claude/skills/verify-branch-ledger.
#
#   verify/branch-ledger/check.sh           run the model and the drift check
#   verify/branch-ledger/check.sh --deep    also run ConcurrentDeep.cfg, about
#                                           11 minutes more
#   verify/branch-ledger/check.sh --resync  record the covered files' hashes
#                                           (only after you've confirmed the
#                                           model matches them)
#
# Exit 0: every config gave its expected result and the covered code hasn't
# changed since the last sync. Exit 1: a config gave an unexpected result.
# Exit 3: results as expected, but covered code changed since the last sync.
# The drift check runs and reports either way.
# TLC's full output for each config goes to verify/branch-ledger/out/.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

# Files the model describes. Keep in step with the skill's coverage table.
covered=(
  internal/policy/git.go
  internal/sshgate/ledger.go
  internal/sshgate/gate.go
  cmd/hallpass/ledger.go
  cmd/hallpass/main.go
  internal/system/system_linux.go
  internal/system/system_darwin.go
)

if [[ "${1:-}" == "--resync" ]]; then
  (cd "$root" && sha256sum "${covered[@]}") > "$here/covered.sha256"
  echo "recorded hashes of ${#covered[@]} covered files in verify/branch-ledger/covered.sha256"
  exit 0
fi

# TLC from tla2tools 1.7.4 (TLC 2.19), pinned by hash. Set TLA2TOOLS_JAR to
# use a copy you already have; it must have the same hash.
version=1.7.4
sha=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
jar=${TLA2TOOLS_JAR:-${XDG_CACHE_HOME:-$HOME/.cache}/hallpass/tla2tools-$version.jar}
if [[ ! -f "$jar" ]]; then
  mkdir -p "$(dirname "$jar")"
  echo "downloading tla2tools $version to $jar"
  curl -fsSL -o "$jar.tmp" "https://github.com/tlaplus/tlaplus/releases/download/v$version/tla2tools.jar"
  mv "$jar.tmp" "$jar"
fi
if ! echo "$sha  $jar" | sha256sum -c --quiet - >/dev/null 2>&1; then
  echo "$jar isn't tla2tools $version (sha256 mismatch)" >&2
  exit 1
fi
command -v java >/dev/null || { echo "java not found; TLC needs Java 11 or later" >&2; exit 1; }

mkdir -p "$here/out"
meta=$(mktemp -d)
trap 'rm -rf "$meta"' EXIT

# config:expected. "pass", or the invariant TLC must report as violated.
#   Concurrent      two pushes at once, restarts, failed writes, ledger add
#   MultiRef        pushes of two refs, atomic or not
#   SanityOwn       expects AgentNeverUpdatesOwnBranch to break: an agent
#                   can go on updating its own branch
#   SanityHanded    expects AgentNeverUpdatesHandedBranch to break: an agent
#                   can update a branch the user handed over
#   ConcurrentDeep  Concurrent with one more commit (--deep only)
expect=(
  Concurrent:pass
  MultiRef:pass
  SanityOwn:AgentNeverUpdatesOwnBranch
  SanityHanded:AgentNeverUpdatesHandedBranch
)
[[ "${1:-}" == "--deep" ]] && expect+=(ConcurrentDeep:pass)

status=0
for e in "${expect[@]}"; do
  cfg=${e%%:*} want=${e#*:}
  out="$here/out/$cfg.txt"
  set +e
  (cd "$here" && java -XX:+UseParallelGC -jar "$jar" -config "$cfg.cfg" \
    -metadir "$meta/$cfg" -workers auto -cleanup BranchLedger.tla) > "$out" 2>&1
  code=$?
  set -e
  rm -rf "${meta:?}/$cfg"
  got=$(sed -n 's/^Error: Invariant \([A-Za-z]*\) is violated\.$/\1/p' "$out" | head -1)
  if [[ $code -eq 0 ]]; then
    got=pass
  elif [[ -z "$got" ]]; then
    got="TLC error (exit $code)"
  fi
  states=$(sed -n 's/.* \([0-9]*\) distinct states found.*/\1/p' "$out" | tail -1)
  if [[ "$got" == "$want" ]]; then
    echo "ok    $cfg: $got as expected (${states:-?} distinct states)"
  else
    echo "FAIL  $cfg: expected $want, got $got. Output: verify/branch-ledger/out/$cfg.txt"
    status=1
  fi
done

if ! drift=$(cd "$root" && sha256sum -c --quiet "$here/covered.sha256" 2>&1); then
  echo "STALE covered code changed since the model was last confirmed against it:"
  echo "$drift" | sed 's/^/      /'
  echo "      Check the model against the change, then run check.sh --resync."
  [[ $status -eq 0 ]] && status=3
fi
exit $status
