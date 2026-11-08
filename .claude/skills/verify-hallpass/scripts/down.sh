#!/usr/bin/env bash
# Stop what up.sh started in SCRATCH_DIR and remove everything there except
# evidence/, which survives at SCRATCH_DIR/evidence.
#   down.sh SCRATCH_DIR
set -uo pipefail
S=${1:?usage: down.sh SCRATCH_DIR}
case "$S" in /tmp/hallpass-verify*) ;; *) [ -f "$S/hallpass.toml" ] || { echo "down.sh: $S doesn't look like an up.sh scratch dir" >&2; exit 1; } ;; esac

# Kill only pids this run recorded, and only if they still belong to $S.
for name in broker fake; do
  pid=$(cat "$S/$name.pid" 2>/dev/null) || continue
  if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -qF "$S/"; then
    kill "$pid"
    for _ in $(seq 30); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid"
    echo "stopped $name ($pid)"
  fi
done

# Keep the final state of GitHub's side as evidence, then clear scratch.
if [ -d "$S/gh-root/acme/widgets.git" ]; then
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -C "$S/gh-root/acme/widgets.git" \
    for-each-ref --format='%(refname) %(objectname)' > "$S/evidence/github-refs-at-teardown.txt" 2>/dev/null
fi
find "$S" -mindepth 1 -maxdepth 1 ! -name evidence -exec rm -rf {} +
echo "evidence kept in $S/evidence:"
ls -1 "$S/evidence"
