# Sourced by bin/worktree and by the shell entry points that touch what a lane
# isolates (the verify-hallpass scripts). POSIX sh, so bash 3.2 and dash both
# read it.
#
#   . bin/worktree-env.sh
#   worktree_load DIR    load DIR's checkout's worktree.env, or refuse to start
#                        in a linked worktree that has none
#
# worktree.env values override what the process inherited, except when the
# inherited WORKTREE_LANE already equals the file's. Then a parent loaded this
# lane on purpose, and its values stand.

# worktree_is_linked TOP: a linked worktree's .git is a file.
worktree_is_linked() {
  [ -f "$1/.git" ]
}

worktree_load() {
  wl_top=$(git -C "$1" rev-parse --show-toplevel 2>/dev/null) || return 0
  worktree_is_linked "$wl_top" || return 0
  if [ ! -f "$wl_top/worktree.env" ]; then
    echo "$wl_top is a linked worktree with no lane. Run bin/worktree setup there first." >&2
    if [ -f "$wl_top/tmp/worktree-setup.failed" ]; then
      echo "The last setup failed; see $wl_top/tmp/worktree-setup.failed." >&2
    fi
    exit 1
  fi
  wl_lane=$(sed -n 's/^WORKTREE_LANE=//p' "$wl_top/worktree.env")
  if [ -n "${WORKTREE_LANE:-}" ] && [ "$WORKTREE_LANE" = "$wl_lane" ]; then
    # Export only what the parent didn't set.
    while IFS='=' read -r wl_k wl_v; do
      case "$wl_k" in ''|'#'*) continue ;; esac
      eval "wl_set=\${$wl_k+x}"
      [ -n "$wl_set" ] || { eval "$wl_k=\$wl_v"; export "$wl_k"; }
    done < "$wl_top/worktree.env"
  else
    set -a
    . "$wl_top/worktree.env"
    set +a
  fi
  unset wl_top wl_lane wl_k wl_v wl_set
}
