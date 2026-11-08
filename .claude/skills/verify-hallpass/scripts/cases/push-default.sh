# push.default: allow it on acme/widgets, restart the broker, push main,
# and put the config back. Run after ssh, which leaves $S/work. See
# features/git-ssh.md.
feature_push_default() {
  [ -d "$S/work/.git" ] || { fail "push-default needs ssh's clone; run ssh first"; return; }
  cd "$S/work" || return
  local cfg="$S/hallpass.toml"
  cp "$cfg" "$S/hallpass.toml.before-push-default"
  # The allow line goes right under the acme/widgets entry's match.
  awk '{print} /^match = "acme\/widgets"$/ {print "allow = [\"push.default\"]"}' "$S/hallpass.toml.before-push-default" > "$cfg"
  restart_broker || return

  case_ push-default-allowed
  check 0 'acme/widgets (+push.default)' 'hallpass status'
  check 0 '' 'echo d >> README && git commit -qam "default push" && git push origin HEAD:main'
  if refs | grep -q "refs/heads/main $(git rev-parse HEAD)"; then ok "the fake's main moved"; else fail "the fake's main didn't move"; fi
  case_ push-default-delete
  check fail "agents can't delete the default branch" 'git push origin :main'

  mv "$S/hallpass.toml.before-push-default" "$cfg"
  restart_broker
}
