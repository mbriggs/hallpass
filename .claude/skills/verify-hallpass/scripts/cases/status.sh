# Status cases. See features/status.md.
feature_status() {
  case_ status-plain
  check 0 "broker:   running at $S/run/hallpass.sock" 'hallpass status'
  check 0 "token:    classic PAT for verifier, 0 days old, doesn't expire" 'hallpass status'
  check 0 "ssh:      $(cut -d' ' -f1,2 "$S/keys/ssh.pub")" 'hallpass status'
  check 0 "signing:  $(cut -d' ' -f1,2 "$S/keys/signing.pub")" 'hallpass status'
  check 0 'repos:    acme/widgets, acme/readonly (read), acme/gadgets' 'hallpass status'
  check fail '' 'hallpass status | grep "^policy:"'

  case_ status-check
  check 0 '          GitHub accepts it for verifier' 'hallpass status --check'
  check fail '' 'hallpass status --check | grep -E "FAILED|BROKEN"'
  fake_has '"path":"/api/user","auth":"token-ok"'
  fake_has '"method":"SSH","path":"shell","auth":"key-ok"'

  case_ status-json
  check 0 '"login": "verifier"' 'hallpass status --json'
  check 0 '"checked": true' 'hallpass status --check --json'

  case_ status-down
  check fail "can't reach the hallpass broker at $S/nowhere/hallpass.sock" "HALLPASS_RUN_DIR=\"$S/nowhere\" hallpass status"
}
