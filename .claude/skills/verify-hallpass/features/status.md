# Status

`hallpass status` asks the broker over its control socket which credentials
loaded and which repos are allowed. `--check` also confirms the token with
GitHub, which needs exactly scope `repo`, and confirms GitHub accepts the
SSH key.

## Sub-features

- `status-plain` lists the broker socket, token, ssh, signing, and repos.
- `status-check` confirms the token and SSH key with GitHub and flags wrong scopes.
- `status-json` prints the same as JSON.
- `status-down` gives a clear error when the broker isn't running.

## Driving it with hallpass

- **Plain.** `hallpass status` exits 0 and prints:
  - `broker:   running at $S/run/hallpass.sock`
  - `token:    classic PAT for verifier, 0 days old, doesn't expire`
  - `ssh:      ` and the key in `$S/keys/ssh.pub`
  - `signing:  ` and the key in `$S/keys/signing.pub`
  - `repos:    acme/widgets, acme/readonly (read), acme/gadgets`
  - `audit:    journalctl -u hallpass`, which names the live broker's
    journal even here. The scratch broker logs to `$S/evidence/broker.log`.

  There's no `policy:` line, because the scratch config sets no global
  allow or deny.
- **Check.** `hallpass status --check` exits 0 with no `FAILED` or `BROKEN`,
  and adds `          GitHub accepts it for verifier` under the `ssh:` line.
  The fake log has `GET /api/user` with `token-ok` and a line with
  `"method":"SSH","path":"shell"` and `"auth":"key-ok"`.
- **JSON.** `hallpass status --json | jq -r .token.login` prints `verifier`.
  The top-level keys are `binary`, `repos`, `signing`, `ssh`, `token`, and
  `version`. With `--check`, `.ssh.login` is `verifier` and `.checked` is
  `true`.
- **Down.** `HALLPASS_RUN_DIR="$S/nowhere" hallpass status` exits 1 with
  `hallpass: can't reach the hallpass broker at $S/nowhere/hallpass.sock: dial unix ...: no such file or directory`.

## Gotchas

- Without `HALLPASS_RUN_DIR`, `hallpass status` reports the live broker,
  with device login `mbriggs` and repos `mbriggs/*`. If you see that, your
  env isn't sourced.
- To make `--check` fail on purpose, change the fake's `X-OAuth-Scopes`
  in `scripts/fakegithub/main.go`, then run `down.sh` and `up.sh` again.
  Expect `check FAILED: the token's scopes are [...]; hallpass needs exactly [repo]`
  and a final `hallpass: not working: token` with exit 1. Don't touch the
  live token.
