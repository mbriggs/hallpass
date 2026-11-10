# Status

`hallpass status` asks the broker over its control socket which credentials
loaded and which repos are allowed. `--check` also confirms the token with
GitHub, which needs exactly scope `repo`, and confirms GitHub accepts the
SSH key.

## Sub-features

- `status-plain` lists the broker socket, token, ssh, signing, and repos.
- `status-check` confirms the token and SSH key with GitHub and flags wrong scopes.
- `status-json` prints the broker's status as JSON. It adds `version` and
  `binary`, and leaves out the socket and `audit:` lines. It exits 0 even
  when a check fails, so read `check_error` and `problem`, not the exit.
- `status-down` gives a clear error when the broker isn't running.

## Driving it

`scripts/drive.sh "$S" status` runs these cases from
`scripts/cases/status.sh`:

- `status-plain`: `hallpass status` names `$S/run/hallpass.sock`, `classic
  PAT for verifier, 0 days old, doesn't expire`, the keys in
  `$S/keys/ssh.pub` and `$S/keys/signing.pub`, and `repos:    acme/widgets,
  acme/readonly (read), acme/gadgets`. There's no `policy:` line, because
  the scratch config sets no global allow or deny. Its `audit:` line names
  the live broker's log even here; the scratch broker logs to
  `$S/evidence/broker.log`.
- `status-check`: `--check` adds `GitHub accepts it for verifier at ADDR`
  under `ssh:`, where ADDR is the fake's SSH address, with no `FAILED` or `BROKEN`. The fake sees `GET /api/user` with
  `token-ok`, and an SSH `shell` session with `key-ok`.
- `status-json`: `--json` has `"login": "verifier"`, and with `--check`,
  `"checked": true`.
- `status-down`: with `HALLPASS_RUN_DIR="$S/nowhere"`, it fails with `can't
  reach the hallpass broker at $S/nowhere/hallpass.sock`.

## Gotchas

- Without `HALLPASS_RUN_DIR`, `hallpass status` reports the live broker,
  with device login `mbriggs` and repos `mbriggs/*`. If you see that, your
  env isn't sourced.
- To make `--check` fail on purpose, change the fake's `X-OAuth-Scopes`
  in `scripts/fakegithub/main.go`, then run `down.sh` and `up.sh` again.
  Expect `check FAILED: the token's scopes are [...]; hallpass needs exactly [repo]`
  and a final `hallpass: not working: token` with exit 1. Don't touch the
  live token.
