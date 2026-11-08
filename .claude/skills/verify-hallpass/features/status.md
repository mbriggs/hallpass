# Status

`hallpass status` asks the broker over its control socket which credentials
loaded and which repos are allowed. `--check` also confirms the token with
GitHub, which needs exactly scope `repo`.

## Sub-features

- `status-plain` lists the broker socket, token, ssh, signing, and repos.
- `status-check` confirms the token with GitHub and flags wrong scopes.
- `status-json` prints the same as JSON.
- `status-down` gives a clear error when the broker isn't running.

## Driving it with hallpass

- **Plain.** `hallpass status` exits 0 and prints
  `broker:   running at $S/run/hallpass.sock`,
  `token:    classic PAT for verifier, 0 days old, doesn't expire`,
  `ssh:      none`, a `signing:` line with the key from `$S/keys/signing.pub`,
  `repos:    acme/widgets, acme/readonly (read)`, and an `audit:` line.
- **Check.** `hallpass status --check` exits 0 with no `FAILED` or `BROKEN`.
  The fake log has `GET /api/user` with `token-ok`.
- **JSON.** `hallpass status --json | jq -r .token.login` prints `verifier`.
- **Down.** `HALLPASS_RUN_DIR="$S/nowhere" hallpass status` exits 1 with an
  error naming `$S/nowhere/hallpass.sock`.

## Gotchas

- Without `HALLPASS_RUN_DIR`, `hallpass status` reports the live broker,
  with device login `mbriggs` and repos `mbriggs/*`. If you see that, your
  env isn't sourced.
- To make `--check` fail on purpose, edit the fake's `X-OAuth-Scopes` and
  rerun `up.sh`. Don't touch the live token.
