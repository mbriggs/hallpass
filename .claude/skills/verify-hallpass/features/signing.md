# Signed commits

git signs commits with `gpg.format=ssh` and `gpg.ssh.program=hallpass-sign`.
`hallpass-sign` asks the broker to sign only when the key is the broker's
signing key and the namespace is `git`. Everything else goes to the real
`ssh-keygen`.

## Sub-features

- `sign-commit` gives a signed commit that verifies against the broker's public key.
- `sign-passthrough` hands a key that isn't the broker's to `ssh-keygen`.

## Driving it with git

Preconditions: a clone at `$S/work` (see git-https.md, Clone).

- **Sign.** `cd "$S/work" && echo s >> README && git commit -q -S -am signed`
  exits 0. `git cat-file commit HEAD` contains `-----BEGIN SSH SIGNATURE-----`.
  `broker.log` has a `msg=signed object=...` line.
- **Verify.** `echo "verify@example.com $(cat "$S/keys/signing.pub")" > "$S/evidence/allowed_signers" && git -c gpg.ssh.allowedSignersFile="$S/evidence/allowed_signers" verify-commit HEAD`
  prints `Good "git" signature for verify@example.com`.
- **Passthrough.** `ssh-keygen -q -t ed25519 -N "" -f "$S/other" && echo hi > "$S/msg" && hallpass-sign -Y sign -n git -f "$S/other.pub" "$S/msg"`
  writes `$S/msg.sig`, with no new `msg=signed` line in `broker.log`.

## Gotchas

- Not yet run end to end from this skill. The agent permission check
  blocked the git batch that included it.
- `hallpass-sign` decides by asking the broker for its public key over the
  control socket. With `HALLPASS_RUN_DIR` unset it asks the live broker,
  which has a different key, and passes through to `ssh-keygen`, which
  fails because it has no private key for `$S/keys/signing.pub`.
