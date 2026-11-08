# Signed commits

git signs commits with `gpg.format=ssh` and `gpg.ssh.program=hallpass-sign`.
`hallpass-sign` asks the broker to sign only when the key is the broker's
signing key and the namespace is `git`. Everything else goes to the real
`ssh-keygen`.

## Sub-features

- `sign-commit` gives a signed commit that verifies against the broker's public key.
- `sign-passthrough` hands a key that isn't the broker's to `ssh-keygen`.
- `sign-refuse-data` refuses to sign anything but an unsigned git commit or tag.
- `sign-refuse-forged` refuses data that starts like a commit but has headers git never writes.

## Driving it with git

Preconditions: a repo at `$S/sign`. Signing needs no remote:
`git init -q "$S/sign" && cd "$S/sign"`.

- **Sign.** `echo s > README && git add README && git commit -q -S -m signed`
  exits 0. `git cat-file commit HEAD` contains `-----BEGIN SSH SIGNATURE-----`.
  `broker.log` has a `msg=signed` line ending in `object="commit \"signed\""`.
  The uid, pid, and procs fields come between them, so match the two parts
  separately.
- **Verify.** `echo "verify@example.com $(cat "$S/keys/signing.pub")" > "$S/evidence/allowed_signers" && git -c gpg.ssh.allowedSignersFile="$S/evidence/allowed_signers" verify-commit HEAD`
  prints `Good "git" signature for verify@example.com`.
- **Passthrough.** `ssh-keygen -q -t ed25519 -N "" -f "$S/other" && echo hi > "$S/msg" && hallpass-sign -Y sign -n git -f "$S/other.pub" "$S/msg"`
  writes `$S/msg.sig`, with no new `msg=signed` line in `broker.log`.
- **Refuse data.** `echo hi > "$S/data" && hallpass-sign -Y sign -n git -f "$S/keys/signing.pub" "$S/data"`
  exits 1 with `hallpass: hallpass only signs unsigned git commits and tags`.
- **Refuse forged.** `printf "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nTHIS IS NOT A GIT COMMIT\0\377" > "$S/fake" && hallpass-sign -Y sign -n git -f "$S/keys/signing.pub" "$S/fake"`
  exits 1 with the same message, and `broker.log` has a `msg=refused` line.
- **Tags and merges.** `git tag -s -m release v1` and, from another branch,
  `git merge -S --no-ff v1` (which writes a `mergetag` header) both sign, and
  `verify-tag` and `verify-commit` print `Good "git" signature`.

## Gotchas

- `hallpass-sign` asks the broker for its status before each signature, so
  each one also logs `msg=allowed op=status check=false`.
- `hallpass-sign` decides by asking the broker for its public key over the
  control socket. With `HALLPASS_RUN_DIR` unset it asks the live broker,
  which has a different key, and passes through to `ssh-keygen`, which
  fails because it has no private key for `$S/keys/signing.pub`.
