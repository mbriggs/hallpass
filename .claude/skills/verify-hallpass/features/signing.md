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
- `sign-other-namespace` never signs for a namespace other than `git`.
- `sign-tag-merge` signs tags and merge commits that carry a signed tag.

## Driving it

`scripts/drive.sh "$S" signing` runs these cases from
`scripts/cases/signing.sh` in `$S/sign`, with no remote:

- `sign-commit`: `git commit -S` gives a commit with an SSH signature,
  `broker.log` has `msg=signed` for `object="commit \"signed\""`, and
  `verify-commit` prints `Good "git" signature for verify@example.com`.
- `sign-passthrough`: a key that isn't the broker's signs through
  `ssh-keygen`, with no `msg=signed` in `broker.log`.
- `sign-refuse-data`: plain data is refused with `hallpass only signs
  unsigned git commits and tags`.
- `sign-refuse-forged`: a commit header with a line git never writes is
  refused the same way, and `broker.log` has `op=sign reason="hallpass only
  signs unsigned git commits and tags"`.
- `sign-other-namespace`: `-n file` passes through to `ssh-keygen`, which
  has no private key for the broker's public key and fails with `No private
  key found`. Nothing is signed.
- `sign-tag-merge`: a signed tag, and a signed merge of it from a branch
  that forks before it, which writes a `mergetag` header. `broker.log` has
  `object="tag \"release\""` and `object="commit \"merge v1\""`, and
  `verify-tag` and `verify-commit` print `Good "git" signature`.

## Gotchas

- `hallpass-sign` asks the broker for its status before each `-Y sign -n git`,
  including passthroughs and refusals, so each one also logs a
  `msg=allowed` line ending in `op=status check=false`. The uid, pid, and
  procs fields come between them.
- `hallpass-sign` decides by asking the broker for its public key over the
  control socket. With `HALLPASS_RUN_DIR` unset it asks the live broker,
  which has a different key, and passes through to `ssh-keygen`, which
  fails because it has no private key for `$S/keys/signing.pub`.
