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
- `sign-namespace` never signs for a namespace other than `git`.
- `sign-tag-merge` signs tags and merge commits that carry a signed tag.

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
- **Refuse forged.** A commit header with a line git never writes:
  `printf "tree %s\nauthor a <a@x> 1 +0000\ncommitter a <a@x> 1 +0000\nx-evil yes\n\nforged\n" "$(git rev-parse HEAD^{tree})" > "$S/fake2" && hallpass-sign -Y sign -n git -f "$S/keys/signing.pub" "$S/fake2"`
  exits 1 with the same message. `broker.log` has a `msg=refused` line
  with `op=sign reason="hallpass only signs unsigned git commits and tags"`.
- **Other namespace.** `hallpass-sign -Y sign -n file -f "$S/keys/signing.pub" "$S/data"`
  passes through to `ssh-keygen`, which has no private key for it, so it
  exits 1 with `No private key found` and `hallpass: exit status 255`. No
  `msg=signed` line.
- **Tags and merges.** The merge needs a branch that forks before the
  tagged commit:
  `git branch side && echo t > tagged && git add tagged && git commit -q -S -m tagged && git tag -s -m release v1`,
  then `git checkout -q side && git merge -q -S --no-ff -m "merge v1" v1`.
  `git cat-file commit HEAD` has a `mergetag` header. `broker.log` has
  `msg=signed` lines with `object="tag \"release\""` and
  `object="commit \"merge v1\""`, and `verify-tag v1` and `verify-commit HEAD`
  (with the allowed signers file above) print `Good "git" signature`.

## Gotchas

- `hallpass-sign` asks the broker for its status before each `-Y sign -n git`,
  including passthroughs and refusals, so each one also logs a
  `msg=allowed` line ending in `op=status check=false`. The uid, pid, and
  procs fields come between them.
- `hallpass-sign` decides by asking the broker for its public key over the
  control socket. With `HALLPASS_RUN_DIR` unset it asks the live broker,
  which has a different key, and passes through to `ssh-keygen`, which
  fails because it has no private key for `$S/keys/signing.pub`.
