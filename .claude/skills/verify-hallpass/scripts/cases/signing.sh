# Signed commit cases. See features/signing.md. Nothing here has a remote.
feature_signing() {
  rm -rf "$S/sign" && git init -q "$S/sign" && cd "$S/sign" || { fail "no repo"; return; }
  local signers="$S/evidence/allowed_signers"
  echo "verify@example.com $(cat "$S/keys/signing.pub")" > "$signers"

  case_ sign-commit
  check 0 '' 'echo s > README && git add README && git commit -q -S -m signed'
  check 0 '-----BEGIN SSH SIGNATURE-----' 'git cat-file commit HEAD'
  broker_has msg=signed
  broker_has 'object="commit \"signed\""'
  check 0 'Good "git" signature for verify@example.com' "git -c gpg.ssh.allowedSignersFile=\"$signers\" verify-commit HEAD"

  case_ sign-passthrough
  rm -f "$S/other" "$S/other.pub" "$S/msg.sig"
  check 0 '' "ssh-keygen -q -t ed25519 -N '' -f \"$S/other\" && echo hi > \"$S/msg\" && hallpass-sign -Y sign -n git -f \"$S/other.pub\" \"$S/msg\" && test -s \"$S/msg.sig\""
  broker_lacks msg=signed

  case_ sign-refuse-data
  check fail 'hallpass only signs unsigned git commits and tags' "echo hi > \"$S/data\" && hallpass-sign -Y sign -n git -f \"$S/keys/signing.pub\" \"$S/data\""

  case_ sign-refuse-forged
  # A commit header with a line git never writes.
  check fail 'hallpass only signs unsigned git commits and tags' "printf 'tree %s\nauthor a <a@x> 1 +0000\ncommitter a <a@x> 1 +0000\nx-evil yes\n\nforged\n' \"\$(git rev-parse 'HEAD^{tree}')\" > \"$S/fake2\" && hallpass-sign -Y sign -n git -f \"$S/keys/signing.pub\" \"$S/fake2\""
  broker_has 'op=sign reason="hallpass only signs unsigned git commits and tags"'

  case_ sign-other-namespace
  check fail 'No private key found' "hallpass-sign -Y sign -n file -f \"$S/keys/signing.pub\" \"$S/data\""
  broker_lacks msg=signed

  case_ sign-tag-merge
  # The merge needs a branch that forks before the tagged commit.
  check 0 '' 'git branch side && echo t > tagged && git add tagged && git commit -q -S -m tagged && git tag -s -m release v1'
  check 0 '' 'git checkout -q side && git merge -q -S --no-ff -m "merge v1" v1'
  check 0 mergetag 'git cat-file commit HEAD'
  broker_has 'object="tag \"release\""'
  broker_has 'object="commit \"merge v1\""'
  check 0 'Good "git" signature' "git -c gpg.ssh.allowedSignersFile=\"$signers\" verify-tag v1"
  check 0 'Good "git" signature' "git -c gpg.ssh.allowedSignersFile=\"$signers\" verify-commit HEAD"
}
