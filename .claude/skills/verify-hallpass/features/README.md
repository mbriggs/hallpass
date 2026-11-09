# hallpass verification map

Each feature file below is the recipe for one area: its sub-feature IDs,
commands, and expected output.

## Fixture

The fake has `acme/widgets` with branches `main` and `colleague` and a
`.github/workflows/ci.yml`. PR and issue 1 are by `verifier` (the token's
login), and 2 is by `colleague`. `acme/readonly` is a git copy of widgets,
allowlisted read-only. `acme/gadgets` is allowlisted, and the fake answers
it as widgets's old name, so git under it reaches widgets. `acme/gizmos` is
allowlisted, and the fake answers it as the old name of `acme/private`,
which isn't, so git under it is refused. `acme/secret` isn't on the
allowlist, and the fake answers it 401 without the token.
`octo/public` isn't either, and the fake shows it to anyone, as GitHub does
a public repo.

## Driving conventions

- `scripts/drive.sh S FEATURE` runs each feature's cases, from
  `scripts/cases/`. Cases run outside the hallpass checkout, because the
  checkout's own `origin` would confuse gh's repo detection: `drive.sh`
  starts each feature in `/tmp`.
- Every refusal reaches the client prefixed `hallpass: `: in gh's error
  (`GraphQL: hallpass: ...` for GraphQL), in git's `remote:` or `! [remote
  rejected]` output, or on stderr. Match on the reason text quoted in each
  feature file.
- Reasons change wording as the policy code changes. When the text differs
  from a feature file but the request is still refused and absent from the
  fake's log, it's a wording change, not a policy failure: report the new
  text and update the file.
- Pushes change the fake's refs. Each journey says which ones it leaves
  behind. Run them in the order given, or start over with a fresh `up.sh`.

## Features

- [gh REST](./gh-rest.md): `gh api` reads and writes, the allowlist,
  read-only repos, operations and reads that are off by default, refused
  routes, and the author check.
- [gh PR commands and GraphQL](./gh-graphql.md): `gh pr comment`, refused
  `merge` and `approve`, the allowlist, the author check, and the ChatOps
  filter.
- [git over SSH](./git-ssh.md): clone and push to agent branches. Refused
  default, protected, colleague, tag, workflow, and read-only pushes, the
  renamed-repo check, and `push.default`.
- [Signed commits](./signing.md): `git commit -S` through `hallpass-sign`.
- [Status](./status.md): `hallpass status`, `--check`, `--json`, and the
  broker-down error.

The setup commands aren't mapped, because the scratch broker can't reach
them, and the TPM backend needs `HALLPASS_VERIFY_BACKEND=tpm`. See SKILL.md.
