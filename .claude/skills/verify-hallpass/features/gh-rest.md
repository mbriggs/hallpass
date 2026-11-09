# gh REST

Agents call GitHub's REST API with `gh api`. The broker adds the token to
the routes its policy allows in allowlisted repos, and returns 403 with a
`hallpass: ` reason for everything else.

## Sub-features

- `rest-read` reads an allowlisted repo.
- `rest-allowlist` refuses a repo outside the allowlist.
- `rest-readonly` refuses writes to a `--read` repo.
- `rest-op` refuses operations that are off by default (merge, opening issues).
- `rest-route` refuses a route hallpass never allows (secrets).
- `rest-read-off` refuses a read that's off by default but config can open
  (Actions variables).
- `rest-author-colleague` refuses edits to a colleague's issue, and
  `rest-author-own` allows edits to your own.
- `rest-short-sha` refuses an abbreviated SHA, which GitHub resolves across
  forks.
- `rest-token` adds the token: gh holds only a placeholder.

## Driving it

`scripts/drive.sh "$S" rest` runs these cases from `scripts/cases/gh-rest.sh`:

- `rest-read`: `gh api repos/acme/widgets` prints `acme/widgets`, and the
  fake logs the GET with `token-ok`.
- `rest-allowlist`: `acme/secret` is refused with `isn't in hallpass's
  allowlist`, and no request reaches the fake.
- `rest-readonly`: a POST to `acme/readonly` is refused with `agents may
  only read acme/readonly`.
- `rest-op`: the merge route is refused with `agents may not merge PRs`,
  and opening an issue with `agents may not open issues`. No PUT or POST
  reaches the fake.
- `rest-route`: `actions/secrets` is refused with `hallpass never allows
  reading repos/{repo}/actions/secrets`.
- `rest-read-off`: `actions/variables` is refused with the command that
  opens it, `policy allow read:actions/variables --repo acme/widgets`, and
  no `actions/` request reaches the fake.
- `rest-author-colleague`: a PATCH to colleague's issue 2 is refused with
  `agents may only change PRs, issues, and comments you wrote`. The fake
  sees the GET but no PATCH.
- `rest-author-own`: a PATCH to your issue 1 passes and reaches the fake.
- `rest-short-sha`: `commits/abc1234` is refused with `hallpass needs the
  full SHA, not "abc1234"`, and no `commits/` request reaches the fake. The
  same check covers `git/{trees,commits,blobs,tags}/`, `?ref=`, `?sha=`,
  and expressions like `main~1`.
- `rest-token`: `$S/gh/hosts.yml` holds only `hallpass-brokered`.

## Gotchas

- A gh that reaches the live broker gives refusals that look right.
  `drive.sh` refuses to run unless gh is the plain binary and
  `GH_CONFIG_DIR` is `$S/gh`.
- The fake returns `[]` for any GET under `acme/widgets/` it doesn't know.
  An allowed read with an empty body is the fake, not a broker bug.
