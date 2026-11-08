# gh REST

Agents call GitHub's REST API with `gh api`. The broker adds the token to
the routes its policy allows in allowlisted repos, and returns 403 with a
`hallpass: ` reason for everything else.

## Sub-features

- `rest-read` reads an allowlisted repo.
- `rest-allowlist` refuses a repo outside the allowlist.
- `rest-readonly` refuses writes to a `--read` repo.
- `rest-op` refuses an operation that's off by default (merge).
- `rest-route` refuses a route hallpass never allows (secrets).
- `rest-author` allows edits to your own issues and refuses a colleague's.
- `rest-token` adds the token: gh holds only a placeholder.

## Driving it with gh

Preconditions: `cd /tmp`.

- **Read.** `gh api repos/acme/widgets --jq .full_name` prints
  `acme/widgets` and exits 0. The fake log has
  `GET /api/repos/acme/widgets` with `auth":"token-ok"`.
- **Allowlist.** `gh api repos/acme/secret` exits 1 with
  `gh: hallpass: acme/secret isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow acme/secret (HTTP 403)`.
  The fake log has no `acme/secret` request.
- **Read-only repo.** `gh api -X POST repos/acme/readonly/issues -f title=x`
  exits 1 with `hallpass: agents may only read acme/readonly`.
- **Operation off.** `gh api -X PUT repos/acme/widgets/pulls/1/merge` exits 1
  with `hallpass: agents may not merge PRs or add them to the merge queue in acme/widgets. To allow it: sudo /opt/hallpass/bin/hallpass policy allow pr.merge --repo acme/widgets`.
  No `PUT` reaches the fake.
- **Refused route.** `gh api repos/acme/widgets/actions/secrets` exits 1 with
  `hallpass: hallpass doesn't allow reading repos/{repo}/actions/secrets. Reads are limited to code, PRs, issues, checks, and Actions runs`.
- **Author check, colleague's issue.** `gh api -X PATCH repos/acme/widgets/issues/2 -f title=x`
  exits 1 with `hallpass: agents may only change PRs, issues, and comments you wrote`.
  The fake log has `GET .../issues/2` and no `PATCH`.
- **Author check, own issue.** `gh api -X PATCH repos/acme/widgets/issues/1 -f title=x`
  exits 0 and prints `{"id":101,...}`. The fake log has the `GET` and then the
  `PATCH` with body `{"title":"x"}`.
- **Token.** `grep oauth_token "$S/gh/hosts.yml"` shows only
  `hallpass-brokered`, while every fake log entry for these calls has
  `token-ok`.

## Gotchas

- If you forgot `. "$S/env"`, the refusals still look right but come from
  the live broker. Check `broker.log` for your pid, or `type gh`.
- The fake returns `[]` for any GET under `acme/widgets/` it doesn't know.
  An allowed read with an empty body is the fake, not a broker bug.
