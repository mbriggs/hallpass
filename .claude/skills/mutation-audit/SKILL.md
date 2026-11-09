---
name: mutation-audit
description: Run mutation testing on a hallpass package and triage the mutants its tests miss.
disable-model-invocation: true
---

# Mutation audit

`make mutate PKG=./internal/<pkg>` builds the pinned gremlins into `bin/`,
mutates the package's code one change at a time, and runs the whole test
suite against each mutant. It prints the mutants no test caught and writes
every mutant's status to `tmp/mutate-<pkg>.json`. Run it in a lane: see the
[worktree](../worktree/SKILL.md) skill. `internal/policy` takes about 8
minutes, so run it in the background, and run one package at a time:
two runs at once slow each other into false timeouts.

The last audit of `internal/policy` left 23 mutants alive, all equivalent,
most of them off-by-one moves of size and depth caps. A count well above that means new code or a weakened
test.

## Switch cases need a hand check, for now

gremlins v0.6.0 never runs a mutant in a switch case expression. Go's
coverage profile has no block for one, so gremlins reports it NOT COVERED
(go-gremlins/gremlins#298). Those lines hold much of the allow and deny
logic, such as `checkUpdate` and `CheckNode`. Until a gremlins release
fixes it, check them by hand.

Before each audit, look for a release newer than `GREMLINS_VERSION` in the
Makefile:

```
curl -s https://proxy.golang.org/github.com/go-gremlins/gremlins/@v/list
```

If there is one, raise `GREMLINS_VERSION` to it, run `make bin/gremlins-<version>`,
and dry-run it:

```
bin/gremlins-<version> unleash --dry-run --invert-logical --invert-loopctrl ./internal/policy
```

v0.6.0 reports 65 mutants NOT COVERED there, and a build with the fix
proposed in #325 reports 18. If the count drops that far, the release fixed
#298: delete this section and keep the new version. Otherwise put
`GREMLINS_VERSION` back, and tell the user the release didn't fix it.

While v0.6.0 stays pinned, take each NOT COVERED mutant on a `case` line in
the packages below. Make the change gremlins names by hand (`>` to `>=`,
`==` to `!=`, `&&` to `||`), run `go test -count=1 ./...`, and undo the
change. A mutant the suite passes with goes in the report like any other
survivor.

## Packages

Audit the packages that decide what an agent may do: `internal/policy`,
`internal/proxy`, `internal/sshgate`. Elsewhere most survivors are wiring,
error text, and TPM calls, and aren't worth the triage.

## Reading the report

`LIVED` means the suite passed with the mutant in place. A few `TIMED OUT`
are loops the mutant made infinite, and count as caught. Dozens mean the
suite got slower and outran the deadline, which hides mutants that live:
raise `--timeout-coefficient` in the Makefile and run again.

`NOT COVERED` means gremlins never ran the mutant. For a `case` line, see
the hand check above. Elsewhere, no test reaches the line, or it's in a
package-level table that runs at init. Read each one.

Sort each survivor into one of these, reading the code around it:

- **A gap.** The mutant would let a request through that the code means to
  refuse, or refuse one it means to allow, and no test shows it. Write a
  test.
- **A shadowed check.** A later check refuses the same input, so the
  refusal tests pass either way. The refusal tables in `rest_test.go` and
  `git_test.go` assert only that a request is refused, not which check
  refused it. Find an input that only this check refuses. If none exists,
  the check is dead: say so, and propose deleting it or keeping it on
  purpose.
- **Equivalent.** The mutant can't change behavior, such as `>` to `>=` on a
  size cap where the exact boundary doesn't matter. Skip it.

## Report

Show the user the gaps and shadowed checks before writing tests. Give the
mutant, the file and line, and the input that would now get through or get
refused:

```
policy/workflows.go:137 INVERT_LOGICAL: !ok || !baseOK became !ok && !baseOK
  gap: a push whose .github tree hallpass can't read goes on to the trust
  check instead of being refused. No test pushes an unreadable tip.
```

Give the count of equivalent mutants without listing them.
