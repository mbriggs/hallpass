#!/usr/bin/env bash
# Run a matrix of real gh commands through a scratch broker, recording each
# request and the broker's verdict with capture/. The commands are the ones
# agents run most, from their session history, plus reads the floor should
# refuse.
#
#   gh-matrix.sh SCRATCH_DIR OUT.jsonl     after up.sh; nothing reaches github.com
#
# Each command's records follow a {"mark": "gh ..."} line. Summarize with
# gh-matrix-report.py OUT.jsonl.
set -uo pipefail
S=${1:?usage: gh-matrix.sh SCRATCH_DIR OUT.jsonl}
OUT=${2:?usage: gh-matrix.sh SCRATCH_DIR OUT.jsonl}
OUT=$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")
here=$(cd "$(dirname "$0")" && pwd)
. "$S/env"

# capture between gh and the broker, and a gh config that points at it.
(cd "$here/capture" && go build -o "$S/bin/capture" main.go) || exit 1
: > "$OUT"
"$S/bin/capture" -listen "$S/run/capture.sock" -broker "$S/run/gh.sock" -out "$OUT" &
cap=$!
trap 'kill $cap 2>/dev/null' EXIT
for _ in $(seq 50); do [ -S "$S/run/capture.sock" ] && break; sleep 0.1; done
mkdir -p "$S/gh-capture"
cp "$S/gh/hosts.yml" "$S/gh-capture/"
sed "s#^http_unix_socket: .*#http_unix_socket: $S/run/capture.sock#" "$S/gh/config.yml" > "$S/gh-capture/config.yml"
export GH_CONFIG_DIR=$S/gh-capture

# A clone of acme/widgets from the fake, with an agent branch pushed.
W=$(mktemp -d "$S/matrix.XXXX")/widgets
git clone -q http://github.com/acme/widgets "$W" || exit 1
cd "$W"
git checkout -q -b agent/matrix
echo matrix > matrix.txt
git add matrix.txt
git commit -q -m "matrix probe"
git push -q -u origin agent/matrix 2>/dev/null

run() {
  printf '{"mark":%s}\n' "$(printf '%s' "gh $*" | python3 -I -c 'import json,sys; print(json.dumps(sys.stdin.read()))')" >> "$OUT"
  out=$(perl -e 'alarm shift; exec @ARGV' 20 gh "$@" 2>&1 </dev/null)
  rc=$?
  printf '{"result":%s,"exit":%d}\n' "$(printf '%s' "$out" | tail -c 400 | python3 -I -c 'import json,sys; print(json.dumps(sys.stdin.read()))')" "$rc" >> "$OUT"
}

# Tier 1: the daily workflow.
run pr view 1
run pr view 1 --comments
run pr view 1 --json title,body,state,reviews,comments,statusCheckRollup,files,commits,labels,assignees
run run view 5
run run view 5 --log
run run view 5 --log-failed
run run view --job 7
run run list
run run list --branch main --json databaseId,status,conclusion,headSha,workflowName
run run list --workflow ci.yml
run run watch 5 --exit-status
run issue view 1
run issue view 1 --comments
run pr list
run pr list --state all --json number,title,headRefName,author
run pr diff 1
run pr edit 1 --title "retitled"
run pr edit 1 --add-label bug
run pr create --base main --head agent/matrix --title "matrix" --body "probe"
run pr checks 1
run repo view
run run rerun 5
run run rerun 5 --failed
run pr merge 1 --squash
run api repos/acme/widgets/pulls/1/comments
run api -X POST repos/acme/widgets/pulls/1/comments/3/replies -f body=reply
run api repos/acme/widgets
run api repos/acme/widgets/actions/runs/5/jobs
run api repos/acme/widgets/actions/jobs/7
run api repos/acme/widgets/actions/jobs/7/logs
run api repos/acme/widgets/releases/latest
run api repos/acme/widgets/releases/tags/v1.0.0
run api "repos/acme/widgets/git/trees/HEAD?recursive=1"
run api repos/acme/widgets/issues/1/comments
run api repos/acme/widgets/pulls/1/reviews
run api repos/acme/widgets/contents/README
run api graphql -f query='{repository(owner:"acme",name:"widgets"){pullRequest(number:1){title reviewThreads(first:10){nodes{isResolved comments(first:5){nodes{body path}}}}}}}'

# Tier 2.
run workflow list
run workflow view ci.yml
run issue list
run issue comment 1 --body "comment"
run issue create --title "matrix" --body "probe"
run pr edit 1 --add-assignee verifier
run pr comment 1 --body "comment"
run run download 5
run search prs --repo acme/widgets matrix
run search issues --repo acme/widgets matrix
run search repos widgets
run pr checkout 1
run release list
run release view v1.0.0
run label list

# Reads the floor or the defaults decide.
run variable list
run secret list
run api repos/acme/widgets/environments
run api repos/acme/widgets/environments/production/secrets
run api repos/acme/widgets/rulesets
run api repos/acme/widgets/branches/main/protection
