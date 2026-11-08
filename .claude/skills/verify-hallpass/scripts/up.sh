#!/usr/bin/env bash
# Start a scratch hallpass broker, as you, against a fake GitHub. Nothing
# here touches /etc/hallpass, /run/hallpass, the live broker, or github.com.
#
#   up.sh [SCRATCH_DIR]     default: a new /tmp/hallpass-verify.XXXXXX, or in a
#                           lane /tmp/hallpass-verify-lane<n>.XXXXXX, which the
#                           lane's teardown stops and deletes
#
# Prints the scratch dir on the last line. Source "$S/env" before driving.
set -euo pipefail

repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
here=$(cd "$(dirname "$0")" && pwd)
# In a linked worktree, load its lane, or refuse if it has none.
. "$repo/bin/worktree-env.sh"
worktree_load "$repo"
# Under /tmp, not the checkout: macOS caps socket paths at 104 bytes.
S=${1:-$(mktemp -d "${HALLPASS_VERIFY_PREFIX:-/tmp/hallpass-verify}.XXXXXX")}
S=$(cd "$(mkdir -p "$S" && echo "$S")" && pwd)
if [ -e "$S/broker.pid" ] && kill -0 "$(cat "$S/broker.pid")" 2>/dev/null; then
  echo "up.sh: a broker from $S is already running; run down.sh $S first" >&2
  exit 1
fi
mkdir -p "$S"/{bin,run,gh,gh-root,evidence,keys}
chmod 700 "$S/keys"

# The binary under test: the checkout, built the way the Makefile builds it.
make -C "$repo" -s build
cp "$repo/bin/hallpass" "$S/bin/hallpass"
ln -sf hallpass "$S/bin/hallpass-sign"
(cd "$here/fakegithub" && go build -o "$S/bin/fakegithub" main.go)

# Credentials, all file-backed and fake. The token only works on the fake.
[ -s "$S/keys/token" ] || { printf 'hpverify_%s' "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$S/keys/token"; chmod 600 "$S/keys/token"; }
if [ ! -s "$S/keys/signing.pem" ]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$S/keys/signing.pem" 2>/dev/null
  chmod 600 "$S/keys/signing.pem"
fi
ssh-keygen -y -f "$S/keys/signing.pem" > "$S/keys/signing.pub"

# Seed GitHub's side: acme/widgets with main and a colleague's branch.
bare="$S/gh-root/acme/widgets.git"
plain=(env GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_AUTHOR_NAME=seed GIT_AUTHOR_EMAIL=seed@example.com GIT_COMMITTER_NAME=seed GIT_COMMITTER_EMAIL=seed@example.com)
if [ ! -d "$bare" ]; then
  "${plain[@]}" git init -q --bare -b main "$bare"
  "${plain[@]}" git -C "$bare" config http.receivepack true
  seed=$(mktemp -d "$S/seed.XXXX")
  "${plain[@]}" git init -q -b main "$seed"
  echo widgets > "$seed/README"
  "${plain[@]}" git -C "$seed" add README
  "${plain[@]}" git -C "$seed" commit -q -m seed
  "${plain[@]}" git -C "$seed" push -q "$bare" main main:colleague
  rm -rf "$seed"
fi

# The fake GitHub.
rm -f "$S/fake.url"
nohup "$S/bin/fakegithub" -root "$S/gh-root" -token-file "$S/keys/token" \
  -log "$S/evidence/github-requests.jsonl" -ready "$S/fake.url" > "$S/fake.log" 2>&1 &
echo $! > "$S/fake.pid"
for _ in $(seq 50); do [ -s "$S/fake.url" ] && break; sleep 0.1; done
[ -s "$S/fake.url" ] || { echo "up.sh: fakegithub didn't start; see $S/fake.log" >&2; exit 1; }
url=$(cat "$S/fake.url")

# The broker's config. protected_branches gives the protected-branch
# refusal something to hit.
cat > "$S/hallpass.toml" <<EOF
uids = [$(id -u)]
protected_branches = ["release/*"]
api_url = "$url/api"
git_url = "$url"

[token]
secret = "file:$S/keys/token"
source = "pat"
login = "verifier"
created = $(date -u +%Y-%m-%dT%H:%M:%SZ)

[signing]
key = "file:$S/keys/signing.pem"
public = "$(cat "$S/keys/signing.pub")"

[[repo]]
match = "acme/widgets"

[[repo]]
match = "acme/readonly"
access = "read"
EOF

# The broker. HALLPASS_RUN_DIR moves its sockets into the scratch dir.
nohup env HALLPASS_RUN_DIR="$S/run" "$S/bin/hallpass" serve --config "$S/hallpass.toml" > "$S/evidence/broker.log" 2>&1 &
echo $! > "$S/broker.pid"
for _ in $(seq 50); do grep -q 'msg=serving' "$S/evidence/broker.log" 2>/dev/null && break; sleep 0.1; done
grep -q 'msg=serving token=true ssh=false signing=true' "$S/evidence/broker.log" || {
  echo "up.sh: broker didn't come up with token and signing; see $S/evidence/broker.log" >&2; cat "$S/evidence/broker.log" >&2; exit 1; }

# Client side: what hallpass install writes, pointed at the scratch sockets,
# with no system or global git config and no credentials anywhere.
cat > "$S/gitconfig" <<EOF
[url "http://github.com/"]
	insteadOf = https://github.com/
	insteadOf = git@github.com:
	insteadOf = ssh://git@github.com/
[http "http://github.com/"]
	proxy = socks5h://localhost$S/run/git.sock
	followRedirects = false
[credential "https://github.com"]
	helper =
	helper = $S/bin/hallpass credential
[credential "http://github.com"]
	helper =
	helper = $S/bin/hallpass credential
[gpg]
	format = ssh
[gpg "ssh"]
	program = $S/bin/hallpass-sign
[user]
	name = Verify Agent
	email = verify@example.com
	signingKey = $S/keys/signing.pub
[init]
	defaultBranch = main
EOF
cat > "$S/gh/config.yml" <<EOF
version: "1"
git_protocol: https
prompt: disabled
telemetry: disabled
http_unix_socket: $S/run/gh.sock
EOF
cat > "$S/gh/hosts.yml" <<'EOF'
github.com:
    users:
        hallpass:
            oauth_token: hallpass-brokered
    git_protocol: https
    oauth_token: hallpass-brokered
    user: hallpass
EOF
cat > "$S/env" <<EOF
# Source this before driving the scratch broker.
export S="$S"
export HALLPASS_RUN_DIR="$S/run"
export PATH="$S/bin:\$PATH"
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL="$S/gitconfig"
export GIT_TERMINAL_PROMPT=0
export GH_CONFIG_DIR="$S/gh"
export GH_NO_UPDATE_NOTIFIER=1 GH_PROMPT_DISABLED=1 NO_COLOR=1
unset GH_TOKEN GITHUB_TOKEN GH_HOST SSH_AUTH_SOCK
# This machine aliases gh to the LIVE broker's wrapper. Drop the alias so
# plain gh is the real binary, which GH_CONFIG_DIR points at the scratch
# broker.
unalias gh git 2>/dev/null || true
EOF
echo "$S"
