#!/usr/bin/env bash
# Eyes Only in ~30 seconds, entirely on this machine (temp dir, local server, two users).
#   alice is in @core: she can read .env and see private/* branches.
#   junior is a member but not in @core: he gets ciphertext and can't see private/*.
# Run: npx eyesonly demo   (or: bash examples/demo.sh)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EO="node $ROOT/bin/eyesonly.mjs"
EOS="node $ROOT/bin/eyesonly-server.mjs"
cleanup() { [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null; rm -rf "$SB"; }
trap cleanup EXIT

B=$'\e[1m' D=$'\e[2m' G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' N=$'\e[0m'
[[ -t 1 ]] || { B= D= G= R= Y= N=; }
step() { printf '\n%s== %s%s\n' "$B" "$1" "$N"; }
say()  { printf '%s%s$%s %s\n' "$D" "$1" "$N" "$2"; }
as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@example.com GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@example.com "$@"; }
declare -A TOK
url() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/app.git"; }

step "Setup: a server, two users, one policy"
for u in alice junior; do TOK[$u]=$($EOS user add "$(as $u $EO keygen $u 2>/dev/null)" 2>/dev/null); done
$EOS repo create app.git --admin alice 2>/dev/null
$EOS policy set app.git - 2>/dev/null <<'EOF'
{ "members": ["*"], "admins": ["alice"],
  "groups":   { "core": ["alice"] },
  "files":    { ".env": ["@core"] },
  "branches": { "refs/heads/private/": ["@core"] } }
EOF
$EOS serve --port 0 2>"$SB/server.log" & SRV=$!   # OS picks a free port
PORT=""
for _ in $(seq 200); do
  PORT=$(grep -o 'listening on http://127\.0\.0\.1:[0-9]*' "$SB/server.log" 2>/dev/null | grep -o '[0-9]*$' || true)
  [[ -n "$PORT" ]] && curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null && break
  PORT=""; sleep 0.05
done
[[ -n "$PORT" ]] || { echo "server did not start:" >&2; cat "$SB/server.log" >&2; exit 1; }
printf '  policy: .env readable by @core (alice); refs/heads/private/* visible to @core only\n'

step "alice commits code and a secret"
mkdir -p "$SB/alice" && cd "$SB/alice" && git init -q -b main && git remote add origin "$(url alice)"
as alice $EO setup 2>/dev/null
echo 'console.log("hello")' > index.js && echo 'STRIPE_SECRET=sk_live_51H_demo' > .env
as alice git add -A && as alice git commit -qm init && as alice git push -q -u origin main 2>/dev/null
say alice 'cat .env'; printf '%s%s%s\n' "$G" "$(cat .env)" "$N"
say server 'git cat-file blob main:.env | head -c 60'
printf '%s%s…%s\n' "$Y" "$(git --git-dir="$EYESONLY_DATA/repos/app.git" cat-file blob main:.env | tr '\n' ' ' | head -c 60)" "$N"

step "junior clones the same repo"
as junior $EO clone "$(url junior)" "$SB/junior" 2>/dev/null
cd "$SB/junior"
say junior 'cat index.js'; cat index.js
say junior 'cat .env | head -c 60'; printf '%s%s…%s\n' "$Y" "$(head -c 60 .env | tr '\n' ' ')" "$N"
say junior 'git status --short'; as junior git status --short; printf '%s(clean)%s\n' "$D" "$N"

step "alice pushes a private branch"
cd "$SB/alice" && as alice git checkout -q -b private/launch
echo 'Launch: March 3' > LAUNCH.md && as alice git add LAUNCH.md && as alice git commit -qm "launch plan" && as alice git push -q origin private/launch 2>/dev/null
SECRET=$(git rev-parse HEAD)
say alice 'git ls-remote origin'; git ls-remote origin 2>/dev/null | sed 's/^\(.\{8\}\)[^\t]*/\1…/'
say junior 'git ls-remote origin'; (cd "$SB/junior" && git ls-remote origin 2>/dev/null | sed 's/^\(.\{8\}\)[^\t]*/\1…/')
say junior "git -c protocol.version=2 fetch origin ${SECRET:0:8}… (he learned the sha somehow)"
(cd "$SB/junior" && git -c protocol.version=2 fetch -q origin "$SECRET" 2>&1 | head -1 | sed "s/^/$R/;s/\$/$N/") || true

step "junior tries to get around it"
cd "$SB/junior"
say junior 'echo DB_PASS=oops > .env && git add .env'
(echo 'DB_PASS=oops' > .env && as junior git add .env 2>&1 | grep '^\[eyesonly\]' | sed "s/^/$R/;s/\$/$N/") || true
as junior git checkout -q -- .env 2>/dev/null || true
say junior 'git -c filter.eyesonly.clean=cat commit -am leak && git push   (client filter disabled)'
echo 'DB_PASS=oops' > .env
as junior git -c filter.eyesonly.clean=cat -c filter.eyesonly.smudge=cat add .env
as junior git -c filter.eyesonly.clean=cat -c filter.eyesonly.smudge=cat commit -qm leak --no-verify
as junior git push -q 2>&1 | grep 'REJECTED' | sed "s/^remote: *//;s/ *$//;s/^/$R/;s/\$/$N/" || true

step "alice merges the private branch into main by mistake"
cd "$SB/alice" && as alice git checkout -q main && as alice git merge -q --no-ff -m "merge launch" private/launch
say alice 'git merge private/launch && git push'
as alice git push -q 2>&1 | grep 'REJECTED' | sed "s/^remote: *//;s/ *$//;s/^/$R/;s/\$/$N/" || true
as alice git reset -q --hard origin/main
as alice git merge -q --squash private/launch >/dev/null && as alice git commit -qm "Launch (squashed)"
say alice 'git merge --squash private/launch && git commit && git push'
as alice git push -q 2>/dev/null && printf '%saccepted: only the squashed content goes public, not the private history%s\n' "$G" "$N"

printf '\n%sThat was the stock git client the whole time. More: README.md, THREAT_MODEL.md, `npm test`.%s\n' "$B" "$N"
