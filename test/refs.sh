#!/usr/bin/env bash
# Ref protection suite: read-only members, protected refs (push/force/delete), and the
# content invariant on every ref update (rewinds to commits the server already holds).
# Team: alice (admin), bob, carol = @core. junior = member, outside @core.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"
PORT="${PORT:-$((20000 + RANDOM % 20000))}"
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
BASE="http://127.0.0.1:$PORT"
BARE="$EYESONLY_DATA/repos/app.git"
ZERO=0000000000000000000000000000000000000000
PASS=0 FAIL=0

cleanup() { [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null; rm -rf "$SB"; }
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
expect_ok()   { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 15; fi; }
expect_fail() { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; sed 's/^/        /' "$SB/out" | tail -n 8; else ok "$d"; fi; }
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
expect_out()  { local d="$1" pat="$2"; shift 2; if "$@" 2>&1 | grep -q -- "$pat"; then ok "$d"; else bad "$d (no '$pat')"; "$@" 2>&1 | sed 's/^/        /' | tail -n 8; fi; }

as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
url() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/app.git"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }
srv_ref() { git --git-dir="$BARE" rev-parse "$1"; }
# policy <extra-json-fields>: base policy (carol in @core unless REVOKED=1) plus extra fields
policy() {
  local core='"alice", "bob", "carol"'; [[ "${REVOKED:-}" == 1 ]] && core='"alice", "bob"'
  cat > "$SB/policy.json" <<EOF
{ "members": ["*"], "admins": ["alice"],
  "groups": { "core": [$core, "ghost"], "release": ["alice"] },
  "files": { ".env": ["@core"], "secrets/**": ["@core"] },
  "branches": { "refs/heads/private/": ["@core"] }${1:+, $1} }
EOF
  $VS policy set app.git "$SB/policy.json" 2>/dev/null
}
# hook_as <user> <old> <new> <ref>: run the pre-receive hook directly (proxy bypassed)
hook_as() { (cd "$BARE" && printf '%s %s %s\n' "$2" "$3" "$4" | EYESONLY_USER="$1" ./hooks/pre-receive); }

declare -A TOK
echo "== setup"
for u in alice bob carol junior; do
  card=$(as $u $EYESONLY keygen $u 2>/dev/null)
  TOK[$u]=$($VS user add "$card" 2>/dev/null)
done
$VS repo create app.git --admin alice 2>/dev/null
policy
source "$ROOT/test/lib/server.sh"
start_server PORT "$SB/server.log"; SRV=$LAST_SRV; BASE="http://127.0.0.1:$PORT"

mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$(url alice)"
as alice $EYESONLY setup 2>/dev/null
echo 'console.log("hello")' > index.js
echo 'STRIPE_SECRET=sk_live_123' > .env
as alice git add -A && as alice git commit -qm init
expect_ok "alice pushes main" as alice git push -q -u origin main
as alice git tag v1 && expect_ok "alice pushes tag v1" as alice git push -q origin v1

echo "== baseline (no writers, no protect)"
expect_ok "bob clones" as bob $EYESONLY clone "$(url bob)" "$SB/bob"
in_ "$SB/bob" bash -c 'echo "STRIPE_SECRET=sk_live_456" > .env && echo v2 >> index.js'
in_ "$SB/bob" as bob git commit -qam "rotate stripe" >/dev/null
expect_ok "bob fast-forwards main" in_ "$SB/bob" as bob git push -q
in_ "$SB/bob" as bob git checkout -q -b feature/bob
in_ "$SB/bob" bash -c 'echo feature >> index.js' && in_ "$SB/bob" as bob git commit -qam feature
expect_ok "bob creates his feature branch" in_ "$SB/bob" as bob git push -q origin feature/bob
expect_ok "bob force-pushes his (unprotected) feature branch" in_ "$SB/bob" as bob git push -q -f origin feature/bob~1:feature/bob
expect_ok "bob deletes his feature branch" in_ "$SB/bob" as bob git push -q origin --delete feature/bob
in_ "$SB/bob" as bob git checkout -q main
expect_ok "junior clones" as junior $EYESONLY clone "$(url junior)" "$SB/junior"
in_ "$SB/junior" as junior git checkout -q -b feature/j
in_ "$SB/junior" bash -c 'echo junior > junior.txt' && in_ "$SB/junior" as junior git add junior.txt && in_ "$SB/junior" as junior git commit -qm junior
expect_ok "junior pushes a feature branch" in_ "$SB/junior" as junior git push -q origin feature/j
in_ "$SB/junior" as junior git checkout -q main

echo "== revoke carol, alice rekeys"
in_ "$SB/alice" as alice git pull -q --rebase >/dev/null 2>&1
PRE=$(in_ "$SB/alice" git rev-parse HEAD)   # last commit with .env still encrypted to carol
REVOKED=1 policy
in_ "$SB/alice" as alice $EYESONLY pull-policy 2>/dev/null
in_ "$SB/alice" as alice $EYESONLY rekey 2>/dev/null
in_ "$SB/alice" as alice git commit -qm "rekey: remove carol" >/dev/null
expect_ok "alice pushes the rekeyed .env" in_ "$SB/alice" as alice git push -q
REKEYED=$(srv_ref main)

echo "== rewind to a stale secret"
in_ "$SB/junior" as junior git fetch -q 2>/dev/null
expect_reject "junior force-pushes main back to the pre-rekey commit" "may not force-push refs/heads/main" \
  in_ "$SB/junior" as junior git push -q -f origin "$PRE:main"
expect_reject "alice (admin) force-pushes main back to the pre-rekey commit (content invariant)" "outside the policy: carol" \
  in_ "$SB/alice" as alice git push -q -f origin "$PRE:main"
[[ "$(srv_ref main)" == "$REKEYED" ]] && ok "main still points at the rekeyed commit" || bad "main moved"
expect_reject "creating a new branch at the pre-rekey commit is rejected too" "outside the policy: carol" \
  in_ "$SB/junior" as junior git push -q origin "$PRE:refs/heads/old"
in_ "$SB/alice" as alice git reset -q --hard "$PRE"
in_ "$SB/alice" as alice $EYESONLY rekey 2>/dev/null
in_ "$SB/alice" as alice git commit -qm "rekey (rewritten)" >/dev/null
expect_ok "alice force-pushes a rewritten main with a current-policy .env" in_ "$SB/alice" as alice git push -q -f origin main
in_ "$SB/bob" as bob git pull -q --rebase >/dev/null 2>&1
in_ "$SB/bob" as bob $EYESONLY pull-policy 2>/dev/null

echo "== deletion and tags"
in_ "$SB/junior" as junior git fetch -q -f --tags 2>/dev/null
expect_reject "junior deletes main" "may not delete refs/heads/main" in_ "$SB/junior" as junior git push -q origin --delete main
expect_reject "junior moves tag v1 with a force push" "may not force-push refs/tags/v1" \
  in_ "$SB/junior" as junior git push -q -f origin "origin/main:refs/tags/v1"
expect_reject "junior deletes tag v1" "may not delete refs/tags/v1" in_ "$SB/junior" as junior git push -q origin --delete v1
expect_reject "a multi-ref push with one bad update is rejected as a whole" "may not delete refs/heads/main" \
  in_ "$SB/junior" as junior git push -q origin "origin/main:refs/heads/junior-ok" ":refs/heads/main"
[[ -z "$(git --git-dir="$BARE" for-each-ref refs/heads/junior-ok)" ]] && ok "no ref from the rejected push was created" || bad "partial push landed"

echo "== fast-forward to an existing commit that changes .env"
in_ "$SB/bob" as bob git checkout -q -b feature/env
in_ "$SB/bob" bash -c 'echo "STRIPE_SECRET=sk_live_789" > .env'
in_ "$SB/bob" as bob git commit -qam "new key (not merged)" >/dev/null
expect_ok "bob pushes feature/env" in_ "$SB/bob" as bob git push -q origin feature/env
in_ "$SB/junior" as junior git fetch -q 2>/dev/null
expect_reject "junior fast-forwards main to bob's existing .env commit" "may not change protected file '.env'" \
  in_ "$SB/junior" as junior git push -q origin "origin/feature/env:main"
expect_ok "bob fast-forwards main to it himself" in_ "$SB/bob" as bob git push -q origin feature/env:main
in_ "$SB/junior" as junior git fetch -q 2>/dev/null
in_ "$SB/junior" as junior git checkout -q feature/j
in_ "$SB/junior" as junior git merge -q --no-edit origin/main >/dev/null 2>&1
expect_ok "junior merges main (with the new .env) into feature/j and pushes" in_ "$SB/junior" as junior git push -q origin feature/j
in_ "$SB/junior" as junior git checkout -q main

echo "== protected push list"
REVOKED=1 policy '"protect": { "refs/heads/main": { "push": ["@release"] }, "refs/heads/private/": { "delete": ["@release"] } }'
in_ "$SB/bob" as bob git checkout -q main && in_ "$SB/bob" as bob git pull -q --rebase >/dev/null 2>&1
in_ "$SB/bob" bash -c 'echo v3 >> index.js' && in_ "$SB/bob" as bob git commit -qam v3
expect_reject "bob (not in @release) fast-forwards main" "may not push to protected ref refs/heads/main" in_ "$SB/bob" as bob git push -q origin main
expect_ok "bob can still push other branches" in_ "$SB/bob" as bob git push -q origin main:refs/heads/feature/v3
in_ "$SB/alice" as alice git pull -q --rebase >/dev/null 2>&1
in_ "$SB/alice" bash -c 'echo v4 >> index.js' && in_ "$SB/alice" as alice git commit -qam v4
expect_ok "alice (in @release) fast-forwards main" in_ "$SB/alice" as alice git push -q origin main
expect_ok "bob pushes private/x (he is in its audience)" in_ "$SB/bob" as bob git push -q origin main:refs/heads/private/x
expect_reject "bob can't delete private/x without delete rights" "may not delete refs/heads/private/x" \
  in_ "$SB/bob" as bob git push -q origin --delete private/x
expect_ok "alice (in the delete list) deletes private/x" in_ "$SB/alice" as alice git push -q origin --delete private/x

echo "== read-only members (writers)"
REVOKED=1 policy '"writers": ["@core"]'
expect_ok "read-only junior can still clone" as junior $EYESONLY clone "$(url junior)" "$SB/junior2"
expect_ok "read-only junior can still fetch" in_ "$SB/junior" as junior git fetch -q
in_ "$SB/junior" as junior git checkout -q -b feature/ro
expect_reject "proxy refuses junior's git push (403)" "403" in_ "$SB/junior" as junior git push origin feature/ro
expect_out "proxy says why: read-only access" "\[eyesonly\] read-only access" \
  curl -s -u "junior:${TOK[junior]}" "$BASE/app.git/info/refs?service=git-receive-pack"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -u "junior:${TOK[junior]}" -X POST "$BASE/app.git/git-receive-pack")
[[ "$CODE" == 403 ]] && ok "POST git-receive-pack as read-only junior is 403" || bad "receive-pack POST ($CODE)"
expect_reject "hook rejects read-only junior directly (proxy bypassed)" "has read-only access to this repository" \
  hook_as junior $ZERO "$(srv_ref main)" refs/heads/feature/ro
expect_ok "bob (writer) still pushes" in_ "$SB/bob" as bob git push -q origin main:refs/heads/feature/bob2

echo "== policy validation"
REVOKED=1
bad_policy() { sed "s|}$|, $1 }|" > "$SB/bad.json" <<<'{ "members": ["*"], "admins": ["alice"] }'; $VS policy set app.git "$SB/bad.json"; }
expect_reject "protect key without refs/ is refused" "must start with refs/" bad_policy '"protect": { "heads/main": { "force": [] } }'
expect_reject "protect value that isn't a list is refused" "must be a list of names" bad_policy '"protect": { "refs/heads/main": { "push": "@core" } }'
expect_reject "unknown key in a protect rule is refused" "not a known key" bad_policy '"protect": { "refs/heads/main": { "admins": [] } }'
expect_reject "writers that isn't a list is refused" "writers must be a list" bad_policy '"writers": "@core"'

echo "== policy endpoint"
REVOKED=1 policy '"writers": ["@core"], "protect": { "refs/heads/private/launch": { "push": ["@core"] } }'
curl -s -u "junior:${TOK[junior]}" "$BASE/app.git/eyesonly/policy" > "$SB/view.json"
expect_fail "policy view does not mention protect" grep -q protect "$SB/view.json"
expect_fail "policy view does not mention writers" grep -q writers "$SB/view.json"
expect_fail "policy view does not leak the private ref prefix" grep -q "private" "$SB/view.json"
grep -q '"files"' "$SB/view.json" && ok "policy view still serves file rules" || bad "policy view broken"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
