#!/usr/bin/env bash
# Pre-commit hook suite: auto-rekey on git mv / policy change, refuse commits the
# server would reject. Team: alice, bob, carol = @core. junior = member, outside @core.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"
PORT="${PORT:-$((20000 + RANDOM % 20000))}"
export VEIL_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
VEIL="node $ROOT/bin/veil.mjs"
VS="node $ROOT/bin/veil-server.mjs"
BASE="http://127.0.0.1:$PORT"
PASS=0 FAIL=0

cleanup() { [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null; rm -rf "$SB"; }
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
expect_ok()   { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 15; fi; }
expect_fail() { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; sed 's/^/        /' "$SB/out" | tail -n 8; else ok "$d"; fi; }
# expect_reject <desc> <pattern> <cmd...>: must fail AND print <pattern> (so it failed for the right reason)
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
expect_out()  { local d="$1" pat="$2"; shift 2; if "$@" 2>&1 | grep -q -- "$pat"; then ok "$d"; else bad "$d (no '$pat')"; "$@" 2>&1 | sed 's/^/        /' | tail -n 8; fi; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

as() { local u="$1"; shift; VEIL_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
url() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/app.git"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }
srv_blob() { git --git-dir="$VEIL_DATA/repos/app.git" cat-file blob "$1"; }
has_path() { srv_blob "$1" | grep -qE "\"path\": *\"$2\""; }

declare -A TOK
echo "== setup"
for u in alice bob carol junior; do
  card=$(as $u $VEIL keygen $u 2>/dev/null)
  TOK[$u]=$($VS user add "$card" 2>/dev/null)
done
$VS repo create app.git --admin alice 2>/dev/null
cat > "$SB/policy.json" <<'EOF'
{ "members": ["*"], "admins": ["alice"],
  "groups": { "core": ["alice", "bob", "carol"] },
  "files": { ".env": ["@core"], "secrets/**": ["@core"] },
  "branches": { "refs/heads/private/": ["@core"] } }
EOF
$VS policy set app.git "$SB/policy.json" 2>/dev/null
$VS serve --port "$PORT" 2>"$SB/server.log" & SRV=$!
for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done

mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$(url alice)"
as alice $VEIL setup 2>/dev/null
echo 'console.log("hello")' > index.js
echo 'STRIPE_SECRET=sk_live_123' > .env
mkdir -p secrets && echo 'db-password' > secrets/db.txt
as alice git add -A
expect_ok "alice's first commit (no HEAD yet) passes the hook" as alice git commit -qm init
expect_ok "alice pushes main with secrets" as alice git push -q -u origin main

echo "== install"
check "veil setup installs an executable pre-commit hook" test -x .git/hooks/pre-commit
expect_out "the hook runs 'veil pre-commit'" "veil.mjs' pre-commit" cat .git/hooks/pre-commit
as alice $VEIL setup 2>/dev/null
[[ "$(grep -c '>>> veil pre-commit' .git/hooks/pre-commit)" == 1 && "$(grep -c "pre-commit || exit 1" .git/hooks/pre-commit)" == 1 ]] \
  && ok "running setup twice leaves exactly one veil invocation" || bad "duplicate veil hook block"
expect_ok "bob clones" as bob $VEIL clone "$(url bob)" "$SB/bob"
check "veil clone installs the hook too" grep -q '>>> veil pre-commit' "$SB/bob/.git/hooks/pre-commit"
# a pre-existing user hook is kept and chained
git clone -q "$(url bob)" "$SB/bob2"
printf '#!/bin/sh\ntouch "$MARK"\n' > "$SB/bob2/.git/hooks/pre-commit" && chmod +x "$SB/bob2/.git/hooks/pre-commit"
in_ "$SB/bob2" as bob $VEIL setup 2>/dev/null
check "the user hook is preserved as pre-commit.local" grep -q 'touch "$MARK"' "$SB/bob2/.git/hooks/pre-commit.local"
check "pre-commit.local keeps its exec bit" test -x "$SB/bob2/.git/hooks/pre-commit.local"
in_ "$SB/bob2" bash -c 'echo "// tweak" >> index.js && git add index.js'
expect_ok "bob commits public code with the chained hook" in_ "$SB/bob2" as bob env MARK="$SB/mark1" git commit -qm tweak
check "the user hook ran (its marker file exists)" test -f "$SB/mark1"
in_ "$SB/bob2" bash -c 'echo STRIPE_SECRET=plain > .env && git -c filter.veil.clean=cat add .env'
expect_reject "veil's check also runs in the chain (plaintext refused)" "plaintext staged for protected path .env" \
  in_ "$SB/bob2" as bob env MARK="$SB/mark2" git commit -qm plain
check "...after the user hook ran" test -f "$SB/mark2"
in_ "$SB/bob2" as bob git reset -q --hard origin/main

echo "== rename happy path"
cd "$SB/alice"
cp secrets/db.txt "$SB/db.saved"
as alice git mv secrets/db.txt secrets/db2.txt
expect_ok "alice commits git mv secrets/db.txt secrets/db2.txt" as alice git commit -qm rename
expect_out "the hook says it rekeyed the file" "rekeyed secrets/db2.txt for alice, bob, carol" cat "$SB/out"
expect_ok "the rename pushes with no manual rekey" as alice git push -q
srv_blob main:secrets/db2.txt | head -1 | grep -q '^VEIL-V1' && ok "server blob is VEIL-V1" || bad "server blob not an envelope"
check "server envelope is bound to secrets/db2.txt" has_path main:secrets/db2.txt 'secrets/db2.txt'
check "working-tree plaintext is byte-identical after the rekey" cmp "$SB/db.saved" secrets/db2.txt
[[ -z "$(as alice git status --porcelain)" ]] && ok "git status is clean after the rekey commit" || { bad "status dirty"; as alice git status --porcelain | sed 's/^/        /'; }
in_ "$SB/bob" as bob git pull -q >/dev/null 2>&1
expect_out "bob reads the renamed secret after git pull" "db-password" cat "$SB/bob/secrets/db2.txt"

echo "== audience change"
sed 's/"alice", "bob", "carol"/"alice", "bob"/' "$SB/policy.json" > "$SB/policy2.json"
$VS policy set app.git "$SB/policy2.json" 2>/dev/null
cd "$SB/alice"
echo 'STRIPE_SECRET=sk_live_rotated' > .env
cp .env "$SB/env.saved"
as alice git add .env                      # sealed for alice, bob, carol (stale policy)
srv_blob main:.env >/dev/null
git cat-file blob :.env | grep -q '"carol"' && ok "staged blob still includes carol before pull-policy" || bad "precondition: no carol"
as alice $VEIL pull-policy 2>/dev/null
expect_ok "alice commits the stale-audience .env (hook rekeys)" as alice git commit -qm "rotate after revocation"
expect_out "the hook rekeyed .env for the new audience" "rekeyed .env for alice, bob" cat "$SB/out"
expect_ok "the server accepts the rekeyed .env" as alice git push -q
srv_blob main:.env | grep -q '"carol"' && bad "pushed envelope still has a carol key" || ok "pushed envelope has no carol key"
check "working-tree .env is byte-identical" cmp "$SB/env.saved" .env
[[ -z "$(as alice git status --porcelain)" ]] && ok "git status is clean after the audience rekey" || bad "status dirty after audience rekey"
# bob still has the old policy and a staged blob produced by update-index from an old (carol) blob
in_ "$SB/bob" as bob git pull -q >/dev/null 2>&1
in_ "$SB/bob" as bob $VEIL pull-policy 2>/dev/null
OLD=$(in_ "$SB/bob" git rev-parse HEAD~1:.env)
in_ "$SB/bob" git update-index --cacheinfo "100644,$OLD,.env"
expect_ok "bob commits an old carol-including blob staged via update-index (hook rekeys)" in_ "$SB/bob" as bob git commit -qm "restore old stripe key"
expect_ok "the server accepts bob's rekeyed blob" in_ "$SB/bob" as bob git push -q
srv_blob main:.env | grep -q '"carol"' && bad "bob's pushed envelope has carol" || ok "bob's pushed envelope has no carol key"
in_ "$SB/alice" as alice git pull -q >/dev/null 2>&1
# bring the rest (secrets/db2.txt) up to the new policy so later checks start clean
in_ "$SB/alice" as alice $VEIL rekey >/dev/null 2>&1 && in_ "$SB/alice" as alice git commit -qm "rekey rest" >/dev/null 2>&1
in_ "$SB/alice" as alice git push -q >/dev/null 2>&1

echo "== junior can't rekey"
expect_ok "junior clones" as junior $VEIL clone "$(url junior)" "$SB/junior"
cd "$SB/junior"
H=$(git rev-parse HEAD)
as junior git mv secrets/db2.txt secrets/db3.txt
expect_reject "junior's in-protection rename aborts: not in its audience" "not in its audience" as junior git commit -qm mv
grep -q "cannot rekey 'secrets/db3.txt'" "$SB/out" && ok "...with 'cannot rekey' and the file name" || bad "message lacks cannot rekey/name"
[[ "$(git rev-parse HEAD)" == "$H" ]] && ok "HEAD is unchanged after the aborted commit" || bad "HEAD moved"
as junior git reset -q --hard
as junior git mv .env .env.bak
expect_reject "junior's git mv .env .env.bak aborts with 'cannot rekey'" "cannot rekey '.env' -> '.env.bak'" as junior git commit -qm mv
[[ "$(git rev-parse HEAD)" == "$H" ]] && ok "HEAD is unchanged again" || bad "HEAD moved"
as junior git reset -q --hard

echo "== filter bypass"
cd "$SB/alice"
echo 'STRIPE_SECRET=sk_live_plain' > .env
as alice git -c filter.veil.clean=cat add .env
expect_reject "plaintext staged via filter bypass is refused" "plaintext staged for protected path .env" as alice git commit -qm plain
as alice git commit -q --no-verify -m plain
expect_reject "with --no-verify the server still rejects the plaintext" "NOT encrypted" as alice git push -q
as alice git reset -q --hard origin/main
cd "$SB/junior"
echo 'DB=leak' > .env
NOF="-c filter.veil.clean=cat -c filter.veil.smudge=cat"   # junior controls their client
as junior git $NOF add .env
expect_reject "junior's plaintext .env is refused locally" "plaintext staged for protected path .env" as junior git $NOF commit -qm leak
as junior git $NOF commit -q --no-verify -m leak
expect_reject "junior's --no-verify push is rejected by the server" "may not modify" as junior git push -q
as junior git reset -q --hard origin/main

echo "== move out of protection"
cd "$SB/alice"
H=$(git rev-parse HEAD)
as alice git mv secrets/db2.txt public.txt
expect_reject "git mv secrets/db2.txt public.txt aborts" "unprotected path" as alice git commit -qm out
grep -q "secrets/db2.txt" "$SB/out" && grep -q "public.txt" "$SB/out" && grep -q "unreadable ciphertext" "$SB/out" \
  && ok "...naming both files and the unreadable-ciphertext risk" || bad "message lacks file names"
[[ "$(git rev-parse HEAD)" == "$H" ]] && ok "HEAD is unchanged" || bad "HEAD moved"
as alice git reset -q --hard

echo "== no-op fast path"
echo '// more' >> index.js && as alice git add index.js
git ls-files -s > "$SB/ls.before"
expect_ok "veil pre-commit with only index.js staged exits 0" as alice env GIT_TRACE="$SB/trace" $VEIL pre-commit
git ls-files -s > "$SB/ls.after"
check "the index is not modified" cmp "$SB/ls.before" "$SB/ls.after"
grep -q 'veil.mjs.* clean' "$SB/trace" && bad "the clean filter was spawned" || ok "the clean filter was not spawned"
[[ "$(grep -c 'trace: built-in: git' "$SB/trace")" -le 4 ]] && ok "only a handful of git calls" || bad "too many git calls: $(grep -c 'built-in: git' "$SB/trace")"
expect_ok "committing only index.js succeeds" as alice git commit -qm "code only"
[[ -z "$(as alice git status --porcelain)" ]] && ok "status clean after code-only commit" || { bad "status dirty"; as alice git status --porcelain | sed 's/^/        /'; }
expect_ok "no policy cached: the hook is a no-op" bash -c "cd '$SB' && git init -q plain && cd plain && $VEIL pre-commit"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
