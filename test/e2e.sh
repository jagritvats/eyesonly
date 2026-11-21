#!/usr/bin/env bash
# Adversarial end-to-end suite. Every "attack" must fail; every "team" flow must work.
# Team: alice (admin), bob, carol = @core. junior = member, outside @core.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"
PORT="${PORT:-$((20000 + RANDOM % 20000))}"
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
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

# as <user> <cmd...>: run with that user's identity and git author
as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
url() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/app.git"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }

declare -A TOK
echo "== setup"
for u in alice bob carol junior; do
  card=$(as $u $EYESONLY keygen $u 2>/dev/null)
  TOK[$u]=$($VS user add "$card" 2>/dev/null)
done
$VS repo create app.git --admin alice 2>/dev/null
# "ghost" is deliberately unregistered: unknown names in a rule must not break audience checks
cat > "$SB/policy.json" <<'EOF'
{ "members": ["*"], "admins": ["alice"],
  "groups": { "core": ["alice", "bob", "carol", "ghost"] },
  "files": { ".env": ["@core"], "secrets/**": ["@core"] },
  "branches": { "refs/heads/private/": ["@core"] } }
EOF
$VS policy set app.git "$SB/policy.json" 2>/dev/null
source "$ROOT/test/lib/server.sh"
start_server PORT "$SB/server.log"; SRV=$LAST_SRV; BASE="http://127.0.0.1:$PORT"

# alice creates the repo contents
mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$(url alice)"
as alice $EYESONLY setup 2>/dev/null
echo 'console.log("hello")' > index.js
echo 'STRIPE_SECRET=sk_live_123' > .env
mkdir -p secrets && echo 'db-password' > secrets/db.txt
as alice git add -A && as alice git commit -qm init
expect_ok "alice pushes main with secrets" as alice git push -q -u origin main
BLOB=$(git --git-dir="$EYESONLY_DATA/repos/app.git" cat-file blob main:.env)
[[ "$BLOB" == EYESONLY-V1* && "$BLOB" != *sk_live* ]] && ok "server stores .env as ciphertext only" || bad "server has plaintext .env"

echo "== team flows"
expect_ok "bob clones" as bob $EYESONLY clone "$(url bob)" "$SB/bob"
expect_out "bob reads .env plaintext" "sk_live_123" cat "$SB/bob/.env"
expect_ok "junior clones" as junior $EYESONLY clone "$(url junior)" "$SB/junior"
expect_out "junior sees only ciphertext" "EYESONLY-V1" head -1 "$SB/junior/.env"
expect_out "junior reads public code" "hello" cat "$SB/junior/index.js"
[[ -z "$(in_ "$SB/junior" as junior git status --porcelain)" ]] && ok "junior's git status is clean" || bad "junior status dirty"
in_ "$SB/bob" bash -c 'echo "STRIPE_SECRET=sk_live_456" > .env'
in_ "$SB/bob" as bob git commit -qam "rotate stripe" >/dev/null
expect_ok "bob pushes an updated secret" in_ "$SB/bob" as bob git push -q
in_ "$SB/alice" as alice git pull -q --rebase >/dev/null 2>&1
expect_out "alice pulls bob's change, decrypted" "sk_live_456" cat "$SB/alice/.env"
in_ "$SB/alice" as alice git add --renormalize . >/dev/null 2>&1
[[ -z "$(in_ "$SB/alice" as alice git status --porcelain)" ]] && ok "re-adding unchanged secrets causes no diff" || bad "noisy diff"
expect_out "git diff shows plaintext to authorized users" "sk_live_999" \
  in_ "$SB/alice" as alice bash -c 'echo STRIPE_SECRET=sk_live_999 > .env && git diff; git checkout -q -- .env'
expect_out "git log -p shows junior a placeholder, not ciphertext" "eyesonly: encrypted" in_ "$SB/junior" as junior git log -p -1 -- .env
expect_out "eyesonly status reports locked files for junior" "locked" in_ "$SB/junior" as junior $EYESONLY status

echo "== attacks on secrets"
cd "$SB/junior" && as junior git pull -q >/dev/null 2>&1
expect_fail "junior can't stage an edit to .env (client refuses)" as junior bash -c 'echo X=1 > .env && git add .env'
as junior git checkout -q -- .env 2>/dev/null; as junior git reset -q --hard
echo 'DB_PASS=leaked' > .env
NOF="-c filter.eyesonly.clean=cat -c filter.eyesonly.smudge=cat"   # attacker disables the client filter
as junior git $NOF add .env && as junior git $NOF commit -q --no-verify -m "pushed the .env too" >/dev/null
expect_reject "plaintext .env push (filters bypassed) is rejected" "may not modify protected file '.env'" as junior git push -q
git reset -q --hard origin/main
# forge: a valid envelope signed by junior and encrypted to the whole team
node --input-type=module -e '
const vc = await import(process.argv[1] + "/src/crypto.mjs");
const fs = await import("node:fs");
const id = JSON.parse(fs.readFileSync(process.argv[2] + "/identity.json"));
const pol = JSON.parse(fs.readFileSync(".git/eyesonly/policy.json"));
const r = {}; for (const u of pol.files[".env"]) r[u] = pol.keys[u].x25519;
r.junior = id.x25519.pub;
fs.writeFileSync(".env", vc.seal({ plaintext: Buffer.from("API_URL=https://evil\n"), path: ".env", recipients: r, signer: id }));
' "$ROOT" "$SB/home/junior"
as junior git add .env && as junior git commit -q --no-verify -m forge >/dev/null
expect_reject "forged envelope signed by junior is rejected" "may not modify" as junior git push -q
git reset -q --hard origin/main
OLD=$(git rev-list --max-parents=0 HEAD)
git cat-file blob "$OLD:.env" > .env && as junior git add .env && as junior git commit -q --no-verify -m rollback >/dev/null
expect_reject "rollback to an old, validly-signed .env is rejected" "may not modify" as junior git push -q
git reset -q --hard origin/main
as junior git rm -q .env && as junior git commit -qm delete >/dev/null
expect_reject "junior can't delete a protected file" "may not delete" as junior git push -q
git reset -q --hard origin/main
mkdir -p secrets && echo 'new-secret' > secrets/new.txt
expect_reject "junior can't add a new file under secrets/" "not allowed to write" as junior bash -c 'git add secrets/new.txt'
rm -rf secrets/new.txt

echo "== attacks on identity and transport"
expect_fail "wrong token for alice is rejected" git ls-remote "http://alice:nope@127.0.0.1:$PORT/app.git"
expect_fail "junior's token can't be used as alice" git ls-remote "http://alice:${TOK[junior]}@127.0.0.1:$PORT/app.git"
expect_fail "anonymous access is rejected" git ls-remote "$BASE/app.git"
SHA1=$(git rev-parse HEAD); OBJ="objects/${SHA1:0:2}/${SHA1:2}"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -u "junior:${TOK[junior]}" "$BASE/app.git/$OBJ")
[[ "$CODE" == 404 ]] && ok "dumb-HTTP object download is blocked ($CODE)" || bad "dumb http object served ($CODE)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -u "junior:${TOK[junior]}" "$BASE/app.git/info/refs")
[[ "$CODE" == 404 ]] && ok "dumb-HTTP ref listing is blocked ($CODE)" || bad "dumb info/refs served ($CODE)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -u "junior:${TOK[junior]}" "$BASE/..%2fusers.json/info/refs?service=git-upload-pack")
[[ "$CODE" == 404 ]] && ok "path traversal in repo name is blocked ($CODE)" || bad "traversal ($CODE)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -u "junior:${TOK[junior]}" "$BASE/nope.git/info/refs?service=git-upload-pack")
[[ "$CODE" == 404 ]] && ok "unknown repo returns 404" || bad "unknown repo ($CODE)"
expect_fail "policy endpoint does not leak private branch names" bash -c "curl -s -u junior:${TOK[junior]} $BASE/app.git/eyesonly/policy | grep -q private"

echo "== private branches"
cd "$SB/alice"
as alice git checkout -q -b private/launch
echo 'Launch: March 3' > LAUNCH.md && as alice git add LAUNCH.md && as alice git commit -qm "launch plan"
expect_ok "alice pushes private/launch" as alice git push -q -u origin private/launch
SECRET=$(git rev-parse HEAD)
expect_out "bob sees private/launch" "private/launch" git ls-remote "$(url bob)"
expect_fail "junior can't see private/launch in ls-remote" bash -c "git ls-remote '$(url junior)' | grep -q private"
expect_fail "junior can't fetch the private commit by SHA (protocol v0)" in_ "$SB/junior" git -c protocol.version=0 fetch -q origin "$SECRET"
expect_fail "junior can't fetch the private commit by SHA (protocol v2)" in_ "$SB/junior" git -c protocol.version=2 fetch -q origin "$SECRET"
grep -m1 -iE "error|fatal" "$SB/out" | sed 's/^/        git says: /'
expect_fail "junior can't fetch it by ref name" in_ "$SB/junior" git fetch -q origin refs/heads/private/launch
in_ "$SB/junior" as junior git checkout -q -b private/mine
expect_reject "junior can't push to private/*" "rejected" in_ "$SB/junior" as junior git push -q origin private/mine
in_ "$SB/junior" as junior git checkout -q main
as alice git checkout -q main
as alice git merge -q --no-ff -m "merge launch" private/launch
expect_reject "merging private history into main is rejected" "narrower audience" as alice git push -q
as alice git reset -q --hard origin/main
as alice git merge -q --squash private/launch && as alice git commit -qm "Launch (squashed)"
expect_ok "squash-merging private work into main is allowed" as alice git push -q

echo "== revocation"
expect_ok "carol clones while still in @core" as carol $EYESONLY clone "$(url carol)" "$SB/carol"
expect_out "carol can read .env" "STRIPE" cat "$SB/carol/.env"
sed 's/"alice", "bob", "carol"/"alice", "bob"/' "$SB/policy.json" > "$SB/policy2.json"
$VS policy set app.git "$SB/policy2.json" 2>/dev/null
in_ "$SB/alice" as alice $EYESONLY pull-policy 2>/dev/null
expect_ok "alice rekeys for the new policy" in_ "$SB/alice" as alice $EYESONLY rekey
in_ "$SB/alice" as alice git commit -qm "rekey: remove carol" >/dev/null
expect_ok "alice pushes the rekeyed secrets" in_ "$SB/alice" as alice git push -q
in_ "$SB/carol" as carol git pull -q >/dev/null 2>&1
expect_out "carol can no longer read the current .env" "EYESONLY-V1" head -1 "$SB/carol/.env"
expect_out "eyesonly audit lists what carol could read before" ".env" in_ "$SB/alice" as alice $EYESONLY audit carol
in_ "$SB/bob" as bob git pull -q --rebase >/dev/null 2>&1
in_ "$SB/bob" bash -c 'echo STRIPE_SECRET=stale > .env'
in_ "$SB/bob" as bob git commit -qam "edit with stale policy" >/dev/null 2>&1
expect_reject "a push still encrypted to revoked carol is rejected" "outside the policy: carol" in_ "$SB/bob" as bob git push -q
in_ "$SB/bob" as bob $EYESONLY pull-policy 2>/dev/null
in_ "$SB/bob" as bob $EYESONLY rekey 2>/dev/null
in_ "$SB/bob" as bob git commit -q --amend --no-edit >/dev/null
expect_ok "after pull-policy + rekey bob's push goes through" in_ "$SB/bob" as bob git push -q

echo "== renames"
cd "$SB/alice" && as alice git pull -q --rebase >/dev/null 2>&1
as alice git mv secrets/db.txt secrets/db2.txt && as alice git commit -q --no-verify -m rename
expect_reject "renamed secret with a stale path binding is rejected (hook bypassed)" "encrypted for path" as alice git push -q
as alice git reset -q --soft HEAD~1 && as alice git commit -qm rename >/dev/null 2>&1
expect_ok "with the pre-commit hook the rename pushes without eyesonly rekey" as alice git push -q

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
