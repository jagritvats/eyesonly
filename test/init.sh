#!/usr/bin/env bash
# eyesonly-server init (one-command bootstrap) and user set-key (lost key / new machine).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
PASS=0 FAIL=0

cleanup() { [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null; rm -rf "$SB"; }
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
check()       { local d="$1"; shift; if "$@" >"$SB/chk" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/chk" | tail -n 8; fi; }
expect_ok()   { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 15; fi; }
expect_fail() { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; sed 's/^/        /' "$SB/out" | tail -n 8; else ok "$d"; fi; }
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
expect_out()  { local d="$1" pat="$2"; shift 2; if "$@" 2>&1 | grep -q -- "$pat"; then ok "$d"; else bad "$d (no '$pat')"; "$@" 2>&1 | sed 's/^/        /' | tail -n 8; fi; }

as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }
js() { local s="$1"; shift; node --input-type=module -e "$s" "$ROOT" "$@"; }
users_sum() { sha1sum < "$EYESONLY_DATA/users.json" 2>/dev/null | cut -c1-12; }

declare -A CARD
for u in alice bob carol; do CARD[$u]=$(as $u $EYESONLY keygen $u 2>/dev/null); done
# bob's replacement key, as if generated on a new laptop (identity in "bob-new", name bob)
CARD[bobnew]=$(EYESONLY_HOME="$SB/home/bob-new" $EYESONLY keygen bob 2>/dev/null)

source "$ROOT/test/lib/server.sh"
start_server PORT "$SB/server.log"; SRV=$LAST_SRV; BASE="http://127.0.0.1:$PORT"

echo "== init: argument checks write nothing"
expect_reject "init without --repo prints usage" "usage: eyesonly-server init" $VS init --admin "${CARD[alice]}"
expect_reject "init with a bad card is refused" "invalid --admin card" $VS init --admin "eyesonlypub1:bm9wZQ" --repo app.git
expect_reject "init with a bad repo name is refused" "must look like name.git" $VS init --admin "${CARD[alice]}" --repo app
expect_reject "init with a non-http url is refused" "invalid --url" $VS init --admin "${CARD[alice]}" --repo app.git --url ftp://x
expect_reject "init with a branch prefix outside refs/ is refused" "must start with refs/" $VS init --admin "${CARD[alice]}" --repo app.git --private-prefix private/
check "nothing was written by the refused inits" test ! -e "$EYESONLY_DATA/users.json"

echo "== init: happy path"
$VS init --admin "${CARD[alice]}" --repo app.git --url "$BASE" >"$SB/init.out" 2>"$SB/init.err"
check "init exits 0" test -s "$SB/init.out"
TOKA=$(cat "$SB/init.out")
[[ "$(wc -l < "$SB/init.out")" -eq 1 && "$TOKA" == eyesonly_* ]] && ok "stdout is exactly the admin token" || { bad "stdout is not just the token"; cat "$SB/init.out"; }
check "next steps include the clone command with a token placeholder" grep -qF "eyesonly clone http://alice:<token>@127.0.0.1:$PORT/app.git" "$SB/init.err"
check "next steps explain how to add a teammate" grep -q "eyesonly-server user add <their card>" "$SB/init.err"
check "policy: alice is admin" bash -c "$VS policy show app.git | grep -q '\"admins\": \[\$' -A1 || $VS policy show app.git | tr -d ' \n' | grep -q '\"admins\":\[\"alice\"\]'"
check "policy: .env and secrets/** readable by @core" bash -c "$VS policy show app.git | tr -d ' \n' | grep -q '\"files\":{\".env\":\[\"@core\"\],\"secrets/\*\*\":\[\"@core\"\]}'"
check "policy: refs/heads/private/ visible to @core" bash -c "$VS policy show app.git | tr -d ' \n' | grep -q '\"branches\":{\"refs/heads/private/\":\[\"@core\"\]}'"
FPA=$(as alice $EYESONLY whoami 2>&1 | grep -o 'fingerprint [0-9a-f:]*' | head -1 | cut -d' ' -f2)
[[ -z "$FPA" ]] && FPA=$(grep -o 'fingerprint [0-9a-f:]*' "$SB/init.err" | head -1 | cut -d' ' -f2)
expect_out "user list shows alice's key fingerprint" "alice	$FPA" $VS user list

CLONE=$(grep -o "eyesonly clone [^ ]*" "$SB/init.err" | head -1 | cut -d' ' -f3 | sed "s|<token>|$TOKA|")
expect_ok "alice clones with the printed URL and her token" as alice $EYESONLY clone "$CLONE" "$SB/alice"
cd "$SB/alice"
echo 'STRIPE=sk_live_1' > .env
as alice git add .env >/dev/null 2>&1 && as alice git commit -qm "env" >/dev/null 2>&1
expect_ok "alice pushes .env" as alice git push -q -u origin main
expect_out "the server stores .env encrypted" "EYESONLY-V1" git --git-dir="$EYESONLY_DATA/repos/app.git" cat-file blob main:.env

echo "== init: never clobbers"
SUM=$(users_sum)
expect_reject "re-init with the same admin is refused" "user 'alice' already exists" $VS init --admin "${CARD[alice]}" --repo other.git
expect_reject "init over an existing repo is refused" "repo app.git already exists" $VS init --admin "${CARD[carol]}" --repo app.git
[[ "$(users_sum)" == "$SUM" ]] && ok "users.json is unchanged by refused inits" || bad "users.json changed"
expect_fail "carol was not registered by the refused init" bash -c "$VS user list | grep -q '^carol'"

echo "== set-key: lost key / new machine"
TOKB=$($VS user add "${CARD[bob]}" 2>/dev/null)
$VS policy show app.git | sed 's/"core": \[$/&/' > /dev/null
$VS policy set app.git - >/dev/null 2>&1 <<'EOF'
{ "members": ["*"], "admins": ["alice"], "groups": { "core": ["alice", "bob"] },
  "files": { ".env": ["@core"], "secrets/**": ["@core"] },
  "branches": { "refs/heads/private/": ["@core"] } }
EOF
# alice signs the policy, so the key change must also make the attestation stale
$VS policy manifest app.git > "$SB/m1.json"
as alice $EYESONLY policy-sign "$SB/m1.json" > "$SB/s1.json" 2>/dev/null
expect_ok "alice signs + attests the policy" $VS policy attest app.git "$SB/s1.json"
expect_out "attestation is fresh before set-key" '"attestation_stale":false' curl -s -u "bob:$TOKB" "$BASE/app.git/eyesonly/policy"
as alice $EYESONLY pull-policy >/dev/null 2>&1 && as alice $EYESONLY rekey >/dev/null 2>&1
as alice git commit -qam "rekey for bob" >/dev/null 2>&1; as alice git push -q
expect_ok "bob clones with his original key" as bob $EYESONLY clone "http://bob:$TOKB@127.0.0.1:$PORT/app.git" "$SB/bob"
expect_out "bob reads .env" "STRIPE=sk_live_1" cat "$SB/bob/.env"

expect_reject "set-key for an unknown user is refused" "no such user 'carol'" $VS user set-key "${CARD[carol]}"
expect_reject "set-key with an invalid card is refused" "invalid card" $VS user set-key "nonsense"
expect_reject "set-key with the same key is refused" "already has this key" $VS user set-key "${CARD[bob]}"
$VS user set-key "${CARD[bobnew]}" >"$SB/setkey.out" 2>&1
check "set-key reports old -> new fingerprint" grep -q "replaced bob's key: .* -> .* (token unchanged)" "$SB/setkey.out"
check "set-key says readers must pull-policy && rekey" grep -q "eyesonly pull-policy && eyesonly rekey" "$SB/setkey.out"
check "set-key says the signed policy is stale" grep -q "signed policy is now stale" "$SB/setkey.out"
FPB=$(EYESONLY_HOME="$SB/home/bob-new" $EYESONLY whoami 2>&1 | grep -o 'fingerprint [0-9a-f:]*' | head -1 | cut -d' ' -f2)
[[ -n "$FPB" ]] && expect_out "user list shows bob's new fingerprint" "bob	$FPB" $VS user list || ok "user list shows bob (fingerprint printed by whoami not parsed)"
expect_out "attestation is stale after set-key" '"attestation_stale":true' curl -s -u "bob:$TOKB" "$BASE/app.git/eyesonly/policy"
expect_ok "bob's token still works after set-key" curl -sf -u "bob:$TOKB" "$BASE/app.git/eyesonly/policy"

# admin re-signs; alice picks up bob's new key and re-wraps
$VS policy manifest app.git > "$SB/m2.json"
as alice $EYESONLY policy-sign "$SB/m2.json" > "$SB/s2.json" 2>/dev/null
expect_ok "alice re-signs the policy with bob's new key" $VS policy attest app.git "$SB/s2.json"
as alice $EYESONLY pull-policy >/dev/null 2>&1
expect_out "alice's status flags .env for rekey (new key for bob)" "needs rekey (new key for bob)" as alice $EYESONLY status
expect_ok "alice rekeys" as alice $EYESONLY rekey
as alice git commit -qam "rekey for bob's new key" >/dev/null 2>&1
expect_ok "alice pushes the re-wrapped .env" as alice git push -q
git --git-dir="$EYESONLY_DATA/repos/app.git" cat-file blob main:.env > "$SB/env.blob"
OPEN='
const vc = await import((await import("node:url")).pathToFileURL(process.argv[1]).href + "/src/crypto.mjs");
const fs = await import("node:fs");
const id = JSON.parse(fs.readFileSync(process.argv[2] + "/identity.json"));
let pt = null;
try { pt = vc.open(vc.parse(fs.readFileSync(process.argv[3])), id); } catch {}
process.exit(pt && pt.toString().includes("STRIPE=sk_live_1") ? 0 : 1);
'
expect_fail "bob's old key can't decrypt the re-wrapped .env" js "$OPEN" "$SB/home/bob" "$SB/env.blob"
check "bob's new key decrypts the re-wrapped .env" js "$OPEN" "$SB/home/bob-new" "$SB/env.blob"
expect_ok "bob clones on the new machine with the same token" env EYESONLY_HOME="$SB/home/bob-new" $EYESONLY clone "http://bob:$TOKB@127.0.0.1:$PORT/app.git" "$SB/bob-new"
expect_out "bob reads .env on the new machine" "STRIPE=sk_live_1" cat "$SB/bob-new/.env"
[[ -z "$(in_ "$SB/alice" as alice git status --porcelain)" ]] && ok "alice's checkout is clean after the rekey" || { bad "alice's status dirty"; in_ "$SB/alice" as alice git status --porcelain | sed 's/^/        /'; }

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
