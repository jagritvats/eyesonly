#!/usr/bin/env bash
# Admin API (eyesonly admin / /_eyesonly/admin/v1), admin tokens, failed-login lockout,
# TLS rules for admin routes, and the hash-chained audit log.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"; export SB
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
PASS=0 FAIL=0
PIDS=()

cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; cd /; rm -rf "$SB"; }
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
check()       { local d="$1"; shift; if "$@" >"$SB/chk" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/chk" | tail -n 8; fi; }
expect_ok()   { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 15; fi; }
expect_fail() { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; sed 's/^/        /' "$SB/out" | tail -n 8; else ok "$d"; fi; }
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
expect_out()  { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/eo" 2>&1 && grep -q -- "$pat" "$SB/eo"; then ok "$d"; else bad "$d (no '$pat')"; sed 's/^/        /' "$SB/eo" | tail -n 8; fi; }

as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }

source "$ROOT/test/lib/compat.sh"
source "$ROOT/test/lib/server.sh"

# http_code <method> <url> [curl args...]: prints only the status code; body goes to $SB/body
http_code() { local m="$1" u="$2"; shift 2; curl -s -o "$SB/body" -w '%{http_code}' -X "$m" "$@" "$u"; }
code_is() { local d="$1" want="$2" got="$3"; [[ "$got" == "$want" ]] && ok "$d" || { bad "$d (HTTP $got, want $want)"; sed 's/^/        /' "$SB/body" 2>/dev/null | head -5; }; }

declare -A CARD
for u in alice bob carol dave junior; do CARD[$u]=$(as $u $EYESONLY keygen $u 2>/dev/null); done
CARD[bobnew]=$(EYESONLY_HOME="$SB/home/bob-new" $EYESONLY keygen bob 2>/dev/null)

TOKA=$($VS init --admin "${CARD[alice]}" --repo app.git 2>/dev/null)
start_server PORT "$SB/server.log" EYESONLY_MAX_ADMIN_BODY=4096; PIDS+=("$LAST_SRV"); BASE="http://127.0.0.1:$PORT"
API="$BASE/_eyesonly/admin/v1"

echo "== admin tokens"
check "init makes the admin a server admin" bash -c "$VS server-admin list | grep -qx alice"
expect_reject "a user who admins nothing can't get an admin token" "is not a server admin or an admin of any repo" bash -c "$VS user add '${CARD[junior]}' >/dev/null 2>&1; $VS admin-token create junior"
$VS admin-token create alice --name laptop >"$SB/adm.out" 2>"$SB/adm.err"
ADM=$(cat "$SB/adm.out")
[[ "$(wc -l < "$SB/adm.out")" -eq 1 && "$ADM" == eyesonlyadm_* ]] && ok "admin-token create prints exactly the token" || { bad "admin-token stdout"; cat "$SB/adm.out"; }
check "it says the token doesn't work for git" grep -q "not for git" "$SB/adm.err"
ADMID=$(echo "$ADM" | cut -d_ -f2)
expect_out "admin-token list shows id, user and label" "$ADMID	alice" $VS admin-token list
check "admin-token list never shows the secret" bash -c "! $VS admin-token list | grep -qF '$ADM'"
check_mode "admin-tokens.json is private" 600 "$EYESONLY_DATA/admin-tokens.json"
check "the file stores a hash, not the token" bash -c "! grep -qF '$ADM' '$EYESONLY_DATA/admin-tokens.json'"

echo "== token scoping, both ways"
code_is "no credentials: 401" 401 "$(http_code GET "$API/whoami")"
code_is "a git token can't call the admin API" 401 "$(http_code GET "$API/whoami" -H "Authorization: Bearer $TOKA")"
code_is "git Basic credentials can't call the admin API" 401 "$(http_code GET "$API/whoami" -u "alice:$TOKA")"
code_is "a mangled admin token is refused" 401 "$(http_code GET "$API/whoami" -H "Authorization: Bearer ${ADM}x")"
code_is "the admin token works" 200 "$(http_code GET "$API/whoami" -H "Authorization: Bearer $ADM")"
expect_fail "the admin token can't be used for git" git ls-remote "http://alice:$ADM@127.0.0.1:$PORT/app.git"
expect_ok "alice's git token still works for git" git ls-remote "http://alice:$TOKA@127.0.0.1:$PORT/app.git"
code_is "the admin prefix is not a repo: git paths there are 404" 404 "$(http_code GET "$BASE/_eyesonly/info/refs?service=git-upload-pack" -u "alice:$TOKA")"

export EYESONLY_ADMIN_TOKEN="$ADM"
ADMIN() { $EYESONLY admin --server "$BASE" "$@"; }

echo "== client: users and repos (server admin)"
expect_out "whoami" "alice (server admin)" ADMIN whoami
ADMIN user add "${CARD[bob]}" >"$SB/bobtok" 2>"$SB/bobadd.err"
TOKB=$(cat "$SB/bobtok")
[[ "$TOKB" == eyesonly_* ]] && ok "user add prints bob's git token" || { bad "user add"; cat "$SB/bobadd.err"; }
expect_ok "bob's new token works for git" git ls-remote "http://bob:$TOKB@127.0.0.1:$PORT/app.git"
expect_out "user list shows bob" "^bob	" ADMIN user list
expect_reject "user add with a bad card is refused" "invalid card" ADMIN user add "eyesonlypub1:bm9wZQ"
expect_reject "user add of an existing user is refused" "user 'bob' exists" ADMIN user add "${CARD[bob]}"
expect_ok "repo create web.git --admin bob" ADMIN repo create web.git --admin bob
expect_out "repo list shows both repos" "web.git" ADMIN repo list
expect_reject "repo create with a bad name is refused" "must look like name.git" ADMIN repo create web --admin bob
expect_reject "repo create with an unknown admin is refused" "admin must be an existing user" ADMIN repo create x.git --admin nobody
expect_reject "repo create over an existing repo is refused" "repo web.git exists" ADMIN repo create web.git --admin bob
OLDB="$TOKB"
ADMIN user token bob >"$SB/bobtok2" 2>/dev/null; TOKB=$(cat "$SB/bobtok2")
expect_fail "user token: bob's old git token stops working" git ls-remote "http://bob:$OLDB@127.0.0.1:$PORT/app.git"
expect_ok "user token: the new one works" git ls-remote "http://bob:$TOKB@127.0.0.1:$PORT/app.git"
expect_out "user set-key prints old -> new fingerprints and next steps" "token unchanged" ADMIN user set-key "${CARD[bobnew]}"
expect_ok "bob's token survives set-key" git ls-remote "http://bob:$TOKB@127.0.0.1:$PORT/app.git"
expect_reject "user set-key for an unknown user is refused" "no such user 'carol'" ADMIN user set-key "${CARD[carol]}"
ADMIN user add "${CARD[carol]}" >/dev/null 2>&1
expect_out "user remove carol" "removed carol" ADMIN user remove carol
expect_reject "removing her twice says no such user" "no such user 'carol'" ADMIN user remove carol
ADMIN user add "${CARD[carol]}" >/dev/null 2>&1

echo "== client: policy, grant, revoke"
expect_out "grant bob read access to .env" 'files\[".env"\]' ADMIN grant bob --repo app.git --files .env
check "the policy now lists bob for .env" bash -c "$VS policy show app.git | tr -d ' \n' | grep -q '\".env\":\[\"@core\",\"bob\"\]'"
expect_out "the answer tells members to rekey" "eyesonly rekey" ADMIN grant carol --repo app.git --files .env
expect_out "grant creates a missing branch rule" 'branches\["refs/heads/release/"\]' ADMIN grant @core --repo app.git --branches refs/heads/release/
expect_out "granting membership when members is * changes nothing" "nothing to grant" ADMIN grant dave --repo app.git
expect_out "revoke bob from .env" 'files\[".env"\]' ADMIN revoke bob --repo app.git --files .env
check "bob is gone from .env" bash -c "! $VS policy show app.git | tr -d ' \n' | grep -q '\".env\":\[[^]]*\"bob\"'"
expect_out "revoke everywhere notes that * still makes carol a member" 'still a member through' ADMIN revoke carol --repo app.git
expect_reject "grant with an invalid principal is refused" "invalid principal" ADMIN grant 'bad name!' --repo app.git
expect_reject "grant with a branch outside refs/ is refused" "must start with refs/" ADMIN grant bob --repo app.git --branches private/
expect_out "policy get prints the policy" '"admins"' ADMIN policy get --repo app.git
echo '{"members":["*"],"admins":["alice"],"branches":{"private/":["alice"]}}' > "$SB/badpol.json"
expect_reject "policy set validates like the CLI" "invalid policy: branch rule 'private/' must start with refs/" ADMIN policy set "$SB/badpol.json" --repo app.git
$VS policy show app.git > "$SB/pol.json"
expect_out "policy set accepts a valid policy" "policy replaced" ADMIN policy set "$SB/pol.json" --repo app.git
expect_reject "policy of a missing repo is 404" "no such repo" ADMIN policy get --repo nope.git

echo "== raw HTTP: methods, content types, size"
H=(-H "Authorization: Bearer $ADM")
code_is "unknown endpoint: 404" 404 "$(http_code GET "$API/nope" "${H[@]}")"
code_is "wrong method: 405" 405 "$(http_code DELETE "$API/repos" "${H[@]}")"
code_is "non-JSON body: 415" 415 "$(http_code POST "$API/users" "${H[@]}" -H 'content-type: text/plain' --data 'card=x')"
code_is "malformed JSON: 400" 400 "$(http_code POST "$API/users" "${H[@]}" -H 'content-type: application/json' --data '{nope')"
head -c 6000 /dev/zero | tr '\0' 'a' | sed 's/^/{"card":"/; s/$/"}/' > "$SB/big.json"
code_is "body over EYESONLY_MAX_ADMIN_BODY: 413" 413 "$(http_code POST "$API/users" "${H[@]}" -H 'content-type: application/json' --data-binary "@$SB/big.json")"
check "responses are JSON with no-store" bash -c "curl -s -D - -o /dev/null -H 'Authorization: Bearer $ADM' '$API/whoami' | tr -d '\r' | grep -qi '^cache-control: no-store'"

echo "== repo admin vs server admin"
expect_reject "a git token can't stand in on the client either" "admin token required" env EYESONLY_ADMIN_TOKEN="$TOKB" $EYESONLY admin --server "$BASE" whoami
$VS admin-token create bob >"$SB/admb" 2>/dev/null; ADMB=$(cat "$SB/admb")
[[ "$ADMB" == eyesonlyadm_* ]] && ok "bob (admin of web.git) can get an admin token" || bad "bob admin token"
BOB() { EYESONLY_ADMIN_TOKEN="$ADMB" $EYESONLY admin --server "$BASE" "$@"; }
expect_out "bob is a repo admin, not a server admin" "bob; repo admin of web.git" BOB whoami
expect_out "bob lists only his repos" "^web.git$" BOB repo list
check "bob does not see app.git" bash -c "! EYESONLY_ADMIN_TOKEN='$ADMB' $EYESONLY admin --server '$BASE' repo list | grep -q app.git"
expect_ok "bob grants carol on his repo" BOB grant carol --repo web.git --files .env
expect_reject "bob can't read app.git's policy (same 404 as a missing repo)" "no such repo" BOB policy get --repo app.git
expect_reject "bob can't change app.git" "no such repo" BOB grant bob --repo app.git --files .env
expect_reject "bob can't add users" "only a server admin" BOB user add "${CARD[dave]}"
expect_reject "bob can't create repos" "only a server admin" BOB repo create x.git --admin bob
expect_reject "bob can't rotate tokens" "only a server admin" BOB user token alice
expect_ok "alice (server admin) can read web.git's policy" ADMIN policy get --repo web.git
echo '{"members":["*"],"admins":["alice"],"files":{".env":["carol"]}}' > "$SB/webpol.json"
ADMIN policy set "$SB/webpol.json" --repo web.git >/dev/null 2>&1
expect_reject "bob's admin token dies once he admins nothing" "admin token required" BOB whoami

echo "== signed policy, remotely"
expect_out "attestation: not signed yet" "app.git: not signed" ADMIN attestation --repo app.git
expect_out "alice signs with her identity" "installed app.git policy v1 signed by alice" as alice $EYESONLY admin --server "$BASE" sign --repo app.git
expect_out "attestation: signed v1, current" "signed v1 by alice, current" ADMIN attestation --repo app.git
expect_out "a policy change says the signature is stale and how to re-sign" "eyesonly admin sign --repo app.git" ADMIN grant carol --repo app.git --files .env
expect_out "attestation: STALE" "STALE" ADMIN attestation --repo app.git
expect_out "re-signing installs v2" "policy v2" as alice $EYESONLY admin --server "$BASE" sign --repo app.git
expect_out "attestation: current again" "signed v2 by alice, current" ADMIN attestation --repo app.git
curl -s -H "Authorization: Bearer $ADM" "$API/repos/app.git/manifest" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(JSON.stringify(JSON.parse(s).manifest)))' > "$SB/m.json"
as junior $EYESONLY policy-sign "$SB/m.json" > "$SB/s-junior.json" 2>/dev/null
code_is "a manifest signed by a non-admin is refused (403)" 403 "$(http_code POST "$API/repos/app.git/attestation" "${H[@]}" -H 'content-type: application/json' --data-binary "@$SB/s-junior.json")"
check "...and says why" grep -q "is not an admin of app.git" "$SB/body"
as alice $EYESONLY policy-sign "$SB/m.json" > "$SB/s3.json" 2>/dev/null
code_is "a fresh admin signature installs (v3)" 200 "$(http_code POST "$API/repos/app.git/attestation" "${H[@]}" -H 'content-type: application/json' --data-binary "@$SB/s3.json")"
code_is "replaying the same signed manifest is refused" 409 "$(http_code POST "$API/repos/app.git/attestation" "${H[@]}" -H 'content-type: application/json' --data-binary "@$SB/s3.json")"
check "...version must increase" grep -q "version must increase" "$SB/body"

echo "== audit log"
ADMIN user add "${CARD[junior]}" >/dev/null 2>&1 || true
TOKJ=$($VS user token junior 2>/dev/null)
as alice $EYESONLY clone "http://alice:$TOKA@127.0.0.1:$PORT/app.git" "$SB/alice" >/dev/null 2>&1
in_ "$SB/alice" as alice bash -c 'echo STRIPE=sk_live_1 > .env && echo hi > a.txt && git add -A' >/dev/null 2>&1
in_ "$SB/alice" as alice git commit -qm init >/dev/null 2>&1
expect_ok "alice pushes (accepted)" in_ "$SB/alice" as alice git push -q -u origin main
as junior $EYESONLY clone "http://junior:$TOKJ@127.0.0.1:$PORT/app.git" "$SB/junior" >/dev/null 2>&1
NOF=(-c filter.eyesonly.process= -c filter.eyesonly.required=false -c filter.eyesonly.clean=cat -c filter.eyesonly.smudge=cat)
in_ "$SB/junior" bash -c 'echo LEAK=1 > .env' && in_ "$SB/junior" as junior git "${NOF[@]}" add .env && in_ "$SB/junior" as junior git "${NOF[@]}" commit -qm leak --no-verify
expect_reject "junior's plaintext push is rejected" "REJECTED" in_ "$SB/junior" as junior git push -q
git ls-remote "http://bob:wrongtoken@127.0.0.1:$PORT/app.git" >/dev/null 2>&1
LOG="$EYESONLY_DATA/audit.log"
check_mode "audit.log is private" 600 "$LOG"
expect_out "accepted push is logged with user and refs" '"type":"push","user":"alice","repo":"app.git","refs":\[{"ref":"refs/heads/main"' cat "$LOG"
check "...result accepted" grep -q '"user":"alice".*"result":"accepted"' "$LOG"
check "rejected push is logged with the reason" grep -q '"user":"junior".*"result":"rejected","reason":"'"'"'junior'"'"' may not modify protected file' "$LOG"
check "admin actions are logged with actor and via" grep -q '"type":"admin","actor":"alice","via":"api","action":"user add","target":"bob"' "$LOG"
check "CLI actions are logged too" grep -q '"actor":"local-cli","via":"cli","action":"init"' "$LOG"
check "policy changes record before/after hashes" grep -q '"action":"policy grant".*"before":"[0-9a-f]\{64\}","after":"[0-9a-f]\{64\}"' "$LOG"
check "attestation installs are logged" grep -q '"type":"attestation","actor":"alice","repo":"app.git","version":3' "$LOG"
check "policy fetches are logged" grep -q '"type":"policy_fetch","user":"junior","repo":"app.git"' "$LOG"
check "bad git credentials are logged" grep -q '"type":"auth_failure","route":"git".*"user":"bob"' "$LOG"
check "bad admin tokens are logged" grep -q '"type":"auth_failure","route":"admin"' "$LOG"
leak=0; for t in "$TOKA" "$TOKB" "$OLDB" "$TOKJ" "$ADM" "$ADMB" wrongtoken; do grep -qF -- "$t" "$LOG" && leak=1; done
[[ $leak -eq 0 ]] && ok "no token (git, admin or wrong) appears in the log" || bad "a token leaked into the audit log"
check "no private keys in the log" bash -c "! grep -q 'priv' '$LOG'"
expect_out "audit-log --verify: chain intact" "chain intact" $VS audit-log --verify
expect_out "audit-log --repo/--type filters" "alice pushed app.git: refs/heads/main" $VS audit-log --repo app.git --type push
check "audit-log --json prints raw lines" bash -c "$VS audit-log --json --type policy_fetch | head -1 | grep -q '^{\"ts\"'"
expect_reject "audit-log --since rejects a bad date" "not a date" $VS audit-log --since yesterdayish

echo "== failed-login lockout"
start_server PORT2 "$SB/server2.log" EYESONLY_AUTH_MAX_FAILURES=3 EYESONLY_AUTH_LOCKOUT_MS=60000; PIDS+=("$LAST_SRV")
API2="http://127.0.0.1:$PORT2/_eyesonly/admin/v1"
for i in 1 2 3; do http_code GET "$API2/whoami" -H "Authorization: Bearer eyesonlyadm_deadbeef_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" >/dev/null; done
code_is "after 3 bad admin tokens even a good one gets 429" 429 "$(http_code GET "$API2/whoami" -H "Authorization: Bearer $ADM")"
check "429 carries Retry-After" bash -c "curl -s -D - -o /dev/null -H 'Authorization: Bearer $ADM' '$API2/whoami' | tr -d '\r' | grep -qi '^retry-after: [1-9]'"
for i in 1 2 3; do git ls-remote "http://bob:nope$i@127.0.0.1:$PORT2/app.git" >/dev/null 2>&1; done
code_is "after 3 bad git logins bob's right token gets 429" 429 "$(http_code GET "http://127.0.0.1:$PORT2/app.git/info/refs?service=git-upload-pack" -u "bob:$TOKB")"
code_is "alice from the same address is not locked out" 200 "$(http_code GET "http://127.0.0.1:$PORT2/app.git/info/refs?service=git-upload-pack" -u "alice:$TOKA")"
check "the lockout is logged" grep -q '"type":"lockout","route":"git","ip":"[^"]*","user":"bob"' "$LOG"
code_is "a request without credentials is not a failure (git's first round trip)" 401 "$(http_code GET "http://127.0.0.1:$PORT2/app.git/info/refs?service=git-upload-pack")"

echo "== admin routes need TLS"
start_server PORT3 "$SB/server3.log" EYESONLY_TRUST_PROXY=1; PIDS+=("$LAST_SRV")
API3="http://127.0.0.1:$PORT3/_eyesonly/admin/v1"
code_is "behind a proxy, X-Forwarded-Proto: http is refused" 403 "$(http_code GET "$API3/whoami" -H "Authorization: Bearer $ADM" -H 'X-Forwarded-Proto: http')"
check "...and says HTTPS is needed" grep -q "needs HTTPS" "$SB/body"
code_is "behind a proxy, no X-Forwarded-Proto is refused (loopback doesn't count)" 403 "$(http_code GET "$API3/whoami" -H "Authorization: Bearer $ADM")"
code_is "behind a proxy, X-Forwarded-Proto: https is allowed" 200 "$(http_code GET "$API3/whoami" -H "Authorization: Bearer $ADM" -H 'X-Forwarded-Proto: https')"
code_is "without EYESONLY_TRUST_PROXY a forged X-Forwarded-Proto changes nothing on loopback" 200 "$(http_code GET "$API/whoami" -H "Authorization: Bearer $ADM" -H 'X-Forwarded-Proto: http')"
LANIP=$(node -e 'for (const a of Object.values(require("os").networkInterfaces()).flat()) if (a && a.family === "IPv4" && !a.internal) { console.log(a.address); break }')
if [[ -n "$LANIP" ]]; then
  node "$ROOT/bin/eyesonly-server.mjs" serve --host 0.0.0.0 --port 0 2>"$SB/server4.log" & PIDS+=("$!")
  for _ in $(seq 200); do P4=$(grep -o 'listening on http://0\.0\.0\.0:[0-9]*' "$SB/server4.log" 2>/dev/null | grep -o '[0-9]*$'); [[ -n "$P4" ]] && break; sleep 0.05; done
  c=$(http_code GET "http://$LANIP:$P4/_eyesonly/admin/v1/whoami" -H "Authorization: Bearer $ADM" --max-time 5)
  if [[ "$c" == 000 ]]; then ok "non-loopback plain HTTP check skipped (LAN address $LANIP not reachable here)"
  else code_is "non-loopback plain HTTP is refused" 403 "$c"; fi
else ok "non-loopback plain HTTP check skipped (no LAN address)"; fi
expect_reject "the client refuses to send a token over plain http to a remote host" "refusing to send an admin token over plain http" $EYESONLY admin --server http://10.1.2.3:8787 whoami
expect_reject "the client refuses tokens on the command line" "not on the command line" $EYESONLY admin --server "$BASE" --token x whoami

echo "== revoking admin tokens"
expect_out "admin-token revoke" "revoked admin token $ADMID" $VS admin-token revoke "$ADMID"
code_is "the revoked token is refused" 401 "$(http_code GET "$API/whoami" -H "Authorization: Bearer $ADM")"

echo "== audit log tamper detection"
node -e 'const fs=require("fs"),f=process.argv[1];const l=fs.readFileSync(f,"utf8").split("\n");l[2]=l[2].replace("\"type\":","\"type\" :");fs.writeFileSync(f,l.join("\n"))' "$LOG"
expect_reject "editing a line breaks the chain at the next line" "FAILED verification at line 4" $VS audit-log --verify

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
