#!/usr/bin/env bash
# Signed policy manifests + admin key pinning (TOFU) against a lying server (A5).
# Team: alice (admin), bob, carol = @core. junior = member. mallory = member who
# colludes with the compromised server. A5 = whoever can write $EYESONLY_DATA.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"
PORT="${PORT:-$((20000 + RANDOM % 20000))}"
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
BASE="http://127.0.0.1:$PORT"
ATT="$EYESONLY_DATA/repos/app.git/eyesonly-attestation.json"
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
# out_has <desc> <pattern>: the output of the previous expect_* contains <pattern>
out_has()     { if grep -q -- "$2" "$SB/out"; then ok "$1"; else bad "$1 (no '$2')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
check()       { local d="$1"; shift; if "$@" >"$SB/chk" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/chk" | tail -n 8; fi; }

as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
url() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/app.git"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }
# js <script> [args...]: run an inline ES module (argv[1] = repo root)
js() { local s="$1"; shift; node --input-type=module -e "$s" "$ROOT" "$@"; }
# policy <file> <admins-json> <core-json> [extra-files-json]: write a server policy
policy() {
  cat > "$1" <<EOF
{ "members": ["*"], "admins": $2,
  "groups": { "core": $3 },
  "files": { ".env": ["@core"], "secrets/**": ["@core"]${4:+, $4} },
  "branches": { "refs/heads/private/": ["@core"] } }
EOF
}
sign() { as "$1" $EYESONLY policy-sign "$2" > "$3" 2>"$SB/sign.err" || { echo "sign failed:"; cat "$SB/sign.err"; }; }

declare -A TOK
echo "== setup"
for u in alice bob carol junior mallory; do
  card=$(as $u $EYESONLY keygen $u 2>/dev/null)
  TOK[$u]=$($VS user add "$card" 2>/dev/null)
done
$VS repo create app.git --admin alice 2>/dev/null
policy "$SB/p1.json" '["alice"]' '["alice", "bob", "carol"]'
$VS policy set app.git "$SB/p1.json" 2>/dev/null
source "$ROOT/test/lib/server.sh"
start_server PORT "$SB/server.log"; SRV=$LAST_SRV; BASE="http://127.0.0.1:$PORT"

mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$(url alice)"
as alice $EYESONLY setup 2>/dev/null
echo 'console.log("hello")' > index.js
echo 'STRIPE_SECRET=sk_live_123' > .env
mkdir -p secrets && echo 'db-password' > secrets/db.txt
as alice git add -A && as alice git commit -qm init
expect_ok "alice pushes main with secrets (unattested repo)" as alice git push -q -u origin main

echo "== unattested repos keep working"
expect_ok "bob clones an unattested repo" as bob $EYESONLY clone "$(url bob)" "$SB/bob"
out_has "clone warns that the policy is not signed" "policy is not signed by an admin"
expect_out "bob still reads .env" "sk_live_123" cat "$SB/bob/.env"
check "no trust.json is written for an unsigned policy" test ! -e "$SB/bob/.git/eyesonly/trust.json"

echo "== eyesonly-server policy manifest"
$VS policy manifest app.git > "$SB/m1.json"
$VS policy manifest app.git > "$SB/m1b.json"
check "manifest is byte-identical across runs" cmp "$SB/m1.json" "$SB/m1b.json"
check "manifest: v1, version 1, files array in rule order, keys for the audience only" js '
const fs = await import("node:fs");
const m = JSON.parse(fs.readFileSync(process.argv[2]));
const want = [[".env", ["alice","bob","carol"]], ["secrets/**", ["alice","bob","carol"]]];
if (m.v !== 1 || m.repo !== "app.git" || m.version !== 1) throw new Error("header " + JSON.stringify(m));
if (JSON.stringify(m.files) !== JSON.stringify(want)) throw new Error("files " + JSON.stringify(m.files));
if (Object.keys(m.keys).sort().join() !== "alice,bob,carol") throw new Error("keys " + Object.keys(m.keys));
' "$SB/m1.json"
check "manifest output is canonical JSON" js '
const fs = await import("node:fs");
const { canonical } = await import((await import("node:url")).pathToFileURL(process.argv[1]).href + "/src/attest.mjs");
const s = fs.readFileSync(process.argv[2], "utf8").trim();
if (canonical(JSON.parse(s)) !== s) throw new Error("not canonical");
' "$SB/m1.json"

echo "== eyesonly-server policy attest rejects bad signatures"
sign junior "$SB/m1.json" "$SB/s-junior.json"
expect_reject "manifest signed by non-admin junior is rejected" "not an admin" $VS policy attest app.git "$SB/s-junior.json"
sign alice "$SB/m1.json" "$SB/s1.json"
js '
const fs = await import("node:fs");
const a = JSON.parse(fs.readFileSync(process.argv[2]));
a.sig = (a.sig[0] === "A" ? "B" : "A") + a.sig.slice(1);
fs.writeFileSync(process.argv[3], JSON.stringify(a));
' "$SB/s1.json" "$SB/s-flip.json"
expect_reject "manifest with a flipped signature char is rejected" "bad signature" $VS policy attest app.git "$SB/s-flip.json"
sign mallory "$SB/m1.json" "$SB/s-mal.json"
js '
const fs = await import("node:fs");
const a = JSON.parse(fs.readFileSync(process.argv[2]));
a.signer = "alice";   // valid signature, but by a key that is not alice registered key
fs.writeFileSync(process.argv[2], JSON.stringify(a));
' "$SB/s-mal.json"
expect_reject "manifest claiming alice but signed with another key is rejected" "bad signature" $VS policy attest app.git "$SB/s-mal.json"
js '
const fs = await import("node:fs");
const m = JSON.parse(fs.readFileSync(process.argv[2]));
m.files[0][1] = ["alice", "carol"];   // hand-edited: drop bob from .env
fs.writeFileSync(process.argv[3], JSON.stringify(m));
' "$SB/m1.json" "$SB/m-edit.json"
sign alice "$SB/m-edit.json" "$SB/s-edit.json"
expect_reject "manifest that differs from eyesonly.json is rejected" "does not match current policy" $VS policy attest app.git "$SB/s-edit.json"
check "no attestation installed after the rejections" test ! -e "$ATT"

echo "== signing and serving"
expect_ok "alice signs + attests v1" $VS policy attest app.git "$SB/s1.json"
expect_out "GET /eyesonly/policy includes the attestation" '"attestation"' curl -s -u "bob:${TOK[bob]}" "$BASE/app.git/eyesonly/policy"
expect_out "fresh attestation is not stale" '"attestation_stale":false' curl -s -u "bob:${TOK[bob]}" "$BASE/app.git/eyesonly/policy"
expect_reject "re-attesting the same version is rejected" "version must increase" $VS policy attest app.git "$SB/s1.json"
expect_out "next manifest is version 2" '"version":2' $VS policy manifest app.git

echo "== first contact (TOFU) and out-of-band pinning"
FP=$(js 'const a = await import((await import("node:url")).pathToFileURL(process.argv[1]).href + "/src/attest.mjs"); const fs = await import("node:fs");
console.log(a.adminFingerprint(JSON.parse(fs.readFileSync(process.argv[2])).signer_ed25519));' "$SB/s1.json")
expect_ok "alice clones the attested repo" as alice $EYESONLY clone "$(url alice)" "$SB/alice2"
out_has "clone prints 'pinned admin alice <fingerprint>'" "pinned admin alice $FP"
check "clone wrote .git/eyesonly/trust.json" test -f "$SB/alice2/.git/eyesonly/trust.json"
check "policy.json keeps its shape {repo,user,files:{glob:[users]},keys} with glob order" js '
const fs = await import("node:fs");
const p = JSON.parse(fs.readFileSync(process.argv[2]));
if (Object.keys(p).join() !== "repo,user,files,keys") throw new Error("shape " + Object.keys(p));
if (p.repo !== "app.git" || p.user !== "alice") throw new Error("header");
if (Object.keys(p.files).join() !== ".env,secrets/**") throw new Error("order " + Object.keys(p.files));
if (p.files[".env"].join() !== "alice,bob,carol" || !p.keys.bob.x25519) throw new Error("content");
' "$SB/alice2/.git/eyesonly/policy.json"
expect_out "alice reads .env in the attested clone" "sk_live_123" cat "$SB/alice2/.env"
expect_reject "clone with a different EYESONLY_PIN_ADMIN fails" "admin key does not match pinned fingerprint" \
  env EYESONLY_PIN_ADMIN=0000:0000:0000:0000 EYESONLY_HOME="$SB/home/carol" $EYESONLY clone "$(url carol)" "$SB/carol-pinned"
check "the failed pinned clone created no directory" test ! -d "$SB/carol-pinned"
expect_ok "clone with the correct EYESONLY_PIN_ADMIN works" env EYESONLY_PIN_ADMIN="$FP" EYESONLY_HOME="$SB/home/carol" $EYESONLY clone "$(url carol)" "$SB/carol"
expect_ok "bob (unsigned before) pulls the signed policy" in_ "$SB/bob" as bob $EYESONLY pull-policy
out_has "bob pins alice on first signed contact" "pinned admin alice $FP"

echo "== policy v2"
policy "$SB/p2.json" '["alice"]' '["alice", "bob", "carol"]' '"config/prod.json": ["@core"]'
$VS policy set app.git "$SB/p2.json" 2>/dev/null
expect_out "GET shows attestation_stale after an unsigned change" '"attestation_stale":true' curl -s -u "bob:${TOK[bob]}" "$BASE/app.git/eyesonly/policy"
$VS policy manifest app.git > "$SB/m2.json"
sign alice "$SB/m2.json" "$SB/s2.json"
expect_ok "alice signs + attests v2" $VS policy attest app.git "$SB/s2.json"
expect_ok "bob pulls v2" in_ "$SB/bob" as bob $EYESONLY pull-policy
check "bob's policy now has config/prod.json" grep -q 'config/prod.json' "$SB/bob/.git/eyesonly/policy.json"
BP="$SB/bob/.git/eyesonly/policy.json" BT="$SB/bob/.git/eyesonly/trust.json"
cp "$BP" "$SB/bob-policy.before"; cp "$BT" "$SB/bob-trust.before"
unchanged() { cmp "$BP" "$SB/bob-policy.before" && cmp "$BT" "$SB/bob-trust.before"; }

echo "== A5: lying server"
js '
const fs = await import("node:fs");
const a = JSON.parse(fs.readFileSync(process.argv[2]));
a.manifest.keys.bob.x25519 = a.manifest.keys.alice.x25519;   // swap in a key the server controls
fs.writeFileSync(process.argv[2], JSON.stringify(a));
' "$ATT"
expect_reject "A5 key swap in the attestation: pull-policy refuses" "policy signature invalid" in_ "$SB/bob" as bob $EYESONLY pull-policy
check "after the key swap policy.json and trust.json are byte-identical" unchanged
cp "$SB/s2.json" "$ATT"

cp "$SB/s1.json" "$ATT"
expect_reject "A5 rollback to the older signed v1 is refused" "policy version 1 is older than last seen 2" in_ "$SB/bob" as bob $EYESONLY pull-policy
check "after the rollback policy.json and trust.json are byte-identical" unchanged
cp "$SB/s2.json" "$ATT"

rm "$ATT"
expect_reject "A5 downgrade to an unsigned policy is refused" "repo was signed; server now serves an unsigned policy" in_ "$SB/bob" as bob $EYESONLY pull-policy
check "after the downgrade policy.json and trust.json are byte-identical" unchanged
cp "$SB/s2.json" "$ATT"

js '
const fs = await import("node:fs");
const m = JSON.parse(fs.readFileSync(process.argv[2]));
m.files[0][1] = ["alice"];
fs.writeFileSync(process.argv[3], JSON.stringify(m));
' "$SB/m2.json" "$SB/m2-alt.json"
sign alice "$SB/m2-alt.json" "$ATT"
expect_reject "a second, different signed v2 is refused" "policy version 2 was re-signed with different content" in_ "$SB/bob" as bob $EYESONLY pull-policy
js '
const fs = await import("node:fs");
const m = JSON.parse(fs.readFileSync(process.argv[2]));
m.repo = "other.git"; m.version = 9;
fs.writeFileSync(process.argv[3], JSON.stringify(m));
' "$SB/m2.json" "$SB/m-other.json"
sign alice "$SB/m-other.json" "$ATT"
expect_reject "an attestation for another repo is refused" "attestation is for repo other.git, not app.git" in_ "$SB/bob" as bob $EYESONLY pull-policy
check "policy.json and trust.json still byte-identical" unchanged
cp "$SB/s2.json" "$ATT"
expect_ok "bob pulls again once the real v2 is back" in_ "$SB/bob" as bob $EYESONLY pull-policy

policy "$SB/p3.json" '["alice", "mallory"]' '["alice", "bob", "carol"]' '"config/prod.json": ["@core"]'
$VS policy set app.git "$SB/p3.json" 2>/dev/null
$VS policy manifest app.git > "$SB/m3.json"
sign mallory "$SB/m3.json" "$SB/s3.json"
expect_ok "A5 makes mallory admin; the server accepts mallory's v3" $VS policy attest app.git "$SB/s3.json"
expect_reject "bob refuses a policy signed by unpinned admin mallory" "not signed by a pinned admin" in_ "$SB/bob" as bob $EYESONLY pull-policy
check "after the forged admin policy.json and trust.json are byte-identical" unchanged
$VS policy set app.git "$SB/p2.json" 2>/dev/null
$VS policy manifest app.git > "$SB/m4.json"
sign alice "$SB/m4.json" "$SB/s4.json"
expect_ok "alice re-signs v4 with the admin set restored" $VS policy attest app.git "$SB/s4.json"
expect_ok "bob accepts alice's v4" in_ "$SB/bob" as bob $EYESONLY pull-policy

echo "== A5: injected recipient (unsigned change)"
policy "$SB/p5.json" '["alice"]' '["alice", "bob", "carol", "mallory"]' '"config/prod.json": ["@core"]'
$VS policy set app.git "$SB/p5.json" 2>/dev/null
expect_out "unsigned view now lists mallory (attestation_stale)" '"attestation_stale":true' curl -s -u "alice:${TOK[alice]}" "$BASE/app.git/eyesonly/policy"
expect_ok "alice pulls the policy" in_ "$SB/alice2" as alice $EYESONLY pull-policy
out_has "alice is warned that the server policy changed since the signature" "server policy changed since the last admin signature"
check "alice's cached policy does not contain mallory" bash -c "! grep -q mallory '$SB/alice2/.git/eyesonly/policy.json'"
in_ "$SB/alice2" bash -c 'echo STRIPE_SECRET=sk_live_rotated > .env'
in_ "$SB/alice2" as alice git commit --no-verify -qam "rotate" >/dev/null
expect_ok "alice pushes the rotated secret" in_ "$SB/alice2" as alice git push -q
BLOB="$SB/env.blob"; git --git-dir="$EYESONLY_DATA/repos/app.git" cat-file blob main:.env > "$BLOB"
check "server .env is encrypted to bob (sanity)" grep -q '"bob"' "$BLOB"
expect_fail "server .env has no key for injected mallory" grep -q '"mallory"' "$BLOB"

echo "== A5: unsigned key cannot sign secrets"
expect_ok "mallory clones (her key is only in the unsigned view)" as mallory $EYESONLY clone "$(url mallory)" "$SB/mallory"
expect_out "mallory can't read .env" "EYESONLY-V1" head -1 "$SB/mallory/.env"
cd "$SB/mallory"
js '
const vc = await import((await import("node:url")).pathToFileURL(process.argv[1]).href + "/src/crypto.mjs");
const fs = await import("node:fs");
const id = JSON.parse(fs.readFileSync(process.argv[2] + "/identity.json"));
const pol = JSON.parse(fs.readFileSync(".git/eyesonly/policy.json"));
const r = { alice: pol.keys.alice.x25519, mallory: id.x25519.pub };
fs.writeFileSync(".env", vc.seal({ plaintext: Buffer.from("API_URL=https://evil\n"), path: ".env", recipients: r, signer: id }));
' "$SB/home/mallory"
as mallory git add .env && as mallory git commit --no-verify -qm "evil env" >/dev/null
expect_ok "server accepts mallory's envelope (she is in @core server-side)" as mallory git push -q
in_ "$SB/alice2" as alice git pull -q >"$SB/out" 2>&1
out_has "alice's smudge refuses mallory's signature" "bad or unknown signature"
expect_out "alice's working copy of .env stays EYESONLY-V1" "EYESONLY-V1" head -1 "$SB/alice2/.env"
expect_fail "alice never sees the planted plaintext" grep -q evil "$SB/alice2/.env"

echo "== A6: truncated GCM tags"
# Node accepts 4-byte GCM tags unless authTagLength is pinned; open() must refuse them.
TRUNC='
const vc = await import((await import("node:url")).pathToFileURL(process.argv[1]).href + "/src/crypto.mjs");
const a = vc.generateIdentity("alice");
const env = vc.parse(vc.seal({ plaintext: Buffer.from("S=1"), path: ".env", recipients: { alice: a.x25519.pub }, signer: a }));
const cut = (s, n) => Buffer.from(s, "base64").subarray(0, n).toString("base64");
const bad = process.argv[2] === "content" ? { ...env, tag: cut(env.tag, 4) }
  : { ...env, keys: { alice: { ...env.keys.alice, key: cut(env.keys.alice.key, 36) } } };
try { vc.open(bad, a); process.exit(1); } catch (e) { if (!/malformed envelope/.test(e.message)) process.exit(2); }
'
check "open() refuses a 4-byte content tag" js "$TRUNC" content
check "open() refuses a wrapped key with a 4-byte tag" js "$TRUNC" wrap

echo "== existing suite"
if bash "$ROOT/test/e2e.sh" >"$SB/e2e.out" 2>&1 && grep -q '^47 passed, 0 failed' "$SB/e2e.out"; then ok "test/e2e.sh: 47 passed"; else bad "test/e2e.sh"; tail -n 20 "$SB/e2e.out" | sed 's/^/        /'; fi

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
