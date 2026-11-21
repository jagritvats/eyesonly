#!/usr/bin/env bash
# Repo mode: no Eyes Only server. The "host" is a plain bare repo (like GitHub); the signed
# policy lives in .eyesonly/policy.json. Same commands as server mode, mode detected.
# Team: alice (admin), bob and carol (@core), junior (member, not in @core), mallory (outsider).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROOT_URL="$(node -e 'console.log(require("node:url").pathToFileURL(process.argv[1]).href)' "$ROOT")"
SB="$(mktemp -d)"
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
PASS=0 FAIL=0

cleanup() { cd "$ROOT"; [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null; rm -rf "$SB"; }
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
expect_ok()   { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 15; fi; }
expect_fail() { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; sed 's/^/        /' "$SB/out" | tail -n 8; else ok "$d"; fi; }
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; sed 's/^/        /' "$SB/out" | tail -n 8; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
expect_out()  { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1 && grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (no '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }
host_blob() { git --git-dir="$SB/host.git" cat-file blob "$1"; }
js() { local s="$1"; shift; node --input-type=module -e "$s" "$ROOT_URL" "$@"; }
card() { as "$1" $EYESONLY whoami 2>/dev/null | tail -1; }
HOST="$SB/host.git"
FILE_URL="$(node -e 'console.log(require("node:url").pathToFileURL(process.argv[1]).href)' "$(cd "$SB" && (pwd -W 2>/dev/null || pwd))/host.git")"

# seal <who-signs> <path> <plaintext> <recipient...>: write a valid envelope signed by <who-signs>
seal() {
  local signer="$1" path="$2" text="$3"; shift 3
  js '
const [root, home, path, text, ...who] = process.argv.slice(1);
const vc = await import(root + "/src/crypto.mjs");
const fs = await import("node:fs");
const id = JSON.parse(fs.readFileSync(home + "/identity.json"));
const att = JSON.parse(fs.readFileSync(".eyesonly/policy.json"));
const r = {}; for (const u of who) r[u] = (u === id.name ? id.x25519.pub : att.manifest.keys[u].x25519);
fs.writeFileSync(path, vc.seal({ plaintext: Buffer.from(text + "\n"), path, recipients: r, signer: id }));
' "$SB/home/$signer" "$path" "$text" "$@"
}

echo "== setup"
for u in alice bob carol junior mallory; do as $u $EYESONLY keygen $u >/dev/null 2>&1; done
git init -q --bare -b main "$HOST"
mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$HOST"
echo 'console.log("hi")' > app.js
as alice git add app.js && as alice git commit -qm base
expect_ok "alice runs eyesonly init --commit (no server)" as alice $EYESONLY init --commit
check "the signed policy is committed" git cat-file -e HEAD:.eyesonly/policy.json
check ".gitattributes routes .env through the filter" grep -qxF '/.env filter=eyesonly diff=eyesonly merge=eyesonly' .gitattributes
check "clone is in repo mode" test "$(git config eyesonly.mode)" = repo
check "pre-push hook installed" grep -q 'eyesonly.* pre-push' .git/hooks/pre-push
echo 'STRIPE_SECRET=sk_live_1' > .env
as alice git add .env && as alice git commit -qm env
expect_ok "alice pushes main (pre-push verify passes)" as alice git push -q -u origin main
expect_out "the host stores .env encrypted" "EYESONLY-V1" host_blob main:.env
expect_fail "the host never saw the plaintext" bash -c "git --git-dir='$HOST' cat-file blob main:.env | grep -q sk_live_1"
expect_reject "init twice is refused" "already exists" as alice $EYESONLY init

echo "== join and grant"
as bob git clone -q "$HOST" "$SB/bob" 2>/dev/null
expect_out "bob joins (writes a request with his card)" "eyesonlypub1:" in_ "$SB/bob" as bob $EYESONLY join
check "request file written" test -f "$SB/bob/.eyesonly/requests/bob.pub"
in_ "$SB/bob" as bob git checkout -q -b join-bob
in_ "$SB/bob" as bob git add .eyesonly/requests && in_ "$SB/bob" as bob git commit -qm "eyesonly: join bob"
expect_ok "bob pushes his request branch" in_ "$SB/bob" as bob git push -q origin join-bob
as alice git fetch -q origin && as alice git merge -q --ff-only origin/join-bob 2>/dev/null || as alice git merge -q --no-edit origin/join-bob
expect_reject "bob (not an admin) can't grant" "only admins" in_ "$SB/bob" as bob $EYESONLY grant mallory --card "$(card mallory)"
expect_out "alice grants bob from his request" "granted bob" as alice $EYESONLY grant bob --from-request
check "the request file is removed" test ! -e .eyesonly/requests/bob.pub
expect_out "alice grants carol by card (single group picked)" "@core" as alice $EYESONLY grant carol --card "$(card carol)"
expect_out "alice grants junior a key but only public.txt" "public.txt" as alice $EYESONLY grant junior --card "$(card junior)" --files public.txt
expect_reject "a card for someone else is refused" "is for 'mallory'" as alice $EYESONLY grant eve --card "$(card mallory)"
expect_out "policy show lists the admin fingerprint" "alice  [0-9a-f]\{4\}:" as alice $EYESONLY policy show
as alice git add -A .eyesonly && as alice git commit -qm "eyesonly: grant bob, carol, junior"
expect_ok "alice rekeys for the new audience" as alice $EYESONLY rekey
as alice git commit -qam rekey
expect_ok "alice pushes the policy and rekeyed .env" as alice git push -q origin main
expect_out "host .env is now readable by bob" '"bob"' host_blob main:.env
expect_out "host .env is now readable by carol" '"carol"' host_blob main:.env
expect_fail "host .env is not encrypted to junior" bash -c "git --git-dir='$HOST' cat-file blob main:.env | grep -q '\"junior\"'"

echo "== members clone (plain git clone + setup, eyesonly clone, any URL)"
in_ "$SB/bob" as bob git checkout -q main
in_ "$SB/bob" as bob git pull -q origin main
expect_ok "bob runs eyesonly setup in his plain clone" in_ "$SB/bob" as bob $EYESONLY setup
expect_out "bob reads .env" "sk_live_1" cat "$SB/bob/.env"
check "bob's clone detected repo mode" test "$(git -C "$SB/bob" config eyesonly.mode)" = repo
[[ -z "$(in_ "$SB/bob" as bob git status --porcelain)" ]] && ok "bob's status is clean" || bad "bob status dirty"
expect_out "carol clones with eyesonly clone (path URL)" "1 decrypted" as carol $EYESONLY clone "$HOST" "$SB/carol"
expect_out "carol reads .env" "sk_live_1" cat "$SB/carol/.env"
expect_out "junior clones with a file:// URL" "repo mode" as junior $EYESONLY clone "$FILE_URL" "$SB/junior"
expect_out "junior gets ciphertext" "EYESONLY-V1" head -1 "$SB/junior/.env"
[[ -z "$(in_ "$SB/junior" as junior git status --porcelain)" ]] && ok "junior's status is clean" || bad "junior status dirty"
expect_out "mallory (not a member) is told to join" "aren't in this repo's policy" as mallory $EYESONLY clone "$HOST" "$SB/mallory"
expect_out "mallory gets ciphertext" "EYESONLY-V1" head -1 "$SB/mallory/.env"
expect_out "status shows repo mode and policy version" "repo mode, policy v4" in_ "$SB/bob" as bob $EYESONLY status
expect_reject "a host without a policy is refused, nothing left behind" "no .eyesonly/policy.json" bash -c "git init -q --bare '$SB/plain.git' && $EYESONLY clone '$SB/plain.git' '$SB/plain'"
check "...and no directory was left" test ! -e "$SB/plain"

echo "== run and env"
expect_out "eyesonly env works in repo mode" "STRIPE_SECRET=\"sk_live_1\"" in_ "$SB/bob" as bob $EYESONLY env --format dotenv
expect_out "eyesonly run injects the secret" "sk_live_1" in_ "$SB/bob" as bob $EYESONLY run -- node -e 'process.stdout.write(process.env.STRIPE_SECRET)'

echo "== forged and unauthorized envelopes"
cd "$SB/junior"
as junior git checkout -q -b forged
seal junior .env "STRIPE_SECRET=sk_evil" alice bob junior
as junior git add .env && as junior git commit -q --no-verify -m forged 2>/dev/null
expect_reject "junior's pre-push hook blocks his own forged .env" "may not write it" as junior git push -q origin forged
expect_ok "junior pushes it anyway (--no-verify): the host can't refuse" as junior git push -q --no-verify origin forged
expect_reject "verify rejects the forged envelope" "signer 'junior' may not write it" in_ "$SB/bob" bash -c "git fetch -q origin && $EYESONLY verify --range origin/main..origin/forged"
in_ "$SB/bob" as bob git checkout -q forged 2>"$SB/smudge.err"
check "bob's smudge refuses the forged envelope" grep -q "is not an allowed writer\|bad or unknown signature" "$SB/smudge.err"
expect_out "bob's working .env stays ciphertext" "EYESONLY-V1" head -1 "$SB/bob/.env"
in_ "$SB/bob" as bob git checkout -q main
cd "$SB/mallory"
as mallory git checkout -q -b mallory-forge
seal mallory .env "STRIPE_SECRET=sk_mal" alice bob mallory
as mallory git add .env && as mallory git commit -q --no-verify -m m 2>/dev/null
as mallory git push -q --no-verify origin mallory-forge
expect_reject "verify rejects an envelope from an unknown key" "signer 'mallory' may not write it" in_ "$SB/bob" bash -c "git fetch -q origin && $EYESONLY verify --range origin/main..origin/mallory-forge"
cd "$SB/bob"
as bob git checkout -q -b moved
mkdir -p secrets && git cat-file blob HEAD:.env > secrets/copy.txt
as bob git -c filter.eyesonly.clean=cat add secrets/copy.txt && as bob git commit -q --no-verify -m moved 2>/dev/null
expect_reject "verify rejects an envelope moved to another path" "is encrypted for path '.env'" $EYESONLY verify --range main..moved
as bob git checkout -q main

echo "== plaintext pushes"
as bob git checkout -q -b leak
echo 'STRIPE_SECRET=sk_live_PLAINTEXT' > .env
as bob git -c filter.eyesonly.clean=cat -c filter.eyesonly.smudge=cat add .env
as bob git -c filter.eyesonly.clean=cat -c filter.eyesonly.smudge=cat commit -q --no-verify -m leak
expect_reject "the pre-push hook blocks plaintext" "is NOT encrypted" as bob git push -q origin leak
expect_fail "...so the host never got it" git --git-dir="$HOST" rev-parse -q --verify refs/heads/leak
expect_reject "verify (CI) rejects plaintext pushed by someone without the client" "is NOT encrypted" $EYESONLY verify --range main..leak
expect_reject "verify also catches it with default range" "is NOT encrypted" $EYESONLY verify
as bob git -c filter.eyesonly.smudge=cat checkout -q -f main
as bob git branch -q -D leak

echo "== policy tampering"
cd "$SB/bob"
as bob git checkout -q -b tamper
node -e 'const fs=require("fs");const p=".eyesonly/policy.json";const a=JSON.parse(fs.readFileSync(p));a.manifest.policy.admins.push("bob");fs.writeFileSync(p,JSON.stringify(a,null,2))'
as bob git commit -q --no-verify -am "unsigned edit"
expect_reject "verify rejects a hand-edited (unsigned) policy" "policy signature invalid" $EYESONLY verify --range main..tamper
as bob git checkout -q main && as bob git branch -q -D tamper
as bob git checkout -q -b selfsigned
js '
const [root, home] = process.argv.slice(1);
const rp = await import(root + "/src/repo-policy.mjs");
const attest = await import(root + "/src/attest.mjs");
const fs = await import("node:fs");
const id = JSON.parse(fs.readFileSync(home + "/identity.json"));
const m = JSON.parse(fs.readFileSync(".eyesonly/policy.json")).manifest;
const rules = { ...rp.rulesOf(m), admins: ["bob"] };
const next = rp.buildRepoManifest({ repo: m.repo, version: m.version + 1, policy: rules, keys: m.keys });
fs.writeFileSync(".eyesonly/policy.json", JSON.stringify(attest.signManifest(next, id), null, 2));
' "$SB/home/bob"
as bob git commit -q --no-verify -am "bob makes himself admin"
expect_reject "verify rejects a policy signed by a non-admin" "who was not an admin before it" $EYESONLY verify --range main..selfsigned
# A copy of the host where the attacker controls main.
git clone -q --bare "$HOST" "$SB/host2.git"
as bob git push -q --no-verify --force "$SB/host2.git" selfsigned:main
expect_reject "a pinned clone refuses a policy signed by a non-admin" "not signed by a pinned admin" bash -c "cd '$SB/carol' && git remote set-url origin '$SB/host2.git' && $EYESONLY pull-policy"
in_ "$SB/carol" git remote set-url origin "$HOST"; in_ "$SB/carol" git fetch -q origin
as bob git checkout -q main && as bob git branch -q -D selfsigned
OLD=$(git log --format=%H -n1 -- .eyesonly/policy.json | xargs -I{} git rev-parse {}^)
git show "$OLD:.eyesonly/policy.json" > "$SB/old-policy.json"
as bob git checkout -q -b rollback
cp "$SB/old-policy.json" .eyesonly/policy.json
as bob git commit -q --no-verify -am rollback
expect_reject "verify rejects rolling the policy back" "doesn't increase" $EYESONLY verify --range main..rollback
as bob git push -q --no-verify --force "$SB/host2.git" rollback:main
expect_reject "a pinned clone refuses an older policy" "older than the last one seen" bash -c "cd '$SB/carol' && git remote set-url origin '$SB/host2.git' && $EYESONLY pull-policy"
in_ "$SB/carol" git remote set-url origin "$HOST"; in_ "$SB/carol" git fetch -q origin
as bob git checkout -q main && as bob git branch -q -D rollback
expect_reject "verify rejects deleting the policy" "turn off enforcement" bash -c "git checkout -q -b nopolicy && git rm -q .eyesonly/policy.json && git -c user.name=b -c user.email=b@x commit -q --no-verify -m rm && $EYESONLY verify --range main..nopolicy"
as bob git checkout -q -f main && as bob git branch -q -D nopolicy
# A validly signed policy on a feature branch doesn't apply until it reaches the default branch.
cd "$SB/alice"
as alice git checkout -q -b loosen
as alice $EYESONLY grant junior --group core >/dev/null 2>&1
as alice git commit -q -am "loosen on a branch"
as alice git push -q origin loosen
expect_ok "verify accepts an admin-signed policy change" $EYESONLY verify --range main..loosen
as alice git checkout -q main
as alice $EYESONLY pull-policy >/dev/null 2>&1
cd "$SB/junior"
as junior git fetch -q origin && as junior git checkout -q -b loosen origin/loosen
expect_out "junior on the feature branch still gets the default branch's policy" "policy v4" as junior $EYESONLY pull-policy
in_ "$SB/junior" as junior git checkout -q main

echo "== revoke"
cd "$SB/alice"
expect_out "alice revokes carol" "revoked carol" as alice $EYESONLY revoke carol
expect_reject "the only admin can't revoke herself" "only admin" as alice $EYESONLY revoke alice
echo 'STRIPE_SECRET=sk_live_rotated' > .env
as alice git add -A && as alice git commit -qm "revoke carol, rotate"
expect_ok "alice rekeys after revoking" as alice $EYESONLY rekey
as alice git commit -qam rekey 2>/dev/null
expect_ok "alice pushes" as alice git push -q origin main
expect_fail "host .env no longer has a key for carol" bash -c "git --git-dir='$HOST' cat-file blob main:.env | grep -q '\"carol\"'"
in_ "$SB/carol" as carol git pull -q origin main 2>/dev/null
expect_ok "carol pulls the new policy" in_ "$SB/carol" as carol $EYESONLY pull-policy
expect_fail "carol can't read the rotated .env" grep -q sk_live_rotated "$SB/carol/.env"
expect_out "audit lists what carol could read" ".env" in_ "$SB/alice" as alice $EYESONLY audit carol
in_ "$SB/bob" as bob git pull -q origin main
in_ "$SB/bob" as bob $EYESONLY pull-policy >/dev/null 2>&1
expect_out "bob still reads the rotated .env" "sk_live_rotated" cat "$SB/bob/.env"
expect_ok "verify accepts the whole real history" in_ "$SB/bob" $EYESONLY verify --range "$(git -C "$SB/bob" rev-list --max-parents=0 HEAD)..main"

echo "== mode detection with a server"
source "$ROOT/test/lib/server.sh"
TOK=$($VS user add "$(card alice)" 2>/dev/null)
$VS repo create srv.git --admin alice >/dev/null 2>&1
$VS policy set srv.git - >/dev/null 2>&1 <<'EOF'
{ "members": ["*"], "admins": ["alice"], "files": { ".env": ["alice"] } }
EOF
start_server PORT "$SB/server.log"; SRV=$LAST_SRV
SURL="http://alice:$TOK@127.0.0.1:$PORT/srv.git"
mkdir -p "$SB/srv" && cd "$SB/srv" && git init -q -b main && git remote add origin "$SURL"
expect_ok "setup against an eyesonly server" as alice $EYESONLY setup
check "...picks server mode" test "$(git config eyesonly.mode)" = server
# A member commits a policy file to a server repo: clients must stay in server mode.
cp "$SB/alice/.eyesonly/policy.json" "$SB/stray.json"
mkdir -p .eyesonly && cp "$SB/stray.json" .eyesonly/policy.json && echo x > a.txt
as alice git add -A && as alice git commit -qm "stray policy file"
as alice git push -q -u origin main 2>/dev/null
expect_ok "eyesonly clone of the server repo" as alice $EYESONLY clone "$SURL" "$SB/srv2"
check "...stays in server mode despite the committed policy file" test "$(git -C "$SB/srv2" config eyesonly.mode)" = server
expect_reject "a repo-mode clone won't silently switch to a server" "set up in repo mode" bash -c "cd '$SB/bob' && git remote set-url origin '$SURL' && $EYESONLY setup"
in_ "$SB/bob" git remote set-url origin "$HOST"
expect_reject "init is refused when origin is an eyesonly server" "is an Eyes Only server" bash -c "cd '$SB/srv' && rm -rf .eyesonly && $EYESONLY init"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
