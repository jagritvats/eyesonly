#!/usr/bin/env bash
# GitHub-mode hardening (0.5): writers, admin pinning in both modes, commit-signature
# attribution in `eyesonly verify`, and migrating a GitHub-mode repo onto a server with the
# pinned admin keys carried over.
# Team: alice (admin), bob (@core writer), carol (@core, read-only), junior (public.txt only),
# dave (server-only user, never pinned in GitHub mode).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROOT_URL="$(node -e 'console.log(require("node:url").pathToFileURL(process.argv[1]).href)' "$ROOT")"
SB="$(mktemp -d)"; export SB
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
PASS=0 FAIL=0
source "$ROOT/test/lib/compat.sh"
source "$ROOT/test/lib/server.sh"

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
js() { local s="$1"; shift; node --input-type=module -e "$s" "$ROOT_URL" "$@"; }
card() { as "$1" $EYESONLY whoami 2>/dev/null | tail -1; }
adminpin() { as "$1" $EYESONLY whoami 2>/dev/null | sed -n 's/^admin pin  \([0-9a-f:]*\).*/\1/p'; }
# An attacker without the client: every eyesonly filter off.
NOF="-c filter.eyesonly.process= -c filter.eyesonly.required=false -c filter.eyesonly.clean=cat -c filter.eyesonly.smudge=cat"
# signed <key-owner> <git args...>: commit as alice (eyesonly hooks run as her), signed with <key-owner>'s SSH key
signed() { local u="$1"; shift; as alice git -c gpg.format=ssh -c user.signingkey="$SB/ssh/$u" "$@"; }

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
mkdir -p "$SB/ssh"
for u in alice bob carol junior dave; do
  as $u $EYESONLY keygen $u >/dev/null 2>&1
  ssh-keygen -q -t ed25519 -N '' -C "$u" -f "$SB/ssh/$u" >/dev/null
done
HOST="$SB/host.git"
git init -q --bare -b main "$HOST"
mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$HOST"
echo 'console.log(1)' > app.js && as alice git add app.js && as alice git commit -qm base
as alice $EYESONLY init --commit >/dev/null 2>&1
printf 'STRIPE=sk_live_1\nA=1\nB=2\nC=3\nDB=pg://one\n' > .env
as alice git add .env && as alice git commit -qm env
as alice git push -q -u origin main
expect_out "alice grants bob (@core, writer)" "(and write)" as alice $EYESONLY grant bob --card "$(card bob)"
expect_out "alice grants carol read-only" "(read-only)" as alice $EYESONLY grant carol --card "$(card carol)" --read-only
expect_ok "alice grants junior public.txt only" as alice $EYESONLY grant junior --card "$(card junior)" --files public.txt
expect_reject "--read-only for an admin is refused" "admins always write" as alice $EYESONLY grant alice --read-only
expect_out "policy show lists carol as read-only" "carol  .*read-only" as alice $EYESONLY policy show
expect_out "policy show names the explicit writers" 'writers: \[' as alice $EYESONLY policy show
as alice git add -A .eyesonly .gitattributes && as alice git commit -qm "grant bob, carol (read-only), junior"
as alice $EYESONLY rekey >/dev/null 2>&1 && as alice git commit -qam rekey
expect_ok "alice pushes policy + rekeyed .env" as alice git push -q origin main
check "the host's .env is readable by carol" bash -c "git --git-dir='$HOST' cat-file blob main:.env | grep -q '\"carol\"'"

echo "== writers: clean, rekey, smudge, pre-push, verify, merge"
expect_out "carol clones and reads .env" "1 decrypted" as carol $EYESONLY clone "$HOST" "$SB/carol"
cd "$SB/carol"
echo 'STRIPE=sk_live_carol' >> .env
expect_reject "carol (read-only) can't stage an edit of .env" "can read but not write '.env'" as carol git add .env
as carol git checkout -q -- .env
expect_out "carol's rekey skips read-only files" "read-only, not rekeyed" as carol $EYESONLY rekey
# carol forges an envelope with her own (valid, registered) key, client filters off
as carol git checkout -q -b carol-forge
seal carol .env "STRIPE=sk_evil" alice bob carol
as carol git $NOF add .env && as carol git $NOF commit -q --no-verify -m forge 2>/dev/null
expect_reject "carol's pre-push hook blocks her own envelope" "may not write it" as carol git push -q origin carol-forge
expect_ok "carol pushes it anyway (--no-verify)" as carol git push -q --no-verify origin carol-forge
expect_reject "verify rejects an envelope signed by a read-only member" "signer 'carol' may not write it" as carol $EYESONLY verify --range main..carol-forge
as bob $EYESONLY clone "$HOST" "$SB/bob" >/dev/null 2>&1
cd "$SB/bob"
BLOB="$SB/carol-forged.env"; git --git-dir="$HOST" cat-file blob carol-forge:.env > "$BLOB"
as bob $EYESONLY smudge .env < "$BLOB" >"$SB/smudged" 2>"$SB/smudge.err"
check "bob's smudge keeps carol's envelope encrypted" grep -q EYESONLY-V1 "$SB/smudged"
check "...and says why" grep -q "not an allowed writer" "$SB/smudge.err"
as bob git fetch -q origin && as bob git checkout -q --detach origin/carol-forge
expect_reject "eyesonly run refuses it too" "not an allowed writer" as bob $EYESONLY run --file .env -- node -e 0
as bob git checkout -q main
# merge driver: bob and alice change different lines on two branches; read-only carol merges
as bob git checkout -q -b bob-db && sed 's#pg://one#pg://bob#' .env > .env.t && mv .env.t .env && as bob git commit -qam "bob: db" && as bob git push -q origin bob-db
cd "$SB/alice" && as alice git pull -q origin main 2>/dev/null
sed 's#sk_live_1#sk_live_2#' .env > .env.t && mv .env.t .env && as alice git commit -qam "alice: stripe" && as alice git push -q origin main
cd "$SB/carol" && as carol git checkout -q main && as carol git pull -q origin main 2>/dev/null && as carol git fetch -q origin
expect_reject "the merge driver refuses to re-seal for read-only carol" "may not write '.env' (read-only)" as carol git merge --no-edit origin/bob-db
as carol git merge --abort 2>/dev/null
cd "$SB/bob" && as bob git checkout -q main && as bob git pull -q origin main 2>/dev/null
expect_ok "writer bob merges the same branches fine" as bob git merge -q --no-edit bob-db
expect_out "bob's merged .env has both changes" "pg://bob" cat .env
check "...including alice's" grep -q sk_live_2 .env
# grant --writer / revoke --writer
cd "$SB/alice"
expect_out "alice makes carol a writer" "(and write)" as alice $EYESONLY grant carol --writer
as alice git commit -qam "carol writes" && as alice git push -q origin main
cd "$SB/carol" && as carol git pull -q origin main 2>/dev/null && as carol $EYESONLY pull-policy >/dev/null 2>&1
echo 'EXTRA=1' >> .env
expect_ok "carol (writer now) stages .env" as carol git add .env
as carol git reset -q --hard
as carol git checkout -q -b private/carol && echo c > c.txt && as carol git add c.txt && as carol git commit -qm "carol private"
expect_ok "carol (writer) seals private/carol" as carol $EYESONLY branch push
as carol git checkout -q main
cd "$SB/alice"
expect_ok "alice revokes carol's write access" as alice $EYESONLY revoke carol --writer
expect_out "carol is read-only again" "carol  .*read-only" as alice $EYESONLY policy show
as alice git commit -qam "carol read-only" && as alice git push -q origin main
cd "$SB/carol" && as carol git push -q origin --delete carol-forge 2>/dev/null
as carol git pull -q origin main 2>/dev/null && as carol $EYESONLY pull-policy >/dev/null 2>&1
as carol git checkout -q -b private/carol2 && echo d > d.txt && as carol git add d.txt && as carol git commit -qm "carol private 2"
expect_reject "read-only carol can't seal a private branch" "but not write it (read-only" as carol $EYESONLY branch push
as carol git checkout -q main
expect_reject "read-only carol can't rotate .env" "read-only" as carol $EYESONLY rotate .env STRIPE=sk_carol
cd "$SB/bob" && as bob git checkout -q main && as bob git pull -q origin main 2>/dev/null && as bob $EYESONLY pull-policy >/dev/null 2>&1
expect_reject "bob refuses private/carol: sealed by carol, who is read-only now" "who may not write" as bob $EYESONLY branch pull private/carol

echo "== admin pin fingerprints"
PIN="$(adminpin alice)"
check "whoami prints an admin pin fingerprint" test -n "$PIN"
expect_out "policy show prints the same fingerprint for alice" "alice  $PIN" in_ "$SB/alice" as alice $EYESONLY policy show
expect_out "EYESONLY_PIN_ADMIN with that fingerprint clones" "repo mode" as junior env EYESONLY_PIN_ADMIN="$PIN" $EYESONLY clone "$HOST" "$SB/junior"
expect_reject "a wrong EYESONLY_PIN_ADMIN is refused" "does not match EYESONLY_PIN_ADMIN" as junior env EYESONLY_PIN_ADMIN=0000:0000:0000:0000 $EYESONLY clone "$HOST" "$SB/junior2"
expect_out "status prints the pinned admins" "pinned admins: alice $PIN" in_ "$SB/junior" as junior $EYESONLY status

echo "== commit signatures (verify --require-signed)"
H2="$SB/host2.git"; git init -q --bare -b main "$H2"
mkdir -p "$SB/a2" && cd "$SB/a2"
git init -q -b main && git remote add origin "$H2"
echo x > app.js && as alice git add app.js && as alice git commit -qm base
as alice $EYESONLY init --commit >/dev/null 2>&1
expect_out "alice registers her SSH signing key" "SSH signing key" as alice $EYESONLY grant alice --ssh-signing-key "$SB/ssh/alice.pub"
expect_ok "...bob with his card and key" as alice $EYESONLY grant bob --card "$(card bob)" --ssh-signing-key "$(cat "$SB/ssh/bob.pub")"
expect_ok "...carol read-only with her key" as alice $EYESONLY grant carol --card "$(card carol)" --read-only --ssh-signing-key "$SB/ssh/carol.pub"
expect_reject "a private key is refused" "private key\|not an SSH public key" as alice $EYESONLY grant bob --ssh-signing-key "$SB/ssh/bob"
expect_out "policy show lists signing keys" "ssh-signing ssh-ed25519" as alice $EYESONLY policy show
echo 'TOKEN=t1' > .env
as alice git add -A && signed alice commit -q -S -m "policy + env"
BASE2=$(git rev-parse HEAD~1)
expect_out "a commit signed by alice passes --require-signed" "every commit signed by a member" as alice $EYESONLY verify --require-signed --range "$BASE2..HEAD"
echo 'TOKEN=t2' > .env && as alice git add .env && as alice git commit -qm unsigned
expect_reject "an unsigned commit is rejected" "isn't signed by a member: not signed" as alice $EYESONLY verify --require-signed --range "$BASE2..HEAD"
as alice git reset -q --hard HEAD~1
echo 'TOKEN=t3' > .env && as alice git add .env && signed dave commit -q -S -m "dave signs"
expect_reject "a commit signed by a key outside the policy is rejected" "not in the policy" as alice $EYESONLY verify --require-signed --range "$BASE2..HEAD"
as alice git reset -q --hard HEAD~1
as alice git rm -q .env && signed carol commit -q -S -m "carol deletes .env"
expect_reject "read-only carol's signed deletion of .env is rejected" "'carol' may not delete protected file '.env'" as alice $EYESONLY verify --require-signed --range "$BASE2..HEAD"
expect_out "without --require-signed it's only a note" "see --require-signed" as alice $EYESONLY verify --range "$BASE2..HEAD"
as alice git reset -q --hard HEAD~1
echo 'TOKEN=t4' > .env && as alice git add .env && signed bob commit -q -S -m "bob edits"
expect_ok "writer bob's signed edit passes" as alice $EYESONLY verify --require-signed --range "$BASE2..HEAD"

echo "== server: every listed admin is pinned"
start_server PORT "$SB/srv.log"; SRV=$LAST_SRV
declare -A TOK
for u in alice bob dave; do TOK[$u]=$($VS user add "$(card $u)" 2>/dev/null); done
url() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/$2"; }
$VS repo create srv.git --admin alice 2>/dev/null
$VS policy set srv.git - <<'EOF' 2>/dev/null
{ "members": ["*"], "admins": ["alice", "bob"], "groups": { "core": ["alice", "bob"] },
  "files": { ".env": ["@core"] }, "branches": {} }
EOF
attest_as() { local who="$1" repo="$2"; $VS policy manifest "$repo" > "$SB/m.json" && as "$who" $EYESONLY policy-sign "$SB/m.json" > "$SB/s.json" 2>/dev/null && $VS policy attest "$repo" "$SB/s.json"; }
expect_ok "alice signs the server policy" attest_as alice srv.git
check "the manifest lists both admins" grep -q '"admins":{"alice"' "$SB/m.json"
expect_ok "dave clones" as dave $EYESONLY clone "$(url dave srv.git)" "$SB/dave"
check "dave pinned alice" grep -q '"alice"' "$SB/dave/.git/eyesonly/trust.json"
check "...and bob, the other listed admin" grep -q '"bob"' "$SB/dave/.git/eyesonly/trust.json"
$VS policy set srv.git - <<'EOF' 2>/dev/null
{ "members": ["*"], "admins": ["alice", "bob"], "groups": { "core": ["alice", "bob", "dave"] },
  "files": { ".env": ["@core"] }, "branches": {} }
EOF
expect_ok "bob signs v2" attest_as bob srv.git
expect_out "dave accepts a policy signed by bob (pinned via the manifest)" "policy updated" in_ "$SB/dave" as dave $EYESONLY pull-policy
expect_out "dave's policy show prints the pinned admins" "bob  [0-9a-f]\{4\}:" in_ "$SB/dave" as dave $EYESONLY policy show
# server writers: a read-only member's envelope can't land, whoever pushes it
$VS policy set srv.git - <<'EOF' 2>/dev/null
{ "members": ["*"], "admins": ["alice"], "writers": ["alice", "bob"], "groups": { "core": ["alice", "bob", "dave"] },
  "files": { ".env": ["@core"] }, "branches": {} }
EOF
mkdir -p "$SB/srv-alice" && cd "$SB/srv-alice" && git init -q -b main && git remote add origin "$(url alice srv.git)"
as alice $EYESONLY setup >/dev/null 2>&1
echo 'K=1' > .env && as alice git add .env && as alice git commit -qm env && as alice git push -q -u origin main 2>/dev/null
js '
const [root, home] = process.argv.slice(1);
const vc = await import(root + "/src/crypto.mjs");
const fs = await import("node:fs");
const id = JSON.parse(fs.readFileSync(home + "/identity.json"));
const pol = JSON.parse(fs.readFileSync(".git/eyesonly/policy.json"));
const r = {}; for (const u of pol.files[".env"]) r[u] = pol.keys[u].x25519;
fs.writeFileSync(".env", vc.seal({ plaintext: Buffer.from("K=dave\n"), path: ".env", recipients: r, signer: id }));
' "$SB/home/dave"
as alice git $NOF add .env && as alice git $NOF commit -q --no-verify -m "dave's envelope"
expect_reject "the server rejects an envelope signed by non-writer dave, pushed by alice" "signer 'dave' may not write it" as alice git push -q origin main
as alice git reset -q --hard origin/main

echo "== migrate GitHub mode -> server, pins carried over"
cd "$SB/bob" && as bob git checkout -q main && as bob git pull -q origin main 2>/dev/null
as bob git checkout -q -b private/launch && echo launch > launch.txt && as bob git add launch.txt && as bob git commit -qm "secret launch"
expect_ok "bob seals private/launch on the old host" as bob $EYESONLY branch push
as bob git checkout -q main
cd "$SB/alice" && as alice git pull -q origin main 2>/dev/null
git show main:.eyesonly/policy.json > "$SB/repo-policy.json"
REPOV=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).manifest.version)' "$SB/repo-policy.json")
expect_reject "import refuses a wrong admin card" "is not an admin of this policy" $VS import app.git --policy "$SB/repo-policy.json" --admin-card "$(card dave)"
check "...and created nothing" test ! -e "$EYESONLY_DATA/repos/app.git"
$VS import app.git --policy "$SB/repo-policy.json" --admin-card "$(card alice)" >"$SB/import.out" 2>"$SB/import.err"
check "import creates the repo" test -d "$EYESONLY_DATA/repos/app.git"
check "import prints tokens for members new to the server" grep -q "^carol" "$SB/import.out"
check "...but not for existing users with the same key" bash -c "! grep -q '^alice' '$SB/import.out'"
TOK[carol]=$(sed -n 's/^carol\t//p' "$SB/import.out")
TOK[junior]=$(sed -n 's/^junior\t//p' "$SB/import.out")
expect_out "the imported server policy keeps carol read-only" '"writers"' $VS policy show app.git
expect_reject "migrate refuses while the server's policy is unsigned" "isn't signed yet" in_ "$SB/alice" as alice $EYESONLY migrate --to "$(url alice app.git)"
check "...without adding a remote" bash -c "! git -C '$SB/alice' config remote.eyesonly.url"
# an admin the GitHub-mode clones never pinned signs first
$VS policy show app.git | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const p=JSON.parse(s);p.admins.push("bob");console.log(JSON.stringify(p))})' > "$SB/p.json"
$VS policy set app.git "$SB/p.json" 2>/dev/null
expect_ok "bob (server admin, not pinned in GitHub mode) signs the server policy" attest_as bob app.git
MV=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).version)' "$SB/m.json")
[[ "$MV" -gt "$REPOV" ]] && ok "the first server version ($MV) is above the repo policy's ($REPOV)" || bad "server version $MV not above $REPOV"
cd "$SB/carol" && as carol git pull -q origin main 2>/dev/null && as carol $EYESONLY pull-policy >/dev/null 2>&1
as carol git remote add eyesonly "$(url carol app.git)"
expect_reject "carol refuses a server policy signed by an unpinned admin" "not signed by a pinned admin ('bob' isn't one)" as carol $EYESONLY setup --remote eyesonly --mode server
check "...and stays in repo mode" test "$(git -C "$SB/carol" config eyesonly.mode)" = repo
expect_ok "alice re-signs the server policy" attest_as alice app.git
cd "$SB/alice"
expect_out "alice migrates" "migrated: this clone now uses the server" as alice $EYESONLY migrate --to "$(url alice app.git)"
check "alice's clone is in server mode" test "$(git config eyesonly.mode)" = server
check "...with the pins carried over" grep -q '"migratedFrom"' .git/eyesonly/trust.json
expect_out "alice still reads .env" "sk_live_2" cat .env
check "the server has main" git --git-dir="$EYESONLY_DATA/repos/app.git" rev-parse --verify -q refs/heads/main
check "...and bob's branch that only lived on the old host" git --git-dir="$EYESONLY_DATA/repos/app.git" rev-parse --verify -q refs/heads/bob-db
check "the sealed private/launch became a real (hidden) branch on the server" git --git-dir="$EYESONLY_DATA/repos/app.git" rev-parse --verify -q refs/heads/private/launch
check "...and no sealed refs were pushed" bash -c "[ -z \"\$(git --git-dir='$EYESONLY_DATA/repos/app.git' for-each-ref refs/eyesonly/)\" ]"
check "the imported server policy keeps the private/ branch rule" bash -c "$VS policy show app.git | grep -q 'refs/heads/private/'"
cd "$SB/carol"
expect_out "carol switches to the server without touching trust.json" "moved to the server" as carol $EYESONLY setup --remote eyesonly --mode server
check "carol's clone is in server mode" test "$(git config eyesonly.mode)" = server
expect_out "carol reads .env from the server" "sk_live_2" cat .env
check "carol now pins both server admins" grep -q '"bob"' .git/eyesonly/trust.json
cd "$SB/junior" && as junior git remote add eyesonly "$(url junior app.git)"
node -e 'const f=process.argv[1];const t=JSON.parse(require("fs").readFileSync(f));t.version=999;require("fs").writeFileSync(f,JSON.stringify(t))' .git/eyesonly/trust.json
expect_reject "a server version below what the clone saw is refused" "older than last seen 999" as junior $EYESONLY setup --remote eyesonly --mode server

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
