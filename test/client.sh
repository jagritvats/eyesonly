#!/usr/bin/env bash
# Client ergonomics suite: long-running filter process, --remote, token storage, portable
# filter commands, eyesonly doctor, refusal of edited ciphertext, CRLF-mangled envelopes.
# Team: alice, bob = @core. junior = member, outside @core.
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
expect_ok()   { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 15; fi; }
expect_fail() { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; sed 's/^/        /' "$SB/out" | tail -n 8; else ok "$d"; fi; }
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
expect_out()  { local d="$1" pat="$2"; shift 2; if "$@" 2>&1 | grep -q -- "$pat"; then ok "$d"; else bad "$d (no '$pat')"; "$@" 2>&1 | sed 's/^/        /' | tail -n 8; fi; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
url() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/app.git"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }
clean_status() { [[ -z "$(in_ "$1" as "$2" git status --porcelain)" ]]; }

declare -A TOK
echo "== setup"
for u in alice bob junior; do
  card=$(as $u $EYESONLY keygen $u 2>/dev/null)
  TOK[$u]=$($VS user add "$card" 2>/dev/null)
done
$VS repo create app.git --admin alice 2>/dev/null
cat > "$SB/policy.json" <<'EOF'
{ "members": ["*"], "admins": ["alice"],
  "groups": { "core": ["alice", "bob"] },
  "files": { ".env": ["@core"], "secrets/**": ["@core"] } }
EOF
$VS policy set app.git "$SB/policy.json" 2>/dev/null
source "$ROOT/test/lib/server.sh"
start_server PORT "$SB/server.log"; SRV=$LAST_SRV

mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$(url alice)"
as alice $EYESONLY setup 2>/dev/null
echo 'console.log(1)' > index.js
echo 'STRIPE_SECRET=sk_live_1' > .env
mkdir -p secrets && for i in $(seq 1 20); do echo "secret-$i" > "secrets/s$i.txt"; done
as alice git add -A
expect_ok "alice commits and pushes 21 protected files" bash -c "$(declare -f as); as alice git commit -qm init && as alice git push -q -u origin main"

echo "== long-running filter process"
check "setup configures filter.eyesonly.process" bash -c "git config filter.eyesonly.process | grep -q 'filter-process$'"
check "the single-shot clean/smudge fallback stays configured" bash -c "git config filter.eyesonly.clean | grep -q 'clean %f$' && git config filter.eyesonly.smudge | grep -q 'smudge %f$'"
for i in $(seq 1 20); do echo "rotated-$i" > "secrets/s$i.txt"; done
GIT_TRACE="$SB/trace" as alice git add secrets
N=$(grep -c 'filter-process' "$SB/trace" || true)
[[ "$N" -ge 1 && "$N" -le 2 ]] && ok "git add of 20 protected files starts one filter process ($N trace line(s))" || bad "expected one filter process, trace shows $N"
check "...and every staged blob is an envelope" bash -c "for i in \$(seq 1 20); do git cat-file blob :secrets/s\$i.txt | head -1 | grep -qx EYESONLY-V1 || exit 1; done"
expect_ok "alice commits and pushes the rotation" bash -c "$(declare -f as); as alice git commit -qm rotate && as alice git push -q"

# Handshake: git offers delay; eyesonly must answer with clean and smudge only.
cat > "$SB/handshake.mjs" <<'EOF'
import { spawn } from 'node:child_process';
const pkt = (s) => { const b = Buffer.from(s + '\n'); return Buffer.concat([Buffer.from((b.length + 4).toString(16).padStart(4, '0')), b]); };
const flush = Buffer.from('0000');
const p = spawn(process.execPath, [process.argv[2], 'filter-process'], { stdio: ['pipe', 'pipe', 'inherit'] });
let out = Buffer.alloc(0);
p.stdout.on('data', (c) => (out = Buffer.concat([out, c])));
p.on('close', () => {
  const lines = [];
  for (let i = 0; i < out.length; ) {
    const n = parseInt(out.subarray(i, i + 4).toString(), 16);
    lines.push(n === 0 ? '<flush>' : out.subarray(i + 4, i + n).toString().trim());
    i += n === 0 ? 4 : n;
  }
  console.log(lines.join(' '));
});
p.stdin.end(Buffer.concat([pkt('git-filter-client'), pkt('version=2'), flush, pkt('capability=clean'), pkt('capability=smudge'), pkt('capability=delay'), flush]));
EOF
HS=$(node "$SB/handshake.mjs" "$ROOT/bin/eyesonly.mjs")
[[ "$HS" == "git-filter-server version=2 <flush> capability=clean capability=smudge <flush>" ]] && ok "handshake: version 2, clean and smudge only" || bad "unexpected handshake: $HS"
[[ "$HS" != *delay* ]] && ok "the delay capability is never advertised" || bad "delay advertised: $HS"

git config --unset filter.eyesonly.process
echo 'NEW=1' > secrets/new.txt && as alice git add secrets/new.txt
check "with the process filter unset, single-shot clean still encrypts" bash -c "git cat-file blob :secrets/new.txt | head -1 | grep -qx EYESONLY-V1"
as alice git rm -q --cached secrets/new.txt && rm secrets/new.txt
as alice $EYESONLY setup >/dev/null 2>&1
check "setup turns the process filter back on" git config filter.eyesonly.process

echo "== --remote"
# bob's origin is a GitHub-like mirror; the Eyes Only server is the remote 'eyes'.
git clone -q --bare "$EYESONLY_DATA/repos/app.git" "$SB/github.git" 2>/dev/null
git clone -q "$SB/github.git" "$SB/bob" 2>/dev/null
cd "$SB/bob"
git remote add eyes "$(url bob)"
expect_reject "setup with a non-Eyes-Only origin explains --remote" "use --remote" as bob $EYESONLY setup
expect_ok "setup --remote eyes works" as bob $EYESONLY setup --remote eyes
check "...and names the remote it used" grep -q "remote 'eyes'" "$SB/out"
check "...and remembers it in eyesonly.remote" bash -c "[[ \$(git config eyesonly.remote) == eyes ]]"
check "origin is untouched" bash -c "git remote get-url origin | grep -q github.git"
expect_out "bob reads .env" "STRIPE_SECRET=sk_live_1" cat .env
expect_out "pull-policy without a flag uses the remembered remote" "remote 'eyes'" as bob $EYESONLY pull-policy
expect_reject "an unknown --remote is refused clearly" "no remote named 'nope'" as bob $EYESONLY pull-policy --remote nope

echo "== token out of .git/config"
mkdir -p "$SB/credhome"
printf '[credential]\n\thelper = store --file=%s\n' "$SB/credhome/store" > "$SB/credhome/gitconfig"
CRED=(env GIT_CONFIG_GLOBAL="$SB/credhome/gitconfig")
as bob "${CRED[@]}" $EYESONLY clone "$(url bob)" "$SB/bob-cred" >"$SB/clone.out" 2>&1
check "clone with a credential helper succeeds" test -f "$SB/bob-cred/.env"
check "the remote URL has no token" bash -c "! git -C '$SB/bob-cred' config remote.origin.url | grep -qF '${TOK[bob]}'"
check "the remote URL keeps the user name" bash -c "git -C '$SB/bob-cred' config remote.origin.url | grep -q '//bob@'"
check "the token went to the helper" grep -qF "${TOK[bob]}" "$SB/credhome/store"
check "clone output never shows the token" bash -c "! grep -qF '${TOK[bob]}' '$SB/clone.out'"
expect_ok "fetch works through the helper" in_ "$SB/bob-cred" as bob "${CRED[@]}" git fetch -q
expect_ok "pull-policy works through the helper" in_ "$SB/bob-cred" as bob "${CRED[@]}" $EYESONLY pull-policy
as bob $EYESONLY clone "$(url bob)" "$SB/bob-nohelper" >"$SB/clone2.out" 2>&1
check "without a helper the token stays in the URL (as before)" bash -c "git -C '$SB/bob-nohelper' config remote.origin.url | grep -qF '${TOK[bob]}'"
check "...with a note on how to avoid it" grep -q "credential helper" "$SB/clone2.out"
check "...and the token is not printed" bash -c "! grep -qF '${TOK[bob]}' '$SB/clone2.out'"

echo "== portable filter commands"
cp_pkg() { mkdir -p "$1" && cp -r "$ROOT/bin" "$ROOT/src" "$ROOT/package.json" "$1/"; }
mkshim() { mkdir -p "$SB/bin" && printf '#!/bin/sh\nexec node "%s/bin/eyesonly.mjs" "$@"\n' "$1" > "$SB/bin/eyesonly" && chmod +x "$SB/bin/eyesonly"; }
cp_pkg "$SB/pkg1"; mkshim "$SB/pkg1"
SHIMPATH="$SB/bin:$PATH"
git clone -q "$(url bob)" "$SB/bob-path" 2>/dev/null
expect_ok "setup through the eyesonly on PATH" in_ "$SB/bob-path" as bob env PATH="$SHIMPATH" eyesonly setup
check "filters call 'eyesonly' from PATH" bash -c "[[ \$(git -C '$SB/bob-path' config filter.eyesonly.process) == 'eyesonly filter-process' ]]"
check "the hook calls 'eyesonly' from PATH" grep -q '^eyesonly pre-commit' "$SB/bob-path/.git/hooks/pre-commit"
mv "$SB/pkg1" "$SB/pkg2"; mkshim "$SB/pkg2"
rm "$SB/bob-path/.env"
expect_ok "after the package moves, checkout still decrypts" in_ "$SB/bob-path" as bob env PATH="$SHIMPATH" git checkout -- .env
expect_out "...the plaintext is back" "STRIPE_SECRET=sk_live_1" cat "$SB/bob-path/.env"
check "...and status is clean" bash -c "[[ -z \$(cd '$SB/bob-path' && EYESONLY_HOME='$SB/home/bob' PATH='$SHIMPATH' git status --porcelain) ]]"
expect_ok "a different eyesonly on PATH means absolute paths" in_ "$SB/bob-path" as bob env PATH="$SHIMPATH" $EYESONLY setup
check "...pointing at this package" bash -c "git -C '$SB/bob-path' config filter.eyesonly.process | grep -qE 'bin[\/]eyesonly.mjs'"

echo "== doctor"
expect_ok "doctor passes on a healthy clone" in_ "$SB/bob-path" as bob $EYESONLY doctor
check "...and says so" grep -q "no problems found" "$SB/out"
expect_reject "doctor: no identity" "no identity at" in_ "$SB/bob-path" env EYESONLY_HOME="$SB/nobody" $EYESONLY doctor
mv "$SB/bob-path/.git/hooks/pre-commit" "$SB/hook.bak"
expect_reject "doctor: missing hook" "pre-commit hook is missing" in_ "$SB/bob-path" as bob $EYESONLY doctor
mv "$SB/hook.bak" "$SB/bob-path/.git/hooks/pre-commit"
cp "$SB/bob-path/.git/info/attributes" "$SB/attrs.bak"
sed -i 's/ -text$//' "$SB/bob-path/.git/info/attributes"
expect_reject "doctor: pinned attributes without -text" "pinned attributes missing or outdated" in_ "$SB/bob-path" as bob $EYESONLY doctor
cp "$SB/attrs.bak" "$SB/bob-path/.git/info/attributes"
cp_pkg "$SB/pkg3"
in_ "$SB/bob-path" as bob env EYESONLY_ABSOLUTE_COMMANDS=1 node "$SB/pkg3/bin/eyesonly.mjs" setup >/dev/null 2>&1
rm -rf "$SB/pkg3"
expect_reject "doctor: the filter command no longer runs (package removed)" "doesn't run" in_ "$SB/bob-path" as bob $EYESONLY doctor
in_ "$SB/bob-path" as bob $EYESONLY setup >/dev/null 2>&1
expect_ok "setup repairs it" in_ "$SB/bob-path" as bob $EYESONLY doctor
sed 's/"alice", "bob"]/"alice", "bob", "junior"]/' "$SB/policy.json" > "$SB/policy2.json"
$VS policy set app.git "$SB/policy2.json" 2>/dev/null
expect_reject "doctor: cached policy out of date" "out of date" in_ "$SB/bob-path" as bob $EYESONLY doctor
in_ "$SB/bob-path" as bob $EYESONLY pull-policy >/dev/null 2>&1
expect_ok "pull-policy fixes it" in_ "$SB/bob-path" as bob $EYESONLY doctor
$VS policy set app.git "$SB/policy.json" 2>/dev/null
in_ "$SB/bob-path" as bob $EYESONLY pull-policy >/dev/null 2>&1
expect_out "doctor: token in the remote URL is a warning" "token is stored in .git/config" in_ "$SB/bob-path" as bob $EYESONLY doctor
in_ "$SB/bob-path" git config --unset filter.eyesonly.clean
expect_reject "doctor: filters not configured" "filters or merge driver are not configured" in_ "$SB/bob-path" as bob $EYESONLY doctor
in_ "$SB/bob-path" as bob $EYESONLY setup >/dev/null 2>&1

echo "== edited ciphertext and CRLF"
as junior $EYESONLY clone "$(url junior)" "$SB/junior" >/dev/null 2>&1
cd "$SB/junior"
expect_out "junior has the envelope" "EYESONLY-V1" head -1 .env
echo 'oops=1' >> .env
expect_reject "staging edited ciphertext is refused" "ciphertext was edited or isn't valid" as junior git add .env
check "...the index still holds the committed envelope" bash -c "[[ \$(git rev-parse :.env) == \$(git rev-parse HEAD:.env) ]]"
expect_ok "git checkout restores it" as junior git checkout -- .env
node --input-type=module -e '
const vc = await import((await import("node:url")).pathToFileURL(process.argv[1]).href + "/src/crypto.mjs");
const fs = await import("node:fs");
const id = JSON.parse(fs.readFileSync(process.argv[2] + "/identity.json"));
const pol = JSON.parse(fs.readFileSync(".git/eyesonly/policy.json"));
const r = { alice: pol.keys.alice.x25519, bob: pol.keys.bob.x25519, junior: id.x25519.pub };
fs.writeFileSync(".env", vc.seal({ plaintext: Buffer.from("API_URL=https://evil\n"), path: ".env", recipients: r, signer: id }));
' "$ROOT" "$SB/home/junior"
expect_reject "staging an envelope signed by a non-writer is refused" "signer 'junior'" as junior git add .env
as junior git checkout -- .env
node -e 'const fs=require("fs");fs.writeFileSync(".env",fs.readFileSync(".env","latin1").replace(/\n/g,"\r\n"),"latin1")'
expect_out "status calls a CRLF envelope corrupted, not decrypted" "corrupted .env" as junior $EYESONLY status
expect_reject "doctor flags converted line endings" "converted line endings" as junior $EYESONLY doctor
expect_ok "git add of the CRLF copy is not an error" as junior git add .env
check "...and stages the original envelope byte for byte" bash -c "[[ \$(git rev-parse :.env) == \$(git rev-parse HEAD:.env) ]]"
as junior git checkout -- .env
cd "$SB/bob-path"
git cat-file blob HEAD:.env | node -e 'process.stdin.on("data",c=>process.stdout.write(c.toString("latin1").replace(/\n/g,"\r\n"),"latin1"))' > "$SB/crlf.env"
expect_out "smudge decrypts a CRLF-mangled envelope" "STRIPE_SECRET=sk_live_1" bash -c "EYESONLY_HOME='$SB/home/bob' $EYESONLY smudge .env < '$SB/crlf.env'"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
