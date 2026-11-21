#!/usr/bin/env bash
# Merge driver for protected files: verify all three sides, 3-way merge the plaintext, re-seal.
# alice and bob read/write .env and secrets/**; junior reads neither.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"
PORT="${PORT:-$((20000 + RANDOM % 20000))}"
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_EDITOR=true
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
BASE="http://127.0.0.1:$PORT"
PASS=0 FAIL=0

cleanup() { [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null; rm -rf "$SB"; }
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
check() { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 15; fi; }
expect_ok()   { check "$@"; }
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
# output goes to a file first: with pipefail, `cmd | grep -q` can fail on SIGPIPE when grep exits early
expect_out()  { local d="$1" pat="$2"; shift 2; "$@" >"$SB/out" 2>&1; if grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (no '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }

as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
url() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/app.git"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }

# dec <file-path>: decrypt an envelope on stdin with the client's verifying tryOpen; prints signer= then plaintext
cat > "$SB/dec.mjs" <<EOF
import fs from 'node:fs';
const { tryOpen, loadPolicy, loadIdentity } = await import('$ROOT/src/client.mjs');
const r = tryOpen(fs.readFileSync(0), process.argv[2], loadPolicy(), loadIdentity());
if (r.error || !r.plaintext) { console.error(r.error || 'not a reader'); process.exit(1); }
console.log('signer=' + r.env.signer);
process.stdout.write(r.plaintext);
EOF
dec() { node "$SB/dec.mjs" "$1"; }
# blob_dec <rev:path> <path>
blob_dec() { git cat-file blob "$1" | dec "$2"; }

# tmp_clean <repo> <label>: no plaintext temp files left, dir mode 700
tmp_clean() {
  local t; t="$(cd "$1" && git rev-parse --path-format=absolute --git-common-dir)/eyesonly/tmp"
  if [[ -d "$t" && -z "$(ls -A "$t")" && "$(stat -c %a "$t")" == 700 ]]; then ok "$2: eyesonly/tmp is empty, mode 700"
  else bad "$2: eyesonly/tmp not clean ($(ls -la "$t" 2>&1 | tr '\n' ' '))"; fi
}

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
$VS serve --port "$PORT" 2>"$SB/server.log" & SRV=$!
for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done

A="$SB/alice"; B="$SB/bob"; J="$SB/junior"
mkdir -p "$A" && cd "$A"
git init -q -b main && git remote add origin "$(url alice)"
# a .gitattributes written by eyesonly before the merge driver existed
printf '*.js text\n/.env filter=eyesonly diff=eyesonly\n/secrets/** filter=eyesonly diff=eyesonly\n' > .gitattributes
as alice $EYESONLY setup 2>"$SB/out"
[[ "$(grep -c '^/.env ' .gitattributes)" == 1 ]] && ok "old .gitattributes line is not duplicated" || { bad "duplicated .env line"; cat .gitattributes; }
grep -qx '/.env filter=eyesonly diff=eyesonly merge=eyesonly' .gitattributes && grep -qx '/secrets/\*\* filter=eyesonly diff=eyesonly merge=eyesonly' .gitattributes \
  && ok "old .gitattributes lines are upgraded to merge=eyesonly" || { bad "not upgraded"; cat .gitattributes; }
grep -qx '\*.js text' .gitattributes && ok "unrelated .gitattributes lines are kept" || bad "lost unrelated line"
printf 'L1=one\nL2=two\nL3=three\nL4=four\nL5=five\nL6=six\n' > .env
mkdir -p secrets && printf 'a1\na2\na3\na4\na5\n' > secrets/a.txt
printf 'f1\nf2\nf3\nf4\nf5\n' > "secrets/my file.txt"
printf 'bin\0one\n' > secrets/blob.bin
as alice git add -A && as alice git commit -qm init
expect_ok "alice pushes main" as alice git push -q -u origin main

echo "== configuration"
expect_ok "bob clones" as bob $EYESONLY clone "$(url bob)" "$B"
expect_out "merge.eyesonly.driver is wired up" "merge-file %O %A %B %P %L" in_ "$B" git config merge.eyesonly.driver
expect_out "check-attr merge on .env is eyesonly" "merge: eyesonly" in_ "$B" git check-attr merge -- .env
expect_ok "junior clones" as junior $EYESONLY clone "$(url junior)" "$J"

echo "== clean auto-merge"
in_ "$A" as alice git checkout -q -b a
in_ "$A" sed -i 's/^L1=.*/L1=alice/' .env
in_ "$A" as alice git commit -qam "alice: L1"
in_ "$A" as alice git push -q -u origin a 2>/dev/null
cd "$B"
sed -i 's/^L3=.*/L3=bob/' .env && as bob git commit -qam "bob: L3"
as bob git fetch -q origin
expect_ok "git merge of non-overlapping .env edits succeeds" as bob git merge --no-edit origin/a
expect_out "committed .env is a EYESONLY-V1 envelope" "^EYESONLY-V1" bash -c 'git cat-file blob HEAD:.env | head -1'
expect_out "merged envelope is signed by the merger (bob)" "signer=bob" as bob blob_dec HEAD:.env .env
as bob blob_dec HEAD:.env .env > "$SB/merged" 2>&1
grep -q '^L1=alice$' "$SB/merged" && grep -q '^L3=bob$' "$SB/merged" && ok "merged plaintext has both edits" || { bad "merged plaintext"; cat "$SB/merged"; }
grep -q '^L1=alice$' .env && grep -q '^L3=bob$' .env && ok "working .env is decrypted merge result" || bad "working .env"
[[ -z "$(as bob git status --porcelain)" ]] && ok "status clean after merge" || { bad "status dirty"; git status --porcelain; }
expect_ok "bob pushes the merge" as bob git push -q
tmp_clean "$B" "auto-merge"

echo "== conflicting edits"
in_ "$A" as alice git checkout -q main
in_ "$A" as alice git pull -q --ff-only 2>/dev/null
in_ "$A" as alice git checkout -q -b c
in_ "$A" sed -i 's/^L5=.*/L5=alice-five/' .env
in_ "$A" as alice git commit -qam "alice: L5"
in_ "$A" as alice git push -q -u origin c 2>/dev/null
cd "$B"
sed -i 's/^L5=.*/L5=bob-five/' .env && as bob git commit -qam "bob: L5"
as bob git fetch -q origin
expect_reject "same-line merge stops with a conflict" "conflict in '.env'" as bob git merge --no-edit origin/c
grep -q '^<<<<<<< ' .env && grep -q 'L5=alice-five' .env && grep -q 'L5=bob-five' .env && ! grep -q EYESONLY-V1 .env \
  && ok "working .env is plaintext with conflict markers and both values" || { bad "conflict file"; cat .env; }
tmp_clean "$B" "conflict"
printf 'L1=alice\nL2=two\nL3=bob\nL4=four\nL5=resolved\nL6=six\n' > .env
as bob git add .env
[[ "$(git cat-file blob :.env | head -c11)" == EYESONLY-V1 ]] && ok "resolution is sealed on git add" || bad "index .env not sealed"
expect_ok "bob commits the resolution" as bob git commit -q --no-edit
expect_ok "bob pushes the resolved merge" as bob git push -q
expect_out "resolved content is readable" "L5=resolved" as bob blob_dec HEAD:.env .env

echo "== rebase"
in_ "$A" as alice git checkout -q main
in_ "$A" as alice git pull -q --ff-only 2>/dev/null
in_ "$A" sed -i 's/^L1=.*/L1=alice-again/' .env
in_ "$A" as alice git commit -qam "alice: L1 again"
in_ "$A" as alice git push -q 2>/dev/null
cd "$B"
sed -i 's/^L6=.*/L6=bob-six/' .env && as bob git commit -qam "bob: L6"
as bob git fetch -q origin
expect_ok "git rebase over a different-line .env edit completes" as bob git rebase origin/main
grep -q '^L1=alice-again$' .env && grep -q '^L6=bob-six$' .env && ok "rebased .env has both edits" || { bad "rebased .env"; cat .env; }
expect_out "rebased envelope is signed by bob" "signer=bob" as bob blob_dec HEAD:.env .env
expect_ok "bob pushes the rebased commit" as bob git push -q
tmp_clean "$B" "rebase"

echo "== path with spaces"
in_ "$A" as alice git pull -q --ff-only 2>/dev/null
in_ "$A" as alice git checkout -q -b sp
in_ "$A" sed -i 's/^f1$/f1-alice/' "secrets/my file.txt"
in_ "$A" as alice git commit -qam "alice: f1"
in_ "$A" as alice git checkout -q main
in_ "$A" sed -i 's/^f5$/f5-alice/' "secrets/my file.txt"
in_ "$A" as alice git commit -qam "alice: f5"
expect_ok "merge of a protected path with spaces succeeds" in_ "$A" as alice git merge --no-edit sp
grep -q '^f1-alice$' "$A/secrets/my file.txt" && grep -q '^f5-alice$' "$A/secrets/my file.txt" && ok "spaced path merged both edits" || bad "spaced path"
tmp_clean "$A" "spaces"

echo "== binary content"
in_ "$A" as alice git checkout -q -b bin
in_ "$A" bash -c "printf 'bin\0two\n' > secrets/blob.bin" && in_ "$A" as alice git commit -qam "bin a"
in_ "$A" as alice git checkout -q main
in_ "$A" bash -c "printf 'bin\0three\n' > secrets/blob.bin" && in_ "$A" as alice git commit -qam "bin b"
expect_reject "binary protected file refuses to merge" "binary content; pick a side" in_ "$A" as alice git merge --no-edit bin
in_ "$A" as alice git merge --abort
tmp_clean "$A" "binary"

echo "== non-reader"
in_ "$A" as alice git checkout -q -b j1
in_ "$A" sed -i 's/^L2=.*/L2=j1/' .env && in_ "$A" as alice git commit -qam j1
in_ "$A" as alice git checkout -q main
in_ "$A" as alice git checkout -q -b j2
in_ "$A" sed -i 's/^L4=.*/L4=j2/' .env && in_ "$A" as alice git commit -qam j2
in_ "$A" as alice git push -q origin j1 j2 2>/dev/null
in_ "$A" as alice git checkout -q main
cd "$J"
as junior git fetch -q origin
as junior git checkout -q -b j1 origin/j1
expect_reject "junior can't merge .env: not a reader" "you are not a reader" as junior git merge --no-edit origin/j2
grep -q "ask one of: alice, bob" "$SB/out" && ok "message lists the readers" || { bad "readers not listed"; cat "$SB/out"; }
cmp -s .env <(git cat-file blob origin/j1:.env) && ok "junior's .env is still the ours envelope" || bad ".env changed"
tmp_clean "$J" "non-reader"
as junior git merge --abort

echo "== forged side"
cd "$A"
FORGED=$(node --input-type=module -e '
const vc = await import(process.argv[1] + "/src/crypto.mjs");
const fs = await import("node:fs");
const id = JSON.parse(fs.readFileSync(process.argv[2] + "/identity.json"));
const pol = JSON.parse(fs.readFileSync(".git/eyesonly/policy.json"));
const r = { junior: id.x25519.pub }; for (const u of ["alice", "bob"]) r[u] = pol.keys[u].x25519;
const pt = Buffer.from("L1=alice-again\nL2=two\nL3=bob\nL4=four\nL5=resolved\nL6=bob-six\nAPI_URL=https://evil\n");
process.stdout.write(vc.seal({ plaintext: pt, path: ".env", recipients: r, signer: id }));
' "$ROOT" "$SB/home/junior" | git hash-object -w --stdin)
plant() { # plant <branch> <blob> <path>: commit on top of main with hooks bypassed, never checked out
  GIT_INDEX_FILE="$SB/idx" git read-tree main
  GIT_INDEX_FILE="$SB/idx" git update-index --cacheinfo "100644,$2,$3"
  local t; t=$(GIT_INDEX_FILE="$SB/idx" git write-tree); rm -f "$SB/idx"
  git branch -f "$1" "$(as junior git commit-tree "$t" -p main -m "$1")"
}
plant forged "$FORGED" .env
sed -i 's/^L3=.*/L3=alice-three/' .env && as alice git commit -qam "alice: L3"
OURS=$(git rev-parse HEAD:.env)
expect_reject "merging a junior-signed .env is refused" "is not an allowed writer\|bad or unknown signature" as alice git merge --no-edit forged
grep -q "can't merge '.env': theirs:" "$SB/out" && ok "refusal names the forged side" || bad "side not named"
! grep -q evil .env && grep -q '^L3=alice-three$' .env && ok "working .env is still ours" || { bad "working .env"; cat .env; }
[[ "$(git ls-files -s .env | awk '$3==2{print $2}')" == "$OURS" ]] && ok "ours stage unchanged" || bad "ours stage"
cat > "$SB/scan.mjs" <<EOF
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
const { tryOpen, loadPolicy, loadIdentity } = await import('$ROOT/src/client.mjs');
const pol = loadPolicy(), id = loadIdentity();
const objs = execFileSync('git', ['cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype)'], { encoding: 'utf8' });
for (const l of objs.split('\n').filter((l) => l.endsWith(' blob'))) {
  const blob = execFileSync('git', ['cat-file', 'blob', l.split(' ')[0]]);
  if (!blob.subarray(0, 11).equals(Buffer.from('EYESONLY-V1'))) continue;
  const r = tryOpen(blob, null, pol, id);
  if (r.env?.signer === 'alice' && r.plaintext?.includes('evil')) { console.log('LAUNDERED ' + l); process.exit(1); }
}
EOF
check "no envelope signed by alice contains the forged content" as alice node "$SB/scan.mjs"
tmp_clean "$A" "forged"
as alice git merge --abort

echo "== path-bound side"
plant moved "$(git rev-parse main:secrets/a.txt)" .env
sed -i 's/^L4=.*/L4=alice-four/' .env && as alice git commit -qam "alice: L4"
expect_reject "a side moved from secrets/a.txt is refused" "envelope is bound to" as alice git merge --no-edit moved
! grep -q '^a1$' .env && ok "working .env is still ours" || bad "moved content leaked into .env"
tmp_clean "$A" "path-bound"
as alice git merge --abort

echo "== stale temp files are swept"
T="$(git rev-parse --path-format=absolute --git-common-dir)/eyesonly/tmp"
echo stale > "$T/old" && touch -d '2 hours ago' "$T/old"
in_ "$A" as alice git checkout -q -b sw1 && sed -i 's/^L2=.*/L2=sw/' .env && as alice git commit -qam sw1
as alice git checkout -q main && sed -i 's/^L6=.*/L6=sw/' .env && as alice git commit -qam sw2
expect_ok "merge after a crash succeeds" as alice git merge --no-edit sw1
tmp_clean "$A" "sweep"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
