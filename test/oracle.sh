#!/usr/bin/env bash
# Object-existence oracle suite (THREAT_MODEL attack #19).
# junior must not learn from upload-pack ACKs whether the server holds a private commit.
# Team: alice (admin), bob = @core. junior = member, outside @core.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"
PORT="${PORT:-$((20000 + RANDOM % 20000))}"
PORT2=$((PORT + 1))
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
BASE="http://127.0.0.1:$PORT"
PASS=0 FAIL=0

cleanup() { [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null; [[ -n "${SRV2:-}" ]] && kill "$SRV2" 2>/dev/null; rm -rf "$SB"; }
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

# --- raw upload-pack requests
pkt() { printf '%04x%s' $((${#1} + 4)) "$1"; }
rand_sha() { openssl rand -hex 20 2>/dev/null || node -e 'console.log(require("crypto").randomBytes(20).toString("hex"))'; }
# body <file> <negotiate|done> <have-or-shallow-line>...: want main tip, then the given lines
body() {
  local f="$1" end="$2"; shift 2
  { pkt "want $MAIN"$'\n'; printf 0000; for l in "$@"; do pkt "$l"$'\n'; done
    if [[ $end == done ]]; then pkt "done"$'\n'; else printf 0000; fi; } > "$f"
}
# post <user> <bodyfile> <outfile> [curl args...]: prints the HTTP status
post() {
  local u="$1" f="$2" o="$3"; shift 3
  curl -s -o "$o" -w '%{http_code}' --data-binary @"$f" -H 'Content-Type: application/x-git-upload-pack-request' \
    "$@" -u "$u:${TOK[$u]}" "$BASE/app.git/git-upload-pack"
}
code_is() { local d="$1" want="$2" got="$3" o="$4" pat="${5:-}"; if [[ "$got" == "$want" ]] && { [[ -z "$pat" ]] || grep -q -- "$pat" "$o"; }; then ok "$d"; else bad "$d (got $got, want $want${pat:+ + '$pat'})"; head -c 300 "$o" | sed 's/^/        /'; echo; fi; }

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
  "files": { ".env": ["@core"], "secrets/**": ["@core"] },
  "branches": { "refs/heads/private/": ["@core"] } }
EOF
$VS policy set app.git "$SB/policy.json" 2>/dev/null
source "$ROOT/test/lib/server.sh"
start_server PORT "$SB/server.log"; SRV=$LAST_SRV; BASE="http://127.0.0.1:$PORT"
start_server PORT2 "$SB/server2.log" EYESONLY_MAX_UPLOAD_PACK_BODY=2000; SRV2=$LAST_SRV

mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$(url alice)"
as alice $EYESONLY setup 2>/dev/null
echo 'console.log("hello")' > index.js && echo 'STRIPE_SECRET=sk_live_123' > .env
as alice git add -A && as alice git commit -qm init
echo 'v2' >> index.js && as alice git commit -qam second
expect_ok "alice pushes main (2 commits)" as alice git push -q -u origin main
as alice git checkout -q -b private/launch
echo 'Launch: March 3' > LAUNCH.md && as alice git add LAUNCH.md && as alice git commit -qm "launch plan"
expect_ok "alice pushes private/launch" as alice git push -q -u origin private/launch
as alice git checkout -q main
PRIV=$(git rev-parse private/launch) MAIN=$(git rev-parse main) MAIN1=$(git rev-parse main~1)
RAND=$(rand_sha)
GD="$EYESONLY_DATA/repos/app.git"
expect_ok "bob clones" as bob $EYESONLY clone "$(url bob)" "$SB/bob"
expect_ok "junior clones" as junior $EYESONLY clone "$(url junior)" "$SB/junior"

echo "== have-negotiation oracle"
R="$SB/r" && mkdir -p "$R"
body "$R/priv.done" done "have $PRIV"
post junior "$R/priv.done" "$R/j.priv" >/dev/null
if grep -q NAK "$R/j.priv" && ! grep -q "ACK $PRIV" "$R/j.priv"; then ok "junior: have <private sha> gets NAK, no ACK"; else bad "junior learned the private commit exists"; head -c 200 "$R/j.priv"; echo; fi
post bob "$R/priv.done" "$R/b.priv" >/dev/null
grep -q "ACK $PRIV" "$R/b.priv" && ok "control: bob gets ACK <private sha>" || bad "bob got no ACK for the private commit"
body "$R/main1.done" done "have $MAIN1"
post junior "$R/main1.done" "$R/j.main1" >/dev/null
grep -q "ACK $MAIN1" "$R/j.main1" && ok "control: junior gets ACK for a visible main commit" || bad "junior got no ACK for main~1"

body "$R/priv.neg" negotiate "have $PRIV"
body "$R/rand.neg" negotiate "have $RAND"
post junior "$R/priv.neg" "$R/j.priv.neg" >/dev/null
post junior "$R/rand.neg" "$R/j.rand.neg" >/dev/null
post bob "$R/priv.neg" "$R/b.priv.neg" >/dev/null
if cmp -s "$R/j.priv.neg" "$R/j.rand.neg" && [[ -s "$R/j.priv.neg" ]]; then ok "junior: response to have <private> is byte-identical to have <random>"; else bad "responses differ (oracle)"; fi
cmp -s "$R/b.priv.neg" "$R/j.rand.neg" && bad "control: bob's response should differ (cmp is vacuous)" || ok "control: bob's response to have <private> differs"
body "$R/mixed.neg" negotiate "have $RAND" "have $PRIV" "have $MAIN1"
post junior "$R/mixed.neg" "$R/j.mixed" >/dev/null
if grep -q "ACK $MAIN1" "$R/j.mixed" && ! grep -q "ACK $PRIV" "$R/j.mixed"; then ok "mixed haves: visible one ACKed, private one dropped"; else bad "mixed haves filtered wrongly"; head -c 200 "$R/j.mixed"; echo; fi
TREE=$(git --git-dir="$GD" rev-parse "$PRIV^{tree}") BLOB=$(git --git-dir="$GD" rev-parse "$PRIV:LAUNCH.md")
body "$R/tree.neg" negotiate "have $TREE" "have $BLOB" "have $(rand_sha)$(rand_sha | cut -c1-24)"
post junior "$R/tree.neg" "$R/j.tree" >/dev/null
cmp -s "$R/j.tree" "$R/j.rand.neg" && ok "tree/blob/64-hex haves are dropped like a missing object" || bad "tree/blob/64-hex haves leak"

echo "== gzip bodies"
gzip -c "$R/priv.done" > "$R/priv.done.gz"
post junior "$R/priv.done.gz" "$R/j.gz" -H 'Content-Encoding: gzip' >/dev/null
if grep -q NAK "$R/j.gz" && ! grep -q "ACK $PRIV" "$R/j.gz"; then ok "gzip body: junior gets no ACK <private>"; else bad "gzip body leaks to junior"; fi
post bob "$R/priv.done.gz" "$R/b.gz" -H 'Content-Encoding: gzip' >/dev/null
grep -q "ACK $PRIV" "$R/b.gz" && ok "control: gzip body parsed for bob (ACK <private>)" || bad "gzip body broken for bob"
post bob "$R/priv.neg" "$R/b.chunked" -H 'Transfer-Encoding: chunked' >/dev/null
cmp -s "$R/b.chunked" "$R/b.priv.neg" && grep -q "ACK $PRIV" "$R/b.chunked" && ok "chunked body without Content-Length is buffered and forwarded" || bad "chunked body broken"
C=$(post junior "$R/priv.done" "$R/o" -H 'Content-Encoding: br')
code_is "unsupported Content-Encoding -> 400" 400 "$C" "$R/o" "unsupported Content-Encoding"

echo "== malformed and oversized requests"
printf zzzz > "$R/zzzz"
C=$(post junior "$R/zzzz" "$R/o"); code_is "non-hex pkt-line length -> 400 (from eyesonly, not git)" 400 "$C" "$R/o" "malformed pkt-line"
{ pkt "want $MAIN"$'\n'; printf 0000; pkt "have nothex"$'\n'; printf 0000; } > "$R/nothex"
C=$(post junior "$R/nothex" "$R/o"); code_is "have line that is not 40/64 hex -> 400" 400 "$C" "$R/o" "malformed 'have' line"
{ printf 00ff; printf 'want %s\n' "$MAIN"; } > "$R/long"
C=$(post junior "$R/long" "$R/o"); code_is "length header past end of body -> 400" 400 "$C" "$R/o" "past the end"
printf 0003 > "$R/l3"
C=$(post junior "$R/l3" "$R/o"); code_is "pkt-line length 0003 -> 400" 400 "$C" "$R/o" "0003"
: > "$R/empty"
C=$(post junior "$R/empty" "$R/o"); code_is "empty body -> 400" 400 "$C" "$R/o" "empty upload-pack request"
printf 'not gzip' > "$R/notgz"
C=$(post junior "$R/notgz" "$R/o" -H 'Content-Encoding: gzip'); code_is "invalid gzip -> 400" 400 "$C" "$R/o" "not valid gzip"
C=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz"); [[ "$C" == 200 ]] && ok "server still healthy after malformed requests" || bad "healthz $C"
head -c 11M /dev/zero > "$R/big"
C=$(post junior "$R/big" "$R/o"); code_is "11 MiB body (Content-Length) -> 413" 413 "$C" "$R/o" "larger than"
C=$(post junior "$R/big" "$R/o" -H 'Transfer-Encoding: chunked'); code_is "11 MiB chunked body (no Content-Length) -> 413" 413 "$C" "$R/o" "larger than"
gzip -c "$R/big" > "$R/big.gz"
C=$(post junior "$R/big.gz" "$R/o" -H 'Content-Encoding: gzip'); code_is "gzip bomb (small compressed, 11 MiB inflated) -> 413" 413 "$C" "$R/o" "decompressed"
body "$R/medium" negotiate $(for _ in $(seq 60); do echo "have $(rand_sha)"; done)
C=$(curl -s -o "$R/o" -w '%{http_code}' --data-binary @"$R/medium" -H 'Content-Type: application/x-git-upload-pack-request' -u "junior:${TOK[junior]}" "http://127.0.0.1:$PORT2/app.git/git-upload-pack")
code_is "EYESONLY_MAX_UPLOAD_PACK_BODY=2000 caps a 3 KB body -> 413" 413 "$C" "$R/o" "larger than 2000"
C=$(curl -s -o "$R/o" -w '%{http_code}' --data-binary @"$R/priv.neg" -H 'Content-Type: application/x-git-upload-pack-request' -u "junior:${TOK[junior]}" "http://127.0.0.1:$PORT2/app.git/git-upload-pack")
code_is "control: the same small-cap server accepts a small body" 200 "$C" "$R/o" "NAK"
C=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz"); [[ "$C" == 200 ]] && ok "server still healthy after oversized requests" || bad "healthz $C"

echo "== shallow / deepen"
shallow_req() { { pkt "want $MAIN"$'\n'; pkt "shallow $1"$'\n'; pkt "deepen 1"$'\n'; printf 0000; printf 0000; } > "$2"; }
shallow_req "$PRIV" "$R/sh.priv"; shallow_req "$RAND" "$R/sh.rand"
post junior "$R/sh.priv" "$R/j.sh.priv" >/dev/null
post junior "$R/sh.rand" "$R/j.sh.rand" >/dev/null
if cmp -s "$R/j.sh.priv" "$R/j.sh.rand" && grep -q "shallow $MAIN" "$R/j.sh.priv"; then ok "junior: shallow <private> + deepen 1 is identical to shallow <random>"; else bad "shallow <private> response differs"; fi
C=$(post bob "$R/sh.priv" "$R/b.sh.priv")
[[ "$C" == 200 ]] && ok "control: bob's shallow <private> request is forwarded" || bad "bob shallow request got $C"
{ pkt "want $MAIN"$'\n'; pkt "shallow $PRIV"$'\n'; printf 0000; } > "$R/shpriv"
node --input-type=module -e '
const { filterUploadPackBody } = await import(process.argv[1] + "/src/negotiate.mjs");
const fs = await import("node:fs");
const body = fs.readFileSync(process.argv[3]);
const j = await filterUploadPackBody({ body, gitDir: process.argv[2], hiddenPrefixes: ["refs/heads/private"] });
const b = await filterUploadPackBody({ body, gitDir: process.argv[2], hiddenPrefixes: [] });
process.exit(!j.includes("shallow ") && b.equals(body) ? 0 : 1);
' "$ROOT" "$GD" "$R/shpriv" && ok "shallow <private> line is dropped for junior's prefixes and kept for bob's" || bad "shallow filtering"
{ pkt "want $MAIN"$'\n'; pkt "deepen-not refs/heads/private/launch"$'\n'; printf 0000; pkt "done"$'\n'; } > "$R/dnot"
C=$(post junior "$R/dnot" "$R/o"); code_is "deepen-not -> 400" 400 "$C" "$R/o" "deepen-not is not supported by eyesonly"

echo "== pass-through is byte-exact"
{ pkt "want $MAIN multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.x"$'\n'; pkt "want $MAIN1"$'\n'
  pkt "deepen 3"$'\n'; printf 0000; pkt "have $PRIV"$'\n'; pkt "have $MAIN1"$'\n'; pkt "have $RAND"$'\n'; printf 0000; pkt "done"$'\n'; } > "$R/caps"
{ pkt "want $MAIN multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.x"$'\n'; pkt "want $MAIN1"$'\n'
  pkt "deepen 3"$'\n'; printf 0000; pkt "have $MAIN1"$'\n'; printf 0000; pkt "done"$'\n'; } > "$R/caps.want"
node --input-type=module -e '
const { filterUploadPackBody } = await import(process.argv[1] + "/src/negotiate.mjs");
const fs = await import("node:fs");
const out = await filterUploadPackBody({ body: fs.readFileSync(process.argv[3]), gitDir: process.argv[2], hiddenPrefixes: ["refs/heads/private"] });
process.exit(out.equals(fs.readFileSync(process.argv[4])) ? 0 : 1);
' "$ROOT" "$GD" "$R/caps" "$R/caps.want" && ok "want lines, capabilities, deepen and done survive byte-for-byte" || bad "filter altered non-have lines"
body "$R/onlypriv" done "have $PRIV"
C=$(post junior "$R/onlypriv" "$R/o"); [[ "$C" == 200 ]] && grep -q PACK "$R/o" && ok "request left with no haves is still valid (pack served)" || bad "request with all haves dropped broke ($C)"

echo "== real git fetches"
cd "$SB/alice"
for i in 1 2; do echo "update $i" > "new$i.txt" && as alice git add "new$i.txt" && as alice git commit -qm "update $i"; done
expect_ok "alice pushes 2 new commits to main" as alice git push -q origin main
expect_ok "junior pulls incrementally" in_ "$SB/junior" as junior git pull -q
expect_out "junior has the new file" "update 2" cat "$SB/junior/new2.txt"
expect_ok "bob pulls incrementally" in_ "$SB/bob" as bob git pull -q
expect_out "bob has the new file" "update 2" cat "$SB/bob/new2.txt"
# junior builds 100 local commits so the next fetch sends >1 KiB, gzip-compressed have lists
cd "$SB/junior"
for i in $(seq 100); do as junior git commit -q --allow-empty -m "local $i"; done
cd "$SB/alice" && echo more > new3.txt && as alice git add new3.txt && as alice git commit -qm "update 3" && as alice git push -q origin main
GIT_TRACE_CURL="$SB/trace" in_ "$SB/junior" as junior git fetch -q origin >"$SB/out" 2>&1 && FETCHED=1 || FETCHED=0
if [[ $FETCHED == 1 ]] && grep -qi "Content-Encoding: gzip" "$SB/trace" && [[ "$(git -C "$SB/junior" rev-parse origin/main)" == "$(git rev-parse main)" ]]; then
  ok "git's own gzip-compressed negotiation (100 unknown haves) fetches correctly"
else bad "gzip fetch failed (fetched=$FETCHED)"; tail -n 5 "$SB/out"; fi

echo "== performance"
HAVES=()
for _ in $(seq 190); do HAVES+=("have $(rand_sha)"); done
for c in "$PRIV" $(git rev-list main); do HAVES+=("have $c"); done   # PRIV first: unfiltered, it would be the one ACKed
body "$R/perf" negotiate "${HAVES[@]}"
T0=$(date +%s%N); C=$(post junior "$R/perf" "$R/o"); T1=$(date +%s%N)
MS=$(((T1 - T0) / 1000000))
if [[ "$C" == 200 && $MS -lt 2000 ]] && ! grep -q "ACK $PRIV" "$R/o" && grep -q "ACK $MAIN" "$R/o"; then ok "${#HAVES[@]} have lines filtered in ${MS} ms (< 2000)"; else bad "perf: ${#HAVES[@]} haves took ${MS} ms (code $C)"; fi

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
