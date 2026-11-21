#!/usr/bin/env bash
# Who could read what, when: `eyesonly audit --file/--at`, `audit <user>`, `offboard` and
# `rotate`, in GitHub (repo) mode and with a server. Commits carry fixed dates so the
# "as of" answers are deterministic.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"; export SB
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
PASS=0 FAIL=0
source "$ROOT/test/lib/compat.sh"
source "$ROOT/test/lib/server.sh"

cleanup() { cd "$ROOT"; [[ -n "${SRV:-}" ]] && { kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; }; rm -rf "$SB"; }
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
expect_ok()   { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 15; fi; }
expect_fail() { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; sed 's/^/        /' "$SB/out" | tail -n 8; else ok "$d"; fi; }
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; sed 's/^/        /' "$SB/out" | tail -n 8; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
expect_out()  { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1 && grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (no '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
# equal <desc> <expected> <actual>
equal() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (want '$2', got '$3')"; fi; }

as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
on() { local d="$1"; shift; GIT_AUTHOR_DATE="$d" GIT_COMMITTER_DATE="$d" "$@"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }
card() { as "$1" $EYESONLY whoami 2>/dev/null | tail -1; }
# readers <audit --file json>: the reader names of every version, comma-joined (sorted)
readers() { node -e 'const j = JSON.parse(require("fs").readFileSync(0, "utf8")); console.log(j.versions.flatMap((v) => v.readers.map((r) => r.name)).sort().join(","))'; }
jsonget() { node -e 'const j = JSON.parse(require("fs").readFileSync(0, "utf8")); const f = new Function("j", "return " + process.argv[1]); console.log(f(j))' "$1"; }
HOST="$SB/host.git"

for u in alice bob carol junior; do as $u $EYESONLY keygen $u >/dev/null 2>&1; done

echo "== GitHub mode: a history with a grant, edits and an offboarding"
git init -q --bare -b main "$HOST"
mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$HOST"
echo 'console.log(1)' > app.js
T1=2026-01-10T12:00:00Z T2=2026-02-10T12:00:00Z T3=2026-03-10T12:00:00Z T4=2026-04-10T12:00:00Z T5=2026-05-10T12:00:00Z
on $T1 as alice git add app.js && on $T1 as alice git commit -qm base
expect_ok "alice inits GitHub mode" on $T1 as alice $EYESONLY init --commit
printf '# payments\nSTRIPE=sk_v1\nDB_PASS=pw1\nCERT="-----BEGIN\nabc\n-----END"\n' > .env
mkdir -p secrets && echo 'db-secret-1' > secrets/db.txt
on $T1 as alice git add .env secrets/db.txt && on $T1 as alice git commit -qm "secrets v1"
expect_ok "alice pushes v1" as alice git push -q -u origin main
V1=$(git rev-parse HEAD)

expect_out "alice grants bob" "granted bob" on $T2 as alice $EYESONLY grant bob --card "$(card bob)"
on $T2 as alice $EYESONLY rekey >/dev/null 2>&1
on $T2 as alice git add .eyesonly && on $T2 as alice git commit -qm "grant bob"
V2=$(git rev-parse HEAD)
expect_out "alice grants junior only public.txt" "public.txt" on $T2 as alice $EYESONLY grant junior --card "$(card junior)" --files public.txt
expect_out "alice adds herself to public.txt (she writes it)" "public.txt" on $T2 as alice $EYESONLY grant alice --files public.txt
echo pub > public.txt
on $T2 as alice git add .eyesonly .gitattributes public.txt && on $T2 as alice git commit -qm "grant junior"
expect_ok "alice pushes the grants" as alice git push -q origin main

printf 'API_TOKEN=tok3\n' >> .env
on $T3 as alice git commit -qam "add API_TOKEN"
expect_ok "alice pushes v3" as alice git push -q origin main

expect_ok "bob clones (plain git clone + setup)" bash -c "git clone -q '$HOST' '$SB/bob' && cd '$SB/bob' && $(declare -f as); as bob $EYESONLY setup"
expect_out "bob reads .env" "API_TOKEN=tok3" cat "$SB/bob/.env"

echo "== audit --file --at"
equal "before the grant: only alice could read .env" "alice" "$(as alice $EYESONLY audit --file .env --at 2026-01-15 --json | readers)"
equal "after the grant: alice and bob" "alice,bob" "$(as alice $EYESONLY audit --file .env --at 2026-02-15 --json | readers)"
equal "--at a commit works too" "alice,bob" "$(as alice $EYESONLY audit --file .env --at "$V2" --json | readers)"
equal "--at the v1 commit: alice only" "alice" "$(as alice $EYESONLY audit --file .env --at "$V1" --json | readers)"
equal "introduced-by is the grant commit" "$V2" "$(as alice $EYESONLY audit --file .env --at 2026-02-15 --json | jsonget 'j.versions[0].introduced.commit')"
check "every reader has a key id" bash -c "$(declare -f as); as alice $EYESONLY audit --file .env --at 2026-02-15 --json | node -e 'const j=JSON.parse(require(\"fs\").readFileSync(0,\"utf8\")); process.exit(j.versions[0].readers.every((r) => /^[0-9a-f]{16}\$/.test(r.kid)) ? 0 : 1)'"
expect_out "before the file existed: not present" "not present" as alice $EYESONLY audit --file .env --at 2025-12-01
expect_out "human output names the readers" "readable by: alice" as alice $EYESONLY audit --file .env --at 2026-01-15
equal "--all-refs covers bob's branch too" "alice,bob" "$(as alice $EYESONLY audit --file .env --at 2026-02-15 --all-refs --json | readers | tr ',' '\n' | sort -u | paste -sd, -)"
expect_reject "--all-refs with a commit is refused" "needs --at <date>" as alice $EYESONLY audit --file .env --at "$V2" --all-refs
expect_reject "a bad --at is refused" "is not a date" as alice $EYESONLY audit --file .env --at "not-a-date-or-rev"

echo "== offboard (GitHub mode)"
expect_reject "offboard without a terminal needs --yes" "pass --yes" as alice $EYESONLY offboard bob </dev/null
expect_reject "you can't offboard yourself" "offboard yourself" as alice $EYESONLY offboard alice --yes
expect_reject "bob (not an admin) can't offboard" "only admins" in_ "$SB/bob" as bob $EYESONLY offboard junior --yes
expect_ok "alice offboards bob" on $T4 as alice $EYESONLY offboard bob --yes --checklist "$SB/checklist.md"
check "the checklist was written" test -s "$SB/checklist.md"
for k in STRIPE DB_PASS CERT API_TOKEN; do check "checklist lists key $k" grep -q -- "- \[ \] $k\$" "$SB/checklist.md"; done
check "checklist lists secrets/db.txt as rotate-everything" grep -q 'rotate everything in secrets/db.txt' "$SB/checklist.md"
for v in sk_v1 pw1 tok3 abc db-secret-1; do expect_fail "checklist doesn't contain the value '$v'" grep -q -- "$v" "$SB/checklist.md"; done
expect_fail "bob is gone from the policy" bash -c "git show :.eyesonly/policy.json | grep -q '\"bob\"'"
check "the rekeyed .env is staged without bob" bash -c "git cat-file blob :.env | grep -q '\"alice\"' && ! git cat-file blob :.env | grep -q '\"bob\"'"
on $T4 as alice git commit -qm "offboard bob"
expect_ok "alice pushes the offboarding" as alice git push -q origin main
expect_fail "the host's .env has no key for bob" bash -c "git --git-dir='$HOST' cat-file blob main:.env | grep -q '\"bob\"'"
expect_ok "bob pulls" in_ "$SB/bob" as bob git pull -q
expect_out "bob now gets ciphertext" "EYESONLY-V1" head -1 "$SB/bob/.env"

echo "== rename is followed"
on $T5 as alice git mv secrets/db.txt secrets/db-prod.txt
on $T5 as alice git commit -qm "rename db secret"
expect_ok "alice pushes the rename" as alice git push -q origin main
equal "audit --file follows the rename back in time" "secrets/db.txt" "$(as alice $EYESONLY audit --file secrets/db-prod.txt --at 2026-02-15 --json | jsonget 'j.versions[0].path')"
equal "...with that version's readers" "alice,bob" "$(as alice $EYESONLY audit --file secrets/db-prod.txt --at 2026-02-15 --json | readers)"
equal "the new name today: alice only" "alice" "$(as alice $EYESONLY audit --file secrets/db-prod.txt --json | readers)"

echo "== audit <user>"
J="$(as alice $EYESONLY audit bob --json)"
equal "bob could read exactly two versions of .env (v2, v3)" "2" "$(jsonget 'j.files.find((f) => f.file === ".env").versions.length' <<<"$J")"
equal "none of bob's .env versions is current" "false" "$(jsonget 'j.files.find((f) => f.file === ".env").versions.some((v) => v.current)' <<<"$J")"
equal "bob's secrets/db.txt version is listed" "1" "$(jsonget 'j.files.filter((f) => f.file === "secrets/db.txt").length' <<<"$J")"
equal "public.txt isn't in bob's list" "0" "$(jsonget 'j.files.filter((f) => f.file === "public.txt").length' <<<"$J")"
equal "--since 2026-03-01: only v3 of .env" "1" "$(as alice $EYESONLY audit bob --since 2026-03-01 --json | jsonget 'j.files.find((f) => f.file === ".env").versions.length')"
expect_out "--until before the grant: nothing" "never had access" as alice $EYESONLY audit bob --until 2026-01-20
equal "junior could read public.txt only" "public.txt" "$(as alice $EYESONLY audit junior --json | jsonget 'j.files.map((f) => f.file).join(",")')"
expect_out "human output keeps the rotate hint" "Rotate the secrets inside them" as alice $EYESONLY audit bob
check "JSON output parses" bash -c "$(declare -f as); as alice $EYESONLY audit bob --json | node -e 'JSON.parse(require(\"fs\").readFileSync(0,\"utf8\"))'"

echo "== rotate"
expect_out "alice rotates STRIPE" "changed STRIPE" as alice $EYESONLY rotate .env STRIPE=sk_v2
check "the working .env has the new value" grep -qx 'STRIPE=sk_v2' .env
check "comments are kept" grep -qx '# payments' .env
check "untouched keys stay" grep -qx 'DB_PASS=pw1' .env
check "the staged .env is encrypted" bash -c "git cat-file blob :.env | head -1 | grep -q EYESONLY-V1"
expect_fail "rotate never prints the value" grep -q sk_v2 "$SB/out"
expect_out "rotate adds a missing key" "added NEW_KEY" as alice $EYESONLY rotate .env NEW_KEY=n1
expect_out "rotate replaces a multi-line value" "changed CERT" as alice $EYESONLY rotate .env CERT=short
expect_fail "...and drops its old continuation lines" grep -qx 'abc' .env
expect_out "--from-stdin takes values with spaces and #" "changed DB_PASS" bash -c "$(declare -f as); printf 'DB_PASS=a b #c\n' | as alice $EYESONLY rotate .env --from-stdin"
equal "the quoted value round-trips through eyesonly env" "a b #c" "$(as alice $EYESONLY env --format json 2>/dev/null | jsonget 'j.DB_PASS')"
expect_out "same value: nothing changed" "nothing changed" as alice $EYESONLY rotate .env STRIPE=sk_v2
expect_reject "a non-protected file is refused" "isn't a protected file" as alice $EYESONLY rotate app.js X=1
expect_reject "a bad pair is refused without echoing it" "expected KEY=value" as alice $EYESONLY rotate .env "not a pair secretvalue"
expect_fail "...and the refusal doesn't echo it" grep -q secretvalue "$SB/out"
in_ "$SB/bob" as bob $EYESONLY pull-policy >/dev/null 2>&1
expect_reject "bob (offboarded) can't rotate .env" "can't write '.env'" in_ "$SB/bob" as bob $EYESONLY rotate .env STRIPE=evil
on $T5 as alice git commit -qm "rotate" && expect_ok "alice pushes the rotation (verify passes)" as alice git push -q origin main

echo "== server mode"
declare -A TOK
for u in alice bob carol; do TOK[$u]=$($VS user add "$(card $u)" 2>/dev/null); done
$VS repo create app.git --admin alice >/dev/null 2>&1
printf '%s' '{ "members": ["*"], "admins": ["alice"], "groups": { "core": ["alice", "bob", "carol"] }, "files": { ".env": ["@core"] } }' > "$SB/policy.json"
$VS policy set app.git "$SB/policy.json" >/dev/null 2>&1
cd "$SB" && start_server PORT "$SB/server.log"; SRV=$LAST_SRV
surl() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/app.git"; }
mkdir -p "$SB/s-alice" && cd "$SB/s-alice"
git init -q -b main && git remote add origin "$(surl alice)"
as alice $EYESONLY setup >/dev/null 2>&1
printf 'TOKEN=srv1\n' > .env
on $T1 as alice git add .env && on $T1 as alice git commit -qm "server .env"
expect_ok "alice pushes to the server" as alice git push -q -u origin main
equal "server mode: audit --file shows alice, bob, carol" "alice,bob,carol" "$(as alice $EYESONLY audit --file .env --json | readers)"
expect_out "offboarding carol while the server still has her prints the server commands" "eyesonly-server user remove carol" as alice $EYESONLY offboard carol --yes --checklist "$SB/s-check.md"
check "...and writes the checklist" grep -q -- '- \[ \] TOKEN' "$SB/s-check.md"
expect_fail "...without the value" grep -q srv1 "$SB/s-check.md"
$VS user remove carol >/dev/null 2>&1
expect_ok "after the server removes carol, offboard re-encrypts" on $T2 as alice $EYESONLY offboard carol --yes --checklist "$SB/s-check.md"
check "the staged .env has no key for carol" bash -c "git cat-file blob :.env | grep -q '\"bob\"' && ! git cat-file blob :.env | grep -q '\"carol\"'"
on $T2 as alice git commit -qm "offboard carol"
expect_ok "alice pushes the re-encrypted .env" as alice git push -q origin main
equal "audit carol lists the one old version" "1" "$(as alice $EYESONLY audit carol --json | jsonget 'j.files[0].versions.length')"
equal "...which isn't current" "false" "$(as alice $EYESONLY audit carol --json | jsonget 'j.files[0].versions[0].current')"
equal "audit --file --at before the offboarding still shows carol" "alice,bob,carol" "$(as alice $EYESONLY audit --file .env --at 2026-01-15 --json | readers)"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
