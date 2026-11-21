#!/usr/bin/env bash
# Private branches without a server (repo / GitHub mode): sealed under refs/eyesonly/b/<id>.
# The "host" is a plain bare repo. Team: alice (admin) and bob (@core), junior (member,
# not in @core: can't read or write private/*).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROOT_URL="$(node -e 'console.log(require("node:url").pathToFileURL(process.argv[1]).href)' "$ROOT")"
source "$ROOT/test/lib/compat.sh"
SB="$(mktemp -d)"; export SB
export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EYESONLY="node $ROOT/bin/eyesonly.mjs"
PASS=0 FAIL=0

cleanup() { cd "$ROOT"; rm -rf "$SB"; }
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
card() { as "$1" $EYESONLY whoami 2>/dev/null | tail -1; }
js() { local s="$1"; shift; node --input-type=module -e "$s" "$ROOT_URL" "$@"; }
HOST="$SB/host.git"
A="$SB/alice"; B="$SB/bob"; J="$SB/junior"
sealed_refs() { git --git-dir="$HOST" for-each-ref --format='%(refname)' refs/eyesonly/b/; }
sealed_ref() { sealed_refs | head -1; }

echo "== setup"
for u in alice bob junior; do as $u $EYESONLY keygen $u >/dev/null 2>&1; done
git init -q --bare -b main "$HOST"
mkdir -p "$A" && cd "$A"
git init -q -b main && git remote add origin "$HOST"
echo 'console.log("hi")' > app.js
as alice git add app.js && as alice git commit -qm base
expect_ok "alice runs eyesonly init --commit" as alice $EYESONLY init --commit
check "init adds a private/ branch rule" grep -q 'refs/heads/private/' .eyesonly/policy.json
as alice $EYESONLY grant bob --card "$(card bob)" --group core >/dev/null 2>&1
expect_out "junior is granted as a plain member" "granted junior" as alice $EYESONLY grant junior --card "$(card junior)" --group contractors
expect_out "policy show lists the private branch rule" "refs/heads/private/\*" as alice $EYESONLY policy show
as alice git add .eyesonly .gitattributes && as alice git commit -qm "eyesonly: team" >/dev/null
expect_ok "alice pushes main" as alice git push -q -u origin main
as alice $EYESONLY pull-policy >/dev/null 2>&1
expect_ok "bob clones" as bob $EYESONLY clone "$HOST" "$B"
expect_ok "junior clones" as junior $EYESONLY clone "$HOST" "$J"

echo "== alice seals private/launch"
as alice git checkout -q -b private/launch
echo 'codename falcon' > launch.txt
as alice git add launch.txt && as alice git commit -qm "secret launch work" >/dev/null
L1=$(git rev-parse HEAD)
expect_out "eyesonly branch push seals it (v1)" "sealed private/launch v1" as alice $EYESONLY branch push
REF=$(sealed_ref); ID=${REF#refs/eyesonly/b/}
[[ "$ID" =~ ^[0-9a-f]{32}$ ]] && ok "the host has one opaque ref refs/eyesonly/b/<32 hex>" || bad "unexpected sealed ref '$REF'"
V1=$(git --git-dir="$HOST" rev-parse "$REF")
check "the host has no private/* branch" test -z "$(git --git-dir="$HOST" for-each-ref refs/heads/private/)"
expect_fail "ls-remote never names the branch" bash -c "git ls-remote '$HOST' | grep -q launch"
check "the sealed commit has no parent" test "$(git --git-dir="$HOST" rev-list --parents -n1 "$REF" | wc -w | tr -d ' ')" = 1
check "the sealed commit's author doesn't name alice" test "$(git --git-dir="$HOST" log -1 --format='%an <%ae> %at' "$REF")" = "eyesonly <eyesonly@localhost> 946684800"
expect_fail "the envelope's outer signer isn't alice" bash -c "git --git-dir='$HOST' cat-file blob '$REF:sealed' | grep -q '\"signer\": \"alice\"'"
expect_ok "the sealed blob is an encrypted envelope bound to its ref" bash -c "git --git-dir='$HOST' cat-file blob '$REF:sealed' | grep -q '\"path\": \"$REF\"'"
expect_out "branch list shows it to alice" "private/launch  v1 by alice" as alice $EYESONLY branch list
expect_out "status mentions the sealed branch" "private/launch: sealed v1, in sync" as alice $EYESONLY status

echo "== what junior (and the host) can see"
in_ "$J" git fetch -q origin '+refs/eyesonly/*:refs/eyesonly/*'
leaks() { git -C "$1" cat-file --batch-all-objects --batch 2>/dev/null | grep -a -c -e 'codename falcon' -e 'secret launch work' -e 'private/launch' || true; }
check "junior's object store has no branch name, message or content" test "$(leaks "$J")" = 0
check "the host's object store has none either" test "$(leaks "$HOST")" = 0
expect_out "junior's branch list counts one branch he can't read" "1 sealed branch(es) not encrypted for you" in_ "$J" as junior $EYESONLY branch list
expect_reject "junior can't pull it" "no sealed 'private/launch' you can read" in_ "$J" as junior $EYESONLY branch pull private/launch
in_ "$J" as junior git checkout -q -b private/junior
expect_reject "junior can't seal under private/ (not in the audience)" "may not write private/" in_ "$J" as junior $EYESONLY branch push

echo "== bob pulls"
expect_out "bob pulls private/launch" "private/launch: v1 by alice, created" in_ "$B" as bob $EYESONLY branch pull
check "bob gets byte-identical commit ids" test "$(git -C "$B" rev-parse private/launch)" = "$L1"
in_ "$B" as bob git checkout -q private/launch
check "bob reads the content" grep -qx 'codename falcon' "$B/launch.txt"

echo "== incremental versions"
echo 'launch date: friday' >> launch.txt
as alice git commit -qam "pick a date" >/dev/null
expect_out "alice seals v2" "sealed private/launch v2" as alice $EYESONLY branch push
check "same ref id for v2" test "$(sealed_refs | wc -l | tr -d ' ')" = 1
V2=$(git --git-dir="$HOST" rev-parse "$REF")
expect_out "bob fast-forwards to v2 (checked-out branch)" "v2 by alice, fast-forwarded" in_ "$B" as bob $EYESONLY branch pull private/launch
check "bob's working tree follows" grep -q friday "$B/launch.txt"
check "bob's tip matches alice's" test "$(git -C "$B" rev-parse HEAD)" = "$(git rev-parse HEAD)"
echo 'bob was here' > "$B/bob.txt"
in_ "$B" as bob git add bob.txt && in_ "$B" as bob git commit -qm "bob's part" >/dev/null
expect_out "bob (in @core) seals v3" "sealed private/launch v3" in_ "$B" as bob $EYESONLY branch push
expect_out "alice pulls bob's v3" "v3 by bob, fast-forwarded" as alice $EYESONLY branch pull
in_ "$B" as bob git gc -q --prune=now 2>/dev/null
expect_out "bob's pull still works after git gc" "up to date" in_ "$B" as bob $EYESONLY branch pull
echo 'conflicting' > "$B/bob2.txt"; in_ "$B" as bob git add bob2.txt; in_ "$B" as bob git commit -qm "bob again" >/dev/null
in_ "$B" as bob $EYESONLY branch push >/dev/null 2>&1
echo 'alice diverges' > other.txt; as alice git add other.txt; as alice git commit -qm "alice diverges" >/dev/null
expect_reject "pushing over someone else's newer version is refused" "eyesonly branch pull first" as alice $EYESONLY branch push
expect_out "a diverged pull lands in <name>-incoming" "private/launch-incoming" as alice $EYESONLY branch pull
as alice git merge -q --no-edit private/launch-incoming >/dev/null 2>&1 && as alice git branch -q -D private/launch-incoming
expect_out "after merging, alice seals v5" "sealed private/launch v5" as alice $EYESONLY branch push
in_ "$B" as bob $EYESONLY branch pull >/dev/null 2>&1
VGOOD=$(git --git-dir="$HOST" rev-parse "$REF")

echo "== attacks on the sealed ref"
# junior (no read or write access) forges a newer version signed by himself
FORGED=$(in_ "$J" as junior js '
const [root, home, id, tip] = process.argv.slice(1);
const b = await import(root + "/src/branches.mjs");
const fs = await import("node:fs");
const me = JSON.parse(fs.readFileSync(home + "/identity.json"));
const pol = JSON.parse(fs.readFileSync(".git/eyesonly/policy.json"));
const r = { alice: pol.keys.alice.x25519, bob: pol.keys.bob.x25519 };
const blob = b.buildSealed({ id, name: "private/launch", counter: 99, prev: null, base: null, tip, bundle: null, recipients: r, signer: me });
console.log(b.writeSealedCommit(process.cwd(), blob));
' "$SB/home/junior" "$ID" "$(git -C "$J" rev-parse origin/main)")
in_ "$J" git push -q --no-verify -f origin "$FORGED:$REF" 2>/dev/null
BTIP=$(git -C "$B" rev-parse private/launch)
expect_reject "bob refuses a version signed by a non-writer" "signed by 'junior', who may not write private/" in_ "$B" as bob $EYESONLY branch pull
check "bob's branch didn't move" test "$(git -C "$B" rev-parse private/launch)" = "$BTIP"
expect_out "alice (a writer) replaces the forged version" "replacing it" as alice $EYESONLY branch push --force
expect_out "bob accepts alice's replacement" "by alice" in_ "$B" as bob $EYESONLY branch pull
# rollback: an old, validly signed version comes back
as alice git push -q --no-verify -f origin "$V1:$REF" 2>/dev/null
expect_reject "bob refuses a rolled-back version" "rolled back" in_ "$B" as bob $EYESONLY branch pull
expect_out "alice re-seals over the rollback" "sealed private/launch v" as alice $EYESONLY branch push --force
expect_ok "bob accepts it again" in_ "$B" as bob $EYESONLY branch pull
# move: a valid sealed commit copied to another id
OTHER="refs/eyesonly/b/0123456789abcdef0123456789abcdef"
as alice git push -q --no-verify origin "$V2:$OTHER" 2>/dev/null
expect_reject "a sealed version moved to another id is refused" "moved from another ref" in_ "$B" as bob $EYESONLY branch pull
git --git-dir="$HOST" update-ref -d "$OTHER"
in_ "$B" git update-ref -d "refs/eyesonly/remotes/origin/b/0123456789abcdef0123456789abcdef" 2>/dev/null
expect_ok "with the moved copy gone, bob's pull is clean again" in_ "$B" as bob $EYESONLY branch pull

echo "== guards: private history never reaches the host as plain git"
expect_reject "git push of a private branch is blocked by pre-push" "is a private branch" as alice git push origin private/launch
check "the host still has no private/* branch" test -z "$(git --git-dir="$HOST" for-each-ref refs/heads/private/)"
as alice git checkout -q main
as alice git merge -q --no-edit private/launch >/dev/null 2>&1
expect_reject "pushing main with private history merged in is blocked" "would expose commit" as alice git push origin main
as alice git reset -q --hard origin/main
in_ "$B" as bob git checkout -q main
in_ "$B" as bob git merge -q --no-edit private/launch >/dev/null 2>&1
expect_reject "bob's pulled branch merged into main is blocked too" "would expose commit" in_ "$B" as bob git push origin main
in_ "$B" as bob git reset -q --hard origin/main
in_ "$B" as bob git checkout -q private/launch
expect_reject "a non-sealed commit can't be pushed under refs/eyesonly/b/" "sealed branches are single parentless commits" as alice git push origin "HEAD:refs/eyesonly/b/fedcba9876543210fedcba9876543210"
expect_reject "nothing else under refs/eyesonly/ either" "only sealed branches" as alice git push origin "HEAD:refs/eyesonly/other"
# a commit made on main before branching stays public
echo 'public change' > public.txt && as alice git add public.txt && as alice git commit -qm "public change" >/dev/null
as alice git checkout -q -b private/x
echo 'x' > x.txt && as alice git add x.txt && as alice git commit -qm "x work" >/dev/null
as alice git checkout -q main
expect_ok "main's own unpushed commit isn't treated as private" as alice git push -q origin main

echo "== publish: squash into main"
expect_out "eyesonly branch publish squashes private/launch into main" "squashed private/launch into main" as alice $EYESONLY branch publish private/launch
check "launch.txt is on main now" test -f launch.txt
expect_ok "pushing the squashed main is allowed" as alice git push -q origin main
expect_fail "no private commit is reachable from the host's main" git merge-base --is-ancestor "$L1" origin/main
expect_fail "private commit messages didn't leak into main" bash -c "git log origin/main --format=%B | grep -q 'secret launch work'"

echo "== verify in CI (no keys)"
expect_out "verify --sealed checks the sealed refs' shape" "checked 1 sealed branch ref" as alice $EYESONLY verify --sealed origin
expect_reject "verify --ref flags a private branch pushed in plaintext" "pushed to the host in plaintext" as alice $EYESONLY verify --ref refs/heads/private/launch
in_ "$J" git push -q --no-verify origin "HEAD:refs/eyesonly/b/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" 2>/dev/null
expect_reject "verify --sealed rejects a plain commit under refs/eyesonly/b/" "parentless" as alice $EYESONLY verify --sealed origin
git --git-dir="$HOST" update-ref -d refs/eyesonly/b/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

echo "== revoke"
as alice $EYESONLY revoke bob --group core >/dev/null 2>&1
as alice git add .eyesonly && as alice git commit -qm "eyesonly: revoke bob" >/dev/null && as alice git push -q origin main
as alice $EYESONLY pull-policy >/dev/null 2>&1
as alice git checkout -q private/launch
echo 'after bob left' > after.txt && as alice git add after.txt && as alice git commit -qm "after revoke" >/dev/null
expect_out "alice's next seal leaves bob out" "for alice ->" as alice $EYESONLY branch push --force
in_ "$B" as bob git checkout -q main && in_ "$B" as bob git pull -q 2>/dev/null
in_ "$B" as bob $EYESONLY pull-policy >/dev/null 2>&1
expect_reject "bob can't read the new version" "no sealed 'private/launch' you can read" in_ "$B" as bob $EYESONLY branch pull private/launch
expect_reject "bob can't seal private/ anymore" "may not write private/" in_ "$B" as bob $EYESONLY branch push private/launch

echo "== delete"
expect_out "alice deletes the sealed branch" "deleted the sealed private/launch" as alice $EYESONLY branch delete private/launch
check "the host has no sealed refs left" test -z "$(sealed_refs)"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
