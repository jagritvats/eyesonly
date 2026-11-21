#!/usr/bin/env bash
# Attribute pinning (.git/info/attributes), redirected filters (git-lfs) on client and
# server, .lfsconfig endpoint hijack, git worktree support, sparse checkouts.
# Team: alice (admin), bob = @core. junior = member, outside @core.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"
PORT="${PORT:-$((20000 + RANDOM % 20000))}"
export VEIL_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
VEIL="node $ROOT/bin/veil.mjs"
VS="node $ROOT/bin/veil-server.mjs"
BASE="http://127.0.0.1:$PORT"
PASS=0 FAIL=0

cleanup() { [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null; rm -rf "$SB"; }
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
expect_ok()   { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 15; fi; }
# expect_reject <desc> <pattern> <cmd...>: must fail AND print <pattern> (so it failed for the right reason)
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
# expect_out <desc> <pattern> <cmd...>: output (stdout+stderr) contains <pattern>, whatever the exit code
expect_out()  { local d="$1" pat="$2"; shift 2; "$@" >"$SB/out" 2>&1; if grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (no '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
# out_has / out_lacks <desc> <pattern>: about the output of the previous expect_*
out_has()     { if grep -q -- "$2" "$SB/out"; then ok "$1"; else bad "$1 (no '$2')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
out_lacks()   { if grep -q -- "$2" "$SB/out"; then bad "$1 (found '$2')"; sed 's/^/        /' "$SB/out" | tail -n 8; else ok "$1"; fi; }
check()       { local d="$1"; shift; if "$@" >"$SB/chk" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/chk" | tail -n 8; fi; }

as() { local u="$1"; shift; VEIL_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
url() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/app.git"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }
is_envelope() { [[ "$(git -C "$1" cat-file blob "$2" | head -c7)" == VEIL-V1 ]]; }
# push_commit <user> <dir> <msg>: commit everything staged (hooks bypassed, like an attacker would) and push
push_commit() { in_ "$2" as "$1" git commit -q --no-verify -m "$3" && in_ "$2" as "$1" git push -q origin HEAD:main; }
reset_main() { in_ "$2" as "$1" git fetch -q origin && in_ "$2" as "$1" git reset -q --hard origin/main; }

declare -A TOK
echo "== setup"
for u in alice bob junior; do
  card=$(as $u $VEIL keygen $u 2>/dev/null)
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
$VS policy manifest app.git > "$SB/m.json"
as alice $VEIL policy-sign "$SB/m.json" > "$SB/s.json" 2>/dev/null
$VS policy attest app.git "$SB/s.json" 2>/dev/null
$VS serve --port "$PORT" 2>"$SB/server.log" & SRV=$!
for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done

mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$(url alice)"
expect_out "alice sets up (TOFU pins herself as admin)" "pinned admin alice" as alice $VEIL setup
echo 'console.log("hello")' > index.js
echo 'STRIPE_SECRET=sk_live_123' > .env
mkdir -p secrets && echo 'db-password' > secrets/db.txt
as alice git add -A && as alice git commit -qm init
expect_ok "alice pushes main with secrets" as alice git push -q -u origin main

echo "== client: filter=veil is pinned in .git/info/attributes"
expect_ok "bob clones" as bob $VEIL clone "$(url bob)" "$SB/bob"
cd "$SB/bob"
check "info/attributes has the managed block" grep -qF '# >>> veil (managed) >>>' .git/info/attributes
check "...with '/.env filter=veil diff=veil merge=veil'" grep -qxF '/.env filter=veil diff=veil merge=veil' .git/info/attributes
check "...and '/secrets/** filter=veil diff=veil merge=veil'" grep -qxF '/secrets/** filter=veil diff=veil merge=veil' .git/info/attributes
echo '.env filter=lfs' >> .gitattributes
expect_out "with an in-tree '.env filter=lfs' override, .env still resolves to veil" ".env: filter: veil" git check-attr filter -- .env
git config filter.lfs.clean "cat > '$SB/leak'"   # stand-in for git-lfs: anything it sees, it 'uploads'
echo 'STRIPE_SECRET=sk_live_bob' > .env
expect_ok "add + commit with hooks bypassed (core.hooksPath, --no-verify)" \
  as bob bash -c 'git -c core.hooksPath=/dev/null add .env && git commit -q --no-verify -m rotate'
check "the index holds a VEIL-V1 envelope, not plaintext" is_envelope . :.env
check "the fake LFS filter never saw the plaintext" test ! -e "$SB/leak"
git config --unset filter.lfs.clean
reset_main bob "$SB/bob"

echo "== client: without the pin, pre-commit and status catch the override"
cp .git/info/attributes "$SB/attrs.saved"
: > .git/info/attributes
echo '.env filter=lfs' >> .gitattributes
expect_out "veil status warns about the redirected filter" "warning: '.env' resolves to filter=lfs; veil requires filter=veil" as bob $VEIL status
echo 'STRIPE_SECRET=sk_live_plain' > .env
as bob git add .env
expect_reject "git commit (hook active) refuses the redirected protected path" "resolves to filter=lfs" as bob git commit -qm leak
reset_main bob "$SB/bob"
printf '*.bin binary\r\n# mine\r\n' > .git/info/attributes
as bob $VEIL pull-policy 2>/dev/null
as bob $VEIL pull-policy 2>/dev/null
check "pull-policy restores the block" grep -qxF '/.env filter=veil diff=veil merge=veil' .git/info/attributes
[[ "$(grep -c '>>> veil (managed)' .git/info/attributes)" == 1 ]] && ok "running it twice leaves exactly one block" || bad "duplicate managed block"
check "the user's own CRLF lines survive byte for byte" grep -q $'^\\*\\.bin binary\r$' .git/info/attributes
echo '.env filter=lfs' >> .gitattributes
expect_out ".env resolves to veil again" ".env: filter: veil" git check-attr filter -- .env
as bob git checkout -q -- .gitattributes

echo "== server: .gitattributes redirects on protected paths"
expect_ok "junior clones" as junior $VEIL clone "$(url junior)" "$SB/junior"
cd "$SB/junior"
echo '.env filter=lfs' >> .gitattributes && as junior git add .gitattributes
expect_reject "push appending '.env filter=lfs' is rejected" "sets filter=lfs on protected path '.env'" push_commit junior . lfs
reset_main junior .
printf '* filter=lfs\n' > "$SB/nested"
OID=$(git hash-object -w --no-filters "$SB/nested")
git update-index --add --cacheinfo "100644,$OID,secrets/.gitattributes"
expect_reject "push adding nested secrets/.gitattributes '* filter=lfs' is rejected" "sets filter=lfs on protected path" push_commit junior . nested
reset_main junior .
git update-index --add --cacheinfo "100644,$OID,secrets/deep/.gitattributes"
expect_reject "nested override in a directory with no files yet is rejected" "sets filter=lfs on protected path 'secrets/deep/" push_commit junior . deep
reset_main junior .
echo '.env -filter' >> .gitattributes && as junior git add .gitattributes
expect_reject "push with '.env -filter' is rejected" "sets filter=unset on protected path '.env'" push_commit junior . unset
reset_main junior .
echo '.env !filter' >> .gitattributes && as junior git add .gitattributes
expect_reject "push with '.env !filter' is rejected" "on protected path '.env'" push_commit junior . unspec
reset_main junior .
printf '[attr]sneaky filter=lfs\n.env sneaky\n' >> .gitattributes && as junior git add .gitattributes
expect_reject "an attribute macro that expands to filter=lfs is rejected" "sets filter=lfs on protected path '.env'" push_commit junior . macro
reset_main junior .
printf '.env filter=lfs\n' > .GITATTRIBUTES && as junior git add .GITATTRIBUTES
expect_reject "a case variant .GITATTRIBUTES is rejected" "must be named exactly" push_commit junior . case
reset_main junior .
echo '*.png binary' >> .gitattributes && as junior git add .gitattributes
expect_ok "an unrelated .gitattributes change (*.png binary) is accepted" push_commit junior . png

echo "== server: .lfsconfig endpoints are admin-only"
reset_main junior .
printf '[lfs]\n\turl = https://attacker/\n' > .lfsconfig && as junior git add .lfsconfig
expect_reject "junior's .lfsconfig with lfs.url is rejected" "only admins may change .lfsconfig endpoints" push_commit junior . lfsurl
reset_main junior .
printf '[remote "origin"]\n\tlfsurl = https://attacker/\n' > .lfsconfig && as junior git add .lfsconfig
expect_reject "junior's .lfsconfig with remote.origin.lfsurl is rejected" "only admins may change .lfsconfig endpoints" push_commit junior . lfsurl2
reset_main junior .
reset_main alice "$SB/alice"
printf '[lfs]\n\turl = https://attacker/\n' > "$SB/alice/.lfsconfig" && in_ "$SB/alice" as alice git add .lfsconfig
expect_ok "alice (admin) pushing the same .lfsconfig is accepted" in_ "$SB/alice" as alice bash -c 'git commit -qm lfs && git push -q origin HEAD:main'
reset_main junior .
printf '[lfs]\n\tfetchexclude = big/\n' >> .lfsconfig && as junior git add .lfsconfig
expect_ok "junior may change other .lfsconfig keys when the endpoint is unchanged" push_commit junior . fetchexclude
reset_main junior .
sed -i 's#attacker#evil#' .lfsconfig && as junior git add .lfsconfig
expect_reject "junior may not edit the admin's endpoint" "only admins may change .lfsconfig endpoints" push_commit junior . swap
reset_main junior .

echo "== worktrees"
cd "$SB/alice"
reset_main alice .
expect_ok "git worktree add in alice's clone" as alice git worktree add -q ../wt -b wt-branch
out_lacks "...without 'no veil policy cached'" "no veil policy cached"
expect_out ".env is decrypted in the worktree" "sk_live_123" cat "$SB/wt/.env"
echo 'STRIPE_SECRET=sk_live_wt' > "$SB/wt/.env"
expect_ok "editing .env and committing inside the worktree works" in_ "$SB/wt" as alice git commit -qam "rotate in wt"
out_lacks "...without 'no veil policy cached'" "no veil policy cached"
check "the committed .env is a VEIL-V1 envelope" is_envelope "$SB/wt" HEAD:.env
expect_ok "the server accepts the worktree commit" in_ "$SB/wt" as alice git push -q origin wt-branch
expect_ok "veil pull-policy inside the worktree" in_ "$SB/wt" as alice $VEIL pull-policy
out_lacks "...reuses the common trust.json (no new TOFU pin)" "pinned admin"
check "...and creates no worktree-local veil state" test ! -e "$SB/alice/.git/worktrees/wt/veil"
mkdir -p "$SB/alice/.git/worktrees/wt/veil"
echo '{"v":1,"signed":true,"admins":{"mallory":"00"},"version":9}' > "$SB/alice/.git/worktrees/wt/veil/trust.json"
expect_reject "a conflicting worktree trust.json makes veil die" "conflicting veil trust" in_ "$SB/wt" as alice $VEIL status
expect_reject "...also in pull-policy (never overrides the main repo's pin)" "conflicting veil trust" in_ "$SB/wt" as alice $VEIL pull-policy
rm -rf "$SB/alice/.git/worktrees/wt/veil"
# a worktree created by an older veil kept its state in .git/worktrees/<n>/veil
git clone -q "$(url alice)" "$SB/plain"
expect_out "smudge without a policy explains what to do (and passes the envelope through)" "no policy for this checkout. Run \`veil setup\`" \
  in_ "$SB/plain" bash -c "git cat-file blob HEAD:.env | VEIL_HOME=$SB/home/alice $VEIL smudge .env"
out_has "...and emits the envelope unchanged" "VEIL-V1"
in_ "$SB/plain" git worktree add -q ../wt3 -b wt3 2>/dev/null
cp -r "$SB/alice/.git/veil" "$SB/plain/.git/worktrees/wt3/veil"
expect_out "the first veil command migrates worktree-local state" "moved this worktree's veil state" in_ "$SB/wt3" as alice $VEIL status
check "...into the common git dir" test -f "$SB/plain/.git/veil/policy.json"
check "...and removes the worktree copy" test ! -e "$SB/plain/.git/worktrees/wt3/veil"

echo "== sparse checkout"
expect_ok "alice clones again" as alice $VEIL clone "$(url alice)" "$SB/sparse"
cd "$SB/sparse"
as alice git sparse-checkout set --no-cone /index.js
check "precondition: sparse-checkout removed secrets/ and .env" test ! -e secrets/db.txt -a ! -e .env
expect_ok "veil setup in the sparse checkout" as alice $VEIL setup
check "veil setup does not materialize excluded secrets/" test ! -e secrets
check "...nor the excluded .env" test ! -e .env
expect_out "veil status works in the sparse checkout" "repo app.git" as alice $VEIL status

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
