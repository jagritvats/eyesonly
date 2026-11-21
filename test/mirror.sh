#!/usr/bin/env bash
# Outbound mirror suite. A local bare repo ($SB/upstream.git) stands in for GitHub; no network.
# Every leak attempt must fail closed with the specific message and leave the upstream unchanged.
# Team: alice (admin), bob, carol = @core. junior = member, outside @core.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/test/lib/compat.sh"
SB="$(mktemp -d)"
PORT="${PORT:-$((20000 + RANDOM % 20000))}"
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
BASE="http://127.0.0.1:$PORT"
R="$EYESONLY_DATA/repos/app.git"
UP="$SB/upstream.git"
STAGE="$R/eyesonly-mirror-stage.git"
PASS=0 FAIL=0

cleanup() { [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null; rm -rf "$SB"; }
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
expect_ok()   { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 15; fi; }
expect_fail() { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; sed 's/^/        /' "$SB/out" | tail -n 8; else ok "$d"; fi; }
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; sed 's/^/        /' "$SB/out" | tail -n 8; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
expect_out()  { local d="$1" pat="$2"; shift 2; if "$@" 2>&1 | grep -q -- "$pat"; then ok "$d"; else bad "$d (no '$pat')"; "$@" 2>&1 | sed 's/^/        /' | tail -n 8; fi; }
out_has()     { if grep -q -- "$2" "$SB/out"; then ok "$1"; else bad "$1 (no '$2')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }

as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
url() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/app.git"; }
up_oid() { git -C "$UP" rev-parse -q --verify "$1" 2>/dev/null || echo none; }
mirror() { $VS mirror "$@"; }

# inject <file>: plumbing commit on the bare repo's main that sets .env to <file> (hook bypassed)
inject() {
  local blob tree c idx="$SB/idx"
  blob=$(git -C "$R" hash-object -w "$1")
  rm -f "$idx"
  GIT_INDEX_FILE="$idx" git -C "$R" read-tree main
  GIT_INDEX_FILE="$idx" git -C "$R" update-index --add --cacheinfo "100644,$blob,.env"
  tree=$(GIT_INDEX_FILE="$idx" git -C "$R" write-tree)
  c=$(echo injected | as alice git -C "$R" commit-tree "$tree" -p main)
  git -C "$R" update-ref refs/heads/main "$c"
  INJECTED_BLOB=$blob
}

declare -A TOK
echo "== setup"
for u in alice bob carol junior; do
  card=$(as $u $EYESONLY keygen $u 2>/dev/null)
  TOK[$u]=$($VS user add "$card" 2>/dev/null)
done
$VS repo create app.git --admin alice 2>/dev/null
cat > "$SB/policy.json" <<'EOF'
{ "members": ["*"], "admins": ["alice"],
  "groups": { "core": ["alice", "bob", "carol"] },
  "files": { ".env": ["@core"], "secrets/**": ["@core"] },
  "branches": { "refs/heads/private/": ["@core"] } }
EOF
sed 's#"refs/heads/private/": \["@core"\]#"refs/heads/private/": ["@core"], "refs/heads/release": ["@core"]#' "$SB/policy.json" > "$SB/policy-release-private.json"
$VS policy set app.git "$SB/policy.json" 2>/dev/null
source "$ROOT/test/lib/server.sh"
start_server PORT "$SB/server.log"; SRV=$LAST_SRV; BASE="http://127.0.0.1:$PORT"

mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$(url alice)"
as alice $EYESONLY setup 2>/dev/null
echo 'console.log("hello")' > index.js
echo 'STRIPE_SECRET=sk_live_123' > .env
as alice git add -A && as alice git commit -qm init
expect_ok "alice pushes main through the proxy" as alice git push -q -u origin main
as alice git checkout -q -b release
echo 'v1' > VERSION && as alice git add VERSION && as alice git commit -qm release
expect_ok "alice pushes release" as alice git push -q -u origin release
as alice git checkout -q main
as alice git checkout -q -b private/launch
echo 'Launch: March 3, codename NIGHTJAR' > LAUNCH.md && as alice git add LAUNCH.md && as alice git commit -qm "launch plan"
expect_ok "alice pushes private/launch" as alice git push -q -u origin private/launch
SECRET=$(git rev-parse HEAD)
SECRET_BLOB=$(git rev-parse HEAD:LAUNCH.md)
as alice git checkout -q main
git init -q --bare "$UP"

echo "== happy path"
expect_ok "mirror set (local upstream, main only)" mirror set app.git --url "$UP" --allow-local --push refs/heads/main
expect_ok "mirror push" mirror push app.git
[[ "$(up_oid refs/heads/main)" == "$(git -C "$R" rev-parse main)" ]] && ok "upstream main has Eyes Only's main oid" || bad "upstream main oid differs"
check_mode "eyesonly-mirror.json is mode 600" 600 "$R/eyesonly-mirror.json"
check_mode "eyesonly-mirror.log is mode 600" 600 "$R/eyesonly-mirror.log"
expect_out "a second push is a no-op" "up to date" mirror push app.git
as alice git tag -a v1.0 -m "v1.0" main && as alice git push -q origin v1.0 2>/dev/null
mirror set app.git --url "$UP" --allow-local --push refs/heads/main 'refs/tags/v*' 2>/dev/null
expect_ok "annotated tag matched by refs/tags/v* is mirrored" mirror push app.git
[[ "$(up_oid refs/tags/v1.0)" == "$(git -C "$R" rev-parse refs/tags/v1.0)" ]] && ok "upstream tag has the same oid" || bad "upstream tag missing"
mirror set app.git --url "$UP" --allow-local --push refs/heads/main 2>/dev/null

echo "== private refs and objects never reach the upstream"
[[ -z "$(git -C "$UP" for-each-ref refs/heads/private/)" ]] && ok "upstream has no refs/heads/private/*" || bad "upstream has private refs"
expect_fail "upstream lacks the private/launch commit object" git -C "$UP" cat-file -e "$SECRET"
expect_fail "upstream lacks the blob only reachable from private/launch" git -C "$UP" cat-file -e "$SECRET_BLOB"
expect_fail "the staging repo lacks the private commit too" git -C "$STAGE" cat-file -e "$SECRET"
expect_ok "mirror set allowlisting private/launch explicitly" mirror set app.git --url "$UP" --allow-local --push refs/heads/main refs/heads/private/launch
expect_reject "explicitly allowlisted private/launch is skipped" "skipping refs/heads/private/launch: not public" mirror push app.git
[[ "$(up_oid refs/heads/private/launch)" == none ]] && ok "upstream still lacks private/launch" || bad "private/launch was pushed"
expect_fail "upstream still lacks the private commit object" git -C "$UP" cat-file -e "$SECRET"
mirror set app.git --url "$UP" --allow-local --push refs/heads/main 2>/dev/null

echo "== content injected behind the hook"
MAIN0=$(git -C "$R" rev-parse main); UP0=$(up_oid refs/heads/main)
echo 'STRIPE_SECRET=sk_live_PLAINTEXT' > "$SB/plain.env"
inject "$SB/plain.env"
expect_reject "plaintext .env committed with plumbing is refused" "is NOT a valid eyesonly envelope (not encrypted" mirror push app.git
[[ "$(up_oid refs/heads/main)" == "$UP0" ]] && ok "upstream main unchanged after plaintext refusal" || bad "upstream main moved"
expect_fail "upstream lacks the plaintext blob" git -C "$UP" cat-file -e "$INJECTED_BLOB"
expect_fail "staging repo pruned the plaintext blob after the refusal" git -C "$STAGE" cat-file -e "$INJECTED_BLOB"
git -C "$R" update-ref refs/heads/main "$MAIN0"

node --input-type=module -e '
const vc = await import((await import("node:url")).pathToFileURL(process.argv[1]).href + "/src/crypto.mjs");
const fs = await import("node:fs");
const id = JSON.parse(fs.readFileSync(process.argv[2] + "/identity.json"));
fs.writeFileSync(process.argv[3], vc.seal({ plaintext: Buffer.from("API_URL=https://evil\n"), path: ".env", recipients: { junior: id.x25519.pub }, signer: id }));
' "$ROOT" "$SB/home/junior" "$SB/forged.env"
inject "$SB/forged.env"
expect_reject "forged envelope signed by junior is refused" "is NOT a valid eyesonly envelope (signer 'junior' may not write" mirror push app.git
[[ "$(up_oid refs/heads/main)" == "$UP0" ]] && ok "upstream main unchanged after forgery refusal" || bad "upstream main moved"
git -C "$R" update-ref refs/heads/main "$MAIN0"

git -C "$R" update-ref refs/heads/main "$SECRET"   # private/launch fast-forwarded into main, hook bypassed
expect_reject "private commit fast-forwarded into main is refused" "reachable only from a narrower-audience ref" mirror push app.git
[[ "$(up_oid refs/heads/main)" == "$UP0" ]] && ok "upstream main unchanged after narrower-audience refusal" || bad "upstream main moved"
expect_fail "upstream still lacks the private commit" git -C "$UP" cat-file -e "$SECRET"
git -C "$R" update-ref refs/heads/main "$MAIN0"
expect_out "after the reset the mirror is clean again" "up to date" mirror push app.git

echo "== policy change makes a mirrored branch private"
mirror set app.git --url "$UP" --allow-local --push refs/heads/main refs/heads/release 2>/dev/null
expect_ok "release is mirrored while public" mirror push app.git
REL=$(git -C "$R" rev-parse release)
[[ "$(up_oid refs/heads/release)" == "$REL" ]] && ok "upstream has release" || bad "upstream lacks release"
$VS policy set app.git "$SB/policy-release-private.json" 2>/dev/null
expect_reject "now-private release is skipped" "skipping refs/heads/release: not public" mirror push app.git
out_has "admin is told the old upstream copy is disclosed" "refs/heads/release was public upstream since .*treat its content as disclosed"
[[ "$(up_oid refs/heads/release)" == "$REL" ]] && ok "deleteUpstream=never leaves the upstream ref alone" || bad "release deleted without on-private"
expect_fail "release is gone from the staging repo" git -C "$STAGE" rev-parse -q --verify refs/upstream/heads/release
$VS policy set app.git "$SB/policy.json" 2>/dev/null
expect_ok "release public again: mirrored again" mirror push app.git
expect_ok "mirror set --delete-upstream on-private" mirror set app.git --url "$UP" --allow-local --push refs/heads/main refs/heads/release --delete-upstream on-private
$VS policy set app.git "$SB/policy-release-private.json" 2>/dev/null
expect_reject "release private again: skipped" "treat its content as disclosed" mirror push app.git
out_has "upstream deletion is reported" "deleted refs/heads/release upstream"
[[ "$(up_oid refs/heads/release)" == none ]] && ok "on-private deleted the upstream release ref" || bad "upstream release still there"
[[ "$(up_oid refs/heads/main)" == "$UP0" ]] && ok "main untouched by the deletion" || bad "main moved"
$VS policy set app.git "$SB/policy.json" 2>/dev/null
mirror set app.git --url "$UP" --allow-local --push refs/heads/main 2>/dev/null

echo "== config validation"
expect_reject "ext:: url is refused" "transport not allowed: ext" mirror set app.git --url "ext::sh -c touch% $SB/pwned" --push refs/heads/main
[[ ! -e "$SB/pwned" ]] && ok "ext:: command never ran" || bad "ext:: command executed"
expect_reject "fd:: url is refused" "transport not allowed: fd" mirror set app.git --url "fd::3" --push refs/heads/main
expect_reject "file:// url without --allow-local is refused" "only allowed with --allow-local" mirror set app.git --url "file://$UP" --push refs/heads/main
expect_reject "path url without --allow-local is refused" "only allowed with --allow-local" mirror set app.git --url "$UP" --push refs/heads/main
expect_reject "a Windows drive path is a local url, not host:path" "only allowed with --allow-local" mirror set app.git --url "C:/repos/up.git" --push refs/heads/main
expect_reject "a backslash path is a local url" "only allowed with --allow-local" mirror set app.git --url 'C:\repos\up.git' --push refs/heads/main
expect_reject "http:// url is refused" "must use https" mirror set app.git --url "http://example.com/a.git" --push refs/heads/main
expect_reject "credentials in the url are refused" "must not embed credentials" mirror set app.git --url "https://x:tok@example.com/a.git" --push refs/heads/main
expect_reject "--push 'refs/*' is too broad" "push allowlist too broad" mirror set app.git --url "$UP" --allow-local --push 'refs/*'
expect_reject "--push '*' is too broad" "push allowlist too broad" mirror set app.git --url "$UP" --allow-local --push '*'
expect_reject "a push list is mandatory" "push allowlist is required" mirror set app.git --url "$UP" --allow-local
expect_reject "'*' only as a trailing glob" "only allowed as a trailing glob" mirror set app.git --url "$UP" --allow-local --push 'refs/heads/*/x'
expect_ok "https, ssh and scp-like urls are accepted" bash -c "$VS mirror set app.git --url https://github.com/o/r.git --push refs/heads/main && $VS mirror set app.git --url ssh://git@gitlab.com/o/r.git --push refs/heads/main && $VS mirror set app.git --url git@github.com:o/r.git --push refs/heads/main refs/tags/v*"
mirror set app.git --url "$UP" --allow-local --push refs/heads/main 2>/dev/null
node -e 'const f=process.argv[1],c=JSON.parse(require("fs").readFileSync(f));c.url="ext::sh -c touch% "+process.argv[2];require("fs").writeFileSync(f,JSON.stringify(c))' "$R/eyesonly-mirror.json" "$SB/pwned2"
expect_reject "hand-edited ext:: config is refused at push time" "transport not allowed: ext" mirror push app.git
[[ ! -e "$SB/pwned2" ]] && ok "hand-edited ext:: command never ran" || bad "ext:: executed at push"
mirror set app.git --url "$UP" --allow-local --push refs/heads/main 2>/dev/null
expect_out "after resetting the url the stage starts over and catches up" "mirrored refs/heads/main" mirror push app.git

echo "== upstream divergence"
git clone -q -b main "$UP" "$SB/upclone" 2>/dev/null
(cd "$SB/upclone" && echo hotfix > HOTFIX && git add HOTFIX && as bob git commit -qm "commit made on the upstream" && git push -q origin main) 2>/dev/null
UPDIV=$(up_oid refs/heads/main)
cd "$SB/alice" && echo 'console.log("v2")' > index.js && as alice git commit -qam v2 && as alice git push -q
expect_reject "diverged upstream: no force" "(non-fast-forward); not retrying with force" mirror push app.git
[[ "$(up_oid refs/heads/main)" == "$UPDIV" ]] && ok "upstream keeps its own commit" || bad "upstream commit overwritten"
mirror set app.git --url "$UP" --allow-local --push refs/heads/main --allow-force 2>/dev/null
expect_reject "even --allow-force won't clobber an upstream change made since the last mirror" "lease failed" mirror push app.git
[[ "$(up_oid refs/heads/main)" == "$UPDIV" ]] && ok "upstream still keeps its own commit" || bad "upstream commit overwritten by force"

echo "== credential handling"
printf 'secret-token-xyz\n' > "$SB/cred" && chmod 600 "$SB/cred"
cp "$SB/cred" "$SB/cred644" && chmod 644 "$SB/cred644"
if [[ -n "$IS_WINDOWS" ]]; then ok "credential file with mode 0644 is refused (skipped: no POSIX modes on Windows)"
else expect_reject "credential file with mode 0644 is refused" "must have mode 0600" mirror set app.git --url "$SB/nope.git" --allow-local --push refs/heads/main --credential-file "$SB/cred644"; fi
cp "$SB/cred" "$R/cred" && chmod 600 "$R/cred"
expect_reject "credential file inside the repo dir is refused" "outside the repo directory" mirror set app.git --url "$SB/nope.git" --allow-local --push refs/heads/main --credential-file "$R/cred"
rm -f "$R/cred"
expect_ok "mirror set with a 0600 credential file" mirror set app.git --url "$SB/nope.git" --allow-local --push refs/heads/main --credential-file "$SB/cred"
REALGIT=$(command -v git)
mkdir -p "$SB/shim"
printf '#!/bin/sh\necho "$@" >> "%s"\nexec "%s" "$@"\n' "$SB/argv.log" "$REALGIT" > "$SB/shim/git" && chmod +x "$SB/shim/git"
if [[ -n "$IS_WINDOWS" ]]; then
  # Node can't spawn an extensionless shell script as `git` on Windows, so the argv shim is POSIX-only.
  expect_reject "push to a failing upstream fails" "upstream push failed" $VS mirror push app.git
  ok "the git shim saw the push argv (skipped on Windows)"; ok "token never appears in git argv (skipped on Windows)"
else
  expect_reject "push to a failing upstream fails" "upstream push failed" env PATH="$SB/shim:$PATH" $VS mirror push app.git
  grep -q -- "push" "$SB/argv.log" && ok "the git shim saw the push argv" || bad "shim saw no push"
  [[ -f "$SB/argv.log" ]] && ! grep -q secret-token-xyz "$SB/argv.log" && ok "token never appears in git argv" || bad "token in argv (or no argv log)"
fi
! grep -q secret-token-xyz "$SB/out" && ok "token never appears in command output" || bad "token in output"
! grep -q secret-token-xyz "$R/eyesonly-mirror.json" && ok "token not stored in eyesonly-mirror.json" || bad "token in config"
expect_out "mirror show prints the credential path" "$(native_path "$SB/cred")" mirror show app.git
expect_fail "mirror show never prints the credential contents" bash -c "$VS mirror show app.git 2>&1 | grep -q secret-token-xyz"

echo "== mirror state is never served over HTTP"
for p in eyesonly-mirror.json eyesonly-mirror.log "eyesonly-mirror-stage.git/info/refs?service=git-upload-pack" "eyesonly-mirror-stage.git/HEAD"; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -u "junior:${TOK[junior]}" "$BASE/app.git/$p")
  [[ "$CODE" == 404 ]] && ok "GET /app.git/$p as junior is 404" || bad "/app.git/$p served ($CODE)"
done
CODE=$(curl -s -o /dev/null -w '%{http_code}' -u "alice:${TOK[alice]}" "$BASE/app.git/eyesonly-mirror.json")
[[ "$CODE" == 404 ]] && ok "GET /app.git/eyesonly-mirror.json as admin is 404" || bad "mirror config served to admin ($CODE)"
expect_fail "policy endpoint doesn't contain mirror config" bash -c "curl -s -u junior:${TOK[junior]} $BASE/app.git/eyesonly/policy | grep -qE 'nope.git|upstream|cred|mirror'"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
