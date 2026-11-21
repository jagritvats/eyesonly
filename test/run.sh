#!/usr/bin/env bash
# eyesonly run / env, EYESONLY_IDENTITY and the GitHub Action script (action/setup.sh).
# Team: alice, bob = @core. deployer reads .env.production. ci reads .env. junior reads nothing.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
unset EYESONLY_IDENTITY GIT_CONFIG_COUNT
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
PASS=0 FAIL=0

cleanup() { [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null; rm -rf "$SB"; }
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
expect_ok()   { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 15; fi; }
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
expect_out()  { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1 && grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (no '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
url() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/app.git"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }
# show <VAR...>: print the named variables as JSON, from inside a child of `eyesonly run`
SHOW='console.log(JSON.stringify(Object.fromEntries(process.argv.slice(1).map((k) => [k, process.env[k] ?? null]))))'

declare -A TOK
echo "== setup"
for u in alice bob junior deployer ci; do
  TOK[$u]=$($VS user add "$(as $u $EYESONLY keygen $u 2>/dev/null)" 2>/dev/null)
done
$VS repo create app.git --admin alice 2>/dev/null
$VS policy set app.git - 2>/dev/null <<'EOF'
{ "members": ["*"], "admins": ["alice"], "groups": { "core": ["alice", "bob"] },
  "files": { ".env": ["@core", "ci"], ".env.production": ["alice", "deployer"], "secrets/**": ["@core"] } }
EOF
source "$ROOT/test/lib/server.sh"
start_server PORT "$SB/server.log"; SRV=$LAST_SRV

mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$(url alice)"
as alice $EYESONLY setup 2>/dev/null
cat > .env <<'EOF'
# shared dev settings
STRIPE=sk_test_1
export DB_URL="postgres://u:p@db/app"   # inline comment
SPACED=value with spaces # trailing comment
SINGLE='literal "x" \n kept'
ESCAPED="line1\nline2 \"q\""
MULTI="first
second"
EMPTY=
EOF
echo 'PROD_KEY=prod_1' > .env.production
mkdir -p secrets && echo 'this is SECRETLINE not kv' > secrets/bad.env
as alice git add -A && as alice git commit -qm init && as alice git push -q -u origin main 2>/dev/null
for u in bob junior deployer; do as $u $EYESONLY clone "$(url $u)" "$SB/$u" >/dev/null 2>&1; done

echo "== EYESONLY_IDENTITY"
mkdir -p "$SB/empty-home"
RAW="$(cat "$SB/home/bob/identity.json")"
B64="$(node -p 'Buffer.from(process.argv[1]).toString("base64")' "$RAW")"
expect_out "raw JSON identity from the environment" "eyesonlypub1:" env EYESONLY_HOME="$SB/empty-home" EYESONLY_IDENTITY="$RAW" $EYESONLY whoami
expect_out "base64 identity from the environment" "eyesonlypub1:" env EYESONLY_HOME="$SB/empty-home" EYESONLY_IDENTITY="$B64" $EYESONLY whoami
expect_ok "clone with only EYESONLY_IDENTITY set" env EYESONLY_HOME="$SB/empty-home" EYESONLY_IDENTITY="$B64" $EYESONLY clone "$(url bob)" "$SB/bob-env"
expect_out "...decrypts .env" "STRIPE=sk_test_1" cat "$SB/bob-env/.env"
[[ -z "$(in_ "$SB/bob-env" env EYESONLY_HOME="$SB/empty-home" EYESONLY_IDENTITY="$B64" git status --porcelain)" ]] && ok "...and git status is clean (filters see the env identity)" || bad "status dirty with env identity"
JUNIOR_B64="$(node -p 'Buffer.from(require("fs").readFileSync(process.argv[1])).toString("base64")' "$SB/home/junior/identity.json")"
expect_out "EYESONLY_IDENTITY wins over the identity file" "^junior " as bob env EYESONLY_IDENTITY="$JUNIOR_B64" $EYESONLY whoami
expect_reject "garbage EYESONLY_IDENTITY is a clean error" "neither identity JSON nor base64" env EYESONLY_IDENTITY="not-an-identity-SECRETMARK" $EYESONLY whoami
! grep -q SECRETMARK "$SB/out" && ok "...that doesn't echo the value" || bad "error echoed EYESONLY_IDENTITY"
! grep -q "    at " "$SB/out" && ok "...and has no stack trace" || bad "stack trace on bad identity"
expect_reject "JSON that isn't an identity is refused" "is not an eyesonly identity" env EYESONLY_IDENTITY='{"name":"x"}' $EYESONLY whoami
expect_reject "broken JSON doesn't leak its contents" "neither identity JSON" env EYESONLY_IDENTITY='{"priv":"SECRETMARK' $EYESONLY whoami
! grep -q SECRETMARK "$SB/out" && ok "...not even a fragment" || bad "JSON.parse fragment leaked"

echo "== eyesonly run"
cd "$SB/bob"
expect_out "run injects .env values" '"STRIPE":"sk_test_1"' as bob $EYESONLY run -- node -e "$SHOW" STRIPE
expect_out "export prefix and inline comment" '"DB_URL":"postgres://u:p@db/app"' as bob $EYESONLY run -- node -e "$SHOW" DB_URL
expect_out "unquoted value with spaces drops the trailing comment" '"SPACED":"value with spaces"' as bob $EYESONLY run -- node -e "$SHOW" SPACED
expect_out "single quotes are literal" '"SINGLE":"literal \\"x\\" \\\\n kept"' as bob $EYESONLY run -- node -e "$SHOW" SINGLE
expect_out "double quotes unescape \\n and \\\"" '"ESCAPED":"line1\\nline2 \\"q\\""' as bob $EYESONLY run -- node -e "$SHOW" ESCAPED
expect_out "double-quoted values can span lines" '"MULTI":"first\\nsecond"' as bob $EYESONLY run -- node -e "$SHOW" MULTI
expect_out "empty value" '"EMPTY":""' as bob $EYESONLY run -- node -e "$SHOW" EMPTY
expect_out "without --, the first non-option starts the command" '"STRIPE":"sk_test_1"' as bob $EYESONLY run node -e "$SHOW" STRIPE
expect_out "files bob can't read are skipped by default" '"PROD_KEY":null' as bob $EYESONLY run -- node -e "$SHOW" PROD_KEY
grep -q "skipping .env.production: you are not a reader" "$SB/out" && ok "...with a note naming the file" || bad "no skip note"
expect_out "deployer gets .env.production" '"PROD_KEY":"prod_1"' as deployer bash -c "cd '$SB/deployer' && $EYESONLY run --file .env.production -- node -e '$SHOW' PROD_KEY"
rm -f "$SB/ran"
expect_reject "--file for a file bob can't read is refused" "you are not a reader of '.env.production'" as bob $EYESONLY run --file .env --file .env.production -- node -e "require('fs').writeFileSync('$SB/ran','')"
[[ ! -e "$SB/ran" ]] && ok "...and the command never runs (no partial env)" || bad "command ran with partial env"
expect_reject "junior can't read any of them" "you can't read any of" as junior bash -c "cd '$SB/junior' && $EYESONLY run -- node -e \"require('fs').writeFileSync('$SB/ran','')\""
[[ ! -e "$SB/ran" ]] && ok "...and nothing runs" || bad "junior's command ran"
expect_reject "a non-protected --file is refused" "isn't a protected file" as bob $EYESONLY run --file README.md -- node -e 1
expect_reject "a malformed line is an error" "secrets/bad.env:1: not a KEY=VALUE line" as bob $EYESONLY env --file secrets/bad.env
! grep -q SECRETLINE "$SB/out" && ok "...that doesn't echo the line" || bad "malformed line echoed"

echo "== reads the staged blob, not the working tree"
git cat-file blob :.env > .env
expect_out "works while the working copy is ciphertext" '"STRIPE":"sk_test_1"' as bob $EYESONLY run -- node -e "$SHOW" STRIPE
echo 'STRIPE=from_working_tree' > .env
expect_out "unstaged plaintext edits aren't used" '"STRIPE":"sk_test_1"' as bob $EYESONLY run -- node -e "$SHOW" STRIPE
grep -q "has unstaged edits" "$SB/out" && ok "...and that's pointed out" || bad "no unstaged-edits note"
as bob git checkout -q -- .env

echo "== forged envelopes"
node --input-type=module -e '
const vc = await import((await import("node:url")).pathToFileURL(process.argv[1]).href + "/src/crypto.mjs");
const fs = await import("node:fs");
const id = JSON.parse(fs.readFileSync(process.argv[2] + "/identity.json"));
const pol = JSON.parse(fs.readFileSync(".git/eyesonly/policy.json"));
const r = { bob: pol.keys.bob.x25519 };
fs.writeFileSync(process.argv[3], vc.seal({ plaintext: Buffer.from("STRIPE=evil\n"), path: ".env", recipients: r, signer: id }));
' "$ROOT" "$SB/home/junior" "$SB/forged"
OID=$(git hash-object -w --no-filters "$SB/forged")
git update-index --cacheinfo "100644,$OID,.env"
rm -f "$SB/ran"
expect_reject "an envelope signed by a non-writer is refused" "refusing to load '.env'" as bob $EYESONLY run -- node -e "require('fs').writeFileSync('$SB/ran','')"
[[ ! -e "$SB/ran" ]] && ok "...and the command never runs" || bad "ran with a forged envelope"
node -e '
const fs = require("fs"); const s = fs.readFileSync(process.argv[1], "utf8");
fs.writeFileSync(process.argv[2], s.replace(/"path": ".env"/, "\"path\": \".env.production\""));' "$SB/forged" "$SB/moved"
git update-index --cacheinfo "100644,$(git hash-object -w --no-filters "$SB/moved"),.env"
expect_reject "an envelope bound to another path is refused" "refusing to load '.env'" as bob $EYESONLY env
as bob git reset -q

echo "== override, exit codes, signals"
expect_out "file values win over the environment by default" '"STRIPE":"sk_test_1"' as bob env STRIPE=from_env $EYESONLY run -- node -e "$SHOW" STRIPE
expect_out "--no-override keeps the environment's value" '"STRIPE":"from_env"' as bob env STRIPE=from_env $EYESONLY run --no-override -- node -e "$SHOW" STRIPE
expect_out "--no-override still adds missing keys" '"DB_URL":"postgres://u:p@db/app"' as bob env STRIPE=from_env $EYESONLY run --no-override -- node -e "$SHOW" DB_URL
as bob $EYESONLY run -- node -e 'process.exit(7)' 2>/dev/null; [[ $? == 7 ]] && ok "the child's exit code is passed through" || bad "exit code not propagated"
if [[ "$OSTYPE" == msys* || "$OSTYPE" == cygwin* ]]; then
  ok "SIGTERM forwarding (skipped: no POSIX signals on Windows)"
else
  rm -f "$SB/sig"
  as bob $EYESONLY run -- node -e "process.on('SIGTERM', () => { require('fs').writeFileSync('$SB/sig', ''); process.exit(3) }); setInterval(() => {}, 1000)" 2>/dev/null &
  RUNPID=$!
  for _ in $(seq 100); do pgrep -P "$RUNPID" >/dev/null && break; sleep 0.05; done
  sleep 0.3; kill -TERM "$RUNPID"; wait "$RUNPID"; CODE=$?
  [[ -e "$SB/sig" && $CODE == 3 ]] && ok "SIGTERM is forwarded to the child and its exit code returned" || bad "signal forwarding (exit $CODE)"
fi
expect_reject "a missing command is a clean error" "command not found" as bob $EYESONLY run -- eyesonly-no-such-command
expect_reject "run with no command prints usage" "usage: eyesonly run" as bob $EYESONLY run

echo "== eyesonly env"
expect_out "env --format dotenv" 'STRIPE="sk_test_1"' as bob $EYESONLY env
grep -q "warning: printing secrets to stdout" "$SB/out" && ok "...warns on stderr" || bad "no stdout warning"
as bob $EYESONLY env --format json 2>/dev/null > "$SB/env.json"
check "env --format json is valid JSON with the values" node -e 'const v = JSON.parse(require("fs").readFileSync(process.argv[1])); if (v.MULTI !== "first\nsecond" || v.SINGLE !== "literal \"x\" \\n kept") process.exit(1)' "$SB/env.json"
as bob $EYESONLY env --format shell 2>/dev/null > "$SB/env.sh"
check "env --format shell round-trips through eval" bash -c ". '$SB/env.sh' && [[ \"\$SINGLE\" == 'literal \"x\" \\n kept' && \"\$MULTI\" == \$'first\\nsecond' ]]"
expect_reject "unknown --format" "unknown --format" as bob $EYESONLY env --format yaml

echo "== GitHub Action (action/setup.sh)"
check "action.yml is a composite action that runs action/setup.sh" grep -q 'run: bash "$GITHUB_ACTION_PATH/action/setup.sh"' "$ROOT/action.yml"
check "every inputs.* reference is declared" node -e '
const y = require("fs").readFileSync(process.argv[1], "utf8");
const declared = new Set([...y.split("outputs:")[0].matchAll(/^  ([a-z-]+):$/gm)].map((m) => m[1]));
const used = [...y.matchAll(/inputs\.([a-z-]+)/g)].map((m) => m[1]);
process.exit(used.length && used.every((u) => declared.has(u)) ? 0 : 1);' "$ROOT/action.yml"
mkdir -p "$SB/bin" && printf '#!/bin/sh\nexec node "%s/bin/eyesonly.mjs" "$@"\n' "$ROOT" > "$SB/bin/eyesonly" && chmod +x "$SB/bin/eyesonly"
CI_B64="$(node -p 'Buffer.from(require("fs").readFileSync(process.argv[1])).toString("base64")' "$SB/home/ci/identity.json")"
action() { # action <dir> <user> <token> <identity> [ENV=VALUE...]
  local d="$1" u="$2" t="$3" i="$4"; shift 4
  mkdir -p "$d/tmp" && : > "$d/env" && : > "$d/output"
  (cd "$d" && env -u EYESONLY_HOME PATH="$SB/bin:$PATH" EO_SKIP_INSTALL=1 RUNNER_TEMP="$d/tmp" GITHUB_ENV="$d/env" GITHUB_OUTPUT="$d/output" \
    EO_URL="http://127.0.0.1:$PORT/app.git" EO_USER="$u" EO_TOKEN="$t" EO_IDENTITY="$i" EO_PATH=app "$@" bash "$ROOT/action/setup.sh")
}
expect_ok "the action clones as ci" action "$SB/gha" ci "${TOK[ci]}" "$CI_B64"
grep -v '::add-mask::' "$SB/out" | grep -qF "${TOK[ci]}" && bad "token appears in the action's output" || ok "the token never appears in the output"
check "...and decrypts .env" grep -q "STRIPE=sk_test_1" "$SB/gha/app/.env"
check "path output is set" grep -q '^path=.*app$' "$SB/gha/output"
! grep -rqF "${TOK[ci]}" "$SB/gha/app/.git/config" && ok "the token isn't in .git/config" || bad "token in .git/config"
! grep -q '@127.0.0.1' "$SB/gha/app/.git/config" && ok "the remote URL has no credentials" || bad "credentials in remote URL"
ghenv() { # run a later "step": the GITHUB_ENV exports apply, nothing else carries over
  local d="$1"; shift
  (set -a; while IFS='=' read -r k v; do export "$k=$v"; done < "$d/env"; cd "$d/app" && env -u EYESONLY_IDENTITY PATH="$SB/bin:$PATH" "$@")
}
expect_ok "a later step can git pull (job-scoped credential helper)" ghenv "$SB/gha" git pull -q
expect_out "a later step can eyesonly run" '"STRIPE":"sk_test_1"' ghenv "$SB/gha" eyesonly run -- node -e "$SHOW" STRIPE
expect_reject "credentials in the url are refused" "must not contain credentials" action "$SB/gha2" ci "${TOK[ci]}" "$CI_B64" EO_URL="$(url ci)"
DEP_B64="$(node -p 'Buffer.from(require("fs").readFileSync(process.argv[1])).toString("base64")' "$SB/home/deployer/identity.json")"
expect_reject "a reader's file staying encrypted fails the step" "ci is a reader of these files but they stayed encrypted: .env" action "$SB/gha3" ci "${TOK[ci]}" "$DEP_B64"
expect_ok "...unless allow-locked is true" action "$SB/gha4" ci "${TOK[ci]}" "$DEP_B64" EO_ALLOW_LOCKED=true
JUN_B64="$(node -p 'Buffer.from(require("fs").readFileSync(process.argv[1])).toString("base64")' "$SB/home/junior/identity.json")"
expect_ok "files outside the user's audience don't fail the step" action "$SB/gha5" junior "${TOK[junior]}" "$JUN_B64"
expect_reject "a bad identity input fails clearly" "identity is neither JSON nor base64" action "$SB/gha6" ci "${TOK[ci]}" "%%%"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
