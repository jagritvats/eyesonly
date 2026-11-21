#!/usr/bin/env bash
# Keys at rest: the identity in the OS keychain instead of a plain file.
# Logic runs everywhere against a fake keychain (EYESONLY_KEYCHAIN_SHIM); the real backend
# runs where it exists: Windows DPAPI, a throwaway macOS keychain, Linux Secret Service.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/test/lib/compat.sh"
SB="$(mktemp -d)"; export SB
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
unset EYESONLY_IDENTITY EYESONLY_KEYCHAIN_SHIM EYESONLY_KEYCHAIN
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
PASS=0 FAIL=0
MACKC=""

cleanup() {
  [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null
  [[ -n "$MACKC" ]] && security delete-keychain "$MACKC" 2>/dev/null
  rm -rf "$SB"
}
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP  $1"; }
expect_ok()   { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 15; fi; }
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
expect_out()  { local d="$1" pat="$2"; shift 2; if "$@" 2>&1 | grep -q -- "$pat"; then ok "$d"; else bad "$d (no '$pat')"; "$@" 2>&1 | sed 's/^/        /' | tail -n 8; fi; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

# The fake keychain: a node script keeping secrets in a JSON file and logging its argv.
SHIM_DIR="$SB/shim"; mkdir -p "$SHIM_DIR"; export SHIM_DIR
cat > "$SB/kc-shim.mjs" <<'EOF'
import fs from 'node:fs';
import path from 'node:path';
const dir = process.env.SHIM_DIR;
const db = path.join(dir, 'store.json');
const [op, account] = process.argv.slice(2);
fs.appendFileSync(path.join(dir, 'argv.log'), process.argv.slice(2).join(' ') + '\n');
const store = fs.existsSync(db) ? JSON.parse(fs.readFileSync(db, 'utf8')) : {};
if (op === 'store') {
  store[account] = fs.readFileSync(0, 'utf8');
  fs.writeFileSync(db, JSON.stringify(store));
} else if (op === 'lookup') {
  if (!(account in store)) { process.stderr.write('The specified item could not be found in the keychain.\n'); process.exit(44); }
  process.stdout.write(store[account]);
} else if (op === 'delete') {
  delete store[account];
  fs.writeFileSync(db, JSON.stringify(store));
} else process.exit(2);
EOF
SHIM="$SB/kc-shim.mjs"
[[ -n "$IS_WINDOWS" ]] && SHIM="$(cygpath -w "$SHIM")"
kc() { EYESONLY_KEYCHAIN_SHIM="$SHIM" "$@"; }
lookups() { grep -c '^lookup ' "$SHIM_DIR/argv.log" 2>/dev/null || echo 0; }

as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }

echo "== keygen into the keychain"
expect_reject "--store must be file or keychain" "--store must be 'file' or 'keychain'" as bob $EYESONLY keygen bob --store vault
expect_ok "bob creates his identity in the keychain" as bob kc $EYESONLY keygen bob --store keychain
BOBCARD=$(as bob kc $EYESONLY whoami 2>/dev/null | tail -1)
check "no plaintext identity file was written" test ! -e "$SB/home/bob/identity.json"
check "config.json names the keychain" grep -q '"store": "keychain"' "$SB/home/bob/config.json"
SECRET=$(as bob kc $EYESONLY identity export --yes 2>/dev/null)
check "config.json holds no key material" bash -c "! grep -q 'priv' '$SB/home/bob/config.json'"
check "the secret never appeared in the keychain tool's argv" bash -c "[[ -n '$SECRET' ]] && ! grep -qF '$SECRET' '$SHIM_DIR/argv.log'"
check "...and the private key isn't in argv either" bash -c "! grep -q 'priv' '$SHIM_DIR/argv.log'"
expect_out "identity show names the store" "test keychain shim (eyesonly/bob)" as bob kc $EYESONLY identity show
expect_out "whoami works from the keychain" "^bob " as bob kc $EYESONLY whoami
expect_reject "keygen won't overwrite a keychain identity" "identity already exists at" as bob kc $EYESONLY keygen bob --store keychain
expect_reject "export needs --yes" "Re-run with --yes" as bob kc $EYESONLY identity export
expect_out "the exported value works as EYESONLY_IDENTITY" "^bob " env EYESONLY_IDENTITY="$SECRET" EYESONLY_HOME="$SB/nobody" $EYESONLY whoami

echo "== server flow with a keychain identity"
TOK_ALICE=$($VS user add "$(as alice $EYESONLY keygen alice 2>/dev/null)" 2>/dev/null)
TOK_BOB=$($VS user add "$BOBCARD" 2>/dev/null)
$VS repo create app.git --admin alice 2>/dev/null
cat > "$SB/policy.json" <<'EOF'
{ "members": ["*"], "admins": ["alice"], "groups": { "core": ["alice", "bob"] },
  "files": { ".env": ["@core"], "secrets/**": ["@core"] } }
EOF
$VS policy set app.git "$SB/policy.json" 2>/dev/null
source "$ROOT/test/lib/server.sh"
start_server PORT "$SB/server.log"; SRV=$LAST_SRV
mkdir -p "$SB/alice" && cd "$SB/alice" && git init -q -b main
git remote add origin "http://alice:$TOK_ALICE@127.0.0.1:$PORT/app.git"
as alice $EYESONLY setup >/dev/null 2>&1
echo 'STRIPE_SECRET=sk_live_1' > .env
mkdir -p secrets && for i in $(seq 1 10); do echo "s$i" > "secrets/s$i.txt"; done
as alice git add -A && as alice git commit -qm init && as alice git push -q -u origin main 2>/dev/null
cd "$SB"
: > "$SHIM_DIR/argv.log"
expect_ok "bob clones with his keychain identity" as bob kc $EYESONLY clone "http://bob:$TOK_BOB@127.0.0.1:$PORT/app.git" "$SB/bob"
expect_out "bob reads .env" "STRIPE_SECRET=sk_live_1" cat "$SB/bob/.env"
check "status is clean" bash -c "[[ -z \$(cd '$SB/bob' && EYESONLY_HOME='$SB/home/bob' EYESONLY_KEYCHAIN_SHIM='$SHIM' git status --porcelain) ]]"
: > "$SHIM_DIR/argv.log"
in_ "$SB/bob" bash -c 'for i in $(seq 1 10); do echo "rotated-$i" > "secrets/s$i.txt"; done'
expect_ok "bob re-seals 10 secrets with git add" in_ "$SB/bob" as bob kc git add -A
N=$(lookups)
[[ "$N" -le 2 ]] && ok "the filter process reads the keychain once, not per file ($N lookup(s) for 10 files)" || bad "keychain read $N times for 10 files"
expect_ok "bob commits and pushes" in_ "$SB/bob" as bob kc bash -c 'git commit -qm rotate && git push -q'

echo "== move between stores"
FP=$(as bob kc $EYESONLY whoami 2>/dev/null | head -1)
expect_out "move keychain -> file" "moved identity 'bob' from the keychain store" as bob kc $EYESONLY identity move --to file
check "...the file exists" test -f "$SB/home/bob/identity.json"
check "...the keychain entry is gone" bash -c "! grep -q '\"bob\"' '$SHIM_DIR/store.json'"
check "...same identity" bash -c "[[ \"\$(EYESONLY_HOME='$SB/home/bob' $EYESONLY whoami 2>/dev/null | head -1)\" == '$FP' ]]"
expect_out "move file -> keychain" "moved identity 'bob' from the file store" as bob kc $EYESONLY identity move --to keychain
check "...the plaintext file is gone" test ! -e "$SB/home/bob/identity.json"
check "...same identity again" bash -c "[[ \"\$(EYESONLY_HOME='$SB/home/bob' EYESONLY_KEYCHAIN_SHIM='$SHIM' $EYESONLY whoami 2>/dev/null | head -1)\" == '$FP' ]]"
expect_out "moving to where it already is changes nothing" "is already there" as bob kc $EYESONLY identity move --to keychain
expect_out "bob still decrypts after the round trip" "rotated-1" bash -c "cd '$SB/bob' && rm secrets/s1.txt && EYESONLY_HOME='$SB/home/bob' EYESONLY_KEYCHAIN_SHIM='$SHIM' git checkout -- secrets/s1.txt && cat secrets/s1.txt"

echo "== failures"
cp "$SHIM_DIR/store.json" "$SB/store.bak"
echo '{}' > "$SHIM_DIR/store.json"
expect_reject "a missing keychain entry is a clear error" "no identity in the test keychain shim (eyesonly/bob)" as bob kc $EYESONLY whoami
expect_reject "doctor reports it" "no identity in the test keychain shim" in_ "$SB/bob" as bob kc $EYESONLY doctor
cp "$SB/store.bak" "$SHIM_DIR/store.json"
expect_out "EYESONLY_IDENTITY still wins over the keychain" "^alice " as bob kc env EYESONLY_IDENTITY="$(cat "$SB/home/alice/identity.json")" $EYESONLY whoami
expect_reject "moving while EYESONLY_IDENTITY is set is refused" "EYESONLY_IDENTITY is set" as bob kc env EYESONLY_IDENTITY="$SECRET" $EYESONLY identity move --to file
expect_out "doctor warns about a plain-file key" "your private key is a plain file" in_ "$SB/alice" as alice $EYESONLY doctor

echo "== real OS keychain"
real_roundtrip() {
  local label="$1" home="$SB/home/real"
  rm -rf "$home"
  expect_ok "$label: keygen --store keychain" env EYESONLY_HOME="$home" $EYESONLY keygen realuser --store keychain
  check "$label: no plaintext file" test ! -e "$home/identity.json"
  expect_out "$label: whoami reads it back" "^realuser " env EYESONLY_HOME="$home" $EYESONLY whoami
  expect_out "$label: move to file" "moved identity 'realuser'" env EYESONLY_HOME="$home" $EYESONLY identity move --to file
  expect_out "$label: move back to the keychain" "moved identity 'realuser'" env EYESONLY_HOME="$home" $EYESONLY identity move --to keychain
  expect_out "$label: still readable" "^realuser " env EYESONLY_HOME="$home" $EYESONLY whoami
  env EYESONLY_HOME="$home" $EYESONLY identity move --to file >/dev/null 2>&1 # removes the keychain entry
}
if [[ -n "$IS_WINDOWS" ]]; then
  real_roundtrip "Windows DPAPI"
  check "Windows DPAPI: the stored blob isn't the identity JSON" bash -c "env EYESONLY_HOME='$SB/home/real2' $EYESONLY keygen r2 --store keychain >/dev/null 2>&1 && ! grep -q priv '$SB/home/real2/identity.dpapi'"
elif [[ "$(uname -s)" == Darwin ]] && command -v security >/dev/null; then
  MACKC="$SB/eyesonly-test.keychain-db"
  security create-keychain -p test "$MACKC" && security unlock-keychain -p test "$MACKC" && security set-keychain-settings "$MACKC"
  export EYESONLY_KEYCHAIN="$MACKC"
  real_roundtrip "macOS Keychain (throwaway keychain)"
  unset EYESONLY_KEYCHAIN
elif command -v secret-tool >/dev/null && [[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]] && echo probe | secret-tool store --label eyesonly-probe service eyesonly-probe account probe 2>/dev/null; then
  secret-tool clear service eyesonly-probe account probe 2>/dev/null
  real_roundtrip "Secret Service"
else
  skip "no usable OS keychain here (needs secret-tool and a D-Bus session with a keyring); the shim covered the logic"
fi

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
