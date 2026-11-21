#!/usr/bin/env bash
# Body of action.yml. Also runnable by hand (test/run.sh does): set the EO_* variables plus
# GITHUB_ENV, GITHUB_OUTPUT and RUNNER_TEMP. EO_SKIP_INSTALL=1 uses the eyesonly on PATH.
#
# The token and identity are written to 0600 files under RUNNER_TEMP. The token reaches git
# (and the eyesonly client, which asks git) through a credential helper configured with
# GIT_CONFIG_* variables in GITHUB_ENV, so it lasts for this job only and never lands in the
# URL, .git/config or ~/.gitconfig.
set -euo pipefail

: "${EO_URL:?url is required}" "${EO_USER:?user is required}" "${EO_TOKEN:?token is required}" "${EO_IDENTITY:?identity is required}"
EO_PATH="${EO_PATH:-app}"
EO_VERSION="${EO_VERSION:-latest}"
fail() { echo "::error::eyesonly: $*"; exit 1; }

echo "::add-mask::$EO_TOKEN"
[[ "$EO_URL" =~ ^https?:// ]] || fail "url must be http(s)://, got '$EO_URL'"
[[ "$EO_URL" =~ ^https?://[^/]*@ ]] && fail "url must not contain credentials; pass user and token instead"
[[ "$EO_USER" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,38}$ ]] || fail "invalid user name '$EO_USER'"

if [[ "${EO_SKIP_INSTALL:-}" != 1 ]]; then
  npm install --global --no-fund --no-audit --loglevel=error "eyesonly@$EO_VERSION" >/dev/null
fi
command -v eyesonly >/dev/null || fail "eyesonly is not on PATH after install"

mixed() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
DIR="$(mixed "${RUNNER_TEMP:?}")/eyesonly"
mkdir -p "$DIR/home" && chmod 700 "$DIR" "$DIR/home"

# Identity: raw JSON or base64, decoded by node so this works the same on every runner OS.
EO_IDENTITY="$EO_IDENTITY" OUT="$DIR/home/identity.json" node -e '
  const fs = require("fs");
  const v = process.env.EO_IDENTITY.trim();
  const text = v.startsWith("{") ? v : Buffer.from(v, "base64").toString("utf8");
  try { JSON.parse(text); } catch { console.error("::error::eyesonly: identity is neither JSON nor base64 of it"); process.exit(1); }
  fs.writeFileSync(process.env.OUT, text, { mode: 0o600 });'
export EYESONLY_HOME="$DIR/home"
WHO="$(eyesonly whoami 2>/dev/null | tail -1)" || fail "identity input is not a valid eyesonly identity"
[[ -n "$WHO" ]] || fail "identity input is not a valid eyesonly identity"

# Token and credential helper.
umask 077
printf '%s' "$EO_TOKEN" > "$DIR/token"
cat > "$DIR/credential-helper.sh" <<EOF
#!/bin/sh
test "\$1" = get || exit 0
echo "username=$EO_USER"
printf 'password=%s\n' "\$(cat '$DIR/token')"
EOF
ORIGIN="$(node -p 'new URL(process.argv[1]).origin' "$EO_URL")"
n="${GIT_CONFIG_COUNT:-0}"
{
  echo "EYESONLY_HOME=$EYESONLY_HOME"
  echo "GIT_TERMINAL_PROMPT=0"
  echo "GCM_INTERACTIVE=never"
  echo "GIT_CONFIG_COUNT=$((n + 2))"
  echo "GIT_CONFIG_KEY_$n=credential.$ORIGIN.helper"
  echo "GIT_CONFIG_VALUE_$n="                          # reset system helpers for this host
  echo "GIT_CONFIG_KEY_$((n + 1))=credential.$ORIGIN.helper"
  echo "GIT_CONFIG_VALUE_$((n + 1))=!sh '$DIR/credential-helper.sh'"
} >> "$GITHUB_ENV"
export GIT_TERMINAL_PROMPT=0 GCM_INTERACTIVE=never GIT_CONFIG_COUNT=$((n + 2))
export "GIT_CONFIG_KEY_$n=credential.$ORIGIN.helper" "GIT_CONFIG_VALUE_$n="
export "GIT_CONFIG_KEY_$((n + 1))=credential.$ORIGIN.helper" "GIT_CONFIG_VALUE_$((n + 1))=!sh '$DIR/credential-helper.sh'"

eyesonly clone "$EO_URL" "$EO_PATH"
ABS="$(cd "$EO_PATH" && mixed "$(pwd)")"
echo "path=$ABS" >> "$GITHUB_OUTPUT"

# Fail if a file this user is a reader of is still ciphertext (wrong identity, stale rekey).
STATUS="$(cd "$EO_PATH" && eyesonly status)"
echo "$STATUS"
ME="$(sed -n '1s/^repo .* as \([^ ]*\).*/\1/p' <<<"$STATUS")"
LOCKED="$(awk -v me="$ME" '$1 == "locked" {
  r = $0; sub(/.*\[/, "", r); sub(/\].*/, "", r); n = split(r, a, /, */)
  for (i = 1; i <= n; i++) if (a[i] == me) print $2 }' <<<"$STATUS")"
if [[ -n "$LOCKED" && "${EO_ALLOW_LOCKED:-false}" != true ]]; then
  fail "$ME is a reader of these files but they stayed encrypted: $(echo $LOCKED). Check the identity secret matches '$ME', or run eyesonly rekey. Set allow-locked: true to continue anyway."
fi
