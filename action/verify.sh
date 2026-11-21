#!/usr/bin/env bash
# `mode: verify` body of action.yml: run `eyesonly verify` on the commits of this push or pull
# request, against the policy committed in the repo. Needs no secrets: it only reads the
# checkout (which must have full history: actions/checkout with fetch-depth: 0).
# Also runnable by hand: EO_PATH, EO_RANGE or EO_BASE/EO_HEAD; EO_SKIP_INSTALL=1 uses the
# eyesonly on PATH.
set -euo pipefail
fail() { echo "::error::eyesonly: $*"; exit 1; }
EO_VERSION="${EO_VERSION:-latest}"

if [[ "${EO_SKIP_INSTALL:-}" != 1 ]]; then
  npm install --global --no-fund --no-audit --loglevel=error "eyesonly@$EO_VERSION" >/dev/null
fi
command -v eyesonly >/dev/null || fail "eyesonly is not on PATH after install"

cd "${EO_PATH:-.}"
git rev-parse --git-dir >/dev/null 2>&1 || fail "${EO_PATH:-.} is not a git checkout; run actions/checkout first"
[[ "$(git rev-parse --is-shallow-repository)" == true ]] && fail "the checkout is shallow; use actions/checkout with fetch-depth: 0 so verify can see the base commit"

range="${EO_RANGE:-}"
if [[ -z "$range" ]]; then
  base="${EO_BASE:-}"
  head="${EO_HEAD:-HEAD}"
  [[ -z "$base" || "$base" =~ ^0+$ ]] && base=""   # new branch: verify falls back to the default branch
  range="${base}..${head}"
fi
args=(--range "$range")
# A private branch pushed as a plain branch (someone without the client) is flagged by name.
[[ -n "${EO_REF:-}" ]] && args+=(--ref "$EO_REF")
# Sealed private branches: each ref under refs/eyesonly/b/ must be one encrypted envelope.
[[ "${EO_SEALED:-true}" == true ]] && git remote get-url origin >/dev/null 2>&1 && args+=(--sealed origin)
echo "eyesonly verify ${args[*]}"
eyesonly verify "${args[@]}"
