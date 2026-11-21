#!/usr/bin/env bash
# Runs every test/*.sh suite (except this runner). Each suite must exit non-zero on failure.
set -u
cd "$(dirname "$0")"
status=0
for t in *.sh; do
  [[ "$t" == run-all.sh ]] && continue
  echo "### $t"
  bash "$t" || status=1
done
exit $status
