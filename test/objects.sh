#!/usr/bin/env bash
# Object-level visibility: pushes that point refs at objects the pusher never sent.
# Regression suite for the v0.3 post-merge security review:
#   - resurrecting commits from a deleted private branch by oid (HIGH)
#   - a tag pointing straight at a private tree (MEDIUM)
#   - a .gitattributes redirect planted before the protected file lands (LOW)
# Uses raw receive-pack requests, because stock `git push` refuses to send a ref
# whose objects it doesn't have. That's exactly the attacker's position.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"
PORT="${PORT:-$((20000 + RANDOM % 20000))}"
export EYESONLY_DATA="$SB/server" GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
EYESONLY="node $ROOT/bin/eyesonly.mjs"
VS="node $ROOT/bin/eyesonly-server.mjs"
BASE="http://127.0.0.1:$PORT"
ZERO=0000000000000000000000000000000000000000
PASS=0 FAIL=0

cleanup() { [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null; rm -rf "$SB"; }
trap cleanup EXIT

ok()  { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
expect_ok()     { local d="$1"; shift; if "$@" >"$SB/out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/        /' "$SB/out" | tail -n 12; fi; }
expect_reject() { local d="$1" pat="$2"; shift 2; if "$@" >"$SB/out" 2>&1; then bad "$d (unexpectedly succeeded)"; elif grep -q -- "$pat" "$SB/out"; then ok "$d"; else bad "$d (failed, but without '$pat')"; sed 's/^/        /' "$SB/out" | tail -n 8; fi; }
as() { local u="$1"; shift; EYESONLY_HOME="$SB/home/$u" GIT_AUTHOR_NAME=$u GIT_AUTHOR_EMAIL=$u@x GIT_COMMITTER_NAME=$u GIT_COMMITTER_EMAIL=$u@x "$@"; }
url() { echo "http://$1:${TOK[$1]}@127.0.0.1:$PORT/app.git"; }
in_() { local d="$1"; shift; (cd "$d" && "$@"); }

# raw_push <user> <old> <new> <ref> <objects-file|-> [repo-for-pack]
#   Sends one receive-pack command plus a pack holding exactly the listed objects.
#   Exits 0 only if the server reports "ok <ref>". Hook stderr goes to the server log.
raw_push() {
  local user="$1" old="$2" new="$3" ref="$4" objs="$5" repo="${6:-$SB/junior}"
  local mark; mark=$(wc -l <"$SB/server.log")
  if [[ "$objs" == - ]]; then : >"$SB/objs"; else cp "$objs" "$SB/objs"; fi
  git -C "$repo" pack-objects --stdout <"$SB/objs" >"$SB/pack" 2>/dev/null
  node --input-type=module -e '
    import fs from "node:fs";
    const [url, user, tok, oldOid, newOid, ref, packFile] = process.argv.slice(1);
    const line = `${oldOid} ${newOid} ${ref}\0report-status\n`;
    const pkt = (s) => (s.length + 4).toString(16).padStart(4, "0") + s;
    const body = Buffer.concat([Buffer.from(pkt(line) + "0000"), fs.readFileSync(packFile)]);
    const res = await fetch(url + "/git-receive-pack", { method: "POST", body,
      headers: { "content-type": "application/x-git-receive-pack-request",
                 authorization: "Basic " + Buffer.from(user + ":" + tok).toString("base64") } });
    const text = Buffer.from(await res.arrayBuffer()).toString("latin1");
    console.log(text);
    process.exit(text.includes("ok " + ref) ? 0 : 1);
  ' "$BASE/app.git" "$user" "${TOK[$user]}" "$old" "$new" "$ref" "$SB/pack"
  local rc=$?
  tail -n +"$((mark + 1))" "$SB/server.log"   # the hook's reason, for expect_reject
  return $rc
}

declare -A TOK
echo "== setup"
for u in alice bob junior; do
  card=$(as $u $EYESONLY keygen $u 2>/dev/null)
  TOK[$u]=$($VS user add "$card" 2>/dev/null)
done
$VS repo create app.git --admin alice 2>/dev/null
cat >"$SB/policy.json" <<'EOF'
{ "members": ["*"], "admins": ["alice"],
  "groups": { "core": ["alice", "bob"] },
  "files": { ".env": ["@core"], "secrets/**": ["@core"] },
  "branches": { "refs/heads/private/": ["@core"] } }
EOF
$VS policy set app.git "$SB/policy.json" 2>/dev/null
$VS serve --port "$PORT" 2>"$SB/server.log" & SRV=$!
for _ in $(seq 50); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.1; done

mkdir -p "$SB/alice" && cd "$SB/alice"
git init -q -b main && git remote add origin "$(url alice)"
as alice $EYESONLY setup 2>/dev/null
echo 'v1' > README.md && echo 'K=1' > .env
as alice git add -A && as alice git commit -qm init && as alice git push -q -u origin main
as bob $EYESONLY clone "$(url bob)" "$SB/bob" 2>/dev/null
as junior $EYESONLY clone "$(url junior)" "$SB/junior" 2>/dev/null

echo "== orphaned private commits (deleted branch)"
cd "$SB/bob"
as bob git checkout -q -b private/tmp
echo 'ORPHAN-PLAN: acquire competitor' > PLAN.md && as bob git add PLAN.md && as bob git commit -qm "private plan"
as bob git push -q origin private/tmp
ORPHAN=$(git rev-parse HEAD); ORPHAN_TREE=$(git rev-parse HEAD^{tree})
as bob git push -q origin :private/tmp
as bob git checkout -q main
MAIN=$(git rev-parse origin/main)
expect_ok "control: junior's raw push of a ref at a visible commit is accepted" raw_push junior $ZERO "$MAIN" refs/heads/junior-ok -
expect_reject "junior can't point a new ref at an orphaned private commit" "existing object" raw_push junior $ZERO "$ORPHAN" refs/heads/leak -
expect_reject "junior can't move his own ref onto it either" "existing object" raw_push junior "$MAIN" "$ORPHAN" refs/heads/junior-ok -
if git ls-remote "$(url junior)" | grep -q "refs/heads/leak"; then bad "leak ref was not created"; else ok "leak ref was not created"; fi
expect_reject "junior can't fetch the orphan by sha" "unadvertised\|not our ref" in_ "$SB/junior" git fetch -q origin "$ORPHAN"

echo "== tags that point at trees or blobs"
cd "$SB/junior"
printf 'object %s\ntype tree\ntag t\ntagger junior <j@x> 0 +0000\n\nx\n' "$ORPHAN_TREE" >"$SB/tag.txt"
TAG=$(git hash-object -t tag -w --literally "$SB/tag.txt")
echo "$TAG" >"$SB/tagobj"
expect_reject "a tag object pointing straight at a private tree is rejected" "must point at a commit" raw_push junior $ZERO "$TAG" refs/tags/t "$SB/tagobj"
BLOB=$(git -C "$SB/bob" rev-parse "$ORPHAN:PLAN.md")
printf 'object %s\ntype blob\ntag b\ntagger junior <j@x> 0 +0000\n\nx\n' "$BLOB" >"$SB/tag2.txt"
TAG2=$(git hash-object -t tag -w --literally "$SB/tag2.txt"); echo "$TAG2" >"$SB/tagobj2"
expect_reject "a tag object pointing straight at a private blob is rejected" "must point at a commit" raw_push junior $ZERO "$TAG2" refs/tags/b "$SB/tagobj2"
# a tree entry naming a hidden blob the pusher never sent (the gitnamespaces attack)
TREE=$(printf '100644 blob %s\tstolen.txt\n' "$BLOB" | git mktree --missing)
COMMIT=$(GIT_AUTHOR_NAME=j GIT_AUTHOR_EMAIL=j@x GIT_COMMITTER_NAME=j GIT_COMMITTER_EMAIL=j@x git commit-tree "$TREE" -p "$MAIN" -m steal)
printf '%s\n%s\n' "$COMMIT" "$TREE" >"$SB/steal"
expect_reject "a commit whose tree names a hidden blob it didn't send is rejected" "existing object" raw_push junior "$MAIN" "$COMMIT" refs/heads/main "$SB/steal"

echo "== no false positives"
in_ "$SB/junior" bash -c 'echo v2 > README.md'
in_ "$SB/junior" as junior git commit -qam v2 && expect_ok "junior pushes a normal change" in_ "$SB/junior" as junior git push -q
in_ "$SB/junior" bash -c 'echo v1 > README.md'
in_ "$SB/junior" as junior git commit -qam "back to v1"
expect_ok "reverting to an old blob (not resent by the client) is accepted" in_ "$SB/junior" as junior git push -q
in_ "$SB/bob" as bob git pull -q --rebase >/dev/null 2>&1
in_ "$SB/bob" as bob git checkout -q -b private/again
in_ "$SB/bob" bash -c 'echo again > NOTE.md'
in_ "$SB/bob" as bob git add NOTE.md && in_ "$SB/bob" as bob git commit -qm again
expect_ok "an authorized user can push a new private branch" in_ "$SB/bob" as bob git push -q origin private/again
expect_ok "admin can restore a deleted branch by oid" raw_push alice $ZERO "$ORPHAN" refs/heads/private/tmp - "$SB/bob"

echo "== .gitattributes redirect planted ahead of the file"
cd "$SB/junior" && as junior git pull -q --rebase >/dev/null 2>&1
echo 'secrets/**/*.pem filter=lfs diff=lfs merge=lfs -text' >> .gitattributes
as junior git add .gitattributes && as junior git commit -qm "lfs for pems"
expect_ok "the redirect line itself matches no existing or sample path, so it lands" as junior git push -q
cd "$SB/bob" && as bob git checkout -q main && as bob git pull -q --rebase >/dev/null 2>&1
mkdir -p secrets/keys && echo 'PRIVATE KEY' > secrets/keys/a.pem
as bob git add secrets/keys/a.pem && as bob git commit -qm "add key" >/dev/null 2>&1
expect_reject "the first protected file under that redirect is rejected" "sets filter=lfs on protected path 'secrets/keys/a.pem'" as bob git push -q

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
