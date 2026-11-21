# Veil

**Private files, private branches and built-in secrets for git.** Works with the stock
`git` client. Zero dependencies (Node ≥ 20 + git).

```
alice$ cat .env          →  STRIPE_SECRET=sk_live_456
junior$ cat .env         →  VEIL-V1 {"path":".env","keys":{"alice":…}}
junior$ git ls-remote    →  main            (private/launch is invisible)
junior$ git push         →  [veil] REJECTED: 'junior' may not modify protected file '.env'
```

- **Plan:** [PLAN.md](PLAN.md). **Threat model:** [THREAT_MODEL.md](THREAT_MODEL.md).
- **Website:** `site/index.html` (served at `/` by `veil-server serve`).
- **Proof:** `npm test` runs 436 adversarial end-to-end checks (8 suites) against a real server.

## Quickstart

```bash
# --- server (behind TLS in production) ---
export VEIL_DATA=/srv/veil
veil-server user add "$(VEIL_HOME=~/.veil veil whoami | tail -1)"   # prints alice's token
veil-server repo create app.git --admin alice
veil-server policy set app.git - <<'EOF'
{ "members": ["*"], "admins": ["alice"],
  "groups":   { "core": ["alice", "bob"] },
  "files":    { ".env": ["@core"], "secrets/**": ["@core"] },
  "branches": { "refs/heads/private/": ["@core"] } }
EOF
veil-server serve --port 8787

# --- every developer, once ---
veil keygen alice            # prints a public card: send it to the admin, get a token back

# --- per repo ---
veil clone http://alice:<token>@git.example.com/app.git   # or: git clone + veil setup
cd app && echo "STRIPE_SECRET=..." > .env && git add .env && git commit -m env && git push
```

Day to day it's just git. `git diff` and `git log -p` show plaintext to people who can
read a file, and `[veil: encrypted, readable by …]` to everyone else. `git mv` of a secret
just works: the pre-commit hook installed by `veil setup` re-seals it for its new path.

| Command | What it does |
|---|---|
| `veil status` | Protected files, who can read them, and whether they need a rekey |
| `veil pull-policy && veil rekey` | After the admin changes access: re-encrypt for the new audience |
| `veil audit <user>` | Offboarding: every protected file the user could ever decrypt (rotate these) |
| `veil-server policy manifest app.git > m.json`, `veil policy-sign m.json > s.json`, `veil-server policy attest app.git s.json` | Admin signs the policy so a compromised server can't swap keys or add readers; clients pin the admin key on first contact (`VEIL_PIN_ADMIN=<fingerprint>` pins it up front) |

## Protected refs and read-only members

Every git host has branch protection; so does Veil. Both fields are optional:

```json
{ "members": ["*"], "admins": ["alice"],
  "groups":  { "core": ["alice", "bob"], "release": ["alice"] },
  "writers": ["@core", "ci-bot"],
  "protect": { "refs/heads/main": { "push": ["@release"], "force": [], "delete": [] },
               "refs/tags/":      { "force": [], "delete": [] } } }
```

- `writers` (default: `members`): everyone else is read-only. They can clone and fetch,
  but pushes get a 403 from the proxy and `has read-only access` from the hook.
- `protect`: longest prefix wins. A missing `push` means writers; a missing `force` or
  `delete` means admins only. Without a `protect` section, tags and the branch HEAD points
  to (usually `main`) can't be force-pushed or deleted by non-admins. Admins bypass
  `protect`.
- Nobody, admins included, can move a ref to a tree whose secrets are invalid under the
  current policy. For example, force-pushing `main` back to a commit from before `veil rekey`
  is refused with `encrypted to users outside the policy`. Neither field is ever sent to
  clients.

## Worktrees, LFS and .gitattributes

- **Pinned filter.** `veil setup`, `veil clone` and `veil pull-policy` write the policy's
  `filter=veil` lines into a managed block of `.git/info/attributes` (between
  `# >>> veil (managed) >>>` markers; your own lines there are kept). That file beats every
  in-tree `.gitattributes`, so a teammate's `.env filter=lfs` line or a nested
  `secrets/.gitattributes` can't route your plaintext to git-lfs, even with `--no-verify`
  or an IDE that skips hooks. `veil status` warns if a protected path resolves to any other
  filter, and the pre-commit hook refuses it.
- **Server.** Pushes that make a protected path resolve to another filter (`filter=lfs`,
  `-filter`, `!filter`, macros, nested files) are rejected, and only admins may set LFS
  endpoints in `.lfsconfig` (`lfs.url`, `remote.*.lfsurl`, `url.*.insteadOf`). The server
  needs git >= 2.40 for this check and refuses such pushes on older git.
- **Worktrees.** `git worktree add` just works: veil keeps its policy and pinned admin key
  in the main repo's git dir, shared by every worktree. State left in
  `.git/worktrees/<n>/veil` by older versions is moved on the first veil command; if it
  holds a different `trust.json`, veil stops and asks you to delete one.
- **Sparse checkouts.** `veil setup` leaves paths excluded by `git sparse-checkout` alone.

## Merging protected files

Every seal produces fresh ciphertext, so without help any two concurrent edits to `.env`
would conflict inside the envelope. `veil setup` and `veil clone` register a merge driver
(`merge=veil` in `.gitattributes`; older `filter=veil diff=veil` lines are upgraded in
place). On `git merge`, `git rebase` or `git pull` it:

1. verifies all three sides (signed by an allowed writer, bound to this path) and refuses
   forged or moved envelopes, so a merge can't launder them under your signature;
2. decrypts them into private temp files (`.git/veil/tmp`, removed right after) and runs
   `git merge-file`;
3. clean merge: re-seals the result for the file's audience, signed by you. Conflict: the
   working file holds plaintext with conflict markers; fix it and `git add` re-encrypts it.

If you can't read the file you get `you are not a reader` plus the list of readers; pick a
side with `git checkout --ours/--theirs -- <path>`. Binary protected files aren't merged
(pick a side). A modify/delete conflict never reaches the driver; git reports it as usual.

## Mirroring to GitHub/GitLab

Keep private branches and the secrets policy in Veil and still get PRs and CI on
GitHub, GitLab or Gitea: `veil-server mirror` pushes **verified public refs only**.

```bash
install -m 600 /dev/stdin /etc/veil/gh-token <<<"$GITHUB_TOKEN"   # outside the repo dir
veil-server mirror set app.git --url https://github.com/acme/app.git \
  --push refs/heads/main 'refs/tags/v*' --credential-file /etc/veil/gh-token
veil-server mirror push app.git        # run by hand or from cron; non-zero exit on any problem
veil-server mirror show app.git        # config (credential path only) + what was mirrored
```

- Only allowlisted refs that are public under the *current* policy are pushed;
  `refs/heads/private/*` never is, and `refs/*` is refused as too broad.
- The push comes from a staging repo (`<repo>.git/veil-mirror-stage.git`) that only ever
  fetched those refs, so private objects can't ride along as delta bases. Before
  anything is pushed, every new commit is re-checked: protected files must be valid,
  authorized envelopes and no history may come from a private branch. Any failure
  pushes nothing.
- Refspecs are explicit; there's no force unless `--allow-force` (and even then with a
  lease, so upstream changes are never clobbered). `--delete-upstream on-private`
  removes refs upstream when the policy makes them private. Either way, treat what was
  already mirrored as disclosed.
- URLs must be `https://`, `ssh://` or `git@host:path` (`ext::` and friends are always
  refused; local paths need `--allow-local`). The token goes in an HTTP header via the
  environment, never in argv or the URL.
- **Required:** turn on upstream branch protection so only the mirror's credential can
  push the mirrored branches. Veil can't police pushes made directly to GitHub/GitLab.

## How it works

1. **Client filter** (`clean`/`smudge`): protected paths are sealed with AES-256-GCM.
   The key is wrapped per reader with X25519, the envelope is signed with Ed25519, and the
   path is bound into the AAD. Unchanged plaintext reuses the existing ciphertext, so
   there's no diff noise.
2. **Proxy** (`veil-server serve`): authenticates tokens, hides refs per user, forces
   protocol v0 (v2 allows fetching hidden commits by SHA, as the test suite shows), and
   serves no dumb HTTP. It also filters fetch negotiation: `have`/`shallow` lines for
   commits the user can't see are dropped, so ACKs don't reveal that a private commit
   exists (request bodies are capped at 10 MiB, `VEIL_MAX_UPLOAD_PACK_BODY` to change).
3. **Hook** (pre-receive): enforces the server-side policy on every new commit, covering
   plaintext, unauthorized edits, forged/replayed envelopes, stale recipients and private
   history leaking into public branches.

## Layout

```
bin/veil.mjs, bin/veil-server.mjs   CLIs
src/crypto.mjs                      envelope format
src/policy.mjs                      glob / ref / group matching
src/client.mjs                      filters + developer commands
src/merge.mjs                       merge driver for protected files
src/refguard.mjs                    protected refs, read-only members, rewind check
src/attrs.mjs                       info/attributes pinning, server filter-redirect check
src/mirror.mjs                      outbound mirror to GitHub/GitLab
src/server.mjs                      admin CLI, HTTP proxy, pre-receive hook
test/e2e.sh                         adversarial suite
site/index.html                     landing page
```
