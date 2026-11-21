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
- **Proof:** `npm test` runs 47 adversarial end-to-end checks against a real server.

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
read a file, and `[veil: encrypted, readable by …]` to everyone else.

| Command | What it does |
|---|---|
| `veil status` | Protected files, who can read them, and whether they need a rekey |
| `veil pull-policy && veil rekey` | After the admin changes access: re-encrypt for the new audience |
| `veil audit <user>` | Offboarding: every protected file the user could ever decrypt (rotate these) |

## How it works

1. **Client filter** (`clean`/`smudge`): protected paths are sealed with AES-256-GCM.
   The key is wrapped per reader with X25519, the envelope is signed with Ed25519, and the
   path is bound into the AAD. Unchanged plaintext reuses the existing ciphertext, so
   there's no diff noise.
2. **Proxy** (`veil-server serve`): authenticates tokens, hides refs per user, forces
   protocol v0 (v2 allows fetching hidden commits by SHA, as the test suite shows), and
   serves no dumb HTTP.
3. **Hook** (pre-receive): enforces the server-side policy on every new commit, covering
   plaintext, unauthorized edits, forged/replayed envelopes, stale recipients and private
   history leaking into public branches.

## Layout

```
bin/veil.mjs, bin/veil-server.mjs   CLIs
src/crypto.mjs                      envelope format
src/policy.mjs                      glob / ref / group matching
src/client.mjs                      filters + developer commands
src/server.mjs                      admin CLI, HTTP proxy, pre-receive hook
test/e2e.sh                         adversarial suite
site/index.html                     landing page
```
