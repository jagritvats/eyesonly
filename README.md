# Eyes Only

![Eyes Only: per-person access inside one git repo](https://raw.githubusercontent.com/jagritvats/eyesonly/main/assets/banner.png)

> **Built to be checked.** 450 adversarial end-to-end tests run against a real server, the
> [threat model](THREAT_MODEL.md) maps every attack to the test that stops it, and the code is
> small, dependency-free and open. Found a hole? [Report it](SECURITY.md).

**Private files, private branches and built-in secrets in one git repo.** The server
enforces it, and everyone keeps using the stock `git` client. Zero runtime dependencies
(Node ≥ 22 + git).

```
alice$ cat .env          →  STRIPE_SECRET=sk_live_456
junior$ cat .env         →  EYESONLY-V1 {"path":".env","keys":{"alice":…}}
junior$ git ls-remote    →  main            (private/launch is invisible)
junior$ git push         →  [eyesonly] REJECTED: 'junior' may not modify protected file '.env'
```

## Why

Git access is all-or-nothing: whoever can clone a repo sees every file and every branch.
So `.env` files travel over Slack, the three-person launch branch lives in a separate repo,
and the contractor fixing a button gets the production keys. Eyes Only adds per-person
access to files and branches in the same repo, without a new VCS or client.

## Try it in 30 seconds

![alice reads .env, junior gets ciphertext, junior's push is rejected by the server](https://raw.githubusercontent.com/jagritvats/eyesonly/main/assets/demo.gif)

```bash
npx eyesonly demo      # temp dir, local server, alice vs junior; needs git, bash and curl
```

It runs the whole story on your machine: alice reads `.env` and junior gets ciphertext;
junior can't list, fetch (even by SHA over protocol v2) or push to `private/*`; his
plaintext push is rejected by the server; and alice's accidental merge of private history
into `main` is rejected while a squash merge goes through.

Proof beyond the demo: `npm test` runs 450 adversarial end-to-end checks (9 suites) against
a real server, with an attacker who controls their own git client.

## Install

```bash
npm i -g eyesonly      # CLIs: eyesonly (also `git eyesonly`) and eyesonly-server
```

Server in Docker: `docker build -t eyesonly . && docker run -p 8787:8787 -v eyesonly-data:/data eyesonly`.
Put TLS in front of it either way, and a reverse proxy (Caddy, nginx) if you want rate
limiting or request timeouts; the server has neither built in.

The client runs on Linux, macOS and Windows (Git for Windows). The server is tested on
Linux and macOS.

## Quickstart

```bash
# --- server (behind TLS in production) ---
export EYESONLY_DATA=/srv/eyesonly
eyesonly-server user add "$(EYESONLY_HOME=~/.eyesonly eyesonly whoami | tail -1)"   # prints alice's token
eyesonly-server repo create app.git --admin alice
eyesonly-server policy set app.git - <<'EOF'
{ "members": ["*"], "admins": ["alice"],
  "groups":   { "core": ["alice", "bob"] },
  "files":    { ".env": ["@core"], "secrets/**": ["@core"] },
  "branches": { "refs/heads/private/": ["@core"] } }
EOF
eyesonly-server serve --port 8787

# --- every developer, once ---
eyesonly keygen alice            # prints a public card: send it to the admin, get a token back

# --- per repo ---
eyesonly clone http://alice:<token>@git.example.com/app.git   # or: git clone + eyesonly setup
cd app && echo "STRIPE_SECRET=..." > .env && git add .env && git commit -m env && git push
```

### Already have a repo or a clone?

```bash
# move a GitHub repo onto Eyes Only (GitHub stays as a second remote)
git remote rename origin github
git remote add origin https://alice:<token>@git.example.com/app.git
git push -u origin --all && git push origin --tags
eyesonly setup && git add .gitattributes && git commit -m "eyesonly" && git push

# teammate with an existing clone: pull first, then setup
git remote set-url origin https://bob:<token>@git.example.com/app.git
git pull && eyesonly setup
```

Secrets already committed in plaintext? The server rejects that history; see
[existing repos and clones](docs/existing-repos.md) for rotating and stripping it.
**[Read the guides →](https://jagritvats.github.io/eyesonly/docs/)**

Day to day it's just git. `git diff` and `git log -p` show plaintext to people who can
read a file, and `[eyesonly: encrypted, readable by …]` to everyone else. `git mv` of a secret
just works: the pre-commit hook installed by `eyesonly setup` re-seals it for its new path.

| Command | What it does |
|---|---|
| `eyesonly status` | Protected files, who can read them, and whether they need a rekey |
| `eyesonly pull-policy && eyesonly rekey` | After the admin changes access: re-encrypt for the new audience |
| `eyesonly audit <user>` | Offboarding: every protected file the user could ever decrypt (rotate these) |
| `eyesonly-server policy manifest app.git > m.json`, `eyesonly policy-sign m.json > s.json`, `eyesonly-server policy attest app.git s.json` | Admin signs the policy so a compromised server can't swap keys or add readers; clients pin the admin key on first contact (`EYESONLY_PIN_ADMIN=<fingerprint>` pins it up front) |

## Guides

Also at [jagritvats.github.io/eyesonly/docs](https://jagritvats.github.io/eyesonly/docs/).

- [Existing repos and clones](docs/existing-repos.md): migrate a repo, onboard clones, start tracking `.env`
- [Team workflows](docs/team-workflows.md): grant and revoke access, private branches, offboarding
- [CI](docs/ci.md): read protected files in CI
- [Server deployment](docs/server-deployment.md): TLS, systemd, Docker, backups
- [Policy reference](docs/policy-reference.md): every policy field
- [Troubleshooting](docs/troubleshooting.md): error messages and fixes

## Protected refs and read-only members

Every git host has branch protection; so does Eyes Only. Both fields are optional:

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
  current policy. For example, force-pushing `main` back to a commit from before `eyesonly rekey`
  is refused with `encrypted to users outside the policy`. Neither field is ever sent to
  clients.

## Worktrees, LFS and .gitattributes

- **Pinned filter.** `eyesonly setup`, `eyesonly clone` and `eyesonly pull-policy` write the policy's
  `filter=eyesonly` lines into a managed block of `.git/info/attributes` (between
  `# >>> eyesonly (managed) >>>` markers; your own lines there are kept). That file beats every
  in-tree `.gitattributes`, so a teammate's `.env filter=lfs` line or a nested
  `secrets/.gitattributes` can't route your plaintext to git-lfs, even with `--no-verify`
  or an IDE that skips hooks. `eyesonly status` warns if a protected path resolves to any other
  filter, and the pre-commit hook refuses it.
- **Server.** Pushes that make a protected path resolve to another filter (`filter=lfs`,
  `-filter`, `!filter`, macros, nested files) are rejected, and only admins may set LFS
  endpoints in `.lfsconfig` (`lfs.url`, `remote.*.lfsurl`, `url.*.insteadOf`). The server
  needs git >= 2.40 for this check and refuses such pushes on older git.
- **Worktrees.** `git worktree add` just works: eyesonly keeps its policy and pinned admin key
  in the main repo's git dir, shared by every worktree. State left in
  `.git/worktrees/<n>/eyesonly` by older versions is moved on the first eyesonly command; if it
  holds a different `trust.json`, eyesonly stops and asks you to delete one.
- **Sparse checkouts.** `eyesonly setup` leaves paths excluded by `git sparse-checkout` alone.

## Merging protected files

Every seal produces fresh ciphertext, so without help any two concurrent edits to `.env`
would conflict inside the envelope. `eyesonly setup` and `eyesonly clone` register a merge driver
(`merge=eyesonly` in `.gitattributes`; older `filter=eyesonly diff=eyesonly` lines are upgraded in
place). On `git merge`, `git rebase` or `git pull` it:

1. verifies all three sides (signed by an allowed writer, bound to this path) and refuses
   forged or moved envelopes, so a merge can't launder them under your signature;
2. decrypts them into private temp files (`.git/eyesonly/tmp`, removed right after) and runs
   `git merge-file`;
3. clean merge: re-seals the result for the file's audience, signed by you. Conflict: the
   working file holds plaintext with conflict markers; fix it and `git add` re-encrypts it.

If you can't read the file you get `you are not a reader` plus the list of readers; pick a
side with `git checkout --ours/--theirs -- <path>`. Binary protected files aren't merged
(pick a side). A modify/delete conflict never reaches the driver; git reports it as usual.

## Mirroring to GitHub/GitLab

Keep private branches and the secrets policy in Eyes Only and still get PRs and CI on
GitHub, GitLab or Gitea: `eyesonly-server mirror` pushes **verified public refs only**.

```bash
install -m 600 /dev/stdin /etc/eyesonly/gh-token <<<"$GITHUB_TOKEN"   # outside the repo dir
eyesonly-server mirror set app.git --url https://github.com/acme/app.git \
  --push refs/heads/main 'refs/tags/v*' --credential-file /etc/eyesonly/gh-token
eyesonly-server mirror push app.git        # run by hand or from cron; non-zero exit on any problem
eyesonly-server mirror show app.git        # config (credential path only) + what was mirrored
```

- Only allowlisted refs that are public under the *current* policy are pushed;
  `refs/heads/private/*` never is, and `refs/*` is refused as too broad.
- The push comes from a staging repo (`<repo>.git/eyesonly-mirror-stage.git`) that only ever
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
  push the mirrored branches. Eyes Only can't police pushes made directly to GitHub/GitLab.

## How it works

1. **Client filter** (`clean`/`smudge`): protected paths are sealed with AES-256-GCM.
   The key is wrapped per reader with X25519, the envelope is signed with Ed25519, and the
   path is bound into the AAD. Unchanged plaintext reuses the existing ciphertext, so
   there's no diff noise.
2. **Proxy** (`eyesonly-server serve`): authenticates tokens, hides refs per user, forces
   protocol v0 (v2 allows fetching hidden commits by SHA, as the test suite shows), and
   serves no dumb HTTP. It also filters fetch negotiation: `have`/`shallow` lines for
   commits the user can't see are dropped, so ACKs don't reveal that a private commit
   exists (request bodies are capped at 10 MiB, `EYESONLY_MAX_UPLOAD_PACK_BODY` to change).
3. **Hook** (pre-receive): enforces the server-side policy on every new commit, covering
   plaintext, unauthorized edits, forged/replayed envelopes, stale recipients and private
   history leaking into public branches. Every object a push makes visible must have been
   sent by the pusher or already be visible to that ref's audience, so nobody can point a
   ref at a private commit, tree or blob they only know the SHA of.

**On protocol v2.** Git documents that `transfer.hideRefs` isn't read access control
([gitnamespaces(7), SECURITY](https://git-scm.com/docs/gitnamespaces#_security)): over
protocol v2 a client can ask for any object the server has by SHA. It's easy to miss when
building this kind of proxy. Eyes Only forces v0 with every `allow*SHA1InWant` off and has
tests for both versions.

## What Eyes Only doesn't do

- **Revocation isn't retroactive.** Someone who could read a secret has seen it.
  `eyesonly audit <user>` lists exactly what to rotate.
- **File names, sizes and timestamps are visible** to everyone who can read the branch.
  Only the contents are protected.
- **The server can see private branches.** It never sees protected file plaintext, and a
  signed policy stops it from adding readers, but private refs are ordinary git objects on it.
- **Admin trust is TOFU** unless you pin the admin key up front (`EYESONLY_PIN_ADMIN`).
- **Protocol v0 only, plain HTTP.** Put TLS in front of the server.
- **Your private key is a plain file.** `~/.eyesonly/identity.json` (mode 0600) isn't
  passphrase-protected. On Windows, file modes aren't enforced, so it relies on your user
  profile's permissions. Anyone who can read it can read your secrets.
- **jj and other git frontends** work for branches, but they don't run git's clean/smudge
  filters, so encrypted files need the git CLI for now.
- **No third-party audit yet.** Every defense has a test and the code is open; reports go
  through [SECURITY.md](SECURITY.md) and get fixed first.

## Prior art

| | Encrypted files | Server blocks plaintext / unauthorized writes | Private branches | Stock git client |
|---|---|---|---|---|
| **Eyes Only** | ✓ | ✓ | ✓ | ✓ |
| git-crypt, git-secret, sops, transcrypt, dotenvx | ✓ | — (client-side only) | — | ✓ |
| Gerrit | — | — | ✓ ref-level Read ACLs | ✓ (but you adopt Gerrit) |
| Gitolite, Bitbucket | — | — | write-only per branch | ✓ |
| GitHub / GitLab | — | push protection for known secret patterns | — (requested / designed) | ✓ |
| [src-control](https://github.com/git-agentic/src-control) | ✓ | ✓ | ✓ | its own `sc` client |
| [Scrim](https://github.com/Derrickkoko1234/scrim) | planned | push and merge-leak guards; secrets planned | ✓ | ✓ (Postgres-backed server) |

The building blocks aren't new: clean/smudge encryption is git-crypt's idea and ref hiding
is built into git. The difference is putting the server in charge of both.

## Layout

```
bin/eyesonly.mjs, bin/eyesonly-server.mjs   CLIs
examples/demo.sh                    the `eyesonly demo` script
src/crypto.mjs                      envelope format
src/attest.mjs                      signed policy manifests + admin key pinning
src/negotiate.mjs                   upload-pack negotiation filter
src/hooks.mjs                       client pre-commit hook
src/policy.mjs                      glob / ref / group matching
src/client.mjs                      filters + developer commands
src/merge.mjs                       merge driver for protected files
src/refguard.mjs                    protected refs, read-only members, rewind check
src/attrs.mjs                       info/attributes pinning, server filter-redirect check
src/mirror.mjs                      outbound mirror to GitHub/GitLab
src/server.mjs                      admin CLI, HTTP proxy, pre-receive hook
test/*.sh                           adversarial suites (npm test runs them all)
site/index.html                     landing page
```
