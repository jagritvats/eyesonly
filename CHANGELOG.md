# Changelog

## 0.5.0 (2026-11-22)

**Upgrading from 0.4:** repos with a signed server policy need one re-sign by an admin
(`eyesonly-server policy manifest` → `eyesonly policy-sign` → `eyesonly-server policy attest`, or
`eyesonly admin sign`), because signed policies now list every admin. In GitHub mode,
`grant --read-only` turns `writers` into an explicit list: members added later are read-only
until granted `--writer`.

- Fix: policy fetches, mode detection and admin-API reads retry on connection resets instead of failing (or guessing the wrong mode).
- Identity in the OS keychain: `eyesonly keygen <name> --store keychain` and `eyesonly identity move --to keychain|file` keep the private identity in the macOS Keychain, Windows DPAPI or Linux Secret Service instead of `~/.eyesonly/identity.json`. The key reaches the keychain tools on stdin only; moves are read back and compared before the old copy is removed; the long-running filter reads it once per git command. Also `eyesonly identity show` and `eyesonly identity export --yes` (base64 for `EYESONLY_IDENTITY`). `doctor` warns about a plain-file key. `EYESONLY_IDENTITY` still wins.
- `eyesonly audit --file <path> [--at <date|rev>] [--all-refs] [--json]`: who could read a file at a given moment, from the recipients (names and key ids) of the envelope version on the default branch (or every ref), plus the commit that introduced it. Follows renames across re-sealed envelopes.
- `eyesonly audit <user>` now lists each version with first/last dates, takes `--since`/`--until`, and has `--json`.
- `eyesonly offboard <user>`: revoke (GitHub mode) or print the server steps, re-encrypt what you can read, stage it, and write a rotation checklist with dotenv key names only.
- `eyesonly rotate <file> KEY=value... | --from-stdin`: set dotenv keys in a protected file, keeping comments and order, and stage it encrypted. Prints key names only.
- Admin API (server): `eyesonly admin --server <url> ...` manages users, repos, policies, grants and revokes over HTTPS, and `eyesonly admin sign` re-signs a signed policy remotely (the private key stays on your machine). Admin tokens (`eyesonly-server admin-token create|list|revoke`) are separate from git tokens and only work for the API; server admins (`init` makes its admin one; `eyesonly-server server-admin`) manage everything, repo admins their repos. Endpoint reference in docs/admin-api.md.
- Admin routes require HTTPS unless the client is on loopback; behind a TLS proxy set `EYESONLY_TRUST_PROXY=1` (the compose kit does).
- Failed logins back off per client address and user name, for git and the admin API (HTTP 429 with Retry-After; `EYESONLY_AUTH_MAX_FAILURES`, `EYESONLY_AUTH_LOCKOUT_MS`, `EYESONLY_AUTH_LOCKOUT_MAX_MS`).
- Audit log: `$EYESONLY_DATA/audit.log` records pushes (accepted or rejected, with refs and reason), failed logins and lockouts, policy fetches, admin actions from the CLI and the API, and installed signatures, never tokens. Each line hashes the previous one; `eyesonly-server audit-log --verify` finds edited, removed or inserted lines. Query with `audit-log --repo/--user/--type/--since/--json`.
- Private branches in GitHub mode (no server): branches under a policy prefix (`init` adds `private/` for the core group; `grant`/`revoke --branches <prefix>`) are sealed on the host as one opaque ref each, `refs/eyesonly/b/<random id>`: a git bundle of the commits since the default branch, encrypted for the prefix's audience, writer-signed inside the ciphertext, bound to its ref. `eyesonly branch push / pull / list / publish / delete`. Readers get identical commit ids and refuse forged, moved, rolled-back or forked versions (pinned per clone). The pre-push hook refuses pushing a private branch as a branch and pushing public refs that carry private commits; `branch publish` squashes with its own message. `eyesonly verify --ref` flags a private branch pushed in plaintext, `--sealed` shape-checks sealed refs without keys, and the Action's verify mode runs both. Policies from 0.4 keep working (no branch rules).
- GitHub mode: `writers` in the signed policy, like the server's, for files and sealed private branches. `eyesonly grant <name> --read-only` / `--writer` and `revoke <name> --writer`. Enforced by `branch push` / `branch pull`, `rotate`, the clean filter (an edit by a read-only member is refused; their unchanged checkout still works), rekey, the pre-commit re-seal, the merge driver, readers' smudge and `eyesonly run`, and `eyesonly verify`. The server's hook now also requires an envelope's signer to be a writer.
- `eyesonly-server import <repo.git> --policy .eyesonly/policy.json [--admin-card <card>]` and `eyesonly migrate --to <server-url>`: move a GitHub-mode repo onto a server. Members and keys come from the verified policy; the admin signs the server policy once with the same key; branch rules carry over, and `migrate` unseals the sealed private branches the admin can read into real branches the server hides; clones switch with `eyesonly setup --remote eyesonly --mode server` and keep their pinned admins (no more deleting trust.json). The first server version is above the repo policy's, and a lower version or an unpinned signer is refused.
- Server manifests list every admin (`admins`), and clients pin all of them, so any admin can sign the next version. `eyesonly whoami` prints the admin-pin fingerprint `EYESONLY_PIN_ADMIN` expects; `policy show` (now in both modes) and `status` print the pinned admins.
- `eyesonly verify --require-signed` (and the Action's `require-signed: true`): every commit must be SSH-signed by a member whose key is in the policy (`eyesonly grant <name> --ssh-signing-key <key>`), and protected-file edits and deletions are attributed to that signer and refused unless they may write the file.

## 0.4.0 (2026-11-22)
- Docs and website lead with GitHub mode (repo mode, no server) and present the server as the upgrade: new guides `docs/github-mode.md` and `docs/choosing-a-mode.md` (including moving from GitHub mode to the server), and both modes covered in existing-repos, CI, team workflows, troubleshooting and the policy reference.
- Repo mode: Eyes Only without a server. The admin-signed policy lives in `.eyesonly/policy.json` and is read from the default branch only (version-monotonic, admin keys pinned on first use); any git host works. Same commands as server mode; `setup`, `clone` and `pull-policy` detect the mode (an Eyes Only server behind the remote always wins), and a clone never switches modes silently (`--mode` to switch). New: `eyesonly init`, `join`, `grant`, `revoke`, `policy show`. See docs/repo-mode.md.
- `eyesonly verify` runs the server's content checks over a commit range against the policy in the repo (plus: policy changes must be signed by an earlier admin with a higher version). A pre-push hook runs it in repo-mode clones, and the GitHub Action has `mode: verify` for a required status check (no secrets).
- The server's pre-receive content checks moved to `src/validate.mjs`, shared with `verify`; behavior unchanged.
- `eyesonly-server init --admin <card> --repo <name.git>`: one-command bootstrap (admin user, first repo, starter policy with a `core` group for `.env` and `secrets/**` and private branches); prints the token once and the next commands. Refuses to touch an existing user or repo.
- `eyesonly-server user set-key <card>`: replace a user's keys (lost key, new machine) and keep their token; prints per-repo next steps (rekey, re-sign, re-pin).
- Envelopes record a key id per recipient, so `rekey`, `status` ("needs rekey (new key for bob)"), the pre-commit hook and the server notice a wrap made for an old public key. Before, a recipient whose key changed under the same name kept the old wrap forever. Older envelopes still open; `eyesonly rekey` upgrades them.
- `eyesonly clone` of an empty repo starts on `main` (protocol v0 can't advertise the unborn branch, so git fell back to `master`).
- Deploy kit: `deploy/docker-compose.yml` + `deploy/Caddyfile` for automatic HTTPS; the Docker image's data dir is mode 0700.
- `eyesonly run [--file <path>]... [--no-override] [--] <cmd>`: runs a command with protected dotenv files (default: every `.env` / `.env.*` you can read) loaded into its environment. Values are decrypted from the staged/committed blob with the same signature checks as the smudge filter, never from the working tree; a forged or moved envelope, or an explicit `--file` you can't read, aborts before the command starts. Exit codes and signals pass through.
- `eyesonly env [--format dotenv|json|shell]`: prints the same variables.
- `EYESONLY_IDENTITY`: the identity JSON (or base64 of it) from the environment; wins over `$EYESONLY_HOME/identity.json`. Error messages never echo it.
- GitHub Action (`uses: jagritvats/eyesonly@v0.3`): installs eyesonly, keeps the token in a job-scoped credential helper (never in URLs or git config), clones, and fails if a file the CI user should read stayed encrypted.
- Docs: separate secrets per environment; CI guide covers the action and `EYESONLY_IDENTITY`.
- `clone`'s identity-mismatch warning now says which identity files are decrypted as.
- Long-running filter process (`filter.eyesonly.process`, git's protocol v2): one process per git command instead of one per protected file. Advertises only `clean` and `smudge`, never `delay`. On Windows with 200 protected files: `git add` 33-51 s -> 4.3 s, `eyesonly clone` 23 s -> 6-9 s, `git status` after a touch 24-27 s -> 6.5 s. Single-shot clean/smudge stay configured as the fallback.
- `eyesonly setup --remote <name>` / `pull-policy --remote <name>`: use a remote other than `origin` for the Eyes Only server (remembered in `eyesonly.remote`), so GitHub can stay `origin`.
- `eyesonly clone https://user:token@...` hands the token to your git credential helper when one is configured and keeps only the user name in `.git/config`.
- Filter, merge and hook commands use `eyesonly` from PATH when it is the same package, so they survive node upgrades and package moves; otherwise absolute paths as before.
- `eyesonly doctor`: checks identity, remote, token storage, filters, hook, pinned attributes and policy freshness against the server; exits non-zero with a fix for each problem.
- The clean filter refuses ciphertext that was edited or doesn't verify (e.g. a non-reader's editor appended to `.env`) instead of letting the server reject it at push time.
- Envelopes whose line endings were converted (`core.autocrlf`) are repaired on smudge and clean, and `eyesonly status` reports them as `corrupted` instead of `decrypted`.

## 0.3.1 (2026-11-22)
- Fix: `eyesonly setup` in an existing clone now decrypts files for readers. It used to skip files whose stat matched the index (any freshly pulled envelope) and left the index stat stale.
- Fix: with `core.autocrlf=true` (Git for Windows' default) readers got ciphertext. The local attribute pin now sets `-text` on protected paths.
- Fix: protected files over about 786 KB stayed modified forever (1 MiB buffer limit in the client's git calls).
- Fix: `eyesonly clone` of an empty repo no longer crashes.
- Fix: `eyesonly demo` runs from PowerShell/cmd on Windows (uses Git for Windows' bash, not WSL's).
- Fix: `eyesonly-server serve --host X` without `--port` crashed.
- Clear one-line errors instead of stack traces (no repo, no `origin`, server unreachable, unreadable identity); URLs in errors have their passwords redacted; `clone` warns when there's no identity or it doesn't match the server's user; `keygen` validates names.
- Guides: existing repos and clones, team workflows, CI, server deployment, policy reference, troubleshooting; rendered at https://jagritvats.github.io/eyesonly/docs/.

## 0.3.0 (2026-11-22)
- Protected refs and read-only members: no force-push, rewind or deletion of protected refs; admins included for content checks.
- `filter=eyesonly` pinned in `.git/info/attributes`; redirected filters (LFS, nested `.gitattributes`) refused on client and server; `git worktree` and sparse-checkout fixed.
- Merge driver that verifies, 3-way merges and re-seals encrypted files.
- Outbound mirror that pushes only verified public refs to GitHub/GitLab/Gitea, fail closed.
- Security: object-level visibility allowlist in the pre-receive hook (orphaned private commits, tags pointing at trees or blobs, tree entries naming hidden blobs); attribute checks on every commit that touches a protected path.
- `eyesonly demo`: self-contained local demo.
- Renamed from Veil to Eyes Only.
- Crypto hardening: GCM auth tags must be exactly 16 bytes (Node otherwise accepts truncated tags).
- Requires Node >= 22 (Node 20 is end-of-life). Test scripts run under Git for Windows.

## 0.2.0 (2026-11-21)
- Admin-signed policy manifests and client-side admin key pinning, so a compromised server can't swap keys, add readers, roll back or downgrade the policy.
- Proxy filters `have`/`shallow` negotiation lines, closing the object-existence oracle.
- Pre-commit hook that re-encrypts on `git mv` and policy changes and refuses plaintext.

## 0.1.0 (2026-11-21)
- Clean/smudge encryption (X25519 + AES-256-GCM + Ed25519, path-bound), authenticating smart-HTTP proxy with per-user ref hiding and forced protocol v0, pre-receive policy enforcement, `rekey`, `audit`.
