# Troubleshooting

For developers and admins who hit an error: the message, what causes it, and how to fix it.

Client messages start with `[eyesonly]`. Server-side rejections show up in `git push`
output as `remote: [eyesonly] REJECTED: ...`. Admin CLI errors start with
`[eyesonly-server]`.

## Cloning and setup

### `no identity at ~/.eyesonly/identity.json. Run: eyesonly keygen <your-name>`

**Cause:** this machine has no key, or `EYESONLY_HOME` points somewhere else.
**Fix:** run `eyesonly keygen <name>` and send the card to your admin. If you keep the key
elsewhere, export `EYESONLY_HOME` in your shell profile. Git runs the filters with your
environment.

### `no eyesonly policy cached for this repo. Run: eyesonly setup`

**Cause:** this clone was made with plain `git clone`, or the policy cache was deleted.
**Fix:** `eyesonly setup` (or `eyesonly pull-policy`). See [existing-repos.md](existing-repos.md).

### `eyesonly needs an http(s) remote, got: <url>`

**Cause:** `origin` is a local path or an SSH URL. The client reads the policy from
`remote.origin.url`, and the server only speaks HTTP(S).
**Fix:** `git remote set-url origin https://<you>@git.example.com/app.git`, then `eyesonly setup`.

### `no credentials for <host>`

**Cause:** the remote URL has no token, and no git credential helper supplied one.
**Fix:** put the token in your credential helper, or in the URL
(`https://<you>:<token>@host/app.git`).

### `policy fetch failed: HTTP 401 authentication required`

**Cause:** wrong user name or token, or the user was removed.
**Fix:** check the user name in the URL. Ask the admin for a new token
(`eyesonly-server user token <name>`).

### `policy fetch failed: HTTP 404 not found`

**Cause:** the repo doesn't exist, you're not in `members`, or `origin` isn't the Eyes Only
server (for example, a GitHub mirror). The server gives the same answer for all of these.
**Fix:** check the URL and ask the admin to check `members`.

### `cloned into ...`, but readable files are still `EYESONLY-V1`

**Cause:** an older client (0.3.0) with Git for Windows' default `core.autocrlf=true`, or a
plain `git clone` that `eyesonly setup` didn't re-check out. Both are fixed in 0.3.1.
**Fix:** upgrade (`npm i -g eyesonly@latest`), then run `eyesonly setup` in the clone.

### `warning: no identity at ..., so nothing will be decrypted`

**Cause:** `eyesonly clone` ran without a key (or with `EYESONLY_HOME` pointing elsewhere).
The clone works, but every protected file stays ciphertext.
**Fix:** `eyesonly keygen <name>` (or set `EYESONLY_HOME`), then `eyesonly setup` in the clone.

### `this repo has no 'origin' remote`

**Cause:** `eyesonly setup` and `pull-policy` read the policy from the `origin` remote.
**Fix:** point `origin` at the Eyes Only server (keep GitHub under another name, e.g.
`github`). See [existing-repos.md](existing-repos.md).

### `can't reach <host>: ...`

**Cause:** the server is down, the URL is wrong, or you're offline.
**Fix:** check `git remote get-url origin` and that `https://<host>/healthz` answers `ok`.

## Committing

### `'.env' has filter=eyesonly in .gitattributes but no rule in the policy. Refusing to commit it in plaintext.`

**Cause:** `.gitattributes` protects a path that the server policy doesn't (anymore), or
your cached policy is old.
**Fix:** `eyesonly pull-policy`. If it still fails, ask the admin to add the rule back, or
remove the line from `.gitattributes`.

### `'junior' is not allowed to write '.env' (allowed: alice, bob)`

**Cause:** you're not in the file's audience, and you changed the file. If you can't read
a file, you can't write it either.
**Fix:** `git checkout -- .env`, or ask to be added to the rule.

### `` plaintext staged for protected path .env. Run `eyesonly setup` and re-add it (the eyesonly clean filter was bypassed). ``

**Cause:** the file was staged without the filter (another tool, a missing setup, or
`-c filter.eyesonly.clean=...`).
**Fix:** `eyesonly setup`, then `git add .env` again.

### `'<path>' resolves to filter=lfs (from .gitattributes); eyesonly requires filter=eyesonly.`

**Cause:** a `.gitattributes` line routes a protected path to another filter, such as
git-lfs.
**Fix:** remove that line, then run `eyesonly setup`. The server rejects such commits too:
`commit <sha> sets filter=lfs on protected path '<path>'`.

### `cannot rekey '.env' -> 'old.env': 'old.env' matches no eyesonly rule ...`

**Cause:** you renamed a protected file to a path no rule covers. It would stay
unreadable ciphertext at an unprotected path.
**Fix:** rename it to a protected path. If you really want it public, decrypt it and commit
the plaintext on purpose.

## Pushing

### `REJECTED: '.env' in <sha> is NOT encrypted. Refusing to store a plaintext secret.`

**Cause:** a protected file reached the server in plaintext, from a clone without
`eyesonly setup`, from `--no-verify`, or from a commit made before the path was protected.
**Fix:** `eyesonly setup`, then re-add and amend the commit. If the plaintext is in older
commits that were never pushed, rewrite them. If it's history from before Eyes Only, see
[existing-repos.md](existing-repos.md).

### `REJECTED: 'junior' may not modify protected file '.env' (<sha>)`

**Cause:** a commit changes a file you're not in the audience for. `may not delete` is the
same check for deletions.
**Fix:** drop the change (`git checkout origin/main -- .env`, then amend or rebase).

### `` REJECTED: '.env' in <sha> is encrypted to users outside the policy: bob. Run `eyesonly pull-policy && eyesonly rekey`. ``

**Cause:** your cached policy is older than the server's. Someone was removed, and your
commit still encrypts to them.
**Fix:** run what it says, `git commit --amend`, then push.

### `` REJECTED: '.env' in <sha> is encrypted for path 'config/.env'. Run `eyesonly rekey` after renaming protected files. ``

**Cause:** an envelope was copied or moved without re-encryption. Each envelope is bound to
its path.
**Fix:** `eyesonly rekey`, then amend. The pre-commit hook handles `git mv` on its own.

### `REJECTED: '.env' in <sha> has an invalid signature or its signer 'mallory' may not write it`

**Cause:** the ciphertext was produced by someone outside the file's audience, or was
tampered with.
**Fix:** treat it as suspicious. Restore the file from a trusted commit.

### `` REJECTED: pushing 'refs/heads/main' would expose commit <sha> from a branch with a narrower audience. Use `git merge --squash`. ``

**Cause:** a merge brings commits from a private branch into a more public one.
**Fix:** `git reset --hard origin/main`, then `git merge --squash private/x && git commit`.
See [team-workflows.md](team-workflows.md#private-branches).

### `REJECTED: pushing 'refs/heads/main' would expose N existing object(s) its audience can't see ...`

**Cause:** the push points a public ref at commits, trees or blobs from a private or
deleted branch that the server already has.
**Fix:** squash the content into new commits, or ask an admin, who may restore deleted
branches.

### `REJECTED: 'junior' may not push to 'refs/heads/private/x'`

**Cause:** the ref is under a `branches` rule you're not in.
**Fix:** push to another branch, or ask to be added to the rule.

### `[eyesonly] read-only access` (HTTP 403), or `REJECTED: 'junior' has read-only access to this repository`

**Cause:** you're a member but not in `writers`.
**Fix:** ask the admin to add you to `writers`.

### `REJECTED: 'bob' may not push to protected ref refs/heads/main` / `may not force-push` / `may not delete`

**Cause:** a `protect` rule (or the default protection of tags and the `HEAD` branch).
**Fix:** open the change on another branch for someone with access. Or rebase instead of
force-pushing.

### `REJECTED: push did not come through the eyesonly server (no authenticated user)`

**Cause:** someone pushed straight into the bare repo on the server's disk, bypassing the
proxy.
**Fix:** push through `https://.../app.git`. The hook refuses everything else, on purpose.

### `REJECTED: server git too old for attribute checks (need >= 2.40)`

**Cause:** the push touches `.gitattributes` or `.lfsconfig`, and the server's git is older
than 2.40.
**Fix (admin):** upgrade git on the server.

### `REJECTED: only admins may change .lfsconfig endpoints (lfs.url, remote.*.lfsurl, url.*.insteadOf)`

**Cause:** a non-admin changed where LFS uploads go.
**Fix:** ask an admin to make the change.

### `upload-pack request is larger than 10485760 bytes` (HTTP 413) on fetch

**Cause:** a fetch negotiation in a huge repo with many local refs.
**Fix (admin):** raise `EYESONLY_MAX_UPLOAD_PACK_BODY` on the server.

### `deepen-not is not supported by eyesonly ...` (HTTP 400)

**Cause:** `git fetch --shallow-exclude`.
**Fix:** use `--depth` or `--shallow-since`.

## Merging

### `` can't merge '.env': you are not a reader. Pick a side with `git checkout --ours/--theirs -- .env`, or ask one of: alice, bob ``

**Cause:** both sides changed a file you can't decrypt.
**Fix:** take one side, as it says, or let a reader do the merge.

### `can't merge '.env': theirs: signer 'junior' is not an allowed writer of '.env'`

**Cause:** the other branch carries an envelope from someone outside the file's audience.
The merge driver refuses rather than re-sign it under your name.
**Fix:** don't take that side. Find out how the envelope got there.

### `` conflict in '.env' (decrypted for you). Resolve it, then `git add .env` re-encrypts it. ``

Not an error. The working file holds plaintext with conflict markers. Fix them, then
`git add .env` and commit.

### `can't merge '.env': binary content; pick a side`

**Cause:** binary protected files aren't merged.
**Fix:** `git checkout --ours -- <path>` or `--theirs`.

## Decrypting

### `refusing to decrypt '.env': bad or unknown signature (signer 'mallory')`

**Cause:** the envelope's signer isn't in your cached policy, or the signature doesn't
verify. Your copy stays ciphertext, and you never see planted content.
**Fix:** `eyesonly pull-policy`. If it persists, the file was forged; restore it from a
trusted commit.

### `refusing to decrypt '.env': signer 'junior' is not an allowed writer of '.env'`

**Cause:** someone outside the file's audience produced this version.
**Fix:** same as above.

### `.env` shows `EYESONLY-V1 ...` and `git diff` shows `[eyesonly: encrypted, readable by alice, bob]`

**Cause:** you're not a reader, or the file hasn't been rekeyed since you were added.
**Fix:** `eyesonly status` shows the audience and whether it `needs rekey`. Ask a reader to
run `eyesonly pull-policy && eyesonly rekey` and push.

## Signed policy and pinning

Client errors appear as
`refusing the server's policy: <reason>. Nothing was changed; ask your admin (if the admin set really changed, delete .git/eyesonly/trust.json to re-pin).`

| Reason | Cause | Fix |
|---|---|---|
| `repo was signed; server now serves an unsigned policy` | the attestation was removed on the server, or the server is lying | the admin re-signs; don't override without checking |
| `policy signature invalid` | tampered or corrupt attestation | the admin re-signs |
| `attestation is for repo X, not Y` | the server serves another repo's signature | report it to the admin |
| `not signed by a pinned admin` | another admin signed | confirm out of band, then re-pin ([team-workflows.md](team-workflows.md#change-the-signing-admin-or-re-pin)) |
| `admin key does not match pinned fingerprint` | the admin's key changed, or `EYESONLY_PIN_ADMIN` is wrong | check the fingerprint ([policy-reference.md](policy-reference.md#pinning)) |
| `policy version N is older than last seen M` | rollback | the admin signs a new version |
| `policy version N was re-signed with different content` | the same version was signed twice | the admin signs a new version |

`warning: server policy changed since the last admin signature; using the signed policy`:
the admin changed the policy or users without re-signing. New readers can't read until
they do.

## Mirror

### `credential file /etc/eyesonly/gh-token must have mode 0600 (it has 644); run chmod 600 ...`

Run the `chmod`. The file must also be a regular file outside the repo directory, holding
one token line.

### `N allowlisted ref(s) skipped because they are not public; remove them from the allowlist`

**Cause:** an allowlisted ref is under a `branches` rule.
**Fix:** remove it with `mirror set ... --push ...`. Private refs are never mirrored.

### `commit <sha> is reachable only from a narrower-audience ref; not mirroring.`

**Cause:** a public branch gained commits that also live on a private branch.
**Fix:** check how they got there. If it's legitimate (a private branch forked from public
commits pushed since the last mirror), run `eyesonly-server mirror push app.git --trust-current`.

### `upstream rejected refs/heads/main (non-fast-forward); not retrying with force`

**Cause:** someone pushed straight to GitHub/GitLab.
**Fix:** turn on branch protection upstream so only the mirror's credential can push.
Reconcile by hand.

### `another mirror push is running (remove .../eyesonly-mirror.lock if it is stale)`

Two mirror pushes overlapped, usually from cron. Remove the lock only if no push is
running.

## Server

### Every push fails after upgrading Node

**Cause:** `hooks/pre-receive` holds the absolute path of the old Node binary.
**Fix:** rewrite the hooks ([server-deployment.md](server-deployment.md#upgrades)).
