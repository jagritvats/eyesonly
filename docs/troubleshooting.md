# Troubleshooting

For developers and admins who hit an error: the message, what causes it, and how to fix it.

Start with `eyesonly doctor` in the clone: it checks your identity, the remote and where
the token comes from, the filters and hook, the pinned attributes and whether the cached
policy matches the server, and prints a fix for each problem.

Client messages start with `[eyesonly]`. Server-side rejections show up in `git push`
output as `remote: [eyesonly] REJECTED: ...`; in GitHub mode `eyesonly verify` (pre-push
hook and CI) prints the same `REJECTED: ...` lines. Admin CLI errors start with
`[eyesonly-server]`. Errors specific to the policy in the repo are under
[GitHub mode](#github-mode).

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

**Cause:** server mode only (GitHub mode works with any URL). The remote eyesonly uses
(`origin`, or the one chosen with `--remote`) is a local path or an SSH URL, for example a
GitHub remote. The server only speaks HTTP(S).
**Fix:** if the Eyes Only server is another remote, `eyesonly setup --remote <name>`.
Otherwise `git remote set-url origin https://<you>@git.example.com/app.git`, then
`eyesonly setup`.

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

**Cause:** `eyesonly setup` and `pull-policy` read the policy from `origin` unless you chose
another remote with `--remote`.
**Fix:** `eyesonly setup --remote <name>` for the remote that points at the Eyes Only server
(remembered in `git config eyesonly.remote`), or add an `origin`. See
[existing-repos.md](existing-repos.md).

### `no remote named '<name>' in this repo`

**Cause:** `--remote` (or the remembered `eyesonly.remote`) names a remote that doesn't exist.
**Fix:** `git remote -v`, then `eyesonly setup --remote <existing-name>`.

### `smudge filter eyesonly failed` / `the configured filter command doesn't run` after moving node or eyesonly

**Cause:** the filters point at a node or eyesonly path that no longer exists (an nvm switch,
a cleared npx cache, a reinstall to another prefix). With `eyesonly` on your PATH, `setup`
writes `eyesonly ...` commands that survive this; otherwise it writes absolute paths.
**Fix:** `eyesonly setup` in the clone rewrites the commands for this machine.

### `can't reach <host>: ...`

**Cause:** the server is down, the URL is wrong, or you're offline.
**Fix:** check `git remote get-url origin` and that `https://<host>/healthz` answers `ok`.

### `EYESONLY_IDENTITY is set but is neither identity JSON nor base64 of it`

**Cause:** the variable holds something else: a truncated secret, a path, or base64 of the
wrong file. The message never repeats the value.
**Fix:** store the whole `identity.json` (or `base64 -w0 identity.json`) in the secret.
Unset the variable to fall back to `$EYESONLY_HOME/identity.json`.

### `refusing to load '.env': ...` / `you are not a reader of '.env.production'` (eyesonly run)

**Cause:** `eyesonly run` and `eyesonly env` only load files you can decrypt, and stop on any
envelope that fails verification (bad signer, moved from another path). An explicit
`--file` you can't read stops everything, and the command doesn't run.
**Fix:** ask a reader to add you (then they `rekey`), or drop that `--file`. Without
`--file`, unreadable files are skipped with a note.

### `note: .env has unstaged edits; using the staged version`

**Cause:** `eyesonly run` reads the staged blob, not the working tree.
**Fix:** `git add .env` to use your edits.

### `eyesonly status` shows `corrupted`, or `line endings were converted before decryption`

**Cause:** git converted the envelope's line endings (`core.autocrlf`) before eyesonly saw it,
usually because the clone predates the `-text` pin.
**Fix:** `eyesonly setup`. Smudge and clean undo the conversion either way, so nothing wrong
gets committed.

### `not a terminal: pass --yes to offboard without a prompt`

**Cause:** `eyesonly offboard` asks before changing the policy, and there's no terminal to ask in
(CI, a script, or input redirected).
**Fix:** add `--yes`.

### `<user> is still in the server's policy for <repo>. On the server, an admin runs: ...` (offboard)

**Cause:** in server mode the server holds the policy, so `offboard` can't remove the user itself.
It has already written the rotation checklist.
**Fix:** run the printed `eyesonly-server` commands on the server, then `eyesonly offboard <user> --yes`
again to re-encrypt for the remaining readers.

### `you can't write '.env' (writers: alice, bob)` (rotate)

**Cause:** `eyesonly rotate` only edits files whose audience includes you.
**Fix:** ask one of the listed people to rotate it, or an admin to grant you the file.

### `` '.env' isn't decrypted in this checkout: run `eyesonly setup` first `` (rotate)

**Cause:** the working copy still holds ciphertext (no identity when it was checked out, or a plain
`git clone`).
**Fix:** `eyesonly setup`, then run `rotate` again.

### `argument: expected KEY=value` / `stdin: expected KEY=value` (rotate)

**Cause:** one of the pairs isn't `KEY=value` (key: letters, digits and `_`, not starting with a
digit). The message never repeats the input, since it may hold a secret.
**Fix:** check the pairs. With `--from-stdin`, blank lines and `#` comments are skipped.

### `--at: '<x>' is not a date` (audit)

**Cause:** `--at` takes a commit, tag or branch, or a date: `YYYY-MM-DD` (end of that day, UTC),
an ISO timestamp, or a relative date like `2 weeks ago`.
**Fix:** use one of those forms. `--all-refs` only works with a date.

## Committing

### `` refusing to stage '.env': its ciphertext was edited or isn't valid (...). If you can't read it, restore it with: git checkout -- .env ``

**Cause:** you can't read the file, and its ciphertext no longer matches anything committed
or staged and doesn't verify: an editor or tool appended to it, it was hand-edited, or it's
an envelope signed by someone who may not write it. The server would reject it anyway.
**Fix:** `git checkout -- .env`. To change the file, ask someone in its audience
(`eyesonly status` lists them).

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

## GitHub mode

### `no Eyes Only policy found: remote 'origin' is not an Eyes Only server and the default branch has no .eyesonly/policy.json`

**Cause:** nobody has run `eyesonly init` on this repo yet, or its commit isn't on the
default branch (or isn't fetched).
**Fix:** `git pull`, or ask an admin to run `eyesonly init --commit` and push. If the policy
lives on another remote, use `--remote <name>`.

### `` you ('bob') aren't in this repo's policy yet: run `eyesonly join` and ask an admin to grant you ``

**Cause:** you can clone and work, but no protected file is encrypted for you.
**Fix:** `eyesonly join`, commit `.eyesonly/requests/bob.pub` in a pull request (or send the
card). After the admin's `grant` and `rekey` are pushed: `git pull && eyesonly pull-policy`.

### `warning: the policy has a different key for 'bob' than your identity; ask an admin to re-grant you`

**Cause:** you made a new key (`keygen` on a new machine) and the policy still has the old one.
**Fix:** send your new card; the admin runs `eyesonly grant bob --card <card>`, commits and
rekeys. Or copy your old `identity.json` to this machine.

### `only admins can change the policy ('bob' isn't one; admins: alice)`

**Cause:** `grant` / `revoke` re-sign the policy, which needs an admin's key.
**Fix:** ask an admin, or have one run `eyesonly grant bob --admin`.

### `.eyesonly/policy.json already exists. Use eyesonly setup, or eyesonly grant / revoke to change it.`

**Cause:** `eyesonly init` on a repo that is already set up.
**Fix:** `eyesonly setup` to use it; `grant` / `revoke` to change it.

### `origin (...) is an Eyes Only server: the server holds the policy.`

**Cause:** `eyesonly init` in a clone of a server repo. Server repos don't use a policy file.
**Fix:** the server admin runs `eyesonly-server init` / `policy set`; you run `eyesonly setup`.

### `this clone was set up in repo mode, but it now looks like server mode. Not switching silently`

**Cause:** the remote changed kind (for example the repo moved onto a server), or the
default branch gained a policy file in a server-mode clone.
**Fix:** if that's intended, `eyesonly setup --mode server` (or `--mode repo`). Moving to a
server also needs `rm .git/eyesonly/trust.json` first; see
[choosing a mode](choosing-a-mode.md#move-from-github-mode-to-the-server).

### `refusing the repo's policy: <reason>. Nothing was changed.`

| Reason | Cause | Fix |
|---|---|---|
| `policy signature invalid` | the file was edited by hand, or tampered with | restore it from the default branch; admins change it with `grant` / `revoke` |
| `policy is malformed or inconsistent (was it edited by hand? ...)` | hand edit or a bad merge of `.eyesonly/policy.json` | take the version from the default branch, redo the change with `grant` / `revoke` |
| `not signed by a pinned admin ('mallory' isn't one)` | someone who isn't a pinned admin signed it | don't override; ask your admin. If the admin set really changed, check out of band, then delete `.git/eyesonly/trust.json` |
| `policy version N is older than the last one seen here (M)` | a rollback | someone reverted the policy; ask the admin to re-sign a newer version |
| `policy belongs to a different repo (id ..., pinned ...)` | the policy file was copied from another repo | restore this repo's policy |
| `admin key ... does not match EYESONLY_PIN_ADMIN (...)` | your pin is wrong, or the admin key changed | check the fingerprint with `eyesonly policy show` and your admin |
| `this clone was set up against an Eyes Only server, not a policy in the repo` | a server clone now sees a policy file | see the mode-switch entry above |

### `REJECTED: ...` from `eyesonly verify` or `push blocked: fix the commits above (CI runs the same check). To push anyway: git push --no-verify`

**Cause:** the pre-push hook or CI ran `eyesonly verify`, which prints the same `REJECTED`
messages as the server (see [Pushing](#pushing)). Fix the commit (`eyesonly setup`, then
amend or recommit the file) rather than pushing with `--no-verify`: CI will fail the same
way, and in GitHub mode a plaintext push is readable on the host right away.

### `commit <sha> deletes .eyesonly/policy.json, which would turn off enforcement.`

**Cause:** a commit removes the policy file.
**Fix:** restore it. Admins change the policy with `grant` / `revoke`; moving to a server is
described in [choosing a mode](choosing-a-mode.md#move-from-github-mode-to-the-server).

### `.eyesonly/policy.json in <sha>: policy change signed by 'bob', who was not an admin before it`

**Cause:** a policy edit in the range wasn't signed by an admin of the previous policy. Same
for `policy version N doesn't increase (was M)`.
**Fix:** drop that commit; an admin makes the change with `grant` / `revoke`.

### `base commit '<sha>' isn't in this clone. Fetch full history` / `the checkout is shallow`

**Cause:** `verify` needs the base of the range. CI checkouts are shallow by default.
**Fix:** `actions/checkout` with `fetch-depth: 0`, or `git fetch --unshallow`.

### `note: '.env' deleted in <sha> (who did it can't be checked without a server)`

**Cause:** GitHub mode can't tell who made a commit, so deletions of protected files are
reported, not refused.
**Fix:** review it like any other change in the pull request.

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
