# Existing repos and clones

For teams that already have a repo (on GitHub, GitLab or anywhere else) and people who
already have clones of it. New to Eyes Only? Run `npx eyesonly demo` first; it shows the whole
model in 30 seconds.

Every step below assumes an Eyes Only server is running
([server-deployment.md](server-deployment.md)) and that you have an identity and a token:

```bash
eyesonly keygen alice          # once per person; prints a public card
# send the card to your admin, who runs: eyesonly-server user add <card>  (prints your token)
```

## Pick your scenario

| You are... | Go to |
|---|---|
| The admin moving a repo onto Eyes Only | [Move an existing repo onto Eyes Only](#move-an-existing-repo-onto-eyes-only) |
| Starting to commit a `.env` that's in `.gitignore` today | [Start tracking a gitignored .env](#start-tracking-a-gitignored-env) |
| A teammate who already has a clone | [Onboard a teammate who already has a clone](#onboard-a-teammate-who-already-has-a-clone) |
| A new teammate with no clone yet | [New teammate: clone from scratch](#new-teammate-clone-from-scratch) |
| Rejected with `is NOT encrypted` on your first push | [History that already contains a plaintext secret](#history-that-already-contains-a-plaintext-secret) |

## Move an existing repo onto Eyes Only

The server becomes `origin`. GitHub can stay as a second remote, and later as a read-only
mirror of the public branches ([Mirroring](../README.md#mirroring-to-githubgitlab)).

**1. Check history for secrets you're about to protect.** The server checks every commit it
receives, including old ones, so a plaintext `.env` anywhere in history gets the push
rejected.

```bash
git log --all --oneline -- .env 'secrets/*'
```

No output: go on. Any output: read
[History that already contains a plaintext secret](#history-that-already-contains-a-plaintext-secret) first.

**2. Branches meant to be private** must live under the private prefix from your policy
(here `private/`) before you push them:

```bash
git branch -m launch private/launch
```

**3. Create the repo and its policy** (admin, on the server):

```bash
eyesonly-server repo create app.git --admin alice
eyesonly-server policy set app.git - <<'EOF'
{ "members": ["*"], "admins": ["alice"],
  "groups":   { "core": ["alice", "bob"] },
  "files":    { ".env": ["@core"], "secrets/**": ["@core"] },
  "branches": { "refs/heads/private/": ["@core"] } }
EOF
```

Field by field: [policy-reference.md](policy-reference.md).

**4. Point `origin` at Eyes Only, keep GitHub as `github`, push everything:**

```bash
git remote rename origin github
git remote add origin https://alice:<token>@git.example.com/app.git
git push -u origin --all
git push origin --tags
```

`eyesonly setup` and `eyesonly pull-policy` always read the policy from the `origin`
remote, so the Eyes Only server has to be `origin`. To keep the token out of
`.git/config`, see [Keep the token out of the remote URL](#keep-the-token-out-of-the-remote-url).

**5. Turn on encryption in your clone and commit the attributes:**

```bash
eyesonly setup
git add .gitattributes
git commit -m "eyesonly: encrypt protected paths"
git push
```

`setup` installs the filters, the pre-commit hook and the merge driver, and writes the
`filter=eyesonly` lines to `.gitattributes`. Commit that file so teammates' clients encrypt
the same paths.

**6. Tell the team** to follow [Onboard a teammate who already has a clone](#onboard-a-teammate-who-already-has-a-clone).
Until they switch remotes, their pushes still go to GitHub.

## Start tracking a gitignored .env

Most repos keep `.env` out of git and pass it around by hand. With Eyes Only it can live in
the repo, encrypted for the people the policy names.

```bash
eyesonly setup                       # if you haven't in this clone
sed -i '/^\.env$/d' .gitignore       # or remove the line in your editor
git add .gitignore .env
git commit -m "track .env (encrypted by eyesonly)"
git push
```

Check that it went up encrypted:

```bash
git show HEAD:.env | head -1         # EYESONLY-V1
cat .env                             # your plaintext, unchanged
eyesonly status                      # decrypted .env  [alice, bob]
```

The server rejects the push if `.env` arrives in plaintext (for example from a clone where
`eyesonly setup` was never run), so a mistake here can't leak the file.

Keep ignoring files that should stay local, like `.env.local`. Only paths that match a
`files` rule in the policy are encrypted. Anything else you commit is stored as normal.

## Onboard a teammate who already has a clone

For someone who cloned from GitHub before the move. **The order matters:** pull first, then
run setup.

```bash
git remote set-url origin https://bob:<token>@git.example.com/app.git
mv .env .env.before-eyesonly 2>/dev/null   # a local .env would block the pull
git pull
eyesonly setup
```

Then check:

```bash
eyesonly status          # decrypted .env [alice, bob]  (or "locked" if you're not a reader)
git status               # clean
```

Why this order:
- An untracked local `.env` (the copy you got over Slack) blocks `git pull` once `.env` is
  tracked: `untracked working tree files would be overwritten by merge`. Move it aside, and
  delete it once the decrypted one matches.
- Running `eyesonly setup` before pulling writes `.gitattributes` into your working tree.
  The pull then refuses to overwrite it. If that already happened:
  `rm .gitattributes && git pull && eyesonly setup`.

If you're not in the file's audience, `.env` stays `EYESONLY-V1 ...` ciphertext and
`git status` stays clean. You can work on everything else normally; the server rejects any
change you push to the protected file.

## New teammate: clone from scratch

```bash
eyesonly keygen bob                  # send the printed card to your admin, get a token
eyesonly clone https://bob:<token>@git.example.com/app.git
cd app
eyesonly status
```

`eyesonly clone` is `git clone` plus `eyesonly setup`: it decrypts what you can read and
leaves the rest as ciphertext. If it warns `no identity at ...`, you skipped `keygen` (or
`EYESONLY_HOME` points somewhere else); fix that and run `eyesonly setup` in the clone.

Already ran plain `git clone`? Run `eyesonly setup` inside it. That's the same thing.

## History that already contains a plaintext secret

If a secret was ever committed in plaintext, the server refuses to store that history:

```
remote: [eyesonly] REJECTED: '.env' in a84fc929 is NOT encrypted. Refusing to store a plaintext secret. Run `eyesonly setup` and recommit.
```

That secret has been readable by everyone with access to the old repo. Encrypting it now
doesn't change that, so:

1. **Rotate it.** New API keys, new database passwords. Do this regardless of what you do
   with history.
2. **Strip it from history**, then push. With [git-filter-repo](https://github.com/newren/git-filter-repo):

   ```bash
   git filter-repo --invert-paths --path .env      # repeat --path for each secret file
   git remote add origin https://alice:<token>@git.example.com/app.git   # filter-repo removes remotes
   git push -u origin --all && git push origin --tags
   ```

   This rewrites every commit hash. Everyone re-clones from Eyes Only afterwards (don't
   pull the old history back in), and the old GitHub repo should be archived or force-pushed
   from the new history.
3. **Commit the rotated values** as in [Start tracking a gitignored .env](#start-tracking-a-gitignored-env).

## Keep the token out of the remote URL

A token in the URL ends up in `.git/config` and in `git remote -v`. With a credential helper
(Git Credential Manager on Windows, osxkeychain on macOS, libsecret or `store` on Linux)
the URL holds only your user name:

```bash
git remote set-url origin https://bob@git.example.com/app.git
printf 'protocol=https\nhost=git.example.com\nusername=bob\npassword=%s\n\n' "$EYESONLY_TOKEN" | git credential approve
eyesonly pull-policy     # the client asks the same helper
```

## Next

- [team-workflows.md](team-workflows.md): giving and removing access, private branches, offboarding
- [ci.md](ci.md): reading protected files in CI
- [troubleshooting.md](troubleshooting.md): error messages and fixes
