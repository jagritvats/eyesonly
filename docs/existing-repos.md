# Existing repos and clones

For teams that already have a repo (on GitHub, GitLab or anywhere else) and people who
already have clones of it. New to Eyes Only? Run `npx eyesonly demo` first; it shows the whole
model in 30 seconds.

There are two ways in, with the same commands afterwards ([choosing a mode](choosing-a-mode.md)):

- **GitHub mode:** the repo stays where it is. Nothing to run. Start here.
- **Server:** the repo moves onto an Eyes Only server (GitHub can stay as a mirror). Pushes
  are checked before they're stored, and private branches become possible.

Everyone needs an identity first:

```bash
eyesonly keygen alice          # once per person; prints a public card
```

## Pick your scenario

| You are... | Mode | Go to |
|---|---|---|
| The admin adding Eyes Only to your GitHub repo | GitHub | [Add Eyes Only to your existing GitHub repo](#add-eyes-only-to-your-existing-github-repo) |
| A teammate with a clone of that repo | GitHub | [Teammates in GitHub mode](#teammates-in-github-mode) |
| The admin moving a repo onto the server | Server | [Move an existing repo onto the Eyes Only server](#move-an-existing-repo-onto-the-eyes-only-server) |
| A teammate whose repo moved to the server | Server | [Onboard a teammate who already has a clone](#onboard-a-teammate-who-already-has-a-clone) |
| Starting to commit a `.env` that's in `.gitignore` today | Both | [Start tracking a gitignored .env](#start-tracking-a-gitignored-env) |
| A new teammate with no clone yet | Both | [New teammate: clone from scratch](#new-teammate-clone-from-scratch) |
| Rejected with `is NOT encrypted` | Both | [History that already contains a plaintext secret](#history-that-already-contains-a-plaintext-secret) |

## Add Eyes Only to your existing GitHub repo

No server: the signed policy is committed in the repo. Works the same on GitLab, Gitea or a
bare repo over SSH.

**1. Check history** for secrets you're about to protect:

```bash
git log --all --oneline -- .env 'secrets/*'
```

Anything listed has been readable by everyone with repo access: rotate it, and strip it if
you can ([history](#history-that-already-contains-a-plaintext-secret)).

**2. Initialize** in your clone (you become the admin):

```bash
eyesonly init --commit        # .env and secrets/** for @core; or --files .env,config/prod.json
git push
```

Protected files that were tracked in plaintext are encrypted in that commit. To start
committing a `.env` you've been ignoring, see [Start tracking a gitignored .env](#start-tracking-a-gitignored-env).

**3. Require the check.** Add [the verify workflow](examples/eyesonly-verify.yml) as
`.github/workflows/eyesonly.yml`, protect `main`, and mark `eyesonly / verify` as required.

**4. Add teammates** with `join` and `grant` ([next section](#teammates-in-github-mode)).

Full guide: [GitHub mode](github-mode.md).

## Teammates in GitHub mode

A teammate with an existing clone pulls the admin's commit, then:

```bash
mv .env .env.before-eyesonly 2>/dev/null   # a local .env would block the pull once .env is tracked
git pull
eyesonly setup                             # mode is detected; installs filters and a pre-push hook
eyesonly join                              # writes .eyesonly/requests/<you>.pub
```

Commit the request on a branch and open a pull request (or send the printed card to the admin).
The admin runs `eyesonly grant <name> --from-request`, commits, runs `eyesonly rekey`,
commits and pushes. Then:

```bash
git pull && eyesonly pull-policy
eyesonly status                            # decrypted .env [alice, bob]
```

Until then, protected files stay `EYESONLY-V1 ...` ciphertext and everything else works as usual.

## Move an existing repo onto the Eyes Only server

You need a running server ([server-deployment.md](server-deployment.md)), and every member
registered on it (`eyesonly-server user add <card>` prints their token). The server becomes
`origin`. GitHub can stay as a second remote, and later as a read-only mirror of the public
branches ([Mirroring](../README.md#mirroring-to-githubgitlab-server)). Already in GitHub mode?
See [choosing a mode](choosing-a-mode.md#move-from-github-mode-to-the-server).

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

Rather keep GitHub as `origin`? Add the Eyes Only server under another name and tell
eyesonly once; it remembers the choice (`git config eyesonly.remote`):

```bash
git remote add eyes https://alice:<token>@git.example.com/app.git
git push -u eyes --all && git push eyes --tags
eyesonly setup --remote eyes
```

Then push to `eyes` for anything protected or private. To keep the token out of
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

If `.env` would go up in plaintext (for example from a clone where `eyesonly setup` was never
run), the pre-push hook blocks it in GitHub mode and the server rejects it in server mode. In
GitHub mode, someone pushing without the client is caught by the required `eyesonly verify`
check, but by then the file is readable on the host: rotate it.

Keep ignoring files that should stay local, like `.env.local`. Only paths that match a
`files` rule in the policy are encrypted. Anything else you commit is stored as normal.

## Onboard a teammate who already has a clone

Server mode: for someone who cloned from GitHub before the move. (GitHub mode:
[Teammates in GitHub mode](#teammates-in-github-mode).) **The order matters:** pull first,
then run setup.

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
eyesonly doctor          # identity, remote, filters, hook, policy freshness: says how to fix anything off
```

Keeping GitHub as `origin`: add the server as another remote instead, pull from it, and
point eyesonly at it:

```bash
git remote add eyes https://bob:<token>@git.example.com/app.git
mv .env .env.before-eyesonly 2>/dev/null
git pull eyes main
eyesonly setup --remote eyes
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
eyesonly keygen bob
eyesonly clone git@github.com:acme/app.git                # GitHub mode: any URL, then `eyesonly join`
eyesonly clone https://bob:<token>@git.example.com/app.git   # server: send your card to the admin first, get a token
cd app
eyesonly status
```

`eyesonly clone` is `git clone` plus `eyesonly setup`, in either mode: it decrypts what you can
read and leaves the rest as ciphertext. If it warns `no identity at ...`, you skipped `keygen` (or
`EYESONLY_HOME` points somewhere else); fix that and run `eyesonly setup` in the clone.

Already ran plain `git clone`? Run `eyesonly setup` inside it. That's the same thing.

## History that already contains a plaintext secret

If a secret was ever committed in plaintext, the server refuses to store that history:

```
remote: [eyesonly] REJECTED: '.env' in a84fc929 is NOT encrypted. Refusing to store a plaintext secret. Run `eyesonly setup` and recommit.
```

In GitHub mode nothing is rejected (that history is already on the host), but the old
versions stay readable by everyone with repo access, and `eyesonly verify` prints the same
message for any new plaintext commit.

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

Server mode only; in GitHub mode you use your host's normal credentials. A token in the URL ends up in `.git/config` and in `git remote -v`. With a credential helper
(Git Credential Manager on Windows, osxkeychain on macOS, libsecret or `store` on Linux)
the URL holds only your user name.

`eyesonly clone https://you:<token>@...` does this for you when a helper is configured: the
token goes to the helper and the stored URL keeps only your user name (without a helper it
says so and keeps the token in the URL). For an existing clone:

```bash
git remote set-url origin https://bob@git.example.com/app.git
printf 'protocol=https\nhost=git.example.com\nusername=bob\npassword=%s\n\n' "$EYESONLY_TOKEN" | git credential approve
eyesonly pull-policy     # the client asks the same helper
```

## Next

- [github-mode.md](github-mode.md): everything about GitHub mode
- [team-workflows.md](team-workflows.md): giving and removing access, private branches, offboarding
- [ci.md](ci.md): `eyesonly verify` as a required check, reading protected files in CI
- [troubleshooting.md](troubleshooting.md): error messages and fixes
