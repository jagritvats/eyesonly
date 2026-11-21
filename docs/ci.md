# CI

For anyone wiring CI to an Eyes Only repo: checking every commit, and giving a build read
access to the protected files it needs, and nothing more.

| Job | GitHub mode | Server |
|---|---|---|
| Block plaintext and forged secrets from merging | [`eyesonly verify` as a required check](#github-mode-eyesonly-verify-as-a-required-check) (no secrets) | the server already rejects them on push |
| Read secrets in a build | [checkout + identity + `eyesonly setup`](#github-mode-read-secrets-in-ci) | [the action's clone mode](#4-clone-in-the-job) |

## GitHub mode: `eyesonly verify` as a required check

Add [examples/eyesonly-verify.yml](examples/eyesonly-verify.yml) as
`.github/workflows/eyesonly.yml`:

```yaml
name: eyesonly
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0             # verify needs the base commit of the push or pull request
      - uses: jagritvats/eyesonly@v0.5
        with:
          mode: verify
```

Then protect `main` and mark `eyesonly / verify` as a required status check (Settings →
Rules, or Branch protection). Pull requests that add a plaintext secret, a forged or moved
envelope, a policy change not signed by an admin, or a `.gitattributes` line that routes a
protected path away from the filter can't be merged.

It needs no secrets: it reads the checkout and the signed policy on the default branch. It
fails on a shallow checkout (`the checkout is shallow; use actions/checkout with
fetch-depth: 0`). Input `range` overrides the default (the pull request's base..head, or the
push's before..after). On GitLab or other CI, run the same check by hand:

```bash
npx -y eyesonly verify --range "$BASE_SHA..$HEAD_SHA"
```

This catches a bad commit before it merges; it can't un-publish a plaintext file someone
pushed to a branch. Rotate anything that `verify` reports as plaintext.

## GitHub mode: read secrets in CI

CI gets its own identity and is granted only the files it needs:

```bash
EYESONLY_HOME=./ci-identity eyesonly keygen ci-bot     # on a trusted machine; prints the card
eyesonly grant ci-bot --card eyesonlypub1:... --files .env.ci        # admin, in the repo
git add .eyesonly .gitattributes && git commit -m "eyesonly: ci-bot reads .env.ci"
eyesonly rekey && git commit -am "rekey for ci-bot" && git push
```

Store `ci-identity/identity.json` (raw or base64; `eyesonly identity export --yes` prints the
base64 form) as the secret `EYESONLY_IDENTITY`, delete
the directory, and store the admin fingerprint from `eyesonly policy show` as the variable
`EYESONLY_PIN_ADMIN`. Then:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read                 # the job can't push, even though ci-bot's key could sign .env.ci
    env:
      EYESONLY_IDENTITY: ${{ secrets.EYESONLY_IDENTITY }}
      EYESONLY_PIN_ADMIN: ${{ vars.EYESONLY_PIN_ADMIN }}
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0             # setup reads the policy from origin's default branch
      - uses: actions/setup-node@v7
        with:
          node-version: 22
      - run: npm i -g eyesonly
      - run: eyesonly setup && ! head -c 11 .env.ci | grep -q EYESONLY-V1   # fail if it stayed encrypted
      - run: eyesonly run --file .env.ci -- npm test
```

`eyesonly setup` in a plain checkout decrypts what `ci-bot` can read. In GitHub mode the
grant is the whole authorization: any member in a file's audience can also sign a new version
of it, so keep CI tokens read-only.

## Server mode

CI is just another user with its own key. Give it read access to the files it needs, keep
it out of `writers`, and store its key and token as CI secrets.

### 1. Create a CI identity

On a trusted machine, in a throwaway directory:

```bash
EYESONLY_HOME=./ci-identity eyesonly keygen ci-bot
# [eyesonly] created identity 'ci-bot' (fingerprint ...) at ./ci-identity/identity.json
# eyesonlypub1:...                      <- the public card
```

`EYESONLY_HOME` is where the client keeps `identity.json` (default `~/.eyesonly`). The
same variable tells every later `eyesonly` command, and every git filter it installs,
where to find the key.

### 2. Register it and grant read access

On the server:

```bash
eyesonly-server user add eyesonlypub1:...      # prints the token once
```

In the policy, add `ci-bot` to the file rules CI needs. Keep it out of `writers`, so the
key can't be used to push:

```json
{
  "members": ["*"],
  "admins":  ["alice"],
  "groups":  { "core": ["alice", "bob"] },
  "writers": ["@core"],
  "files":   { ".env.ci": ["@core", "ci-bot"], ".env": ["@core"] }
}
```

Then:

- a current reader runs `eyesonly pull-policy && eyesonly rekey`, commits and pushes, so
  the files are encrypted to `ci-bot`;
- if the policy is signed, re-sign it ([policy-reference.md](policy-reference.md#signed-policies)).

Read access to a protected file normally includes write access. Leaving `ci-bot` out of
`writers` is what keeps it read-only: its pushes get `[eyesonly] read-only access`.

### 3. Store two secrets

| Secret | Value |
|---|---|
| `EYESONLY_IDENTITY` | the contents of `ci-identity/identity.json` (raw JSON, or `base64` of it) |
| `EYESONLY_TOKEN` | the token from `user add` |

Then delete `ci-identity/`. The JSON file holds the private key, unencrypted.

If the policy is signed, also store the admin's policy fingerprint as a non-secret variable
`EYESONLY_PIN_ADMIN`. Every CI run clones fresh, so without a pin each run trusts whichever
admin signature the server presents (trust on first use).

### 4. Clone in the job

#### GitHub Actions: the eyesonly action

```yaml
name: build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest          # macos-latest and windows-latest work too
    env:
      EYESONLY_PIN_ADMIN: ${{ vars.EYESONLY_PIN_ADMIN }}   # omit if the policy isn't signed
    steps:
      - uses: jagritvats/eyesonly@v0.5
        with:
          url: https://git.example.com/app.git
          user: ci-bot
          token: ${{ secrets.EYESONLY_TOKEN }}
          identity: ${{ secrets.EYESONLY_IDENTITY }}
          path: app
      - run: npm ci && npm test
        working-directory: app
      - run: eyesonly run -- ./scripts/smoke-test.sh     # .env values as environment variables
        working-directory: app
```

What the action does:

- installs Node 22 if the runner has an older one, then `npm i -g eyesonly` (input `version`
  pins it);
- writes the identity to a 0600 file under `$RUNNER_TEMP` and sets `EYESONLY_HOME` for the
  rest of the job;
- gives git the token through a credential helper set with `GIT_CONFIG_*` variables for this
  job only. The token never appears in the URL, `.git/config` or `~/.gitconfig`, and is
  masked in logs;
- runs `eyesonly clone`, then fails the step if a file `ci-bot` is a reader of stayed
  encrypted (wrong identity secret, or nobody ran `eyesonly rekey` after `ci-bot` was
  added). Set `allow-locked: true` to continue anyway.

Later steps can run `git pull`, `git fetch` and `eyesonly run` without extra setup. Output
`path` is the clone's absolute path.

On a self-hosted runner, `$RUNNER_TEMP` is cleaned between jobs by the runner; the git
configuration lives only in the job's environment.

#### Without the action

The client reads `EYESONLY_IDENTITY` straight from the environment, so a job-level `env`
is enough. Give git the token through a credential helper:

```yaml
    env:
      EYESONLY_IDENTITY: ${{ secrets.EYESONLY_IDENTITY }}
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm i -g eyesonly
      - name: Clone with secrets
        env:
          EYESONLY_TOKEN: ${{ secrets.EYESONLY_TOKEN }}
        run: |
          git config --global credential.helper "store --file $RUNNER_TEMP/git-credentials"
          printf 'https://ci-bot:%s@git.example.com\n' "$EYESONLY_TOKEN" > "$RUNNER_TEMP/git-credentials"
          eyesonly clone https://ci-bot@git.example.com/app.git app
          ! head -c 11 app/.env.ci | grep -q EYESONLY-V1      # fail fast if it stayed encrypted
```

Notes:

- `EYESONLY_IDENTITY` (JSON or base64) wins over `$EYESONLY_HOME/identity.json`. Set it at
  job level, not just on the clone step: git runs the `eyesonly` filters itself during
  checkout, merges and `git add`, and the filters read the same variable.
- With no password in the URL, the client asks git's credential helper. This keeps the token
  out of `.git/config`, which is where `eyesonly clone https://ci-bot:<token>@...` would
  leave it.
- Error messages redact the password part of URLs, but git itself and your CI's command
  echo may not. Another reason to use the credential helper.
- A clone without an identity, or with the wrong key, still succeeds (with a warning). The
  files just stay ciphertext, hence the check above.

## Use the secrets in a job (both modes)

`eyesonly run` loads protected dotenv files into a command's environment, decrypted from the
committed blobs, so nothing extra is written to disk:

```bash
eyesonly run -- npm test                               # every .env / .env.* this user can read
eyesonly run --file .env.ci -- ./deploy.sh             # just one file; refuses if unreadable
eyesonly env --format shell > "$RUNNER_TEMP/env.sh"    # or export them for later steps (writes secrets to a file)
```

Values in the file win over variables already set; `--no-override` flips that.

## Other CI systems

The steps are the same anywhere:

1. Install Node 22+, git and `npm i -g eyesonly`.
2. Put the identity JSON (or base64 of it) in `EYESONLY_IDENTITY` for the whole job, or
   write it to `$EYESONLY_HOME/identity.json` with mode 600.
3. Make the token available to git's credential helper, or embed it in the URL.
4. Run `eyesonly clone`, with `EYESONLY_PIN_ADMIN` set if the policy is signed.

## CI on a GitHub/GitLab mirror (server)

With `eyesonly-server mirror`, GitHub or GitLab gets your public branches, so its CI runs on
them. Here's what that CI can and can't do:

- The mirror carries **ciphertext**. A normal `actions/checkout` gives the build
  `EYESONLY-V1` envelopes for every protected file. Builds and tests that don't need secrets
  work as usual.
- Private branches are never mirrored, so CI never runs on them there.
- To decrypt on the mirror's CI, the job needs the CI identity **and** network access to
  your Eyes Only server. Smudging verifies each envelope's signer against the policy, which
  comes from the server. Clone from the Eyes Only server, as above, instead of using the
  mirror checkout.
- `eyesonly setup` in a mirror checkout fails: it reads the policy from `origin`, which is
  GitHub (`eyesonly needs an http(s) remote` or a 404).
- Secrets that only CI needs (deploy keys, registry tokens) can live in the CI system's own
  secret store instead. Keep protected files for secrets that developers and CI share.

## Least privilege

- Use one CI user per pipeline or environment (`ci-staging`, `ci-prod`), each in only the
  file rules it needs.
- Split secrets by audience: `.env.ci` for CI, `.env` for developers, `deploy/prod.env` for
  the prod deploy user only.
- Keep CI users out of `writers` and out of `branches` rules, unless CI must build private
  branches.
- To revoke CI: `eyesonly-server user remove ci-bot`, then rotate what `eyesonly audit ci-bot`
  lists ([team-workflows.md](team-workflows.md#offboard-someone)).
- Rotate the token alone with `eyesonly-server user token ci-bot`.
