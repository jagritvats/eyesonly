# CI

For anyone wiring CI to an Eyes Only repo: how a build gets read access to protected files, and nothing more.

CI is just another user with its own key. Give it read access to the files it needs, keep
it out of `writers`, and store its key and token as CI secrets.

## 1. Create a CI identity

On a trusted machine, in a throwaway directory:

```bash
EYESONLY_HOME=./ci-identity eyesonly keygen ci-bot
# [eyesonly] created identity 'ci-bot' (fingerprint ...) at ./ci-identity/identity.json
# eyesonlypub1:...                      <- the public card
```

`EYESONLY_HOME` is where the client keeps `identity.json` (default `~/.eyesonly`). The
same variable tells every later `eyesonly` command, and every git filter it installs,
where to find the key.

## 2. Register it and grant read access

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

## 3. Store two secrets

| Secret | Value |
|---|---|
| `EYESONLY_IDENTITY` | the full contents of `ci-identity/identity.json` |
| `EYESONLY_TOKEN` | the token from `user add` |

Then delete `ci-identity/`. The JSON file holds the private key, unencrypted.

If the policy is signed, also store the admin's policy fingerprint as a non-secret variable
`EYESONLY_PIN_ADMIN`. Every CI run clones fresh, so without a pin each run trusts whichever
admin signature the server presents (trust on first use).

## 4. Clone in the job (GitHub Actions)

```yaml
name: build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      EYESONLY_PIN_ADMIN: ${{ vars.EYESONLY_PIN_ADMIN }}   # omit if the policy isn't signed
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm i -g eyesonly@0.3.1
      - name: Restore CI identity
        env:
          EYESONLY_IDENTITY: ${{ secrets.EYESONLY_IDENTITY }}
        run: |
          mkdir -p ~/.eyesonly && chmod 700 ~/.eyesonly
          printf '%s' "$EYESONLY_IDENTITY" > ~/.eyesonly/identity.json
          chmod 600 ~/.eyesonly/identity.json
      - name: Clone with secrets
        env:
          EYESONLY_TOKEN: ${{ secrets.EYESONLY_TOKEN }}
        run: |
          git config --global credential.helper "store --file $HOME/.eyesonly/git-credentials"
          printf 'https://ci-bot:%s@git.example.com\n' "$EYESONLY_TOKEN" > ~/.eyesonly/git-credentials
          chmod 600 ~/.eyesonly/git-credentials
          eyesonly clone https://ci-bot@git.example.com/app.git app
      - run: npm ci && npm test
        working-directory: app
```

Notes:

- The identity goes in the default location, `~/.eyesonly`. If you use `EYESONLY_HOME`
  instead, set it for every step that runs git in the repo, not just the clone. Git runs
  the `eyesonly` filters itself during checkout, merges and `git add`, and the filters read
  the same variable.
- With no password in the URL, the client asks git's credential helper. This keeps the token
  out of `.git/config`, which is where `eyesonly clone https://ci-bot:<token>@...` would
  leave it.
- Error messages redact the password part of URLs, but git itself and your CI's command
  echo may not. Another reason to use the credential helper.
- A clone without `EYESONLY_HOME` set, or with the wrong key, still succeeds (with a
  warning). The files just stay ciphertext. Fail fast with a check:

```bash
! head -c 11 app/.env.ci | grep -q EYESONLY-V1
```

## Other CI systems

The steps are the same anywhere:

1. Install Node 22+, git and `npm i -g eyesonly`.
2. Write the identity JSON to `$EYESONLY_HOME/identity.json` with mode 600.
3. Make the token available to git's credential helper, or embed it in the URL.
4. Run `eyesonly clone`, with `EYESONLY_HOME` (and `EYESONLY_PIN_ADMIN`) set for every git
   command that follows.

## CI on a GitHub/GitLab mirror

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
