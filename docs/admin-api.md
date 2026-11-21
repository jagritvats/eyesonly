# Admin API

For server admins and repo admins who want to manage an Eyes Only server from their own
machine instead of a shell on the server. Server only; GitHub mode has no server to talk to
(see [github-mode.md](github-mode.md) for `eyesonly grant` there).

Everything here goes through `eyesonly admin` on your machine, which calls
`/_eyesonly/admin/v1/...` on the server. The server-side CLI (`eyesonly-server user add`,
`policy set`, ...) keeps working and does the same thing.

## Get an admin token

On the server, once:

```bash
eyesonly-server admin-token create alice --name laptop
# admin token 3f9c1a2b for alice (laptop). Shown once; it only works for the admin API, not for git:
# eyesonlyadm_3f9c1a2b_...
```

Store it in a file only you can read, and point the client at the server:

```bash
install -m 600 /dev/stdin ~/.eyesonly/admin-token <<<"eyesonlyadm_3f9c1a2b_..."
export EYESONLY_ADMIN_SERVER=https://git.example.com
alias eadmin='eyesonly admin --token-file ~/.eyesonly/admin-token'
eadmin whoami
# alice (server admin)
```

The token can also come from `EYESONLY_ADMIN_TOKEN`. The client never takes it as a
command-line argument, because argv shows up in `ps` and shell history.

- Admin tokens and git tokens are separate. An admin token can't clone or push, and a git
  token can't call the admin API.
- Who can hold one: a **server admin**, or an admin of at least one repo. `init` makes its
  admin a server admin; change the list with `eyesonly-server server-admin add|remove|list`.
- A token stops working when its user is removed or no longer admins anything.
- `eyesonly-server admin-token list` shows ids, users and labels (never the secret);
  `admin-token revoke <id>` kills one.

## Who can do what

| | Server admin | Repo admin |
|---|---|---|
| Add, remove, re-key users; rotate their git tokens | yes | no |
| Create repos | yes | no |
| List repos | all | the ones they admin |
| Read and change a repo's policy, grant, revoke | every repo | their repos |
| Install a signed policy | every repo (the signer must be a repo admin) | their repos |

A repo admin asking about a repo they don't admin gets the same `no such repo` as for a repo
that doesn't exist, so repo names don't leak.

## Common tasks

```bash
eadmin user add eyesonlypub1:eyJuYW1lIjoiYm9iIi...    # prints bob's git token, once
eadmin user list
eadmin grant bob --repo app.git --files .env           # bob can read .env
eadmin grant @core --repo app.git --branches refs/heads/release/
eadmin revoke bob --repo app.git --files .env
eadmin revoke bob --repo app.git                       # members, every file and branch rule, every group
eadmin user token bob                                  # new git token; the old one stops working
eadmin user set-key eyesonlypub1:...                   # bob's new laptop; token unchanged
eadmin user remove bob
eadmin repo create web.git --admin bob
eadmin policy get --repo app.git > policy.json         # edit, then:
eadmin policy set policy.json --repo app.git
```

After any change to who can read a file, someone who can read it runs
`eyesonly pull-policy && eyesonly rekey`, commits and pushes. The answers say so.

`grant` without `--files` or `--branches` adds the name to `members`; when `members` is
`["*"]` that changes nothing and says so. `revoke` without targets can't take someone out of
`"*"`; to cut a user off completely, `user remove` them.

## Signed policies, remotely

If the repo's policy is signed ([policy-reference.md](policy-reference.md#signed-policies)),
every change above makes the signature stale and the answer tells you to re-sign. Clients
keep using the last signed version until you do:

```bash
eadmin attestation --repo app.git
# app.git: signed v1 by alice, STALE (policy changed since; re-sign)
eadmin sign --repo app.git
# signing app.git policy v2 as alice: .env -> alice,bob; secrets/** -> alice
# installed app.git policy v2 signed by alice. Next: members pick it up with `eyesonly pull-policy`.
```

`sign` fetches the manifest, shows what you're signing, signs it on your machine with your
identity (the private key never leaves it) and installs the signature. The server checks it
exactly like `eyesonly-server policy attest`: the signer must be a repo admin with that
registered key, the manifest must match the current policy and the version must go up.

## HTTP reference

Base: `https://<server>/_eyesonly/admin/v1`. Every request needs
`Authorization: Bearer eyesonlyadm_...`. Bodies are JSON (`content-type: application/json`),
answers are JSON with `cache-control: no-store`. Errors are `{"error": "..."}` with a
meaningful status (400 bad input, 401 no or bad token, 403 not allowed or not HTTPS, 404,
405, 409 conflict, 413 body too large, 415 not JSON, 422 invalid policy or signature,
429 locked out with `Retry-After`).

| Method and path | Body | Who | Answer |
|---|---|---|---|
| `GET /whoami` | | any | `{user, server_admin, repo_admin: [repos]}` |
| `GET /users` | | any | `{users: [{name, fingerprint, created}]}` |
| `POST /users` | `{card}` | server admin | 201 `{name, fingerprint, token}` (git token, once) |
| `DELETE /users/:name` | | server admin | `{removed, next}` |
| `PUT /users/:name/key` | `{card}` (same name) | server admin | `{old_fingerprint, new_fingerprint, next: [...]}` |
| `POST /users/:name/token` | | server admin | `{token}` (new git token, once) |
| `GET /repos` | | any | `{repos}` (all, or the ones you admin) |
| `POST /repos` | `{name, admin}` | server admin | 201 `{repo, admin}` |
| `GET /repos/:repo/policy` | | admin of repo | `{policy, attestation: {signed, version, signer, stale}}` |
| `PUT /repos/:repo/policy` | `{policy}` | admin of repo | `{changed, changes, policy, attestation, next}` |
| `POST /repos/:repo/grant` | `{principal, files?, branches?}` | admin of repo | same as above, or `{changed: false, notes}` |
| `POST /repos/:repo/revoke` | `{principal, files?, branches?}` | admin of repo | same, plus `notes` |
| `GET /repos/:repo/attestation` | | admin of repo | `{signed, version, signer, stale}` |
| `GET /repos/:repo/manifest` | | admin of repo | `{manifest}` to sign (next version) |
| `POST /repos/:repo/attestation` | signed manifest (`eyesonly policy-sign` output) | admin of repo | `{installed, signer}` |

`principal` is a user name or `@group`; `files` and `branches` are a string or a list
(branch rules start with `refs/`). Policies go through the same validation as
`eyesonly-server policy set`.

```bash
curl -s -H "Authorization: Bearer $EYESONLY_ADMIN_TOKEN" \
  https://git.example.com/_eyesonly/admin/v1/repos/app.git/policy
```

## Security

- **HTTPS only.** Admin routes answer 403 over plain HTTP unless the client is on loopback.
  Behind a TLS proxy set `EYESONLY_TRUST_PROXY=1` (the compose kit does): the server then
  goes by the proxy's `X-Forwarded-Proto` and `X-Forwarded-For`, and loopback no longer
  counts, because every request arrives from the proxy. Only set it when nothing but the
  proxy can reach the server. `EYESONLY_ALLOW_INSECURE_ADMIN=1` turns the check off, for
  tests.
- **Failed logins back off**, for git and the admin API alike: after 5 failures from one
  address for one user, that pair is locked out for 1 s, doubling with each further failure
  up to 15 minutes; one address failing 20 times across user names is locked out too. A
  success clears it. State is in memory and resets on restart. Tune with
  `EYESONLY_AUTH_MAX_FAILURES`, `EYESONLY_AUTH_LOCKOUT_MS`, `EYESONLY_AUTH_LOCKOUT_MAX_MS`.
- **Bodies are capped** at 1 MiB (`EYESONLY_MAX_ADMIN_BODY`).
- **Tokens are stored hashed** (`admin-tokens.json`, mode 0600) and compared in constant time.
- **Everything is logged** in the audit log, with the acting user, never the token
  ([server-deployment.md](server-deployment.md#audit-log)).
- A signed policy still protects members against a compromised admin token: whoever holds
  it can change the server's policy, but clients only trust what a pinned admin signed with
  their own private key, which the API never sees.
