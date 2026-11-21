# Policy reference

For repo admins writing `eyesonly.json`: every field, how matching works, and how to sign a policy.

This page covers the server's policy. In [GitHub mode](github-mode.md) the policy lives in the
repo instead; see [GitHub mode policy](#github-mode-policy) at the end.

Each repo has one policy, stored on the server at `repos/<name>.git/eyesonly.json`. You
manage it with:

```bash
eyesonly-server policy show app.git
eyesonly-server policy set app.git policy.json     # or `-` for stdin; validated before saving
```

After a change that affects files, members should run `eyesonly pull-policy && eyesonly rekey`
(see [team-workflows.md](team-workflows.md)).

## Example

```json
{
  "members":  ["*"],
  "admins":   ["alice"],
  "groups":   { "core": ["alice", "bob"], "release": ["alice"] },
  "writers":  ["@core", "junior"],
  "files":    { ".env": ["@core", "ci-bot"], "secrets/**": ["@core"] },
  "branches": { "refs/heads/private/": ["@core"] },
  "protect":  { "refs/heads/main": { "push": ["@release"] } }
}
```

## Principals

Every list of people takes these entries:

| Entry | Means |
|---|---|
| `"alice"` | the registered user `alice` |
| `"@core"` | every user listed in `groups.core` |
| `"*"` | every registered user |

Rules:

- Names that aren't registered users (`eyesonly-server user list`) are ignored. They can't
  authenticate, so they never count.
- Groups list plain user names. Groups inside groups (`"@other"`) and `"*"` inside a group
  are ignored.
- Admins get no special read access to files. List them in `files` if they need to read.

## Fields

### `members` (required)

Who may access the repo at all. Anyone else gets `404 not found` for every URL under the
repo, the same answer as for a repo that doesn't exist.

### `admins`

Who may sign the policy, bypass `protect` rules, change LFS endpoints in `.lfsconfig`, and
restore objects from deleted private branches. `repo create --admin <user>` sets the first one. Admins can't push invalid
secrets. The content checks apply to them too.

### `groups`

`{ "name": ["user", ...] }`. Referenced as `@name`.

### `writers`

Who may push. Default: everyone in `members`. Admins can always push. Anyone else in
`members` is read-only: they can clone and fetch, but pushes get HTTP 403
`[eyesonly] read-only access` from the server, and the hook rejects them too.

### `files`

`{ "glob": [principals] }`. Each matching path is encrypted to exactly those users. The
same users are the only ones who may change or delete the file. For protected files,
readers and writers are the same set.

Matching:

- The **first** matching glob wins, in the order written.
- Globs are anchored at the repo root. `.env` matches only the top-level `.env`. Use
  `**/.env` for every `.env` in the tree.
- `*` matches within one path segment, `**/` matches zero or more directories, `**`
  elsewhere matches anything, and `?` matches one character. There are no `[...]`
  character classes; brackets match literally.

| Glob | Matches | Doesn't match |
|---|---|---|
| `.env` | `.env` | `api/.env` |
| `**/.env` | `.env`, `api/.env` | `.env.local` |
| `.env*` | `.env`, `.env.local` | `api/.env` |
| `secrets/**` | `secrets/a`, `secrets/x/y` | `secrets` |
| `config/*.key` | `config/prod.key` | `config/x/prod.key` |

`eyesonly setup`, `clone` and `pull-policy` translate these globs into `filter=eyesonly`
lines in `.gitattributes` and `.git/info/attributes`. Commit the `.gitattributes` change so
other clients encrypt the new paths too.

### `branches`

`{ "refs/...": [principals] }`. Refs that match a rule are visible only to those users.
Refs that match no rule are public to all `members`.

- Every key must start with `refs/`.
- A key ending in `/` is a prefix: `refs/heads/private/` covers `private/launch` and
  `private/x/y`.
- A key without a trailing `/` covers that exact ref and everything below it:
  `refs/heads/release` covers `release` and `release/1.0`.
- For pushes and the merge check, the **longest** matching key decides the audience.
- For hiding, every matching key counts. If any rule that covers a ref leaves you out, the
  ref is hidden from you. A nested rule can narrow a namespace, but it can't open one branch
  in it to extra people. Give such a branch its own namespace instead:

```json
"branches": {
  "refs/heads/private/": ["@core"],
  "refs/heads/shared/":  ["@core", "designer"]
}
```

For users outside a rule, those refs aren't listed by `git ls-remote` or fetched, can't be
fetched by SHA, and can't be pushed to (`'junior' may not push to 'refs/heads/private/x'`).

Commits from a branch can't reach a branch with a wider audience. A plain
`git merge private/x` into `main` is refused, and `git merge --squash` works. See
[team-workflows.md](team-workflows.md#private-branches).

### `protect`

Branch protection: `{ "refs/...": { "push": [...], "force": [...], "delete": [...] } }`.
All three keys are optional.

| Key | When missing |
|---|---|
| `push` | `writers` may push |
| `force` | only admins may force-push |
| `delete` | only admins may delete |

- The longest matching prefix wins, the same as `branches`.
- Admins bypass `protect`.
- Moving a tag counts as a force-push.
- **Without a `protect` section,** non-admins can't force-push or delete tags
  (`refs/tags/`) or the branch `HEAD` points to (usually `main`).
- With a `protect` section, only the rules you write apply. Add
  `"refs/tags/": { "force": [], "delete": [] }` if you still want tags locked.

### Other keys

Keys not listed above are ignored without a warning. A typo such as `"branch"` silently
does nothing, so check `eyesonly-server policy show` after a change.

## What clients see

`GET /<repo>/eyesonly/policy` returns, for the signed-in user:

- `files`, with each glob expanded to the final list of user names;
- the public keys of everyone in a file audience;
- the user's own name;
- the signed manifest, if there is one.

It never includes `branches`, `protect`, `writers`, `groups`, `members` or `admins`. Branch
names would reveal that private branches exist.

## Validation errors

`policy set` refuses a policy with `invalid policy: <reason>`:

| Reason | Fix |
|---|---|
| `members must be a list of names` | `members` is required and must be an array of strings |
| `admins must be a list of names` | same for `admins` |
| `groups.<g> must be a list of names` | each group is an array of strings |
| `files["<glob>"] must be a list of names` | each file rule is an array |
| `branch rule '<key>' must start with refs/` | use `refs/heads/...` |
| `branches["<key>"] must be a list of names` | each branch rule is an array |
| `writers must be a list of names` | array of strings |
| `protect must be an object of { "refs/...": { push, force, delete } }` | `protect` is an object |
| `protect rule '<key>' must start with refs/` | use `refs/...` keys |
| `protect["<key>"].<k> is not a known key (use push, force, delete)` | only those three keys |
| `protect["<key>"].<k> must be a list of names` | arrays only |

## Signed policies

Clients encrypt to the public keys the server hands them. A compromised server could swap a
key or add a reader. To stop that, an admin signs the parts that decide encryption: the file
rules (in order) and the public keys of everyone in them. Branch rules, `writers` and
`protect` aren't signed, because the server enforces those itself.

### Sign and install

```bash
# on the server
eyesonly-server policy manifest app.git > m.json

# on the admin's machine (needs the admin's identity in ~/.eyesonly or EYESONLY_HOME)
eyesonly policy-sign m.json > s.json

# on the server
eyesonly-server policy attest app.git s.json
# installed policy v1 signed by alice. Members pick it up with `eyesonly pull-policy`.
```

Each manifest carries a version, one higher than the installed one. Clients refuse older
versions, and refuse the same version with different content.

### Re-sign after every change to files or keys

The signature covers file audiences and keys. Re-sign after any of these:

- `policy set` changes a `files` rule, or a group used in one;
- a user is added or removed, and they're in a file audience (directly, through a group,
  or through `"*"`).

Until you re-sign, clients keep using the **last signed** policy and print
`warning: server policy changed since the last admin signature; using the signed policy`.
A new teammate won't be able to read until you do.

### Pinning

On first contact (`eyesonly clone`, or `eyesonly setup` in a clone without trust state), a
client pins the admin who signed, in `.git/eyesonly/trust.json`, and prints:

```
[eyesonly] pinned admin alice 67e9:46a6:0bf6:44a7
```

From then on it refuses unsigned policies, other signers, and older versions.

- **Only the admin who signed first is pinned.** A policy signed later by a second admin is
  refused with `not signed by a pinned admin`. Have one admin do the signing, or have every
  client delete `.git/eyesonly/trust.json` and re-pin after a handover.
- **Once a repo is signed, it stays signed.** Clients refuse an unsigned policy afterwards.
- **Pin up front** to skip trust-on-first-use. Set `EYESONLY_PIN_ADMIN` to the admin's
  policy fingerprint when cloning:

```bash
EYESONLY_PIN_ADMIN=67e9:46a6:0bf6:44a7 eyesonly clone https://alice@git.example.com/app.git
```

This fingerprint is **not** the one `eyesonly whoami` prints. It's derived from the admin's
signing key only. The admin can print it with:

```bash
node -e 'const c=require("crypto"),f=require("fs");const id=JSON.parse(f.readFileSync(process.argv[1]));console.log(c.createHash("sha256").update(id.ed25519.pub).digest("hex").slice(0,16).match(/.{4}/g).join(":"))' ~/.eyesonly/identity.json
```

Or copy it from the `pinned admin` line of their own first clone. Share it out of band.

### Signing errors

On the server (`policy attest`):

| Message | Cause |
|---|---|
| `` not a signed manifest (expected the output of `eyesonly policy-sign`) `` | wrong file |
| `'<name>' is not an admin of app.git` | the signer isn't in `admins` |
| `bad signature: not a valid signature by <name>'s registered key` | signed with another key, or edited after signing |
| `signed manifest does not match current policy. Re-run: eyesonly-server policy manifest app.git` | the policy or users changed after `manifest` |
| `version must increase (installed: N, signed: M)` | re-run `policy manifest` and sign the new output |

On clients, see [troubleshooting.md](troubleshooting.md#signed-policy-and-pinning).

## GitHub mode policy

In GitHub mode the policy is committed as `.eyesonly/policy.json`: a manifest signed by an
admin, holding

- `policy`: the rules as written, with the same meaning as above: `members`, `admins`,
  `groups` and `files` (`writers`, `protect` and `branches` don't exist here; use your host's
  branch protection);
- `files`: each glob expanded to its readers, in rule order (first match wins);
- `keys`: every member's public keys;
- `repo` (a random id made by `init`) and `version`, which only goes up.

Don't edit it by hand: the signature would no longer match and every client would refuse it.
Change it with `eyesonly grant` / `eyesonly revoke` (which re-sign and bump the version), and
read it with `eyesonly policy show`. Clients read it only from the default branch, so a policy
edited on a feature branch takes effect once it's merged. Pinning works as above:
`.git/eyesonly/trust.json`, `EYESONLY_PIN_ADMIN`.
