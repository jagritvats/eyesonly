# Team workflows

For admins and developers on a team that already runs Eyes Only: day-to-day access changes, private branches and offboarding.

The first section is for [GitHub mode](github-mode.md) (no server). The rest is for the
server, except where a section says it applies to both. Server commands run where the
server's data dir is (see [server-deployment.md](server-deployment.md)). Policy fields are
described in [policy-reference.md](policy-reference.md). To bring an existing repo or clone
onto Eyes Only, see [existing-repos.md](existing-repos.md).

## GitHub mode: add, change and remove access

Admins change the signed policy on their own laptop; every change is a commit.

| Task | Commands (admin, in the repo) |
|---|---|
| Add a teammate | they run `eyesonly join` and open a PR with `.eyesonly/requests/<name>.pub`; you merge it, then `eyesonly grant <name> --from-request` |
| Add someone by card | `eyesonly grant <name> --card eyesonlypub1:...` |
| Put someone in a group | `eyesonly grant <name> --group <g>` |
| Give someone one path | `eyesonly grant <name> --files .env.production` (also adds a `.gitattributes` line) |
| Make someone an admin | `eyesonly grant <name> --admin` |
| Remove someone from a group | `eyesonly revoke <name> --group <g>` |
| Remove someone entirely | `eyesonly offboard <name>`: revokes, re-encrypts, writes a rotation checklist ([Offboard someone](#offboard-someone)) |
| New key for someone (lost key, new machine) | `eyesonly grant <name> --card <new card>` (prints `replacing <name>'s key ... readers must rekey`) |
| See who can read what | `eyesonly policy show` |

After any of these:

```bash
git add .eyesonly .gitattributes && git commit -m "eyesonly: <what changed>"
eyesonly rekey && git commit -am "rekey" && git push      # re-encrypt for the new audience
```

Teammates pick it up with `git pull && eyesonly pull-policy`. The policy takes effect once
it's on the default branch: a grant sitting in an unmerged branch changes nothing.
`rekey`, rotation and offboarding work as in the sections below.

## Add a teammate (server)

1. The teammate creates a key on their machine and sends you the card it prints:

```bash
eyesonly keygen bob
# eyesonlypub1:eyJuYW1lIjoiYm9iIi...
```

2. You register them. The token is printed once; send it to them privately:

```bash
eyesonly-server user add eyesonlypub1:eyJuYW1lIjoiYm9iIi...
# added bob (fingerprint 46b8:a993:7334:9fd1). Token, shown once:
# eyesonly_...
```

Check the fingerprint with them over another channel. They can print it with
`eyesonly whoami`.

3. If they should read protected files, add them to the relevant `files` rule or group,
   then `policy set`. With `"*"` or a group they're already in, skip this step.
4. If the policy is signed, re-sign it ([policy-reference.md](policy-reference.md#signed-policies)).
5. Someone who can already read each file runs `rekey` (see below). Until then the new
   reader sees ciphertext, and pushes print
   `note: '.env' in <commit> is not readable by bob yet (eyesonly rekey)`.
6. Bob clones:

```bash
eyesonly clone https://bob:<token>@git.example.com/app.git
```

## Change who can read a file

Edit the `files` rule (or a group it uses) and `policy set` it. Encryption happens on the
client, so the existing ciphertext only changes when a reader re-encrypts it:

```bash
# any current reader of the file
eyesonly pull-policy
eyesonly rekey            # re-encrypts every protected file you can read, for the new audience
git commit -m "rekey for new policy"
git push
```

- `rekey` only touches files that are decrypted in your working copy. It says
  `can't rekey (not decrypted here)` for the rest.
- **Adding a reader:** until someone rekeys, the new reader can't read.
- **Removing a reader:** until someone rekeys, the old ciphertext stays readable to them.
  Their next edit is refused (`may not modify protected file`). After `pull-policy`, any
  edit you make re-encrypts the file without them, because each write seals for your cached
  policy.
  Removal isn't retroactive: they can still decrypt old versions in history. Rotate the
  secret if that matters (see [Offboarding](#offboard-someone)).
- The pre-commit hook installed by `setup` re-encrypts staged protected files whose
  audience is out of date, so commits after `pull-policy` come out right.

`eyesonly status` shows, per file, whether you can read it and whether it needs a rekey:

```
repo app.git as alice
  decrypted .env  [alice, bob]
  locked    secrets/prod.key  [ops]
  decrypted config/app.key  [alice, bob]  needs rekey (encrypted for alice; policy says alice,bob)
```

## Read-only members (server)

Put the people who may push in `writers`. Every other member can clone and fetch, but can't
push:

```json
{ "members": ["*"], "writers": ["@core"], "admins": ["alice"] }
```

Pushes from others get `[eyesonly] read-only access` (HTTP 403). This suits auditors,
contractors who send patches, and CI users ([ci.md](ci.md)).

## Private branches

Server only. GitHub mode doesn't have private branches yet: anyone with repo access sees
every branch. Give a namespace an audience:

```json
"branches": { "refs/heads/private/": ["@core"] }
```

### Create one

```bash
git switch -c private/launch
git push -u origin private/launch
```

Only `@core` can see, fetch or push it. For everyone else it doesn't show in
`git ls-remote` or `git fetch`, can't be fetched by SHA, and pushing to it gives
`'junior' may not push to 'refs/heads/private/launch'`.

### Merge it into main

Merging the branch's commits into a branch more people can see would expose its history,
so a plain merge is refused:

```
[eyesonly] REJECTED: pushing 'refs/heads/main' would expose commit f041fc7d from a branch
with a narrower audience. Use `git merge --squash`.
```

Squash it into one new commit instead:

```bash
git switch main
git merge --squash private/launch
git commit -m "Launch"
git push
```

Merging `main` into the private branch is fine.

### Delete it

```bash
git push origin --delete private/launch
```

The objects stay on the server. Nobody but an admin can bring them back onto a public
branch. Pointing a ref at those commits gets
`would expose N existing object(s) its audience can't see`.

### Make it public

Remove or widen the rule and `policy set`. Everything already on that branch, history
included, becomes visible to the new audience.

## Protect main (server)

By default (no `protect` section), non-admins can't force-push or delete tags or the
branch `HEAD` points to. To also limit who can push to `main`:

```json
"protect": {
  "refs/heads/main": { "push": ["@release"] },
  "refs/tags/":      { "force": [], "delete": [] }
}
```

Admins bypass these rules, but not the content checks. Nobody, admins included, can move a
ref to a tree whose protected files are invalid under the current policy. That includes
force-pushing `main` back to a commit from before a rekey, which fails with
`encrypted to users outside the policy`.

## Separate secrets per environment

Give each environment its own file and its own audience. Developers get development values,
only the deploy pipeline and a couple of people get production. (GitHub mode: `eyesonly grant
<name> --files .env.production` per person; see [github-mode.md](github-mode.md#separate-secrets-per-environment).)
On the server:

```json
{
  "members": ["*"],
  "admins":  ["alice"],
  "groups":  { "core": ["alice", "bob", "carol"], "deploy": ["alice", "ci-prod"] },
  "writers": ["@core"],
  "files": {
    ".env.development": ["*"],
    ".env.staging":     ["@core", "ci-staging"],
    ".env.production":  ["@deploy"]
  }
}
```

- `"*"` means every registered user, so contractors can run the app locally without seeing
  staging or production values.
- After changing the policy, someone in each file's audience runs
  `eyesonly pull-policy && eyesonly rekey` and pushes. Only readers can rekey a file.
- Everyone else sees ciphertext for the files outside their audience, and the server
  rejects their changes to them.

Load one environment into a command with `eyesonly run`. It decrypts from the committed
version of the file, so nothing extra lands on disk:

```bash
eyesonly run --file .env.development -- npm run dev
eyesonly run --file .env.production -- ./deploy.sh     # refuses unless you're in @deploy
```

With no `--file`, `eyesonly run` loads every `.env` and `.env.*` you can read (in sorted
order, later files winning) and skips the rest with a note. An explicit `--file` you can't
read is an error, and the command doesn't run. For CI users, see [ci.md](ci.md).

## Rotate a secret (both modes)

1. Get a new value from the provider (Stripe, AWS, ...).
2. Put it in the file and stage it encrypted, without opening an editor:

```bash
eyesonly rotate .env STRIPE_SECRET=sk_live_new           # several KEY=value pairs at once is fine
printf 'STRIPE_SECRET=sk_live_new\n' | eyesonly rotate .env --from-stdin   # keeps it out of shell history
# .env: changed STRIPE_SECRET. Staged (encrypted); commit and push.
```

   `rotate` keeps comments, order and `export ` prefixes, adds keys that don't exist yet,
   quotes values that need it, and only prints key names. It refuses files you can't write.
   Editing the file by hand works too.
3. Commit and push. The new ciphertext is sealed for the current policy.
4. Revoke the old value at the provider. The old ciphertext is still in history.

## Who could read a secret on a given date

Every envelope records who it was encrypted for, so git history answers this in both modes:

```bash
eyesonly audit --file .env --at 2026-03-01
# .env at 2026-03-01: version 3f2a1c09ab on origin/main
#   introduced by 9b8c7d6e5f on 2026-02-10 12:00
#   readable by: alice [1c4e9a02], bob [7d03f5b1]

eyesonly audit --file .env --at v1.4.0      # a commit, tag or branch instead of a date
eyesonly audit --file .env --at 2026-03-01 --all-refs   # every branch, not just the default one
eyesonly audit --file .env --json           # for tooling
```

- A bare date means the end of that day (UTC). Without `--at`, it answers for now.
- The bracketed id is the reader's key id; `old key` means the policy has a newer key for
  that person since. Versions from before key ids existed say `no key id`.
- Renames are followed: asking about `secrets/db-prod.txt` on a date before it was renamed
  shows the version under its old name.

The other direction, everything one person could ever decrypt:

```bash
eyesonly audit bob                          # every version, with first and last dates
eyesonly audit bob --since 2026-03-01       # only versions readable on or after that date
eyesonly audit bob --json
```

`audit` scans the refs in your clone, so fetch every branch first
(`git fetch origin '+refs/heads/*:refs/remotes/origin/*'`). Versions committed in plaintext
count as readable by everyone.

## Offboard someone

`eyesonly offboard <name>` does the whole job in a clone where you can read the secrets:

```bash
eyesonly offboard bob
# [eyesonly] rotation checklist: .git/eyesonly/offboard-bob.md (2 file(s); key names only, no values)
# [eyesonly] revoked bob: policy v7
# [eyesonly] re-encrypted 2 file(s) for the current policy.
# [eyesonly] next: git commit -m "eyesonly: offboard bob" && git push, then rotate what the checklist lists
```

It asks before changing anything (`--yes` skips the prompt; without a terminal it's
required). `--checklist <file>` writes the checklist somewhere else. The checklist lists
each file bob could decrypt, when he last could, and for dotenv files every key name he saw,
as checkboxes. It never contains values:

```markdown
## .env

Last readable by bob: 2026-04-10 · 2 versions

- [ ] STRIPE_SECRET
- [ ] DB_PASS
```

Then rotate each item at its provider and commit the new values with `eyesonly rotate`.
Revocation isn't retroactive: bob has seen what he could read.

**GitHub mode:** `offboard` revokes bob in the signed policy, re-encrypts every protected
file you can read, and stages both. Commit and push. Also remove bob from the repo on your
host; Eyes Only can't stop him reading what's still there.

**Server:** the server holds the policy, so it takes two runs:

1. `eyesonly offboard bob` writes the checklist and, since bob is still in the server's
   policy, prints what to run on the server:

```bash
eyesonly-server user remove bob
# if the repo has a signed policy, re-sign it:
eyesonly-server policy manifest app.git > m.json && eyesonly policy-sign m.json > s.json && eyesonly-server policy attest app.git s.json
```

   Removing the user stops their token right away and drops them from every audience.
   Also take their name out of policies and groups (`policy set`); otherwise a new user
   registered as `bob` later would inherit the access.
2. Run `eyesonly offboard bob --yes` again. It pulls the policy, sees bob is gone and
   re-encrypts for the remaining readers. Commit and push.

## Rotate a user's token (server)

For a lost or leaked token. Their key stays the same:

```bash
eyesonly-server user token bob      # prints the new token; the old one stops working
```

## Change the signing admin, or re-pin

Clients pin the first admin who signed the policy. If another admin takes over signing, or
a client says `refusing the server's policy: not signed by a pinned admin`, first confirm
out of band that the change is real. Then, in each clone:

```bash
rm .git/eyesonly/trust.json
eyesonly pull-policy        # pins the current signer; compare the printed fingerprint
```

Set `EYESONLY_PIN_ADMIN=<fingerprint>` while doing this to refuse anything else.

## Keep your key in the OS keychain

By default your private identity is `~/.eyesonly/identity.json` (mode 0600). To keep it in
the operating system's keychain instead:

```bash
eyesonly keygen alice --store keychain     # new identity, straight into the keychain
eyesonly identity move --to keychain       # or move the one you have
eyesonly identity show                     # where it lives, name, fingerprint
```

| OS | Where it goes |
|---|---|
| macOS | Keychain (generic password, service `eyesonly`, account `<name>`) |
| Windows | DPAPI (CurrentUser): `~/.eyesonly/identity.dpapi`, readable only by your Windows account |
| Linux | Secret Service through `secret-tool` (GNOME Keyring, KWallet); needs a D-Bus session |

- The move writes the new copy, reads it back and compares it before deleting the old
  one, so a failed move leaves the identity where it was. `eyesonly identity move --to file`
  goes the other way.
- `~/.eyesonly/config.json` records the choice. It holds no key material.
- The key is handed to the keychain tools on stdin, never on a command line. The
  long-running filter reads it once per git command, not once per file.
- What it protects against: a stolen disk or backup, another local user, a stray
  `cat ~/.eyesonly/*` in a screen share. What it doesn't: malware running as you can ask
  the keychain for it like any other keychain secret.
- On a headless Linux box with no keyring, use the file store or `EYESONLY_IDENTITY`.
- `eyesonly doctor` warns when the key is a plain file.

`EYESONLY_IDENTITY` still wins over both stores. CI should keep using it
([ci.md](ci.md)); `eyesonly identity export --yes` prints the value to paste into a CI
secret.

## Lost private key or new machine

There's no key escrow. A user who loses `~/.eyesonly/identity.json`, or wants a fresh key
on a new laptop instead of copying the old file, gets a new key under the same name. Their
token, group memberships and policy entries stay as they are.

1. The user makes a new key with the **same name**:

   ```bash
   eyesonly keygen bob          # on the new machine; prints a new card
   ```

2. The admin swaps the key on the server:

   ```bash
   eyesonly-server user set-key eyesonlypub1:...
   ```

   It prints the old and new fingerprints and, per repo, what has to happen next.

   In GitHub mode the admin runs `eyesonly grant bob --card eyesonlypub1:...` in the repo
   instead, commits `.eyesonly`, and skips step 3 (the grant is the signed change).

3. **Signed policy:** if the repo uses one, re-sign it. Clients keep the old keys until you
   do (`policy manifest` -> `eyesonly policy-sign` -> `policy attest`, see
   [policy-reference.md](policy-reference.md)). If the user is the signing admin, members
   also re-pin once they've checked the new fingerprint with them (see above).

4. **Re-wrap the files** for the new key. Someone who can read them and has them decrypted:

   ```bash
   eyesonly pull-policy && eyesonly rekey
   git commit -am "rekey for bob's new key" && git push
   ```

   `eyesonly status` shows `needs rekey (new key for bob)` until this is done.

5. The user clones on the new machine with their existing token (or runs `eyesonly setup`
   in an existing clone).

Things to know:

- Files the user last wrote were signed with the old key. Clients refuse those until step 4
  re-seals them, so do step 4 promptly.
- Files only the lost key could read can't be recovered.
- If the old key was lost or stolen, whoever has it can still read everything it could
  decrypt before. Run `eyesonly offboard <name>` (or `eyesonly audit <name>`) and rotate what it lists.
- To give one person several machines, copy `identity.json` to each (mode 0600). One key
  per user is all the server tracks today.
