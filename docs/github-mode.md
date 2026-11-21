# GitHub mode (no server)

For teams who want encrypted `.env` files and secrets in the repo they already have, on
GitHub, GitLab, Gitea or any git host, without running anything. Same commands as with the
Eyes Only server; each clone detects the mode. (The code and some messages call it "repo
mode".)

The policy lives in the repo as `.eyesonly/policy.json`, signed by an admin. Clients read it
from the **default branch only**, check the signature, refuse an older version, and pin the
admin keys the first time they see them. Protected files are encrypted for each reader and
signed by the writer, exactly as with a server.

Not sure which mode you need? See [choosing a mode](choosing-a-mode.md).

## Start (admin)

```bash
eyesonly keygen alice                              # once per person
cd your-repo
eyesonly init --commit                             # default: .env and secrets/** for @core
git push
```

`init` writes the signed policy and the `.gitattributes` lines, sets up the filters and a
pre-push hook, encrypts protected files that were tracked in plaintext, and prints your admin
fingerprint. Without `--commit` it prints the `git add` / `git commit` to run.

Options: `--files .env,config/prod.json,secrets/**` and `--group core`.

Files that were already committed in plaintext stay readable in history. Rotate those
secrets, or strip them first ([existing repos](existing-repos.md#history-that-already-contains-a-plaintext-secret)).

If `.env` is in `.gitignore` today, start tracking it after `init`:

```bash
sed -i '/^\.env$/d' .gitignore
git add .gitignore .env && git commit -m "track .env (encrypted)" && git push
git show HEAD:.env | head -1                       # EYESONLY-V1
```

## Add a teammate

The teammate:

```bash
eyesonly keygen bob
eyesonly clone git@github.com:acme/app.git && cd app     # any URL; or: git clone + eyesonly setup
eyesonly join                                      # writes .eyesonly/requests/bob.pub
git checkout -b join-bob && git add .eyesonly/requests && git commit -m "join bob" && git push -u origin join-bob
```

Until they're granted, protected files stay `EYESONLY-V1 ...` ciphertext and `eyesonly clone`
says `you ('bob') aren't in this repo's policy yet`. Everything else works normally.

The admin merges that branch (or gets the card another way), then:

```bash
eyesonly grant bob --from-request                  # or: --card eyesonlypub1:...
git add .eyesonly && git commit -m "eyesonly: grant bob"
eyesonly rekey && git commit -am "rekey for bob"
git push
```

Bob then runs:

```bash
git pull && eyesonly pull-policy                   # .env is now decrypted for bob
eyesonly status                                    # decrypted .env  [alice, bob]
```

`grant` options: `--group <g>` (picked automatically when there's only one group),
`--files <glob>` (a rule for that path only), `--admin`. Several grants can be chained
before committing. `eyesonly policy show` lists groups, rules, members, admins and
pending requests.

## Separate secrets per environment

Give a path its own audience. `--files` adds a rule for that path (rules are checked in
order, first match wins, so pick a path no earlier rule covers):

```bash
eyesonly grant deploy-bot --card eyesonlypub1:... --files .env.production
eyesonly grant alice --files .env.production       # the admin needs a rule to write it too
git add .eyesonly .gitattributes && git commit -m "eyesonly: .env.production for deploy-bot"
```

A new path also gets a `.gitattributes` line, so commit that file with the policy.

`eyesonly run --file .env.production -- ./deploy.sh` then loads only that file.

## Remove access

```bash
eyesonly revoke carol                              # or: --group core to drop her from one group
git add .eyesonly && git commit -m "eyesonly: revoke carol"
eyesonly rekey && git commit -am rekey && git push
eyesonly audit carol                               # what to rotate
```

Revocation isn't retroactive: carol keeps whatever she could already decrypt, including old
versions in history. Rotate it. The only admin can't be revoked until another admin exists.

## Read-only members (writers)

By default every member who can read a file can also write it. To let someone read without
changing it:

```bash
eyesonly grant carol --card <card> --read-only     # new member, reads @core files, writes nothing
eyesonly grant carol --read-only                   # existing member
eyesonly revoke carol --writer                     # same thing
eyesonly grant carol --writer                      # undo
```

This sets `writers` in the policy (an explicit list; admins always write), like the server's
`writers`. A writer of a path is in its audience **and** a writer. It's enforced everywhere
an envelope is made or trusted:

- `git add` of an edited file: `'carol' can read but not write '.env' (read-only; writers: alice, bob)`.
  Her unchanged checkout keeps working: git maps it back to the writer's envelope.
- `eyesonly rekey` skips read-only files, and the merge driver refuses to re-seal:
  `'carol' may not write '.env' (read-only); pick a side with ...`.
- Readers' smudge, `eyesonly run` and `eyesonly verify` reject envelopes she signs anyway:
  `signer 'carol' is not an allowed writer of '.env'` / `'.env' in <sha> has an invalid signature or its signer 'carol' may not write it`.

## Check commits: `eyesonly verify`

```bash
eyesonly verify                                    # your branch vs its upstream (or the default branch)
eyesonly verify --range origin/main..my-branch
```

It runs the server's content checks against the policy on the default branch:

- every protected file is an encrypted envelope bound to its path,
- signed by a key of an allowed writer of that path,
- encrypted only to that path's audience,
- no `.gitattributes` / `.lfsconfig` change routes a protected path away from the filter,
- every policy change is signed by an admin of the previous policy, for the same repo, with a
  higher version, and the policy file isn't deleted,
- the resulting tree is valid as a whole, including files that predate the range.

### Attribute commits to people: `--require-signed`

Without a server, verify can't know who pushed, so it attributes changes to the envelope
signer and only reports deletions. With SSH commit signing it can do better:

```bash
eyesonly grant bob --ssh-signing-key ~/.ssh/id_ed25519.pub     # admin, once per member (key or .pub path)
git config gpg.format ssh && git config user.signingkey ~/.ssh/id_ed25519.pub && git config commit.gpgsign true   # each member
eyesonly verify --require-signed --range origin/main..HEAD
```

It builds git's allowed-signers file from the policy (the one that applies to each commit) and
checks every commit with git's own signature verification. Then:

- an unsigned commit, or one signed with a key that isn't in the policy, is rejected:
  `commit 1a2b3c4d isn't signed by a member: not signed` / `...: signed with a key that is not in the policy`;
- an edit or deletion of a protected file is attributed to the commit's signer and rejected
  unless they may write it: `'carol' may not delete protected file '.env' (1a2b3c4d, attributed by its commit signature)`.

GitHub's **Require signed commits** rule complements it: GitHub checks that every commit is
signed by *some* verified key, `--require-signed` checks it's a member allowed to make that
change. Merges made in GitHub's web UI are signed by GitHub, not a member, so merge locally
or use squash/rebase merges by members. In the Action, set `require-signed: true`.

A failure looks like the server's:

```
[eyesonly] REJECTED: '.env' in 34328bbe is NOT encrypted. Refusing to store a plaintext secret. Run `eyesonly setup` and recommit.
```

`eyesonly setup` and `eyesonly clone` install a **pre-push hook** that runs the same check on
what you're about to push, so plaintext never leaves a laptop that has the client:

```
[eyesonly] push blocked: fix the commits above (CI runs the same check). To push anyway: git push --no-verify
```

### Require it in CI

Make it a required status check on the default branch, and protect that branch. It needs no
secrets:

```yaml
# .github/workflows/eyesonly.yml
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
          fetch-depth: 0                           # verify needs the base commit
      - uses: jagritvats/eyesonly@v0.4
        with:
          mode: verify
          # require-signed: true                    # see --require-signed above
```

A copy is in [examples/eyesonly-verify.yml](examples/eyesonly-verify.yml). In the repo's
settings, mark `eyesonly / verify` as required (Rules or Branch protection). On GitLab or
elsewhere, run `npx eyesonly verify --range <base>..<head>` in the pipeline the same way.

To read secrets in CI as well, see [ci.md](ci.md#github-mode-read-secrets-in-ci).

## What GitHub mode guarantees, and what needs the server

| | GitHub mode | Eyes Only server |
|---|---|---|
| File contents encrypted per reader (the host can't read them either) | yes | yes |
| Readers reject forged or unauthorized envelopes | yes | yes |
| Policy can't be loosened by a branch, rolled back, or re-signed by a non-admin | yes (signed, default branch only, pinned) | yes (with a signed policy) |
| Plaintext push by someone **with** the client | blocked by the pre-push hook | rejected by the server |
| Plaintext push by someone **without** the client | **detected**, not prevented: CI fails, but the plaintext is already readable by everyone with repo access. Rotate it | rejected before it's stored |
| Who changed or deleted a file | attributed to the envelope signer; deletions are reported, not refused (with `--require-signed`: the commit's signer, enforced) | the authenticated pusher |
| Read-only members | `writers` in the signed policy, enforced by every client and `verify` | `writers`, enforced on push |
| Private branches | not yet (planned: encrypted branches; name, size and timing stay visible) | invisible to non-members |
| Force-push / rewind protection | your host's branch protection | built in |

Detection becomes prevention for the default branch once you protect it and require the
`eyesonly verify` check: nothing unverified gets merged.

## Trust on first use

The first time a clone sees the policy it pins the signing admin keys and prints the
fingerprint (`pinned admin alice 1048:0820:8872:99c1`). Compare it with your admin, or pin it
up front:

```bash
EYESONLY_PIN_ADMIN=1048:0820:8872:99c1 eyesonly clone git@github.com:acme/app.git
```

`eyesonly whoami` prints your own pin fingerprint (`admin pin  1048:0820:8872:99c1`) so an
admin can hand it out; `eyesonly policy show` prints every admin's, plus what this clone
pinned, and `eyesonly status` prints the pinned admins. After that, only a policy signed by a
pinned admin is accepted, and admin changes come only through such a policy (every admin it
lists is pinned).

## Switching modes

A clone remembers its mode (`git config eyesonly.mode`) and won't switch silently. A remote
that turns out to be an Eyes Only server, or a repo whose default branch gains a policy file,
needs an explicit `eyesonly setup --mode server|repo`. When the remote is an Eyes Only server,
server mode always wins, so a policy file committed to a server repo changes nothing.

Moving a GitHub-mode repo onto the server keeps every pinned admin key:
`eyesonly-server import`, one signature, then `eyesonly migrate`. See
[choosing a mode](choosing-a-mode.md#move-from-github-mode-to-the-server).
