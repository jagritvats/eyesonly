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

## Private branches

A branch under a private prefix of the policy (`eyesonly init` creates `private/` for your
core group) never goes to the host as a git branch. `eyesonly branch push` seals it: the
commits since the default branch are bundled, encrypted for the branch's audience and signed
by you, and stored as one opaque ref, `refs/eyesonly/b/<random id>`.

```bash
git checkout -b private/launch
# ...work, commit as usual...
eyesonly branch push                     # seal and push (v1, v2, ... on every push)
eyesonly branch pull                     # teammates: fetch, verify and update private/launch
eyesonly branch list                     # what you can read, versions, who sealed it, sync state
eyesonly branch publish private/launch   # squash it into main when it ships, then git push
eyesonly branch delete private/launch    # remove the sealed ref from the host
```

Readers get the same commit ids as the writer. Before updating a branch, `pull` checks that
the version is signed by someone allowed to write that prefix under the current policy, that
it's bound to its own ref, and that it isn't older than, or a fork of, the version you already
have (versions are pinned per clone in `.git/eyesonly/branches.json`). A rolled-back,
replayed, forged or moved version is refused; a writer's next `branch push` replaces it.
If your local branch and the sealed one diverged, the sealed version lands in
`<name>-incoming` for you to merge.

**Guards.** The pre-push hook refuses `git push origin private/launch` (it would put the
branch on the host in plaintext), and refuses pushing a public branch that contains commits
made on a private branch: squash them in with `eyesonly branch publish` instead. Commits made
on `main` before you branched don't count as private. The publish commit gets its own
message, so private commit messages stay private too.

**What the host and other repo readers see:** that a sealed ref exists, its size, and when it
was pushed. Not the branch name, commit messages, files or authors: the sealed commit is
authored by `eyesonly <eyesonly@localhost>` at a fixed date, and the writer's signature is
inside the ciphertext. The envelope lists its recipients, which is the prefix's audience from
the policy file everyone can already read. Any writer of the repo can delete or overwrite a
sealed ref (readers detect rollback, not deletion), and the host keeps old ciphertext. With
the server, private branches are invisible altogether.

Admins change who can read and write a prefix with `eyesonly grant <name> --branches private/`
and `eyesonly revoke <name> --branches private/`. The next `branch push` seals for the new
audience; versions sealed before stay readable by whoever had them, like any secret.

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
  push:                                            # every branch: a plaintext private/* push is flagged
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
```

In verify mode the Action also checks that the pushed branch isn't a private branch pushed in
plaintext (`eyesonly verify --ref`), and that every sealed ref on the host is one encrypted
envelope bound to its ref (`eyesonly verify --sealed origin`; turn it off with
`sealed: false`). A copy is in [examples/eyesonly-verify.yml](examples/eyesonly-verify.yml). In the repo's
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
| Who changed or deleted a file | attributed to the envelope signer; deletions are reported, not refused | the authenticated pusher |
| Private branches | sealed on the host: name, content and author hidden; size and push times visible; rollback refused | invisible to non-members |
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

`eyesonly policy show` prints every admin's fingerprint. After that, only a policy signed by
a pinned admin is accepted, and admin changes come only through such a policy.

## Switching modes

A clone remembers its mode (`git config eyesonly.mode`) and won't switch silently. A remote
that turns out to be an Eyes Only server, or a repo whose default branch gains a policy file,
needs an explicit `eyesonly setup --mode server|repo`. When the remote is an Eyes Only server,
server mode always wins, so a policy file committed to a server repo changes nothing.

Moving a GitHub-mode repo onto the server: [choosing a mode](choosing-a-mode.md#move-from-github-mode-to-the-server).
