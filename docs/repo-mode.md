# Repo mode (no server)

For teams who want encrypted files in a repo that stays on GitHub, GitLab or any git host,
without running an Eyes Only server. Same commands as with a server; the mode is detected.

The policy lives in the repo as `.eyesonly/policy.json`, signed by an admin. Clients read it
from the **default branch only**, check the signature, refuse a lower version, and pin the
admin keys the first time they see them. Protected files are encrypted for each reader and
signed by the writer, exactly as with a server.

## Start (admin)

```bash
eyesonly keygen alice                              # once per person
cd your-repo
eyesonly init --commit                             # default: .env and secrets/** for @core
git push
```

`init` writes the signed policy and the `.gitattributes` lines, sets up the filters and a
pre-push hook, encrypts protected files that were tracked in plaintext (their old versions
stay in history: rotate those secrets), and prints your admin fingerprint.

Options: `--files .env,config/prod.json,secrets/**` and `--group core`.

## Add a teammate

The teammate:

```bash
eyesonly keygen bob
git clone git@github.com:acme/app.git && cd app     # any URL; or: eyesonly clone <url>
eyesonly setup
eyesonly join                                      # writes .eyesonly/requests/bob.pub
git checkout -b join-bob && git add .eyesonly/requests && git commit -m "join bob" && git push -u origin join-bob
```

The admin merges that branch (or gets the card another way), then:

```bash
eyesonly grant bob --from-request                  # or: --card eyesonlypub1:...
git add .eyesonly && git commit -m "eyesonly: grant bob"
eyesonly rekey && git commit -am "rekey for bob"
git push
```

Bob runs `git pull && eyesonly pull-policy` and can read the files.

`grant` options: `--group <g>` (the only group is picked if there's just one), `--files <glob>`
(a rule for that path), `--admin`. Several grants can be chained before committing.

## Remove access

```bash
eyesonly revoke carol                              # or: --group core
git add .eyesonly && git commit -m "eyesonly: revoke carol"
eyesonly rekey && git commit -am rekey && git push
eyesonly audit carol                               # what to rotate
```

Revocation isn't retroactive: carol keeps whatever she could already decrypt. Rotate it.

## Check commits: `eyesonly verify`

```bash
eyesonly verify                                    # your branch vs its upstream (or the default branch)
eyesonly verify --range origin/main..my-branch
```

It runs the server's checks against the policy in the repo:

- every protected file is an encrypted envelope bound to its path,
- signed by a key of an allowed writer of that path,
- encrypted only to that path's audience,
- no `.gitattributes` / `.lfsconfig` change routes a protected path away from the filter,
- every policy change is signed by an admin of the previous policy, for the same repo, with a
  higher version, and the policy file isn't deleted,
- the resulting tree is valid as a whole, including files that predate the range.

`eyesonly setup` installs a **pre-push hook** that runs the same check on what you're about
to push, so plaintext never leaves a laptop that has the client.

### Require it in CI (GitHub)

Make this a required status check on the default branch, and protect that branch:

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
```

It needs no secrets. A full copy is in [examples/eyesonly-verify.yml](examples/eyesonly-verify.yml).

## What repo mode guarantees, and what needs a server

| | Repo mode (no server) | With an Eyes Only server |
|---|---|---|
| File contents encrypted per reader (GitHub can't read them either) | yes | yes |
| Readers reject forged or unauthorized envelopes | yes | yes |
| Policy can't be loosened by a branch, rolled back, or re-signed by a non-admin | yes (signed, default branch only, pinned) | yes |
| Plaintext push by someone **with** the client | blocked by the pre-push hook | rejected by the server |
| Plaintext push by someone **without** the client | **detected**, not prevented: CI fails, but the plaintext is already readable by everyone with repo access. Rotate it | rejected before it's stored |
| Who changed or deleted a file | attributed to the envelope signer; deletions are reported, not refused | the authenticated pusher |
| Private branches | not yet (planned: encrypted branches; name, size and timing stay visible) | invisible to non-members |
| Force-push / rewind protection | your host's branch protection | built in |

Detection becomes prevention for the default branch when you protect it and require the
`eyesonly verify` check: nothing unverified gets merged.

## Trust on first use

The first time a clone sees the policy it pins the signing admin keys and prints the
fingerprint. Compare it with your admin, or pin it up front:

```bash
EYESONLY_PIN_ADMIN=6bf8:4145:71a3:0fb0 eyesonly clone git@github.com:acme/app.git
```

`eyesonly policy show` prints every admin's fingerprint. After that, only a policy signed by
a pinned admin is accepted, and admin changes come only through such a policy.

## Switching modes

A clone remembers its mode (`git config eyesonly.mode`) and won't switch silently: a remote
that turns out to be an Eyes Only server, or a repo whose default branch gains a policy file,
needs an explicit `eyesonly setup --mode server|repo`. When the remote is an Eyes Only server,
server mode always wins, so a policy file committed to a server repo changes nothing.
