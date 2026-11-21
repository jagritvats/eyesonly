# Choosing a mode

For whoever decides how a team uses Eyes Only. Both modes use the same client, the same
commands and the same encrypted files; they differ in where the policy lives and who enforces
it.

## At a glance

- **GitHub mode:** nothing to run. The repo stays on GitHub, GitLab, Gitea or any git host.
  The signed policy is committed in `.eyesonly/policy.json`. Clients and CI check every
  commit. Guide: [github-mode.md](github-mode.md).
- **Server mode:** a small Node service in front of your repos. It holds the policy, checks
  every push before storing it, and hides private branches. GitHub can stay as a mirror for
  PRs and CI. Guide: [server-deployment.md](server-deployment.md).

## Which mode do I need?

Start with GitHub mode unless one of these is true:

- **You need private branches** (a launch branch only three people can see). Only the server
  hides refs.
- **A plaintext secret must never reach the host,** even from someone who skips or removes the
  client. In GitHub mode the pre-push hook stops honest mistakes and CI catches the rest, but a
  push made without the client is readable on the host until you rotate.
- **You need to know who pushed,** not just who signed the encrypted file.
- **Some members must be read-only,** or you want push rules per branch enforced by Eyes Only
  itself rather than by your host.

## What each mode guarantees

| | GitHub mode | Server |
|---|---|---|
| File contents encrypted per reader (the host can't read them either) | yes | yes |
| Readers reject forged or unauthorized envelopes | yes | yes |
| Signed policy: no loosening on a branch, no rollback, admin keys pinned | yes | yes, once you sign it ([policy-reference.md](policy-reference.md#signed-policies)) |
| Plaintext push by someone with the client | blocked by the pre-push hook | rejected |
| Plaintext push by someone without the client | detected by the required `eyesonly verify` check; already readable on the host | rejected before it's stored |
| Writes attributed to | the envelope's signer | the authenticated pusher |
| Deleting a protected file | reported by `verify`, not refused | refused for non-writers |
| Private branches | not yet | invisible to non-members, even by SHA |
| Read-only members, protected refs | your host's settings | built in (`writers`, `protect`) |
| Access tokens, a service to run and back up | none | yes |
| Mirror to GitHub/GitLab for PRs and CI | not needed | built in (verified public refs only) |

## Same commands

`eyesonly clone`, `setup`, `pull-policy`, `status`, `rekey`, `audit`, `run`, `env` and
`doctor` work in both modes. Each clone detects its mode and remembers it in
`git config eyesonly.mode`:

- the remote is an Eyes Only server → server mode (this always wins, so a policy file
  committed to a server repo changes nothing);
- otherwise the default branch has `.eyesonly/policy.json` → GitHub mode.

A clone never switches silently. If the remote changes kind, eyesonly stops with
`this clone was set up in repo mode, but it now looks like server mode` and asks for
`eyesonly setup --mode server` (or `--mode repo`).

Admin commands differ: in GitHub mode the admin runs `eyesonly init`, `grant`, `revoke` and
`policy show` on their own laptop; with a server they run `eyesonly-server init`, `user add`
and `policy set` on the server.

## Move from GitHub mode to the server

Encrypted files carry over as they are (envelopes don't depend on the mode), and so do the
admin keys every clone pinned: nobody deletes `.git/eyesonly/trust.json`.

1. **Import the policy on the server.** It checks the repo policy's signature, registers every
   member with the key it lists (tokens printed once), and creates the repo with the same
   groups, file rules and writers:

   ```bash
   git show main:.eyesonly/policy.json > policy.json                 # in a clone
   eyesonly-server import app.git --policy policy.json --admin-card "$(eyesonly whoami | tail -1)"
   ```

   `--admin-card` is optional: it makes import refuse a policy that isn't signed by you.
   Members who already exist on the server must have the same key (import never changes one).

2. **Sign the server's policy with the same admin key** clients already pinned. The repo
   policy's signature can't be reused: a server manifest names the server repo and lists only
   the keys of file audiences, so it's a new document. Its version starts above the repo
   policy's, so clients see the version go up:

   ```bash
   eyesonly-server policy manifest app.git > m.json                  # on the server
   eyesonly policy-sign m.json > s.json                              # on your machine
   eyesonly-server policy attest app.git s.json                      # on the server
   ```

3. **Move the repo** (admin, in a GitHub-mode clone). `migrate` checks the server's policy
   first, then pushes every branch (including ones that only exist on the old host), every
   tag and `refs/eyesonly/*` to a new remote `eyesonly`, and switches the clone to the server:

   ```bash
   eyesonly migrate --to https://alice:<token>@git.example.com/app.git
   ```

   The server checks every commit it receives, so this works only if every envelope in
   history was signed by a writer of that path. History with plaintext secrets: see
   [existing-repos.md](existing-repos.md#history-that-already-contains-a-plaintext-secret).

4. **Teammates switch** with their token from step 1:

   ```bash
   git remote add eyesonly https://bob:<token>@git.example.com/app.git
   git fetch eyesonly && eyesonly setup --remote eyesonly --mode server
   ```

   The clone accepts the server's policy because it's signed by an admin it already pinned,
   with a version at least as high as the last policy it saw. Anything else is refused:
   `not signed by a pinned admin ('dave' isn't one)`, `policy version 3 is older than last
   seen 5`, or, if step 2 was skipped, `the server's policy isn't signed yet`.

5. **Clean up.** Make the old host read-only, or keep it as a [mirror](../README.md#mirroring-to-githubgitlab-server)
   of the public branches. `.eyesonly/policy.json` can stay in history: when the remote is an
   Eyes Only server, server mode always wins.

Going the other way (server to GitHub mode) means running `eyesonly init` in a clone on the
new host and granting each member again; the server's private branches don't carry over.
