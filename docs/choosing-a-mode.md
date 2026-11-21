# Choosing a mode

For whoever decides how a team uses Eyes Only. Both modes use the same client, the same
commands and the same encrypted files; they differ in where the policy lives and who enforces
it.

## At a glance

- **GitHub mode:** nothing to run. The repo stays on GitHub, GitLab, Gitea or any git host.
  The signed policy is committed in `.eyesonly/policy.json`. Clients and CI check every
  commit. Guide: [github-mode.md](github-mode.md).
- **Server mode:** a small Node service in front of your repos. It holds the policy, checks
  every push before storing it, and hides private branches altogether. GitHub can stay as a mirror for
  PRs and CI. Guide: [server-deployment.md](server-deployment.md).

## Which mode do I need?

Start with GitHub mode unless one of these is true:

- **A private branch must be invisible,** not just unreadable. GitHub mode seals private
  branches (`eyesonly branch push`): the host can't read the name, commits or files, but it
  sees that a sealed ref exists, its size and when it changes, and any writer can delete it.
  Only the server hides refs altogether.
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
| Private branches | sealed on the host: name, commits and author encrypted; size and push times visible | invisible to non-members, even by SHA |
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

The encrypted files carry over as they are: envelopes don't depend on the mode.

1. **Set up the server** and register every member with their existing card. Cards are in the
   policy (`eyesonly policy show` lists members; each member can print theirs with
   `eyesonly whoami`):

   ```bash
   eyesonly-server user add "$(eyesonly whoami | tail -1)"     # per member; prints their token
   eyesonly-server repo create app.git --admin alice
   eyesonly-server policy set app.git policy.json              # same groups and file rules as before
   ```

   Field names match: `admins`, `groups` and `files` copy over. See
   [policy-reference.md](policy-reference.md).

2. **Push the history** (admin):

   ```bash
   git remote rename origin github
   git remote add origin https://alice:<token>@git.example.com/app.git
   git push -u origin --all && git push origin --tags
   ```

   The server checks every commit it receives, so this works only if every envelope in
   history was signed by a member who is a writer of that path under the new policy.

3. **Switch each clone.** The clone pinned the GitHub-mode policy, so re-pin and switch
   explicitly:

   ```bash
   rm .git/eyesonly/trust.json
   eyesonly setup --mode server
   eyesonly status
   ```

   Teammates do the same after `git remote set-url origin https://<them>:<token>@git.example.com/app.git`
   and `git pull`.

4. **Clean up.** Remove `.eyesonly/` in a commit (it no longer does anything once the remote
   is a server), sign the server policy so clients pin the admin again
   ([signed policies](policy-reference.md#signed-policies)), and if GitHub stays, set up the
   [mirror](../README.md#mirroring-to-githubgitlab-server) and stop pushing to it directly.

Going the other way (server to GitHub mode) means running `eyesonly init` in a clone on the
new host and granting each member again; the server's private branches don't carry over.
