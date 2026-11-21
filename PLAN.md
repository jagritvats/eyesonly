# Eyes Only: product plan

> Git is all-or-nothing: clone access means you get every file and every branch.
> Eyes Only adds **private files, private branches and built-in secrets** to ordinary git
> repos, and keeps them working with the stock `git` CLI, IDEs and CI.

## 1. Problem

Teams want three things that git's data model doesn't allow:

| Need | What teams do today | Why it hurts |
|---|---|---|
| Keep `.env` / keys next to the code | Vault, Doppler, 1Password CLI, `sops`, `git-crypt` | Another vendor, another login, secrets drift away from the commit that needs them |
| A branch only 3 people can see (stealth launch, security fix, M&A) | Fork into a separate private repo | History splits, rebasing between repos is painful, CI is set up twice |
| Contractors and juniors on the main repo without prod secrets | Separate repos or "please don't look" | Either a lot of overhead or no real control |

Git can't do this natively because a commit hashes its whole tree. You can't leave a
file out for one user without changing the hash for everyone.

## 2. Insight

Split access control into **three layers that each work with stock git**:

1. **Content layer** (client): a clean/smudge filter encrypts protected paths per
   recipient. The tree stays identical for everyone; only the people the policy names
   can read the blob.
2. **Visibility layer** (server): an authenticating smart-HTTP proxy hides refs per
   user (`transfer.hideRefs`), forces protocol v0 so hidden objects can't be fetched by
   SHA, and refuses dumb HTTP.
3. **Enforcement layer** (server): a pre-receive hook checks every incoming commit
   against the server's copy of the policy. That rules out plaintext secrets,
   unauthorized edits, forged or replayed ciphertext, and private history merged into
   public branches.

The client is a convenience. **The server is the security boundary.** A user who
removes the client filter can't get anything onto the server that the policy forbids.

## 3. Users and positioning

- **Beachhead:** 5–50 engineer startups on self-hosted git, or anyone fed up with a
  separate secrets manager for a handful of `.env` files.
- **Expansion:** agencies and consultancies (client code plus contractors), open-core
  companies (one repo, private enterprise directory), regulated teams (audit trail of
  who could read which secret, and when).
- **Alternatives:**
  - *git-crypt / sops / transcrypt* encrypt files, but anyone can push plaintext and
    nothing enforces who may write. They also have no private branches.
  - *Separate repos* give real isolation, but history fragments.
  - *GitHub/GitLab* permissions are per repo, not per path or branch read.
  - *Vault / Doppler* do runtime secrets well, but they're a separate system that
    drifts from the code.

Pitch: **"git-crypt, but the server enforces it, plus private branches."**

## 4. MVP scope (this repo, v0.1)

Shipped in v0.1 and covered by `test/e2e.sh` (47 adversarial checks; 436 across all suites as of v0.3):

- `eyesonly` client: `keygen`, `clone`, `setup`, `pull-policy`, `status`, `rekey`, `audit`,
  plus the clean/smudge/textconv filters (`git diff` shows plaintext to readers and a
  placeholder to everyone else).
- Crypto: X25519 + HKDF + AES-256-GCM envelopes, path-bound AAD, Ed25519 writer
  signatures. Zero dependencies (Node ≥ 20 and git).
- `eyesonly-server`: users with hashed bearer tokens, repos, validated JSON policy,
  smart-HTTP proxy with per-user ref hiding, pre-receive enforcement.
- Landing page (`site/index.html`, also served at `/` by `eyesonly-server serve`).

Explicitly **out of MVP**: TLS termination (put Caddy/nginx in front), web UI, SSH
transport, hosting a GitHub/GitLab-compatible API, SSO, key escrow, partial clone.

## 5. Roadmap

| Phase | Ships | Exit criterion |
|---|---|---|
| **0.1 MVP** (done) | Everything above | 47/47 e2e checks green |
| **0.2 Trust the client, not the host** (done) | Admin-signed policy + client key pinning (vs. a lying server); have-negotiation oracle closed; pre-commit hook that rekeys on `git mv` / policy change | 200/200 checks across 4 suites |
| **0.3 Safe in a real team's workflow** (done) | Protected refs + read-only members (no force-push/rewind to a stale secret, admins included); `filter=eyesonly` pinned in `info/attributes` and redirected filters (LFS, nested `.gitattributes`) refused client- and server-side, `git worktree`/sparse-checkout fixed; merge driver that verifies, merges and re-seals encrypted files; outbound mirror to GitHub/GitLab from a sanitized staging repo | 436/436 checks across 9 suites, including post-merge security fixes |
| **0.3.1** (done) | Onboarding fixes for existing clones, autocrlf, large secrets, Windows demo; guides + docs site | Clean onboarding on Linux, macOS and Windows |
| **0.4 Start without a server** (done) | GitHub mode (signed policy in the repo, same commands, `init`/`join`/`grant`/`revoke`, `eyesonly verify` as pre-push hook and required CI check); `eyesonly-server init` + compose/Caddy kit, `user set-key`; `eyesonly run`/`env`, `EYESONLY_IDENTITY`, GitHub Action; long-running filter process, `doctor`, `--remote`, credential-helper tokens; CI on Linux, macOS and Windows | 696 checks × 13 suites green on 3 OSes |
| **0.5 Private branches everywhere, teams that scale** (done) | (1) **Private branches in GitHub mode**: sealed, signed, rollback-checked bundles under `refs/eyesonly/`, `eyesonly branch push/pull/list/publish`, pre-push guard so `private/*` never goes to the host in plaintext; (2) **GitHub-mode hardening**: `writers` in the repo policy, `eyesonly migrate` to the server with pins carried over, commit-signature attribution in `verify`; (3) **Keys at rest**: identity in the OS keychain (macOS Keychain, Windows DPAPI, Linux Secret Service) instead of a plain file; (4) **Server admin API**: `eyesonly admin ...` (user add, grant, revoke, policy) over HTTPS with admin-scoped tokens, plus an append-only server audit log; (5) **Who could read what, when**: `eyesonly audit --file .env --at <date>` from git history, and `eyesonly offboard <user>` (revoke, rekey, rotation checklist) | Every feature with adversarial tests on 3 OSes; a team can run private branches on GitHub with no server |
| **0.6 Teams** | Web dashboard (policy editor, audit log, offboarding wizard), multiple devices per person, identity from GitHub SSH keys, inbound sync from GitHub | Paid pilot |
| **1.0** | SSO/SCIM groups → policy groups, hardware keys (WebAuthn PRF), CI identities with short-lived keys, SOC 2 | 10 paying teams |

## 6. Business model

- **Open source core** (MIT): client, server, hook. Trust requires being able to read the crypto.
- **Eyes Only Cloud**: hosted proxy/mirror, dashboard, audit log, SSO. $8/dev/month, free ≤ 5 devs.
- **Enterprise**: self-hosted with SSO/SCIM, HSM-backed server keys, support.

## 7. Go-to-market

1. Launch as a reply to the "git is 100% or 0% access" discussion: a 60-second demo
   (`npm test` printing 47 attacks being blocked) plus the threat model, written up
   honestly, including the limitations.
2. Show HN / r/programming: "We tried to break per-user git permissions. Here's what we
   couldn't stop," led by the protocol-v2 SHA-fetch finding.
3. Design partners: 5 startups currently paying for a secrets manager only for `.env` files.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Crypto or protocol bug ⇒ loss of trust | Small, readable code; no custom primitives; an external audit before 1.0; adversarial tests in CI |
| Git upstream changes `hideRefs` / protocol semantics | e2e suite pins behavior on every git release; proxy forces protocol v0 |
| "Just use separate repos" inertia | Lead with the secrets use case (immediate value), then private branches |
| Revocation can't be retroactive (they already saw it) | Be upfront about it: `eyesonly audit` lists exactly what to rotate |

See [THREAT_MODEL.md](THREAT_MODEL.md) for the adversarial analysis.
