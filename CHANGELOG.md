# Changelog

## 0.3.0 (2026-11-22)
- Protected refs and read-only members: no force-push, rewind or deletion of protected refs; admins included for content checks.
- `filter=eyesonly` pinned in `.git/info/attributes`; redirected filters (LFS, nested `.gitattributes`) refused on client and server; `git worktree` and sparse-checkout fixed.
- Merge driver that verifies, 3-way merges and re-seals encrypted files.
- Outbound mirror that pushes only verified public refs to GitHub/GitLab/Gitea, fail closed.
- Security: object-level visibility allowlist in the pre-receive hook (orphaned private commits, tags pointing at trees or blobs, tree entries naming hidden blobs); attribute checks on every commit that touches a protected path.
- `eyesonly demo`: self-contained local demo.
- Renamed from Veil to Eyes Only.

## 0.2.0 (2026-11-21)
- Admin-signed policy manifests and client-side admin key pinning, so a compromised server can't swap keys, add readers, roll back or downgrade the policy.
- Proxy filters `have`/`shallow` negotiation lines, closing the object-existence oracle.
- Pre-commit hook that re-encrypts on `git mv` and policy changes and refuses plaintext.

## 0.1.0 (2026-11-21)
- Clean/smudge encryption (X25519 + AES-256-GCM + Ed25519, path-bound), authenticating smart-HTTP proxy with per-user ref hiding and forced protocol v0, pre-receive policy enforcement, `rekey`, `audit`.
