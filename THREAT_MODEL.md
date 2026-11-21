# Veil threat model

**Security boundary:** the `veil-server` process, its data directory and its
pre-receive hook. Clients are untrusted. The client filter only makes things
convenient; the server enforces.

## Assets

1. Plaintext of protected files (`.env`, `secrets/**`, …)
2. Existence and content of private branches (names, commits, trees)
3. Integrity of protected files (nobody can plant a malicious `API_URL=`)
4. User identities (tokens, private keys)

## Adversaries

| ID | Adversary | Capabilities |
|---|---|---|
| A1 | **Insider outside the audience** (junior, contractor) | Valid token, repo member, full control of their own git client |
| A2 | **Outsider** | Network access to the server, no token |
| A3 | **Revoked member** | Used to be in the audience and kept old clones and keys |
| A4 | **Careless authorized dev** | Forgets the filter, merges the wrong branch, renames files |
| A5 | **Compromised server / host admin** | Out of scope for confidentiality of *refs*, but not of *files* (see below) |

## Attacks and defenses (each one has a test in `test/*.sh`)

| # | Attack | Defense | Test |
|---|---|---|---|
| 1 | A4/A1 pushes a plaintext `.env` with filters disabled | Hook: every protected path must be a valid `VEIL-V1` envelope | ✅ |
| 2 | A1 encrypts their own `.env` to the whole team (validly) and pushes it | Hook: the pusher must be in the file's audience to change it; the envelope's signer must be an allowed writer | ✅ |
| 3 | A1 replays an older, validly signed `.env` (rollback) | Hook: any change to a protected blob needs an authorized pusher, so a signature alone isn't enough | ✅ |
| 4 | A1 deletes a protected file | Hook: deletion counts as a modification | ✅ |
| 5 | A1 moves a ciphertext from `secrets/a` to `.env` | Path is in the GCM AAD and the signature; the hook and smudge check `env.path` | ✅ (rename test) |
| 6 | A2 guesses tokens or impersonates a user | Random 192-bit tokens, stored as SHA-256 and compared in constant time; username must match the token | ✅ |
| 7 | A1 reads objects via **dumb HTTP** (`GET /repo.git/objects/ab/cdef…`) | Proxy serves only the 3 smart-protocol routes; `http.getanyfile=false` as well | ✅ |
| 8 | A1 fetches a hidden commit **by SHA over protocol v2** | **Verified real**: stock `hideRefs` doesn't stop v2 `want <sha>`. The proxy drops `Git-Protocol`, forcing v0 with every `allow*SHA1InWant=false` | ✅ (fails if `VEIL_ALLOW_PROTOCOL_V2=1`) |
| 9 | A1 lists or fetches private refs by name | Per-user `transfer.hideRefs` | ✅ |
| 10 | A1 pushes to `private/*` | Hidden refs can't be updated (git) **and** the hook's branch write rule | ✅ |
| 11 | A4 merges `private/launch` into `main` (exposing its history) | Hook: commits that become reachable from a ref must not come from a ref with a narrower audience. Squash merges are allowed | ✅ |
| 12 | A1 grants themselves access by editing the policy | Policy lives on the server (`<repo>.git/veil.json`), not in the repo; the client copy is advisory | by design |
| 13 | A1 learns private branch names from the policy endpoint | The client policy view omits branch rules | ✅ |
| 14 | A3 reads secrets changed after revocation | `veil rekey` re-encrypts without them; hook rejects envelopes that include non-audience recipients | ✅ |
| 15 | A4 pushes with a stale policy that still includes a revoked user | Same check as #14; error tells them to `pull-policy && rekey` | ✅ |
| 16 | Path traversal via repo name | Strict `^[A-Za-z0-9][A-Za-z0-9._-]*\.git$`; unknown and non-member repos both return 404 | ✅ |
| 17 | Malicious env injection into `git http-backend` | Env is built from scratch (allow-list), `GIT_CONFIG_NOSYSTEM=1` | by design |
| 18 | A1's client is tricked into decrypting/using a forged secret | Smudge checks the Ed25519 signature and that the signer is an allowed writer before writing plaintext | by design |
| 19 | A1 probes whether the server holds a private commit via `have <sha>` ACKs (object-existence oracle) | Proxy parses the upload-pack body and drops have/shallow lines for objects not reachable from refs visible to the user; the response is byte-identical to a nonexistent sha | ✅ (test/oracle.sh) |
| 20 | A5 swaps a teammate's public key so new secrets are encrypted to the server | An admin signs a manifest of file rules + keys (`veil policy-sign`); clients verify it and use only the manifest's keys. A tampered manifest fails with `policy signature invalid` and the cached policy is left untouched | ✅ (test/attest.sh) |
| 21 | A5 makes itself (or mallory) an admin and re-signs the policy | Clients pin the admin key on first contact (`.git/veil/trust.json`, or out of band with `VEIL_PIN_ADMIN`) and refuse other signers: `not signed by a pinned admin` | ✅ (test/attest.sh) |
| 22 | A5 rolls back to an older, validly signed policy (e.g. one that still includes a revoked user) | Manifests carry a version; clients refuse anything older than the last version they saw, and a same-version manifest with different content | ✅ (test/attest.sh) |
| 23 | A5 downgrades to an unsigned policy | Once a repo was signed, the client refuses an unsigned policy: `repo was signed; server now serves an unsigned policy` | ✅ (test/attest.sh) |
| 24 | A5 injects a recipient (or a signing key) into the unsigned part of the policy view | Clients encrypt only to, and accept envelope signatures only from, keys in the signed manifest; the server flags `attestation_stale` and the client warns | ✅ (test/attest.sh) |
| 25 | A4 renames a protected file with `git mv` (stale path binding) | Pre-commit hook re-seals the envelope for the new path (refuses moves to unprotected paths); if the hook is bypassed the server still rejects the stale binding | ✅ (test/hooks.sh) |
| 26 | A4/A1 stages plaintext or a stale-audience envelope | Pre-commit hook refuses plaintext and re-seals stale audiences before anything leaves the laptop (defense in depth; the server hook remains the boundary) | ✅ (test/hooks.sh) |

## Known limitations

These are stated plainly, because over-claiming is how security products lose trust.

1. **Revocation isn't retroactive.** A3 keeps every version they could already
   decrypt. `veil audit <user>` lists exactly which files to rotate. Crypto can't fix
   this; only rotation does.
2. **Metadata leaks on shared branches.** A1 sees that `.env` exists, its size (roughly),
   when it changed and who signed it. Hiding file *existence* needs a virtual-filesystem
   approach (Piper/CitC-style), not git's Merkle DAG.
3. **Object-existence oracle.** Closed in v0.2 (attack #19). Remaining: the proxy still sees full bodies; unreachable-object checks rely on hideRefs prefixes.
4. **Compromised server (A5).** The server can't read protected *files* (it never holds
   private keys) and, once an admin signs the policy, it can't lie about public keys or
   audiences (#20-24). It still sees private *branches* (they're plaintext git objects).
   Admin trust is TOFU: the first contact is trusted unless `VEIL_PIN_ADMIN` is set,
   unsigned repos are only warned about, and adding or rotating an admin needs a
   re-pin (re-clone, or delete `.git/veil/trust.json`).
5. **Pre-receive cost.** The hook runs `ls-tree -r` per new commit; large monorepos
   need path-filtered diffs (roadmap 0.2).
6. **Protocol v0 only.** That's a deliberate trade-off (see #8) and costs some fetch
   efficiency on very large repos.
7. **Transport.** `veil-server` speaks plain HTTP. Deploy it behind TLS. Tokens are
   bearer credentials.
8. **No forward secrecy for files.** Losing a user's X25519 private key exposes every
   envelope addressed to them. Store keys with `0600` (done), and move to hardware-backed
   keys (roadmap 1.0).

## Crypto summary

- Content: AES-256-GCM, random 256-bit DEK and 96-bit IV per seal,
  AAD = `"veil-v1\0" || path`.
- Key wrap: an ephemeral X25519 key per seal; per recipient
  `KEK = HKDF-SHA256(ECDH, salt = epk || rpk, info = "veil-wrap-v1")`, then the DEK is
  wrapped with AES-256-GCM, AAD = `"veil-wrap\0" || name`.
- Authenticity: Ed25519 over canonical JSON (sorted keys) of every field except `sig`.
- All primitives come from Node's OpenSSL bindings; nothing is hand-rolled.
