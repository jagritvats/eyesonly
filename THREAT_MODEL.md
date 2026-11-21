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
| 40 | A4 (admin) allowlists a private ref for the outbound mirror, or a glob catches one | `mirror push` re-evaluates the current policy every run: only allowlisted refs whose audience covers all members are eligible, `refs/heads/private/*` never is, `refs/*`/`*` allowlists are refused (`push allowlist too broad`), and skipped refs make the run exit non-zero | ✅ (test/mirror.sh) |
| 41 | Private objects leak upstream as thin-pack delta bases, or the upstream's advertised shas become an existence oracle | The push runs from a separate staging repo that fetched only eligible refs through upload-pack, so it physically lacks private objects; refspecs are explicit per ref (never `--mirror`/`--all`/`--tags`/`+`); failed attempts are pruned from the stage | ✅ (test/mirror.sh) |
| 42 | A plaintext or forged protected blob reaches the upstream after being written behind the hook (plumbing, hook bug), or private history is fast-forwarded into a public ref | Every commit new to the upstream is re-verified in the stage: protected paths must be valid envelopes signed by a registered writer in the file's audience, and no commit may come only from a narrower-audience ref (relative to what the upstream already has). Any failure pushes nothing | ✅ (test/mirror.sh) |
| 43 | A policy change makes an already-mirrored branch private | The next run skips it and says plainly that the upstream copy must be treated as disclosed (forks, `refs/pull/*` and caches keep it); `--delete-upstream on-private` deletes the upstream ref; the stage drops it and prunes its objects | ✅ (test/mirror.sh) |
| 44 | Code execution through the mirror URL (`ext::`, `fd::`, `file://`) | `<transport>::` URLs are always refused, local paths only with `--allow-local`; the push runs with `protocol.allow=never` plus https/ssh (file only with `--allow-local`), checked again at push time | ✅ (test/mirror.sh) |
| 45 | The upstream credential leaks via argv, the URL, logs or the HTTP proxy | Token is read from a 0600 file outside the repo dir and passed as `http.extraHeader` through `GIT_CONFIG_*` env, never argv or URL; redirects are not followed; error output is scrubbed; `veil-mirror.json` is 0600, shows only the path, and nothing under the repo dir but the 3 smart-HTTP routes is served | ✅ (test/mirror.sh) |
| 46 | Someone pushes directly to the upstream, bypassing Veil | **Limitation**: Veil can't police another host. Upstream branch protection must allow only the mirror's credential to push mirrored branches; Veil refuses to force over upstream changes (`non-fast-forward; not retrying with force`, leases with `--allow-force`) | ✅ (divergence test); protection is documented |

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
