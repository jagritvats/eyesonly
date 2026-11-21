// Signed policy manifests (shared by client and server).
//
// The server alone decides who may push, but the *client* decides whom it encrypts to
// and whose signatures it trusts, from the public keys in the policy endpoint. A lying
// server (A5) could swap a teammate's key or add a recipient. An admin therefore signs
// a manifest of the file rules and keys with their Ed25519 identity key:
//
//   manifest:    { v: 1, repo, version, files: [[glob, [users]], ...], keys: { user: card } }
//   attestation: { manifest, signer, signer_ed25519, sig = Ed25519("eyesonly-policy-v1\0" + canonical(manifest)) }
//
// `files` is an ordered array because file rules are first-match-wins and canonical
// JSON sorts object keys. Clients pin the admin key on first contact (TOFU, in
// .git/eyesonly/trust.json) and refuse unsigned, re-signed, rolled-back or foreign policies.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { pubKey, privKey } from './crypto.mjs';
import { expand } from './policy.mjs';
import { identityPath, readIdentity } from './identity.mjs';

const DOMAIN = 'eyesonly-policy-v1\0';
const b64 = (b) => Buffer.from(b).toString('base64');
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

/** Sorted-key JSON, identical to the envelope canonicalization in crypto.mjs. */
export function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

/** Pure and deterministic: the same server state always yields the same manifest. */
export function buildManifest({ repo, policy, users, version }) {
  const all = Object.keys(users);
  const files = [];
  const keys = {};
  for (const [glob, who] of Object.entries(policy.files || {})) {
    const audience = [...expand(policy, who, all)].filter((u) => Object.hasOwn(users, u)).sort();
    files.push([glob, audience]);
    for (const u of audience) keys[u] = { x25519: users[u].x25519, ed25519: users[u].ed25519 };
  }
  return { v: 1, repo, version, files, keys };
}

/** The parts of a manifest that must match the server's current policy. */
export const manifestContent = (m) => canonical({ repo: m.repo, files: m.files, keys: m.keys });

export const manifestBytes = (m) => Buffer.from(DOMAIN + canonical(m));
export const manifestHash = (m) => sha256hex(canonical(m));

export function signManifest(manifest, identity) {
  return {
    manifest,
    signer: identity.name,
    signer_ed25519: identity.ed25519.pub,
    sig: b64(crypto.sign(null, manifestBytes(manifest), privKey(identity.ed25519.priv))),
  };
}

export function verifyAttestation(att) {
  try {
    return crypto.verify(null, manifestBytes(att.manifest), pubKey(att.signer_ed25519), Buffer.from(att.sig, 'base64'));
  } catch {
    return false;
  }
}

export function adminFingerprint(ed25519b64) {
  return sha256hex(ed25519b64).slice(0, 16).match(/.{4}/g).join(':');
}

export function validManifest(m) {
  const names = (a) => Array.isArray(a) && a.every((x) => typeof x === 'string');
  return (
    m && m.v === 1 && typeof m.repo === 'string' && Number.isInteger(m.version) && m.version >= 1 &&
    Array.isArray(m.files) && m.files.every((f) => Array.isArray(f) && f.length === 2 && typeof f[0] === 'string' && names(f[1])) &&
    m.keys && typeof m.keys === 'object' && !Array.isArray(m.keys) &&
    Object.values(m.keys).every((k) => k && typeof k.x25519 === 'string' && typeof k.ed25519 === 'string')
  );
}

/** The .git/eyesonly/policy.json shape the filters already understand. Insertion order keeps first-match order. */
export function manifestToPolicy(m, user) {
  return { repo: m.repo, user, files: Object.fromEntries(m.files), keys: m.keys };
}

/**
 * Decide which policy to trust. `raw` is the /eyesonly/policy response, `trust` the pinned
 * state (or null on first contact), `pin` an out-of-band admin fingerprint.
 * Returns { policy, trust, notes }; throws with a user-facing message on any attack.
 */
export function resolvePolicy(raw, { trust, repoName, pin }) {
  const notes = [];
  const att = raw.attestation;
  if (!att) {
    if (trust?.signed) throw new Error('repo was signed; server now serves an unsigned policy');
    notes.push('warning: policy is not signed by an admin');
    const { repo, user, files, keys } = raw;
    return { policy: { repo, user, files, keys }, trust: trust ?? null, notes };
  }
  if (!verifyAttestation(att)) throw new Error('policy signature invalid');
  const m = att.manifest;
  if (!validManifest(m)) throw new Error('policy signature invalid (malformed manifest)');
  if (m.repo !== repoName) throw new Error(`attestation is for repo ${m.repo}, not ${repoName}`);
  const fp = adminFingerprint(att.signer_ed25519);
  if (pin && pin !== fp) throw new Error('admin key does not match pinned fingerprint');
  const hash = manifestHash(m);
  let admins;
  if (trust) {
    if (!Object.hasOwn(trust.admins || {}, att.signer)) throw new Error('not signed by a pinned admin');
    if (trust.admins[att.signer] !== fp) throw new Error('admin key does not match pinned fingerprint');
    if (m.version < trust.version) throw new Error(`policy version ${m.version} is older than last seen ${trust.version}`);
    if (m.version === trust.version && hash !== trust.manifestHash) {
      throw new Error(`policy version ${m.version} was re-signed with different content`);
    }
    admins = trust.admins;
  } else {
    admins = { [att.signer]: fp };
    notes.push(`pinned admin ${att.signer} ${fp}`);
  }
  if (raw.attestation_stale) notes.push('warning: server policy changed since the last admin signature; using the signed policy');
  return {
    policy: manifestToPolicy(m, raw.user),
    trust: { v: 1, repo: m.repo, signed: true, admins, version: m.version, manifestHash: hash },
    notes,
  };
}

const trustPath = (gitDir) => path.join(gitDir, 'eyesonly', 'trust.json');

export function loadTrust(gitDir) {
  const p = trustPath(gitDir);
  return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : null;
}

export function saveTrust(gitDir, trust) {
  const p = trustPath(gitDir);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p + '.tmp', JSON.stringify(trust, null, 2));
  fs.renameSync(p + '.tmp', p);
}

// ------------------------------------------------------------- admin (client)


/** eyesonly policy-sign [file]: sign the output of `eyesonly-server policy manifest`. */
export function cmdPolicySign([file]) {
  const fail = (msg) => {
    console.error('[eyesonly]', msg);
    process.exit(1);
  };
  let identity;
  try {
    identity = readIdentity();
  } catch (e) {
    fail(e.message);
  }
  if (!identity) fail(`no identity at ${identityPath()}. Run: eyesonly keygen <your-name> (or set EYESONLY_IDENTITY)`);
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(file && file !== '-' ? file : 0, 'utf8'));
  } catch (e) {
    fail(`can't read manifest: ${e.message}. Usage: eyesonly-server policy manifest <repo> > m.json && eyesonly policy-sign m.json`);
  }
  if (!validManifest(manifest)) fail('not an eyesonly policy manifest (expected the output of `eyesonly-server policy manifest <repo>`)');
  console.log(JSON.stringify(signManifest(manifest, identity)));
  console.error(`[eyesonly] signed ${manifest.repo} policy v${manifest.version} as ${identity.name}. Install it with: eyesonly-server policy attest ${manifest.repo} <this-file>`);
}
