// Server state and the operations on it, shared by the admin CLI (eyesonly-server ...)
// and the admin HTTP API (src/admin.mjs). Operations throw OpError instead of exiting,
// so each front end decides how to report: the CLI prints and exits, the API answers
// with the error's HTTP status.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as attest from './attest.mjs';
import * as vc from './crypto.mjs';
import { expand } from './policy.mjs';
import * as refguard from './refguard.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER_CLI = path.resolve(HERE, '..', 'bin', 'eyesonly-server.mjs');

export const DATA = () => path.resolve(process.env.EYESONLY_DATA || 'eyesonly-data');
export const REPO_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.git$/;
export const sha256 = (s) => crypto.createHash('sha256').update(s).digest();
export const sha256hex = (s) => sha256(s).toString('hex');

export class OpError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

/** Write a file atomically (tmp + rename), optionally with a mode. */
function writeAtomic(file, text, mode) {
  fs.writeFileSync(file + '.tmp', text, mode ? { mode } : undefined);
  fs.renameSync(file + '.tmp', file);
}

// ------------------------------------------------------------------- users

const usersFile = () => path.join(DATA(), 'users.json');
export function loadUsers() {
  return fs.existsSync(usersFile()) ? JSON.parse(fs.readFileSync(usersFile(), 'utf8')).users : {};
}
export function saveUsers(users) {
  fs.mkdirSync(DATA(), { recursive: true, mode: 0o700 });
  writeAtomic(usersFile(), JSON.stringify({ users }, null, 2), 0o600);
}

export function newToken() {
  return 'eyesonly_' + crypto.randomBytes(24).toString('base64url');
}

export function parseCard(s, what = 'card') {
  try {
    return vc.decodeCard(s || '');
  } catch (e) {
    throw new OpError(`invalid ${what}: ${e.message}`);
  }
}

export const userFingerprint = (u) => vc.fingerprint({ x25519: u.x25519, ed25519: u.ed25519 });

/** Register a user; returns their git token (shown once by the caller). */
export function addUser(users, card) {
  if (Object.hasOwn(users, card.name)) throw new OpError(`user '${card.name}' exists`, 409);
  const token = newToken();
  users[card.name] = { x25519: card.x25519, ed25519: card.ed25519, tokenHash: sha256hex(token), created: new Date().toISOString() };
  saveUsers(users);
  return token;
}

export function getUser(users, name) {
  const u = Object.hasOwn(users, name || '') ? users[name] : null;
  if (!u) throw new OpError(`no such user '${name}'`, 404);
  return u;
}

/** Lost key or new machine: same user, same token, new public keys. Returns old/new fingerprints. */
export function setUserKey(users, card) {
  const u = Object.hasOwn(users, card.name) ? users[card.name] : null;
  if (!u) throw new OpError(`no such user '${card.name}' (new users: eyesonly-server user add <card>)`, 404);
  if (u.x25519 === card.x25519 && u.ed25519 === card.ed25519) throw new OpError(`'${card.name}' already has this key`, 409);
  const old = userFingerprint(u);
  Object.assign(u, { x25519: card.x25519, ed25519: card.ed25519, keyChanged: new Date().toISOString() });
  saveUsers(users);
  return { old, new: vc.fingerprint(card) };
}

export function rotateUserToken(users, name) {
  const u = getUser(users, name);
  const token = newToken();
  u.tokenHash = sha256hex(token);
  saveUsers(users);
  return token;
}

export function removeUser(users, name) {
  getUser(users, name);
  delete users[name];
  saveUsers(users);
}

/** What has to happen after a user's public keys change, per repo (one line each). */
export function keyChangeAdvice(name, users) {
  const all = Object.keys(users);
  const lines = [];
  for (const repo of listRepos()) {
    const dir = repoDir(repo);
    const policy = loadPolicy(dir);
    const reads = Object.values(policy.files || {}).some((who) => expand(policy, who, all).has(name));
    const att = loadAttestation(dir);
    if (reads) {
      lines.push(
        `${repo}: a reader with a decrypted checkout runs \`eyesonly pull-policy && eyesonly rekey\`, commits and pushes, so files are re-wrapped for ${name}'s new key. ` +
          `Files ${name} last wrote were signed with the old key; clients refuse them until they're re-sealed that way.`
      );
    }
    if (att && (reads || att.signer === name)) {
      lines.push(`${repo}: the signed policy is now stale and clients keep the old keys until an admin re-signs (policy manifest -> eyesonly policy-sign -> policy attest).`);
    }
    if (att?.signer === name) {
      lines.push(`${repo}: members pinned ${name}'s old admin key. After re-signing, they verify the new fingerprint with ${name} and re-pin (delete .git/eyesonly/trust.json, or set EYESONLY_PIN_ADMIN).`);
    }
  }
  lines.push(`Whoever holds the old private key can still read everything it could decrypt before. If it was lost or stolen, run \`eyesonly audit ${name}\` and rotate what it lists.`);
  return lines;
}

// ------------------------------------------------------- server-wide admins

const serverFile = () => path.join(DATA(), 'server.json');
export function loadServerConfig() {
  const c = fs.existsSync(serverFile()) ? JSON.parse(fs.readFileSync(serverFile(), 'utf8')) : {};
  return { server_admins: Array.isArray(c.server_admins) ? c.server_admins : [], ...c };
}
export function saveServerConfig(c) {
  fs.mkdirSync(DATA(), { recursive: true, mode: 0o700 });
  writeAtomic(serverFile(), JSON.stringify(c, null, 2), 0o600);
}
export function isServerAdmin(user, users = loadUsers()) {
  return Object.hasOwn(users, user) && loadServerConfig().server_admins.includes(user);
}

// -------------------------------------------------------------------- repos

export const repoDir = (name) => path.join(DATA(), 'repos', name);
export const policyFile = (dir) => path.join(dir, 'eyesonly.json');
export function loadPolicy(dir) {
  return JSON.parse(fs.readFileSync(policyFile(dir), 'utf8'));
}

export function listRepos() {
  const root = path.join(DATA(), 'repos');
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root).filter((r) => REPO_RE.test(r) && fs.existsSync(policyFile(repoDir(r))));
}

/** The directory of an existing repo, or a 404 (same answer for bad names and missing repos). */
export function existingRepo(name) {
  const dir = repoDir(name || '');
  if (!REPO_RE.test(name || '') || !fs.existsSync(policyFile(dir))) throw new OpError('no such repo', 404);
  return dir;
}

export function validatePolicy(p) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) throw new Error('policy must be a JSON object');
  const arr = (v, what) => {
    if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) throw new Error(`${what} must be a list of names`);
  };
  arr(p.members, 'members');
  arr(p.admins || [], 'admins');
  for (const [g, m] of Object.entries(p.groups || {})) arr(m, `groups.${g}`);
  for (const [f, m] of Object.entries(p.files || {})) arr(m, `files["${f}"]`);
  for (const [b, m] of Object.entries(p.branches || {})) {
    if (!b.startsWith('refs/')) throw new Error(`branch rule '${b}' must start with refs/`);
    arr(m, `branches["${b}"]`);
  }
  refguard.validateRefPolicy(p);
  return p;
}

/** Validate and store a repo's policy; returns { before, after } content hashes. */
export function savePolicy(dir, p) {
  try {
    validatePolicy(p);
  } catch (e) {
    throw new OpError(`invalid policy: ${e.message}`, 422);
  }
  const file = policyFile(dir);
  const before = fs.existsSync(file) ? sha256hex(fs.readFileSync(file)) : null;
  const text = JSON.stringify(p, null, 2);
  writeAtomic(file, text);
  return { before, after: sha256hex(text) };
}

function installHook(dir) {
  const hook = path.join(dir, 'hooks', 'pre-receive');
  fs.writeFileSync(hook, `#!/bin/sh\nexec '${process.execPath}' '${SERVER_CLI}' hook pre-receive\n`, { mode: 0o755 });
}

export function createRepo(name, policy) {
  if (!REPO_RE.test(name || '')) throw new OpError('repo name must look like name.git');
  const dir = repoDir(name);
  if (fs.existsSync(dir)) throw new OpError(`repo ${name} exists`, 409);
  fs.mkdirSync(path.dirname(dir), { recursive: true });
  execFileSync('git', ['init', '--quiet', '--bare', '-b', 'main', dir]);
  execFileSync('git', ['config', '-f', path.join(dir, 'config'), 'http.getanyfile', 'false']);
  installHook(dir);
  fs.writeFileSync(policyFile(dir), JSON.stringify(policy, null, 2));
  return dir;
}

export const starterPolicy = (admin) => ({ members: ['*'], admins: [admin], groups: {}, files: {}, branches: {} });

export function isRepoAdmin(user, dir, users = loadUsers()) {
  const policy = loadPolicy(dir);
  return expand(policy, policy.admins || [], Object.keys(users)).has(user);
}

/** Repos where `user` is an admin. */
export function adminRepos(user, users = loadUsers()) {
  return listRepos().filter((r) => isRepoAdmin(user, repoDir(r), users));
}

// -------------------------------------------------------- grant / revoke

const PRINCIPAL_RE = /^(@[A-Za-z0-9._-]{1,64}|[a-z0-9][a-z0-9._-]{0,38})$/i;

/**
 * Add a user or @group to file rules, branch rules or (with no targets) the members list.
 * Missing rules are created. Returns the list of human-readable changes (empty if none).
 */
export function grant(policy, principal, { files = [], branches = [] } = {}) {
  if (!PRINCIPAL_RE.test(principal || '')) throw new OpError(`invalid principal '${principal}' (a user name or @group)`);
  const changes = [];
  const add = (obj, key, label) => {
    obj[key] ||= [];
    if (!obj[key].includes(principal)) {
      obj[key].push(principal);
      changes.push(label);
    }
  };
  for (const b of branches) {
    if (!String(b).startsWith('refs/')) throw new OpError(`branch rule '${b}' must start with refs/`);
  }
  if (!files.length && !branches.length) {
    if (policy.members.includes('*')) return changes; // already a member through "*"
    add(policy, 'members', 'members');
  }
  policy.files ||= {};
  policy.branches ||= {};
  for (const f of files) add(policy.files, f, `files["${f}"]`);
  for (const b of branches) add(policy.branches, b, `branches["${b}"]`);
  return changes;
}

/**
 * Remove a user or @group from the given rules, or with no targets from members, every
 * file and branch rule and every group. Returns { changes, notes }.
 */
export function revoke(policy, principal, { files = [], branches = [] } = {}) {
  if (!PRINCIPAL_RE.test(principal || '')) throw new OpError(`invalid principal '${principal}' (a user name or @group)`);
  const changes = [];
  const notes = [];
  const drop = (obj, key, label) => {
    const list = obj?.[key];
    if (!Array.isArray(list) || !list.includes(principal)) return;
    obj[key] = list.filter((x) => x !== principal);
    changes.push(label);
  };
  const everything = !files.length && !branches.length;
  if (everything) {
    drop(policy, 'members', 'members');
    for (const f of Object.keys(policy.files || {})) drop(policy.files, f, `files["${f}"]`);
    for (const b of Object.keys(policy.branches || {})) drop(policy.branches, b, `branches["${b}"]`);
    if (!principal.startsWith('@')) for (const g of Object.keys(policy.groups || {})) drop(policy.groups, g, `groups.${g}`);
    if (policy.members.includes('*') && !principal.startsWith('@')) {
      notes.push(`${principal} is still a member through "*"; to cut off all access, remove the user (user remove).`);
    }
    if ((policy.admins || []).includes(principal)) notes.push(`${principal} is still an admin of this repo; edit "admins" to change that.`);
  } else {
    for (const f of files) drop(policy.files, f, `files["${f}"]`);
    for (const b of branches) drop(policy.branches, b, `branches["${b}"]`);
  }
  return { changes, notes };
}

// ------------------------------------------------------------- attestation

export const attestationFile = (dir) => path.join(dir, 'eyesonly-attestation.json');
export function loadAttestation(dir) {
  return fs.existsSync(attestationFile(dir)) ? JSON.parse(fs.readFileSync(attestationFile(dir), 'utf8')) : null;
}

/** Installed signed policy and whether the live policy has drifted from it. */
export function attestationStatus(repo, dir, users = loadUsers()) {
  const att = loadAttestation(dir);
  if (!att) return { signed: false };
  const current = attest.buildManifest({ repo, policy: loadPolicy(dir), users, version: 0 });
  return { signed: true, version: att.manifest.version, signer: att.signer, stale: attest.manifestContent(current) !== attest.manifestContent(att.manifest || {}) };
}

export const resignHint = (repo) =>
  `re-sign: eyesonly admin sign --repo ${repo}  (or on the server: eyesonly-server policy manifest ${repo} > m.json && eyesonly policy-sign m.json > s.json && eyesonly-server policy attest ${repo} s.json)`;

// After `import`, the first server version must exceed the GitHub-mode policy's, so clones
// that pinned admins in GitHub mode see the version go up, never down.
export const importFile = (dir) => path.join(dir, 'eyesonly-import.json');
export function importFloor(dir) {
  try {
    return JSON.parse(fs.readFileSync(importFile(dir), 'utf8')).version || 0;
  } catch {
    return 0;
  }
}

/** The manifest an admin signs next (version = installed + 1, and above any imported policy). */
export function nextManifest(repo, dir, users = loadUsers()) {
  const installed = loadAttestation(dir);
  const version = Math.max(installed?.manifest.version || 0, importFloor(dir)) + 1;
  return attest.buildManifest({ repo, policy: loadPolicy(dir), users, version });
}

/**
 * GitHub mode -> server. Verify a repo's signed .eyesonly/policy.json, register its members
 * with the keys it lists, and create the repo with the same rules (groups, files, writers,
 * branches). The repo policy's signature can't be reused: a server manifest binds the server
 * repo name and only the keys of file audiences, so an admin signs once more with the same
 * key, and clones that pinned that admin in GitHub mode accept it without re-pinning.
 * Returns { dir, manifest, rules, tokens: [[name, token]], existing: [names] }.
 */
export async function importRepo(name, attText, { adminCard = null, pin = null } = {}) {
  if (!REPO_RE.test(name || '')) throw new OpError('repo name must look like name.git');
  if (fs.existsSync(repoDir(name))) throw new OpError(`repo ${name} already exists; import only creates new repos`, 409);
  const rp = await import('./repo-policy.mjs');
  let m;
  try {
    const att = rp.parseAttestation(attText);
    m = rp.resolveRepoPolicy(att, { trust: null, pin }).manifest;
    if (adminCard) {
      const card = parseCard(adminCard, 'admin card');
      if (!m.policy.admins.includes(card.name) || m.keys[card.name]?.ed25519 !== card.ed25519 || m.keys[card.name]?.x25519 !== card.x25519) {
        throw new Error(`'${card.name}' with that card is not an admin of this policy`);
      }
      if (att.signer !== card.name) throw new Error(`the policy is signed by '${att.signer}', not by '${card.name}'`);
    }
  } catch (e) {
    throw new OpError(`can't import that policy: ${e.message}`, 422);
  }
  const rules = rp.rulesOf(m);
  const users = loadUsers();
  const fresh = [];
  const existing = [];
  for (const [u, k] of Object.entries(m.keys)) {
    if (!Object.hasOwn(users, u)) fresh.push(u);
    else if (users[u].x25519 !== k.x25519 || users[u].ed25519 !== k.ed25519) {
      throw new OpError(`user '${u}' already exists on this server with a different key. Fix that first (eyesonly-server user set-key), then import again.`, 409);
    } else existing.push(u);
  }
  const policy = {
    members: rules.members,
    admins: rules.admins,
    groups: rules.groups,
    files: rules.files,
    branches: rules.branches || {},
    ...(rules.writers !== undefined ? { writers: rules.writers } : {}),
  };
  try {
    validatePolicy(policy);
  } catch (e) {
    throw new OpError(`the repo policy doesn't convert to a server policy: ${e.message}`, 422);
  }
  fs.mkdirSync(DATA(), { recursive: true, mode: 0o700 });
  const tokens = fresh.map((u) => [u, addUser(users, { name: u, x25519: m.keys[u].x25519, ed25519: m.keys[u].ed25519 })]);
  const dir = createRepo(name, policy);
  fs.writeFileSync(importFile(dir), JSON.stringify({ from: m.repo, version: m.version, admins: rules.admins, imported: new Date().toISOString() }, null, 2));
  return { dir, manifest: m, rules, tokens, existing };
}

/** Verify and install an admin-signed manifest. Returns the installed version. */
export function installAttestation(repo, dir, att, users = loadUsers()) {
  const policy = loadPolicy(dir);
  if (!att?.manifest || typeof att.signer !== 'string') throw new OpError('not a signed manifest (expected the output of `eyesonly policy-sign`)');
  if (!expand(policy, policy.admins || [], Object.keys(users)).has(att.signer)) throw new OpError(`'${att.signer}' is not an admin of ${repo}`, 403);
  const u = Object.hasOwn(users, att.signer) ? users[att.signer] : null;
  if (!u || att.signer_ed25519 !== u.ed25519 || !attest.verifyAttestation(att)) {
    throw new OpError(`bad signature: not a valid signature by ${att.signer}'s registered key`, 422);
  }
  const installed = loadAttestation(dir);
  const current = attest.buildManifest({ repo, policy, users, version: 0 });
  if (attest.manifestContent(att.manifest) !== attest.manifestContent(current)) {
    throw new OpError(`signed manifest does not match current policy. Re-run: eyesonly-server policy manifest ${repo}`, 409);
  }
  const v = att.manifest.version;
  if (att.manifest.v !== 1 || !Number.isInteger(v) || v < 1 || (installed && v <= installed.manifest.version)) {
    throw new OpError(`version must increase (installed: ${installed?.manifest.version ?? 'none'}, signed: ${v}). Re-run: eyesonly-server policy manifest ${repo}`, 409);
  }
  writeAtomic(attestationFile(dir), JSON.stringify(att, null, 2));
  return v;
}
