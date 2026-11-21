// Repo mode: the policy lives in the repo as an admin-signed file, no server needed.
//
//   .eyesonly/policy.json = attestation { manifest, signer, signer_ed25519, sig }
//   manifest = { v: 1, kind: 'repo', repo: <random id>, version,
//                policy: { members, admins, groups, files, branches, writers? }, // the rules as written
//                files: [[glob, [users]], ...],                  // expanded audiences, rule order
//                branches: [[prefix, [users]], ...],             // expanded, sorted by prefix
//                keys: { user: { x25519, ed25519, ssh_signing? } } } // every member's public keys
//
// `writers` (optional, default: members) narrows who may sign protected files and seal private
// branches, exactly like the server's `writers`: a writer of a path or branch is in its audience
// AND a writer; admins always write. `ssh_signing` is an optional SSH public key used by
// `eyesonly verify --require-signed` to attribute commits.
//
// `branches` (private branches, sealed under refs/eyesonly/, see branches.mjs) is optional:
// policies written before 0.5 have none, and older clients ignore it.
//
// It is the server flow's signed manifest (src/attest.mjs) plus the raw rules, so admins can
// edit groups and `eyesonly verify` can apply the same checks as the server's hook. The repo id
// replaces the server repo name: it pins the policy to this repo, so a policy signed for
// another repo can't be swapped in once a clone has seen this one.
//
// Clients read the file from the DEFAULT BRANCH tip, never from the current branch, so a
// feature branch can't loosen access. They verify the signature, require a version that
// never goes down, and pin the admin keys on first contact (.git/eyesonly/trust.json,
// EYESONLY_PIN_ADMIN to pin up front). Admin changes propagate only through a policy signed
// by an already-pinned admin.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import * as attest from './attest.mjs';
import { expand } from './policy.mjs';

export const POLICY_FILE = '.eyesonly/policy.json';
export const REQUESTS_DIR = '.eyesonly/requests';

const git = (args, cwd) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 30 }).trim();
const tryGit = (args, cwd) => {
  try {
    return git(args, cwd);
  } catch {
    return null;
  }
};

// ------------------------------------------------------------------ location

/**
 * The default branch to read the policy from: <remote>/HEAD, then <remote>/main|master, then
 * local main|master. <remote> is `remote`, else `git config eyesonly.remote`, else origin.
 */
export function defaultRef(cwd, remote) {
  const r0 = remote || tryGit(['config', 'eyesonly.remote'], cwd) || 'origin';
  const head = tryGit(['symbolic-ref', '-q', `refs/remotes/${r0}/HEAD`], cwd);
  if (head) return head;
  for (const r of [`refs/remotes/${r0}/main`, `refs/remotes/${r0}/master`, 'refs/heads/main', 'refs/heads/master']) {
    if (tryGit(['rev-parse', '--verify', '-q', r], cwd)) return r;
  }
  return null;
}

/** The policy file's text at `rev`, or null. */
export function policyTextAt(rev, cwd) {
  if (!rev) return null;
  if (!tryGit(['rev-parse', '--verify', '-q', `${rev}:${POLICY_FILE}`], cwd)) return null;
  return execFileSync('git', ['cat-file', 'blob', `${rev}:${POLICY_FILE}`], { cwd, encoding: 'utf8', maxBuffer: 1 << 30 });
}

export function parseAttestation(text) {
  let att;
  try {
    att = JSON.parse(text);
  } catch {
    throw new Error(`${POLICY_FILE} is not valid JSON`);
  }
  if (!att || typeof att !== 'object' || !att.manifest || typeof att.sig !== 'string' || typeof att.signer !== 'string' || typeof att.signer_ed25519 !== 'string') {
    throw new Error(`${POLICY_FILE} is not a signed eyesonly policy (expected the file written by \`eyesonly init\`)`);
  }
  return att;
}

// ------------------------------------------------------------------ manifest

const names = (a) => Array.isArray(a) && a.every((x) => typeof x === 'string');

/** Expanded audiences in rule order, exactly as the server's buildManifest computes them. */
function expandFiles(policy, keys) {
  const all = Object.keys(keys);
  return Object.entries(policy.files || {}).map(([glob, who]) => [glob, [...expand(policy, who, all)].sort()]);
}

/** Everyone who may sign protected files or seal branches: writers (default members) plus admins. */
export function effectiveWriters(rules, all) {
  return new Set([...expand(rules, rules.writers ?? rules.members, all), ...expand(rules, rules.admins || [], all)]);
}

/** Expanded branch audiences, sorted by prefix (branch rules are longest-prefix, so order doesn't matter). */
function expandBranches(policy, keys) {
  const all = Object.keys(keys);
  return Object.keys(policy.branches || {}).sort().map((prefix) => [prefix, [...expand(policy, policy.branches[prefix], all)].sort()]);
}

/** A branch rule prefix: a full ref under refs/heads/. `private/` is accepted as `refs/heads/private/`. */
export function branchPrefix(s) {
  const p = s.startsWith('refs/') ? s : `refs/heads/${s}`;
  return /^refs\/heads\/[A-Za-z0-9._\/-]+$/.test(p) && !p.includes('..') ? p : null;
}

export function buildRepoManifest({ repo, version, policy, keys }) {
  const rules = {
    members: policy.members || ['*'],
    admins: policy.admins || [],
    groups: policy.groups || {},
    files: policy.files || {},
    branches: policy.branches || {},
    ...(policy.writers !== undefined ? { writers: policy.writers } : {}),
  };
  return { v: 1, kind: 'repo', repo, version, policy: rules, files: expandFiles(rules, keys), branches: expandBranches(rules, keys), keys };
}

/** Structure and self-consistency checks on a repo manifest (the signature is checked separately). */
export function validRepoManifest(m) {
  if (!attest.validManifest(m) || m.kind !== 'repo' || !/^[0-9a-f]{32}$/.test(m.repo)) return false;
  const p = m.policy;
  if (!p || typeof p !== 'object' || !names(p.members) || !names(p.admins) || !p.admins.length) return false;
  if (!p.groups || typeof p.groups !== 'object' || !Object.values(p.groups).every(names)) return false;
  if (!p.files || typeof p.files !== 'object' || !Object.values(p.files).every(names)) return false;
  if (p.writers !== undefined && !names(p.writers)) return false;
  if (!Object.values(m.keys).every((k) => k.ssh_signing === undefined || typeof k.ssh_signing === 'string')) return false;
  if (!p.admins.every((a) => Object.hasOwn(m.keys, a))) return false;
  // Branch rules (0.5+): both the raw rules and the expanded audiences, or neither.
  if ((p.branches === undefined) !== (m.branches === undefined)) return false;
  if (p.branches !== undefined) {
    if (!p.branches || typeof p.branches !== 'object' || Array.isArray(p.branches) || !Object.values(p.branches).every(names)) return false;
    if (!Object.keys(p.branches).every((k) => branchPrefix(k) === k)) return false;
    if (attest.canonical(expandBranches(p, m.keys)) !== attest.canonical(m.branches)) return false;
  }
  // The expanded audiences must be what the rules say, in the same order.
  const globs = m.files.map(([g]) => g);
  if (globs.length !== Object.keys(p.files).length || !globs.every((g) => Object.hasOwn(p.files, g))) return false;
  const expected = expandFiles(rulesOf(m), m.keys);
  return attest.canonical(expected) === attest.canonical(m.files);
}

/** The raw rules with file order taken from the signed array (JSON key order isn't signed). */
export function rulesOf(m) {
  return { ...m.policy, files: Object.fromEntries(m.files.map(([g]) => [g, m.policy.files[g]])) };
}

/** The .git/eyesonly/policy.json cache the filters read. */
export function cachePolicy(m, user) {
  const writers = [...effectiveWriters(rulesOf(m), Object.keys(m.keys))].sort();
  return { ...attest.manifestToPolicy(m, user), branches: Object.fromEntries(m.branches || []), mode: 'repo', version: m.version, writers };
}

const fingerprints = (m, who) => Object.fromEntries(who.map((a) => [a, attest.adminFingerprint(m.keys[a].ed25519)]));

/**
 * Check a signed repo policy against the pinned trust (null on first contact).
 * Returns { manifest, trust, notes }; throws with a user-facing message on any problem.
 */
export function resolveRepoPolicy(att, { trust, pin }) {
  const notes = [];
  if (!attest.verifyAttestation(att)) throw new Error('policy signature invalid');
  const m = att.manifest;
  if (!validRepoManifest(m)) throw new Error('policy is malformed or inconsistent (was it edited by hand? admins change it with eyesonly grant/revoke)');
  if (!m.policy.admins.includes(att.signer) || m.keys[att.signer].ed25519 !== att.signer_ed25519) {
    throw new Error(`policy is signed by '${att.signer}', who is not an admin in it`);
  }
  const fp = attest.adminFingerprint(att.signer_ed25519);
  const hash = attest.manifestHash(m);
  if (trust) {
    if (trust.mode !== 'repo') throw new Error('this clone was set up against an Eyes Only server, not a policy in the repo');
    if (trust.repo !== m.repo) throw new Error(`policy belongs to a different repo (id ${m.repo}, pinned ${trust.repo})`);
    if (!Object.hasOwn(trust.admins || {}, att.signer)) throw new Error(`not signed by a pinned admin ('${att.signer}' isn't one)`);
    if (trust.admins[att.signer] !== fp) throw new Error(`admin key for '${att.signer}' does not match the pinned fingerprint`);
    if (m.version < trust.version) throw new Error(`policy version ${m.version} is older than the last one seen here (${trust.version})`);
    if (m.version === trust.version && hash !== trust.manifestHash) throw new Error(`policy version ${m.version} was re-signed with different content`);
  } else {
    if (pin && pin !== fp) throw new Error(`admin key ${fp} does not match EYESONLY_PIN_ADMIN (${pin})`);
    notes.push(`pinned admin ${att.signer} ${fp}${m.policy.admins.length > 1 ? ` (and ${m.policy.admins.length - 1} more admin(s) listed in that policy)` : ''}. Compare it with your admin out of band.`);
  }
  return {
    manifest: m,
    // A policy signed by a pinned admin may change the admin set: pin the new one.
    trust: { v: 1, mode: 'repo', repo: m.repo, signed: true, admins: fingerprints(m, m.policy.admins), version: m.version, manifestHash: hash },
    notes,
  };
}

/** Sign `manifest` with an admin identity. */
export function signRepoManifest(manifest, identity) {
  if (!manifest.policy.admins.includes(identity.name)) throw new Error(`'${identity.name}' is not an admin of this repo`);
  if (manifest.keys[identity.name]?.ed25519 !== identity.ed25519.pub) throw new Error(`your identity's key doesn't match '${identity.name}' in the policy`);
  return attest.signManifest(manifest, identity);
}

export function writePolicyFile(top, att) {
  const p = path.join(top, POLICY_FILE);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(att, null, 2) + '\n');
}

export const newRepoId = () => crypto.randomBytes(16).toString('hex');
