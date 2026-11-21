// Content checks shared by the server's pre-receive hook and `eyesonly verify` (repo mode).
//
// For one policy, `contentChecker` validates protected blobs and whole commits:
//   - every protected path holds a regular file that is a parseable EYESONLY-V1 envelope,
//   - bound to that path, signed by a known key of an allowed writer of that path,
//   - encrypted only to members of that path's audience,
//   - no .gitattributes / .lfsconfig change redirects a protected path away from the filter.
//
// Who made a change is the caller's business: the server knows the authenticated pusher,
// repo mode only knows envelope signers. `authorize(kind, file, commit, allowed)` decides
// ('modify' | 'delete'); `reject(msg)` must not return (exit or throw).
import { execFileSync } from 'node:child_process';
import * as vc from './crypto.mjs';
import * as attrs from './attrs.mjs';
import { expand, fileRule, isSubset } from './policy.mjs';

export const gitRunner = (cwd) => ({
  g: (args) => execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 1 << 30 }).trim(),
  gBuf: (args) => execFileSync('git', args, { cwd, maxBuffer: 1 << 30 }),
});

/**
 * @param {object} o
 * @param {object} o.policy   raw policy (members, admins, groups, files)
 * @param {Record<string,{x25519:string, ed25519:string}>} o.users  name -> public keys
 * @param {(args:string[]) => string} o.g      git, stdout as trimmed string
 * @param {(args:string[]) => Buffer} o.gBuf   git, stdout as Buffer
 * @param {(msg:string) => never} o.reject
 * @param {(kind:string, file:string, commit:string, allowed:Set<string>) => void} o.authorize
 * @param {boolean} [o.isAdmin]  may change .lfsconfig endpoints
 * @param {(msg:string) => void} [o.note]
 */
export function contentChecker({ policy, users, g, gBuf, reject, authorize, isAdmin = false, note = (m) => console.error(m) }) {
  const all = Object.keys(users);
  const treeCache = new Map();
  const protectedEntries = (commit) => {
    if (treeCache.has(commit)) return treeCache.get(commit);
    const map = new Map();
    for (const e of g(['ls-tree', '-r', '-z', commit]).split('\0').filter(Boolean)) {
      const tab = e.indexOf('\t');
      const [mode, type, oid] = e.slice(0, tab).split(' ');
      const file = e.slice(tab + 1);
      if (fileRule(policy, file)) map.set(file, { mode, type, oid });
    }
    treeCache.set(commit, map);
    return map;
  };
  const audience = (file) => expand(policy, fileRule(policy, file), all);

  const validated = new Set();
  const validateBlob = (commit, file, entry, allowed) => {
    const key = `${entry.oid}\0${file}`;
    if (validated.has(key)) return;
    const at = `'${file}' in ${commit.slice(0, 8)}`;
    if (entry.type !== 'blob' || entry.mode === '120000') reject(`${at} must be a regular encrypted file`);
    const blob = gBuf(['cat-file', 'blob', entry.oid]);
    if (!vc.isEnvelope(blob)) reject(`${at} is NOT encrypted. Refusing to store a plaintext secret. Run \`eyesonly setup\` and recommit.`);
    let env;
    try {
      env = vc.parse(blob);
    } catch (e) {
      reject(`${at}: ${e.message}`);
    }
    if (env.path !== file) reject(`${at} is encrypted for path '${env.path}'. Run \`eyesonly rekey\` after renaming protected files.`);
    if (!allowed.has(env.signer) || !users[env.signer] || !vc.verify(env, users[env.signer].ed25519)) {
      reject(`${at} has an invalid signature or its signer '${env.signer}' may not write it`);
    }
    const recips = new Set(Object.keys(env.keys));
    if (!isSubset(recips, allowed)) {
      reject(`${at} is encrypted to users outside the policy: ${[...recips].filter((r) => !allowed.has(r)).join(', ')}. Run \`eyesonly pull-policy && eyesonly rekey\`.`);
    }
    const current = Object.fromEntries([...recips].filter((u) => users[u]).map((u) => [u, users[u].x25519]));
    const missing = [...[...allowed].filter((u) => !recips.has(u)), ...vc.staleRecipients(env, current)];
    if (missing.length) note(`[eyesonly] note: ${at} is not readable by ${missing.join(', ')} yet (eyesonly rekey)`);
    validated.add(key);
  };

  const checkCommit = (commit) => {
    const parents = g(['rev-list', '--parents', '-n1', commit]).split(' ').slice(1);
    attrs.checkCommitAttributes({ commit, parents, policy, git: g, reject, isAdmin });
    const mine = protectedEntries(commit);
    const theirs = parents.map(protectedEntries);
    for (const [file, entry] of mine) {
      if (theirs.length && theirs.some((t) => t.get(file)?.oid === entry.oid)) continue; // unchanged from a parent
      const allowed = audience(file);
      authorize('modify', file, commit, allowed);
      validateBlob(commit, file, entry, allowed);
    }
    for (const t of theirs) {
      for (const file of t.keys()) {
        if (mine.has(file)) continue;
        authorize('delete', file, commit, audience(file));
      }
    }
  };

  /** Every protected blob in `commit`'s tree must be valid now (not only the changed ones). */
  const checkTree = (commit) => {
    for (const [file, entry] of protectedEntries(commit)) validateBlob(commit, file, entry, audience(file));
  };

  return { validateBlob, checkCommit, checkTree, protectedEntries };
}
