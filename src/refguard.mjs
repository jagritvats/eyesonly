// Ref protection: read-only members, protected refs, and the content invariant on
// every ref update (including rewinds to commits the server already has).
//
// Policy additions (both optional):
//   "writers": ["@core", "ci-bot"]                       default: members. Admins always write.
//   "protect": { "refs/heads/main": { "push": ["@release"], "force": [], "delete": [] } }
//              longest prefix wins. Missing key: push = writers, force = delete = admins only.
// Without "protect", refs/tags/ and the branch HEAD points to get force [] and delete [].
//
// Pure functions: git access, rejection and blob validation come in as callbacks.

import { expand, fileRule, refMatches } from './policy.mjs';

const ZERO = '0'.repeat(40);
const RULE_KEYS = ['push', 'force', 'delete'];

const isNames = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string');
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Throws on a malformed writers/protect section. */
export function validateRefPolicy(p) {
  if (p.writers !== undefined && !isNames(p.writers)) throw new Error('writers must be a list of names');
  if (p.protect === undefined) return p;
  if (!isObject(p.protect)) throw new Error('protect must be an object of { "refs/...": { push, force, delete } }');
  for (const [prefix, rule] of Object.entries(p.protect)) {
    if (!prefix.startsWith('refs/')) throw new Error(`protect rule '${prefix}' must start with refs/`);
    if (!isObject(rule)) throw new Error(`protect["${prefix}"] must be an object with push/force/delete lists`);
    for (const [k, v] of Object.entries(rule)) {
      if (!RULE_KEYS.includes(k)) throw new Error(`protect["${prefix}"].${k} is not a known key (use push, force, delete)`);
      if (!isNames(v)) throw new Error(`protect["${prefix}"].${k} must be a list of names`);
    }
  }
  return p;
}

const admins = (policy, all) => expand(policy, policy.admins || [], all);
const writers = (policy, all) => expand(policy, policy.writers ?? policy.members, all);

/** True if `user` may push at all (writers, default members; admins always). */
export function canWrite(policy, user, all) {
  return admins(policy, all).has(user) || writers(policy, all).has(user);
}

/** The protect rule for `ref` (longest prefix) as { prefix, rule }, or null when unprotected. */
export function protectRule(policy, ref, headRef) {
  const rules = policy.protect ?? {
    'refs/tags/': { force: [], delete: [] },
    ...(headRef ? { [headRef]: { force: [], delete: [] } } : {}),
  };
  let best = null;
  for (const [prefix, rule] of Object.entries(rules)) {
    if (refMatches(prefix, ref) && (!best || prefix.length > best.prefix.length)) best = { prefix, rule };
  }
  return best;
}

// `git diff-tree -r -z --no-renames` output -> [{ file, mode, oid, deleted }].
function parseDiffTree(out) {
  const parts = out.split('\0').filter(Boolean);
  const changes = [];
  for (let i = 0; i + 1 < parts.length; i += 2) {
    const [, newMode, , newOid, status] = parts[i].replace(/^:/, '').split(' ');
    changes.push({ file: parts[i + 1], mode: newMode, oid: newOid, deleted: status === 'D' });
  }
  return changes;
}

// file -> { mode, type, oid } for the protected paths of a tree.
function protectedTree(policy, git, tree) {
  const map = new Map();
  for (const e of git(['ls-tree', '-r', '-z', tree]).split('\0').filter(Boolean)) {
    const tab = e.indexOf('\t');
    const [mode, type, oid] = e.slice(0, tab).split(' ');
    const file = e.slice(tab + 1);
    if (fileRule(policy, file)) map.set(file, { mode, type, oid });
  }
  return map;
}

const typeOf = (mode) => (mode === '160000' ? 'commit' : mode === '040000' ? 'tree' : 'blob');

function treeOf(git, oid) {
  try {
    return git(['rev-parse', '--verify', '-q', `${oid}^{tree}`]) || null;
  } catch {
    return null; // e.g. a tag pointing at a blob: no tree, nothing to check
  }
}

function isAncestor(git, oldOid, newOid) {
  try {
    git(['merge-base', '--is-ancestor', oldOid, newOid]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Checks one ref update (rules + content invariant); calls reject(msg), which must not
 * return, on a violation. The pre-receive hook calls the two halves separately so its
 * per-commit checks report first for commits that are new to the server.
 *   git(args) -> trimmed stdout, throws on a non-zero exit
 *   validate(commit, file, entry, allowedSet) -> validates an envelope under the current policy
 *   audienceOf(file) -> Set (optional; defaults to the expanded file rule)
 */
export function checkRefUpdate(args) {
  checkRefRules(args);
  checkRefContent(args);
}

/** Writers + protect rules (push / delete / force). Runs for every update, deletions included. */
export function checkRefRules({ policy, all, user, oldOid, newOid, ref, headRef, git, reject }) {
  if (!canWrite(policy, user, all)) reject(`'${user}' has read-only access to this repository`);
  const isAdmin = admins(policy, all).has(user);
  const may = (rule, key, dflt) => isAdmin || (rule[key] ? expand(policy, rule[key], all) : dflt).has(user);
  const deleting = newOid === ZERO && oldOid !== ZERO;
  const creating = oldOid === ZERO && newOid !== ZERO;
  const p = protectRule(policy, ref, headRef);
  if (!p) return;
  if (!may(p.rule, 'push', writers(policy, all))) reject(`'${user}' may not push to protected ref ${ref}`);
  if (deleting && !may(p.rule, 'delete', new Set())) reject(`'${user}' may not delete ${ref}`);
  // Tags are immutable: any move counts as a force-push.
  const forced = !creating && !deleting && (ref.startsWith('refs/tags/') || !isAncestor(git, oldOid, newOid));
  if (forced && !may(p.rule, 'force', new Set())) reject(`'${user}' may not force-push ${ref}`);
}

/**
 * Content invariant (admins included): whatever the ref ends up pointing at must be valid
 * under the CURRENT policy, even if every commit already exists on the server.
 */
export function checkRefContent({ policy, all, user, oldOid, newOid, ref, headRef, git, reject, validate, audienceOf }) {
  const audience = audienceOf || ((file) => expand(policy, fileRule(policy, file), all));
  const creating = oldOid === ZERO;
  if (newOid === ZERO || !Object.keys(policy.files || {}).length) return;

  const newTree = treeOf(git, newOid);
  if (!newTree) return;

  // Content already on the default branch was accepted there: a path whose new state
  // equals the HEAD branch tip is exempt (branching off main, merging main into a feature
  // branch). An update of the HEAD branch itself never gets this exemption. Other ref
  // tips are NOT trusted: a stale branch nobody rekeyed must not launder its blobs.
  let head;
  const headTip = () => {
    if (head !== undefined) return head;
    head = null;
    if (headRef && headRef !== ref) {
      let tip = null;
      try {
        tip = treeOf(git, git(['rev-parse', '--verify', '-q', headRef]));
      } catch {}
      if (tip) head = protectedTree(policy, git, tip);
    }
    return head;
  };

  if (creating) {
    // No audience requirement (feature branches may start anywhere), but every protected
    // blob not on the HEAD branch tip must pass validation under the current policy.
    for (const [file, entry] of protectedTree(policy, git, newTree)) {
      if (headTip()?.get(file)?.oid === entry.oid) continue;
      validate(newOid, file, entry, audience(file));
    }
    return;
  }

  const oldTree = treeOf(git, oldOid);
  if (!oldTree) return;
  for (const c of parseDiffTree(git(['diff-tree', '-r', '-z', '--no-renames', oldTree, newTree]))) {
    if (!fileRule(policy, c.file)) continue;
    const tip = headTip();
    if (tip && (c.deleted ? !tip.has(c.file) : tip.get(c.file)?.oid === c.oid)) continue;
    const who = audience(c.file);
    if (!who.has(user)) reject(`'${user}' may not change protected file '${c.file}' via ref update of ${ref}`);
    if (!c.deleted) validate(newOid, c.file, { mode: c.mode, type: typeOf(c.mode), oid: c.oid }, who);
  }
}
