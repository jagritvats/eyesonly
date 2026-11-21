// Private branches without a server (repo / GitHub mode): sealed branches.
//
// A private branch (a branch matching a `branches` rule of the signed repo policy, e.g.
// refs/heads/private/) never goes to the host as a git branch. `eyesonly branch push` seals
// it instead, as one parentless commit under refs/eyesonly/b/<id>:
//
//   commit  author/committer "eyesonly <eyesonly@localhost>", fixed date, message "sealed"
//   tree    one blob, "sealed": an EYESONLY-V1 envelope (crypto.mjs) bound to the path
//           refs/eyesonly/b/<id>, encrypted for the branch's audience
//   plain   "EYESONLY-BRANCH-V1\n" + header JSON + "\n" + git bundle of <tip> --not <base>
//   header  { v, id, name, counter, prev, base, tip, signer, bundle (sha256 or null), size, sig }
//
// <id> is random per branch, never derived from the name. The envelope's outer signature is
// made with a throwaway key (its `signer` is always "sealed"), so the host doesn't learn who
// pushed; the writer signs the header inside the ciphertext (Ed25519 over
// "eyesonly-branch-v1\0" + canonical(header without sig)), and the header binds the id and
// the bundle's hash. Readers check that the writer is in the branch's audience under the
// current signed policy, and pin { counter, commit } per id in .git/eyesonly/branches.json:
// a lower counter (rollback), a different commit with the same counter (equivocation) or a
// successor that doesn't build on the pinned version (fork) is refused.
//
// What the host and non-members see: opaque ref ids, blob sizes, push times, how many sealed
// branches exist, and (in the envelope) the recipient names, which are the branch rule's
// audience from the policy file that every reader of the repo can see anyway.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import * as vc from './crypto.mjs';
import * as rp from './repo-policy.mjs';
import { canonical } from './attest.mjs';
import { refRule } from './policy.mjs';
import { gitDir, loadIdentity, loadPolicy, repoTop } from './client.mjs';

export const SEALED_NS = 'refs/eyesonly/b/';
const TRACK_NS = (remote) => `refs/eyesonly/remotes/${remote}/b/`;
const TMP_NS = 'refs/eyesonly/tmp/';
const MAGIC = 'EYESONLY-BRANCH-V1\n';
const DOMAIN = 'eyesonly-branch-v1\0';
const BLOB_NAME = 'sealed';
const ID_RE = /^[0-9a-f]{32}$/;
const FIXED = {
  GIT_AUTHOR_NAME: 'eyesonly',
  GIT_AUTHOR_EMAIL: 'eyesonly@localhost',
  GIT_AUTHOR_DATE: '946684800 +0000',
  GIT_COMMITTER_NAME: 'eyesonly',
  GIT_COMMITTER_EMAIL: 'eyesonly@localhost',
  GIT_COMMITTER_DATE: '946684800 +0000',
};

const log = (...a) => console.error('[eyesonly]', ...a);
function die(msg) {
  log(msg);
  process.exit(1);
}

const run = (args, opts = {}) => execFileSync('git', args, { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 30, ...opts });
const g = (args, opts) => run(args, { encoding: 'utf8', ...opts }).trim();
const tryG = (args, opts) => {
  try {
    return g(args, opts);
  } catch {
    return null;
  }
};
const isAncestor = (a, b, cwd) => spawnSync('git', ['merge-base', '--is-ancestor', a, b], { cwd }).status === 0;
const hasCommit = (cwd, oid) => spawnSync('git', ['cat-file', '-e', `${oid}^{commit}`], { cwd }).status === 0;
const short = (oid) => (oid ? oid.slice(0, 8) : '-');
const b64 = (b) => Buffer.from(b).toString('base64');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const bare = (ref) => ref.replace(/^refs\/heads\//, '');

// ------------------------------------------------------------------ format

/** Sign a header with the writer's identity (returns a new header with `sig`). */
function signHeader(h, identity) {
  const { sig, ...rest } = h;
  const s = crypto.sign(null, Buffer.from(DOMAIN + canonical(rest)), vc.privKey(identity.ed25519.priv));
  return { ...rest, sig: b64(s) };
}

function headerSigOk(h, ed25519Pub) {
  try {
    const { sig, ...rest } = h;
    return crypto.verify(null, Buffer.from(DOMAIN + canonical(rest)), vc.pubKey(ed25519Pub), Buffer.from(sig, 'base64'));
  } catch {
    return false;
  }
}

/**
 * Build a sealed blob (an EYESONLY-V1 envelope) for one version of a private branch.
 * Exported for tests and tools; `eyesonly branch push` is the normal way in.
 */
export function buildSealed({ id, name, counter, prev = null, base = null, tip, bundle = null, recipients, signer }) {
  const header = signHeader(
    { v: 1, id, name, counter, prev, base, tip, signer: signer.name, bundle: bundle ? sha256(bundle) : null, size: bundle ? bundle.length : 0 },
    signer,
  );
  const plaintext = Buffer.concat([Buffer.from(MAGIC + JSON.stringify(header) + '\n'), bundle || Buffer.alloc(0)]);
  // The outer envelope signature uses a throwaway key: who pushed stays inside the ciphertext.
  return vc.seal({ plaintext, path: SEALED_NS + id, recipients, signer: vc.generateIdentity(BLOB_NAME) });
}

function parsePlain(buf) {
  if (!buf.subarray(0, MAGIC.length).equals(Buffer.from(MAGIC))) throw new Error('not a sealed branch');
  const nl = buf.indexOf(0x0a, MAGIC.length);
  if (nl === -1) throw new Error('malformed sealed branch');
  const header = JSON.parse(buf.subarray(MAGIC.length, nl).toString('utf8'));
  return { header, bundle: buf.subarray(nl + 1) };
}

/** Write a sealed blob as the fixed-shape parentless commit; returns the commit id. */
export function writeSealedCommit(top, sealedBlob) {
  const blob = g(['hash-object', '-w', '--stdin'], { cwd: top, input: sealedBlob, stdio: ['pipe', 'pipe', 'pipe'] });
  const tree = g(['mktree'], { cwd: top, input: `100644 blob ${blob}\t${BLOB_NAME}\n`, stdio: ['pipe', 'pipe', 'pipe'] });
  return g(['commit-tree', tree, '-m', BLOB_NAME], { cwd: top, env: { ...process.env, ...FIXED } });
}

/**
 * Shape check that needs no keys (CI, the pre-push hook): a parentless commit with exactly one
 * blob named "sealed" that is an envelope bound to refs/eyesonly/b/<id>. Returns { env, size }.
 */
export function checkShape(top, commit, id) {
  if (!ID_RE.test(id)) throw new Error(`'${SEALED_NS}${id}' isn't a sealed-branch ref (ids are 32 hex characters)`);
  const parents = tryG(['rev-list', '--parents', '-n', '1', commit], { cwd: top });
  if (parents == null) throw new Error(`${short(commit)} isn't a commit`);
  if (parents.split(' ').length !== 1) throw new Error(`${SEALED_NS}${id} points at a commit with parents (sealed branches are single parentless commits)`);
  const entries = g(['ls-tree', commit], { cwd: top }).split('\n').filter(Boolean);
  if (entries.length !== 1) throw new Error(`${SEALED_NS}${id}: the sealed commit must hold exactly one file`);
  const m = /^(\d+) (\w+) ([0-9a-f]+)\t(.+)$/.exec(entries[0]);
  if (!m || m[1] !== '100644' || m[2] !== 'blob' || m[4] !== BLOB_NAME) throw new Error(`${SEALED_NS}${id}: the sealed commit must hold one regular file named '${BLOB_NAME}'`);
  const blob = run(['cat-file', 'blob', m[3]], { cwd: top });
  if (!vc.isEnvelope(blob)) throw new Error(`${SEALED_NS}${id} holds plaintext, not an encrypted envelope`);
  let env;
  try {
    env = vc.parse(blob);
  } catch (e) {
    throw new Error(`${SEALED_NS}${id}: ${e.message}`);
  }
  if (env.path !== SEALED_NS + id) throw new Error(`${SEALED_NS}${id} holds an envelope sealed for '${env.path}' (moved from another ref)`);
  return { env, size: blob.length };
}

// ------------------------------------------------------------------ policy, pins

function requireRepoPolicy() {
  const policy = loadPolicy();
  if (policy.mode !== 'repo') return null;
  return policy;
}

/** { prefix, who } when `name` is a private branch under the policy, else null. */
export function privateRule(policy, name) {
  return refRule({ branches: policy.branches || {} }, name.startsWith('refs/') ? name : `refs/heads/${name}`);
}

const pinsPath = () => path.join(gitDir(), 'eyesonly', 'branches.json');
function loadPins() {
  try {
    return JSON.parse(fs.readFileSync(pinsPath(), 'utf8')).pins || {};
  } catch {
    return {};
  }
}
function savePins(pins) {
  const p = pinsPath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p + '.tmp', JSON.stringify({ v: 1, pins }, null, 2));
  fs.renameSync(p + '.tmp', p);
}

const remoteOf = (top) => tryG(['config', 'eyesonly.remote'], { cwd: top }) || 'origin';

// ------------------------------------------------------------------ reading

/**
 * Decrypt and check one sealed version. Returns { readable: false } when `identity` isn't a
 * recipient; throws a user-facing Error when it's forged, moved, malformed or not allowed.
 */
export function readVersion(top, { id, commit }, policy, identity) {
  let shape;
  try {
    shape = checkShape(top, commit, id);
  } catch (e) {
    throw Object.assign(e, { shape: true });
  }
  const { env, size } = shape;
  try {
    return openVersion({ id, commit, env, size }, policy, identity);
  } catch (e) {
    throw Object.assign(e, { mine: true }); // it was encrypted for us: a problem we should hear about
  }
}

function openVersion({ id, commit, env, size }, policy, identity) {
  const plain = identity ? vc.open(env, identity) : null; // throws on tampering
  if (!plain) return { id, commit, size, readable: false, recipients: Object.keys(env.keys) };
  let header;
  let bundle;
  try {
    ({ header, bundle } = parsePlain(plain));
  } catch (e) {
    throw new Error(`${SEALED_NS}${id}: ${e.message}`);
  }
  const at = `${SEALED_NS}${id}`;
  if (header.v !== 1 || header.id !== id) throw new Error(`${at}: the sealed header is for another ref (id ${header.id})`);
  if (typeof header.name !== 'string' || spawnSync('git', ['check-ref-format', `refs/heads/${header.name}`]).status !== 0) throw new Error(`${at}: invalid branch name in the sealed header`);
  if (!Number.isInteger(header.counter) || header.counter < 1) throw new Error(`${at}: invalid counter`);
  const rule = privateRule(policy, header.name);
  if (!rule) throw new Error(`${at} claims to be '${header.name}', which isn't a private branch under the current policy`);
  const key = policy.keys?.[header.signer];
  if (!key || !headerSigOk(header, key.ed25519)) throw new Error(`${at} ('${header.name}'): bad or unknown writer signature (signer '${header.signer}')`);
  if (!rule.who.includes(header.signer)) throw new Error(`${at} ('${header.name}') is signed by '${header.signer}', who may not write ${bare(rule.prefix)}* (allowed: ${rule.who.join(', ') || 'nobody'})`);
  if ((header.bundle ?? null) !== (bundle.length ? sha256(bundle) : null)) throw new Error(`${at} ('${header.name}'): the bundle doesn't match its signed hash`);
  return { id, commit, size, readable: true, header, bundle, recipients: Object.keys(env.keys) };
}

function fetchSealed(top, remote) {
  if (!tryG(['config', `remote.${remote}.url`], { cwd: top })) die(`no remote named '${remote}' (git remote -v lists them)`);
  try {
    run(['fetch', '--quiet', remote], { cwd: top });
    run(['fetch', '--quiet', '--prune', remote, `+${SEALED_NS}*:${TRACK_NS(remote)}*`], { cwd: top });
  } catch (e) {
    die(`couldn't fetch from ${remote}: ${(e.stderr || '').toString().trim() || e.message}`);
  }
}

function tracked(top, remote) {
  const out = tryG(['for-each-ref', '--format=%(objectname) %(refname)', TRACK_NS(remote)], { cwd: top }) || '';
  return out.split('\n').filter(Boolean).map((l) => {
    const [commit, ref] = l.split(' ');
    return { id: ref.slice(TRACK_NS(remote).length), commit };
  });
}

/** Read every tracked sealed version: [{ id, commit, readable, header?, error? }]. */
function scan(top, remote, policy, identity) {
  return tracked(top, remote).map((t) => {
    try {
      return readVersion(top, t, policy, identity);
    } catch (e) {
      return { ...t, readable: false, error: e.message, relevant: !!(e.mine || e.shape) };
    }
  });
}

/** Pins for ids no longer on the host are kept (replay protection) but don't own their name. */
function retireMissing(pins, versions) {
  const live = new Set(versions.map((v) => v.id));
  for (const [id, p] of Object.entries(pins)) if (!live.has(id)) p.retired = true;
}

/** Check a readable version against the pins; returns 'new' | 'same' | 'newer'. Throws on attacks. */
function checkPins(v, pins) {
  const h = v.header;
  const p = pins[v.id];
  const at = `'${h.name}' (${SEALED_NS}${v.id})`;
  if (p) {
    if (p.name !== h.name) throw new Error(`${SEALED_NS}${v.id} used to be '${p.name}' and now claims to be '${h.name}'. Refusing; ask the branch's writers.`);
    if (h.counter < p.counter) throw new Error(`${at} was rolled back on the host: version ${h.counter} is older than the version ${p.counter} you already have. Refusing.`);
    if (h.counter === p.counter) {
      if (v.commit !== p.commit) throw new Error(`${at}: the host serves a different version ${h.counter} than the one you pinned (forked or replayed history). Refusing.`);
      return 'same';
    }
    if (h.counter === p.counter + 1 && h.prev !== p.commit) throw new Error(`${at}: version ${h.counter} doesn't build on the version ${p.counter} you have (forked history). Refusing.`);
    return 'newer';
  }
  for (const [otherId, q] of Object.entries(pins)) {
    if (q.name === h.name && otherId !== v.id && !q.retired) throw new Error(`two sealed branches claim '${h.name}' (${SEALED_NS}${otherId} and ${SEALED_NS}${v.id}). Refusing; ask the branch's writers which one is current.`);
  }
  return 'new';
}

const pinOf = (v) => ({ name: v.header.name, counter: v.header.counter, commit: v.commit, tip: v.header.tip, base: v.header.base, signer: v.header.signer });

// ------------------------------------------------------------------ commands

function currentBranch(top) {
  const ref = tryG(['symbolic-ref', '-q', 'HEAD'], { cwd: top });
  return ref && ref.startsWith('refs/heads/') ? bare(ref) : null;
}

function tmpDir() {
  const d = path.join(gitDir(), 'eyesonly', 'tmp');
  fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  return d;
}

function makeBundle(top, id, tip, base) {
  const file = path.join(tmpDir(), `${id}.bundle`);
  const ref = TMP_NS + id;
  g(['update-ref', ref, tip], { cwd: top });
  try {
    run(['bundle', 'create', '--quiet', file, ref, ...(base ? [`^${base}`] : [])], { cwd: top });
    return fs.readFileSync(file);
  } finally {
    tryG(['update-ref', '-d', ref], { cwd: top });
    fs.rmSync(file, { force: true });
  }
}

function unbundle(top, v) {
  const h = v.header;
  if (!v.bundle.length) {
    if (!hasCommit(top, h.tip)) throw new Error(`'${h.name}' points at ${short(h.tip)}, which isn't in this clone yet: git fetch, then retry`);
    return;
  }
  const file = path.join(tmpDir(), `${v.id}.bundle`);
  fs.writeFileSync(file, v.bundle, { mode: 0o600 });
  try {
    const verify = spawnSync('git', ['bundle', 'verify', '--quiet', file], { cwd: top, encoding: 'utf8' });
    if (verify.status !== 0) throw new Error(`'${h.name}' builds on commits this clone doesn't have (${(verify.stderr || '').trim().split('\n').pop()}). Run git fetch, then retry.`);
    run(['fetch', '--quiet', '--no-write-fetch-head', file, `${TMP_NS}${v.id}:refs/eyesonly/incoming/${v.id}`], { cwd: top });
    const got = g(['rev-parse', `refs/eyesonly/incoming/${v.id}`], { cwd: top });
    if (got !== h.tip) throw new Error(`'${h.name}': the bundle's tip ${short(got)} isn't the signed tip ${short(h.tip)}`);
  } finally {
    tryG(['update-ref', '-d', `refs/eyesonly/incoming/${v.id}`], { cwd: top });
    fs.rmSync(file, { force: true });
  }
}

/** Move refs/heads/<name> to the sealed tip; returns a short description. */
function updateBranch(top, name, tip) {
  const ref = `refs/heads/${name}`;
  const local = tryG(['rev-parse', '--verify', '-q', ref], { cwd: top });
  if (!local) {
    g(['update-ref', '-m', 'eyesonly branch pull', ref, tip], { cwd: top });
    return 'created';
  }
  if (local === tip) return 'up to date';
  if (isAncestor(local, tip, top)) {
    if (currentBranch(top) === name) {
      execFileSync('git', ['merge', '--ff-only', '--quiet', tip], { cwd: top, stdio: ['ignore', 'inherit', 'inherit'] });
    } else g(['update-ref', '-m', 'eyesonly branch pull', ref, tip, local], { cwd: top });
    return 'fast-forwarded';
  }
  if (isAncestor(tip, local, top)) return 'your local branch is ahead (eyesonly branch push)';
  g(['update-ref', '-m', 'eyesonly branch pull', `${ref}-incoming`, tip], { cwd: top });
  return `diverged: the sealed version is in ${name}-incoming; merge it (git merge ${name}-incoming), then eyesonly branch push`;
}

function recipientsFor(policy, who) {
  return Object.fromEntries(who.filter((u) => policy.keys?.[u]).map((u) => [u, policy.keys[u].x25519]));
}

function cmdPush(args) {
  const force = args.includes('--force');
  const rest = args.filter((a) => a !== '--force');
  const top = repoTop();
  const policy = requireRepoPolicy();
  if (!policy) die('in server mode private branches are ordinary branches the server hides from non-members: git push origin <branch>');
  const id0 = loadIdentity();
  const name = rest[0] ? bare(rest[0]) : currentBranch(top);
  if (!name) die('usage: eyesonly branch push [<branch>] (no branch checked out)');
  const rule = privateRule(policy, name);
  if (!rule) die(`'${name}' isn't a private branch: the policy's private prefixes are ${Object.keys(policy.branches || {}).map((p) => bare(p) + '*').join(', ') || '(none)'}. Push public branches with git push.`);
  if (!rule.who.includes(id0.name)) die(`you ('${id0.name}') may not write ${bare(rule.prefix)}* (allowed: ${rule.who.join(', ') || 'nobody'})`);
  const tip = tryG(['rev-parse', '--verify', '-q', `refs/heads/${name}^{commit}`], { cwd: top });
  if (!tip) die(`no local branch '${name}'`);

  const remote = remoteOf(top);
  fetchSealed(top, remote);
  const pins = loadPins();
  const versions = scan(top, remote, policy, id0);
  retireMissing(pins, versions);
  const pinned = Object.entries(pins).find(([, p]) => p.name === name && !p.retired);
  let cur = versions.find((v) => v.readable && v.header.name === name);
  if (pinned) {
    const onHost = versions.find((v) => v.id === pinned[0]);
    if (onHost && !onHost.readable && !onHost.error) die(`the sealed '${name}' on ${remote} isn't encrypted for you anymore (were you removed from ${bare(rule.prefix)}*?)`);
    // Forged or broken: readers refuse it anyway; a writer replaces it on top of their pinned version.
    if (onHost?.error) log(`warning: the sealed '${name}' on ${remote} is invalid (${onHost.error}); replacing it with your version`);
  }
  if (cur) {
    try {
      checkPins(cur, pins);
    } catch (e) {
      if (!pins[cur.id]) die(e.message);
      log(`warning: ${e.message.replace(/ Refusing.*$/, '')} Replacing it with a new version on top of the one you have.`);
      cur = null;
    }
    if (cur && !force && !isAncestor(cur.header.tip, tip, top)) {
      die(`the sealed '${name}' on ${remote} (v${cur.header.counter}, by ${cur.header.signer}) has commits you don't: eyesonly branch pull first (or --force to replace it)`);
    }
  }
  const id = cur?.id || pinned?.[0] || crypto.randomBytes(16).toString('hex');
  const pin = pins[id];
  const counter = Math.max(cur?.header.counter || 0, pin?.counter || 0) + 1;
  const prev = cur?.commit || pin?.commit || null;
  const expected = versions.find((v) => v.id === id)?.commit || '';

  const defRef = rp.defaultRef(top, remote);
  const defTip = defRef && defRef !== `refs/heads/${name}` ? tryG(['rev-parse', '--verify', '-q', `${defRef}^{commit}`], { cwd: top }) : null;
  const base = defTip ? tryG(['merge-base', tip, defTip], { cwd: top }) : null;
  const bundle = base === tip ? null : makeBundle(top, id, tip, base);
  const recipients = recipientsFor(policy, rule.who);
  const sealed = buildSealed({ id, name, counter, prev, base, tip, bundle, recipients, signer: id0 });
  const commit = writeSealedCommit(top, sealed);

  const r = spawnSync('git', ['push', '--quiet', remote, `${commit}:${SEALED_NS}${id}`, `--force-with-lease=${SEALED_NS}${id}:${expected}`], { cwd: top, encoding: 'utf8' });
  if (r.status !== 0) {
    const err = (r.stderr || '').trim();
    if (/stale info|rejected/.test(err)) die(`someone pushed '${name}' meanwhile: eyesonly branch pull, then push again\n${err}`);
    die(`push failed:\n${err}`);
  }
  g(['update-ref', TRACK_NS(remote) + id, commit], { cwd: top });
  pins[id] = { name, counter, commit, tip, base, signer: id0.name };
  savePins(pins);
  const n = base ? Number(g(['rev-list', '--count', tip, `^${base}`], { cwd: top })) : Number(g(['rev-list', '--count', tip], { cwd: top }));
  log(`sealed ${name} v${counter} (${n} private commit(s)${base ? ` on top of ${short(base)}` : ''}, ${sealed.length} bytes) for ${Object.keys(recipients).join(', ')} -> ${remote} ${SEALED_NS}${id}`);
}

function cmdPull(args) {
  const all = args.includes('--all');
  const want = args.filter((a) => a !== '--all').map(bare)[0];
  const top = repoTop();
  const policy = requireRepoPolicy();
  if (!policy) die('in server mode private branches are ordinary branches: git fetch / git pull');
  const id0 = loadIdentity();
  const remote = remoteOf(top);
  fetchSealed(top, remote);
  const pins = loadPins();
  const versions = scan(top, remote, policy, id0);
  retireMissing(pins, versions);
  let problems = 0;
  let matched = 0;
  const targets = versions.filter((v) => (v.readable ? all || !want || v.header.name === want : false));
  for (const v of versions.filter((x) => x.error && (x.relevant || pins[x.id]))) {
    log(`refusing ${SEALED_NS}${v.id}${pins[v.id] ? ` ('${pins[v.id].name}')` : ''}: ${v.error}`);
    problems++;
  }
  for (const v of targets) {
    matched++;
    try {
      const state = checkPins(v, pins);
      if (state !== 'same' || !tryG(['rev-parse', '--verify', '-q', `refs/heads/${v.header.name}`], { cwd: top })) unbundle(top, v);
      const what = updateBranch(top, v.header.name, v.header.tip);
      pins[v.id] = pinOf(v); // also un-retires it
      log(`${v.header.name}: v${v.header.counter} by ${v.header.signer}, ${what}`);
    } catch (e) {
      log(`refusing '${v.header.name}': ${e.message}`);
      problems++;
    }
  }
  savePins(pins);
  if (want && !matched) {
    const unreadable = versions.filter((v) => !v.readable && !v.error).length;
    die(`no sealed '${want}' you can read on ${remote}${unreadable ? ` (${unreadable} sealed branch(es) aren't encrypted for you)` : ''}`);
  }
  if (!targets.length && !want) log(`no sealed branches you can read on ${remote}`);
  if (problems) process.exit(1);
}

function cmdList(args) {
  const top = repoTop();
  const policy = loadPolicy();
  if (policy.mode !== 'repo') {
    log('server mode: private branches are ordinary branches the server hides from people outside their audience');
    process.stdout.write(tryG(['branch', '-a', '--list', '*private/*'], { cwd: top }) + '\n');
    return;
  }
  const id0 = loadIdentity({ required: false });
  const remote = remoteOf(top);
  if (!args.includes('--no-fetch')) fetchSealed(top, remote);
  const pins = loadPins();
  const versions = scan(top, remote, policy, id0);
  const readable = versions.filter((v) => v.readable);
  for (const v of readable.sort((a, b) => a.header.name.localeCompare(b.header.name))) {
    const local = tryG(['rev-parse', '--verify', '-q', `refs/heads/${v.header.name}`], { cwd: top });
    let state = 'not checked out (eyesonly branch pull)';
    if (local === v.header.tip) state = 'in sync';
    else if (local && isAncestor(v.header.tip, local, top)) state = `${g(['rev-list', '--count', `${v.header.tip}..${local}`], { cwd: top })} local commit(s) to push`;
    else if (local && isAncestor(local, v.header.tip, top)) state = 'behind (eyesonly branch pull)';
    else if (local) state = 'diverged';
    console.log(`  ${v.header.name}  v${v.header.counter} by ${v.header.signer}, ${v.size} bytes, readers ${v.recipients.join(', ')}${pins[v.id] ? '' : ' (not pinned yet)'}  [${state}]`);
  }
  for (const v of versions.filter((x) => x.error)) console.log(`  ?  ${SEALED_NS}${v.id}  REFUSED: ${v.error}`);
  const hidden = versions.filter((v) => !v.readable && !v.error).length;
  const localOnly = (tryG(['for-each-ref', '--format=%(refname:short)', 'refs/heads/'], { cwd: top }) || '').split('\n').filter((b) => b && privateRule(policy, b) && !readable.some((v) => v.header.name === b));
  for (const b of localOnly) console.log(`  ${b}  never pushed (eyesonly branch push ${b})`);
  if (!readable.length && !localOnly.length) console.log('  (no private branches you can read)');
  if (hidden) console.log(`  + ${hidden} sealed branch(es) not encrypted for you`);
}

function cmdPublish(args) {
  const onto0 = args.indexOf('--onto');
  const onto = onto0 >= 0 ? args[onto0 + 1] : null;
  const name = args.filter((a, i) => onto0 < 0 || (i !== onto0 && i !== onto0 + 1)).map(bare)[0];
  if (!name) die('usage: eyesonly branch publish <private-branch> [--onto <branch>]');
  const top = repoTop();
  const policy = requireRepoPolicy();
  if (!policy) die('in server mode, publish with git merge --squash: the server refuses plain merges of private history');
  if (!privateRule(policy, name)) die(`'${name}' isn't a private branch`);
  const tip = tryG(['rev-parse', '--verify', '-q', `refs/heads/${name}^{commit}`], { cwd: top });
  if (!tip) die(`no local branch '${name}' (eyesonly branch pull ${name})`);
  const target = onto || bare(rp.defaultRef(top, remoteOf(top)) || 'main').replace(/^refs\/remotes\/[^/]+\//, '');
  if (privateRule(policy, target)) die(`'${target}' is a private branch too; publish onto a public branch`);
  if (tryG(['status', '--porcelain', '--untracked-files=no'], { cwd: top })) die('commit or stash your changes first');
  if (currentBranch(top) !== target) execFileSync('git', ['checkout', '--quiet', target], { cwd: top, stdio: ['ignore', 'inherit', 'inherit'] });
  const r = spawnSync('git', ['merge', '--squash', '--quiet', tip], { cwd: top, stdio: ['ignore', 'inherit', 'inherit'] });
  if (r.status !== 0) die(`conflicts while squashing ${name} into ${target}: resolve them, then git commit -m "Publish ${name}" (don't paste the private commit messages unless you mean to)`);
  if (!tryG(['diff', '--cached', '--name-only'], { cwd: top })) die(`nothing to publish: ${target} already has ${name}'s changes`);
  const n = g(['rev-list', '--count', tip, `^${target}`], { cwd: top });
  // An explicit message: git's SQUASH_MSG would copy every private commit message into public history.
  execFileSync('git', ['commit', '--quiet', '-m', `Publish ${name} (${n} private commit(s), squashed)`], { cwd: top, stdio: ['ignore', 'inherit', 'inherit'] });
  log(`squashed ${name} into ${target} as ${short(g(['rev-parse', 'HEAD'], { cwd: top }))}; its private history stays private. Push ${target} with git push.`);
}

function cmdDelete(args) {
  const name = args.map(bare)[0];
  if (!name) die('usage: eyesonly branch delete <private-branch>');
  const top = repoTop();
  const policy = requireRepoPolicy();
  if (!policy) die('in server mode: git push origin --delete <branch>');
  const id0 = loadIdentity();
  const remote = remoteOf(top);
  fetchSealed(top, remote);
  const pins = loadPins();
  const v = scan(top, remote, policy, id0).find((x) => x.readable && x.header.name === name);
  if (!v) die(`no sealed '${name}' you can read on ${remote}`);
  const rule = privateRule(policy, name);
  if (!rule?.who.includes(id0.name)) die(`you may not write ${name}`);
  const r = spawnSync('git', ['push', '--quiet', remote, `:${SEALED_NS}${v.id}`, `--force-with-lease=${SEALED_NS}${v.id}:${v.commit}`], { cwd: top, encoding: 'utf8' });
  if (r.status !== 0) die(`delete failed:\n${(r.stderr || '').trim()}`);
  tryG(['update-ref', '-d', TRACK_NS(remote) + v.id], { cwd: top });
  delete pins[v.id];
  savePins(pins);
  log(`deleted the sealed ${name} on ${remote} (your local branch is kept). The ciphertext may still exist in the host's storage and in other clones.`);
}

const USAGE = `usage: eyesonly branch push [<branch>] [--force]
       eyesonly branch pull [<branch> | --all]
       eyesonly branch list [--no-fetch]
       eyesonly branch publish <branch> [--onto <public-branch>]
       eyesonly branch delete <branch>`;

export async function cmdBranch([sub, ...args]) {
  const table = { push: cmdPush, pull: cmdPull, list: cmdList, ls: cmdList, publish: cmdPublish, delete: cmdDelete };
  if (!table[sub]) die(USAGE);
  return table[sub](args);
}

// ------------------------------------------------------------------ guards

/**
 * Commits that exist only on private branches (local ones and the sealed versions pinned
 * here), minus what any remote-tracking branch already has: Map<commit, branchName>.
 * A local branch's commits from before it was created (its reflog's first entry) don't count,
 * so committing on main and then branching doesn't make main's commit "private".
 */
export function privateCommits(top, policy) {
  const out = new Map();
  const pins = loadPins();
  const add = (name, tip, exclude) => {
    if (!tip || !hasCommit(top, tip)) return;
    const list = tryG(['rev-list', tip, '--not', '--remotes', ...exclude.filter(Boolean)], { cwd: top }) || '';
    for (const c of list.split('\n').filter(Boolean)) if (!out.has(c)) out.set(c, name);
  };
  const heads = (tryG(['for-each-ref', '--format=%(refname:short) %(objectname)', 'refs/heads/'], { cwd: top }) || '').split('\n').filter(Boolean);
  for (const line of heads) {
    const [name, tip] = line.split(' ');
    if (!privateRule(policy, name)) continue;
    const reflog = (tryG(['log', '-g', '--format=%H', `refs/heads/${name}`], { cwd: top }) || '').split('\n').filter(Boolean);
    const created = reflog.length ? reflog[reflog.length - 1] : null;
    const pinned = Object.values(pins).find((p) => p.name === name && !p.retired);
    // A branch that arrived by `eyesonly branch pull` starts at a private tip: use the pin's base instead.
    add(name, tip, [pinned && created && created === pinned.tip ? pinned.base : created || pinned?.base]);
  }
  for (const p of Object.values(pins)) add(p.name, p.tip, [p.base]);
  return out;
}

/**
 * Pre-push checks for repo mode. `lines` are git's pre-push stdin lines; returns error strings.
 * Sealed refs must have the sealed shape; private branches never go to the host as branches;
 * a public ref may not carry commits that exist only on a private branch.
 */
export function prePushChecks(top, lines) {
  let policy;
  try {
    policy = loadPolicy({ required: false });
  } catch {
    policy = null;
  }
  if (!policy || policy.mode !== 'repo') return [];
  const errors = [];
  let priv = null;
  for (const line of lines) {
    const [, loid, rref] = line.split(' ');
    if (!loid || /^0+$/.test(loid)) continue;
    if (rref.startsWith(SEALED_NS)) {
      try {
        checkShape(top, loid, rref.slice(SEALED_NS.length));
      } catch (e) {
        errors.push(e.message);
      }
      continue;
    }
    if (rref.startsWith('refs/eyesonly/')) {
      errors.push(`'${rref}': only sealed branches (${SEALED_NS}<id>, written by eyesonly branch push) may be pushed under refs/eyesonly/`);
      continue;
    }
    const rule = rref.startsWith('refs/heads/') ? privateRule(policy, rref) : null;
    if (rule) {
      errors.push(`'${bare(rref)}' is a private branch (${bare(rule.prefix)}*): pushing it would put its commits on the host in plaintext. Use \`eyesonly branch push ${bare(rref)}\`.`);
      continue;
    }
    priv ||= privateCommits(top, policy);
    if (!priv.size) continue;
    const fresh = (tryG(['rev-list', loid, '--not', '--remotes'], { cwd: top }) || '').split('\n').filter(Boolean);
    const hit = fresh.find((c) => priv.has(c));
    if (hit) {
      errors.push(`pushing '${bare(rref)}' would expose commit ${short(hit)} from the private branch '${priv.get(hit)}' (a branch with a narrower audience). Squash it in instead: \`eyesonly branch publish ${priv.get(hit)}\` (or git merge --squash). If that commit was meant to be public, push it before branching.`);
    }
  }
  return errors;
}

/** Shape-check every sealed ref on `remote` (no keys needed): for `eyesonly verify --sealed`. */
export function verifySealedRefs(top, remote) {
  if (remote && tryG(['config', `remote.${remote}.url`], { cwd: top })) {
    try {
      run(['fetch', '--quiet', '--prune', remote, `+${SEALED_NS}*:${TRACK_NS(remote)}*`], { cwd: top });
    } catch (e) {
      throw new Error(`couldn't fetch sealed branches from ${remote}: ${(e.stderr || '').toString().trim() || e.message}`);
    }
  }
  const refs = (tryG(['for-each-ref', '--format=%(objectname) %(refname)', 'refs/eyesonly/'], { cwd: top }) || '').split('\n').filter(Boolean);
  const errors = [];
  let checked = 0;
  for (const l of refs) {
    const [commit, ref] = l.split(' ');
    const m = /^refs\/eyesonly\/(?:remotes\/[^/]+\/)?b\/(.+)$/.exec(ref);
    if (!m) continue;
    checked++;
    try {
      checkShape(top, commit, m[1]);
    } catch (e) {
      errors.push(e.message);
    }
  }
  return { checked, errors };
}

/** For `eyesonly status` / `doctor`: one line per private branch. */
export function branchSummary(top, policy) {
  if (policy.mode !== 'repo' || !Object.keys(policy.branches || {}).length) return [];
  const pins = loadPins();
  const lines = [];
  const heads = (tryG(['for-each-ref', '--format=%(refname:short) %(objectname)', 'refs/heads/'], { cwd: top }) || '').split('\n').filter(Boolean);
  for (const l of heads) {
    const [name, tip] = l.split(' ');
    if (!privateRule(policy, name)) continue;
    const p = Object.values(pins).find((x) => x.name === name);
    if (!p) lines.push(`${name}: never sealed (eyesonly branch push ${name})`);
    else if (p.tip === tip) lines.push(`${name}: sealed v${p.counter}, in sync`);
    else if (isAncestor(p.tip, tip, top)) lines.push(`${name}: sealed v${p.counter}, ${g(['rev-list', '--count', `${p.tip}..${tip}`], { cwd: top })} commit(s) not pushed (eyesonly branch push)`);
    else lines.push(`${name}: sealed v${p.counter}, diverged from your local branch`);
  }
  return lines;
}
