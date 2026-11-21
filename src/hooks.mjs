// Client-side pre-commit hook.
//
// Defense in depth only: the server's pre-receive hook is the security boundary.
// This hook makes the common cases just work before anything leaves the laptop:
//   - `git mv` of a protected file re-seals the envelope for its new path,
//   - a staged envelope with a stale audience (after `veil pull-policy`) is re-sealed,
//   - plaintext at a protected path (filter bypassed) and moves of ciphertext to an
//     unprotected path are refused with a message that says what to do.
//
// It never writes the working tree and never decrypts unless a rekey is needed. When
// nothing protected is staged it costs a few git calls and no filter runs.
//
// Must not import client.mjs (client.mjs imports this file), so the few helpers it
// needs are duplicated here.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as vc from './crypto.mjs';
import { fileRule } from './policy.mjs';
import { commonGitDir, checkResolvedFilters } from './attrs.mjs';

const CLI = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'veil.mjs');
const VEIL_HOME = () => process.env.VEIL_HOME || path.join(os.homedir(), '.veil');

const MARK_BEGIN = '# >>> veil pre-commit >>>';
const MARK_END = '# <<< veil pre-commit <<<';

const log = (msg) => console.error('[veil] ' + msg);

function git(args, opts = {}) {
  return execFileSync('git', args, { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 30, ...opts });
}
const gitStr = (args, opts) => git(args, { encoding: 'utf8', ...opts }).trim();

function tryGitStr(args) {
  try {
    return gitStr(args);
  } catch {
    return null;
  }
}

const gitDir = () => commonGitDir(); // shared by every git worktree

function loadPolicy() {
  const p = path.join(gitDir(), 'veil', 'policy.json');
  return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : null;
}

function loadIdentity() {
  const p = path.join(VEIL_HOME(), 'identity.json');
  return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : null;
}

function recipientsFor(policy, allowed) {
  const out = {};
  for (const u of allowed) if (policy.keys?.[u]) out[u] = policy.keys[u].x25519;
  return out;
}

const sameSet = (a, b) => a.length === b.length && a.every((x) => b.includes(x));

// ----------------------------------------------------------------- install

const q = (s) => `'${s.replace(/'/g, `'\\''`)}'`;

function veilBlock() {
  return `${MARK_BEGIN}\n${q(process.execPath)} ${q(CLI)} pre-commit || exit 1\n${MARK_END}\n`;
}

/** Install (or refresh) the veil pre-commit hook, chaining any existing user hook. */
export function installPreCommitHook(cwd) {
  const hook = path.resolve(cwd, gitStr(['rev-parse', '--git-path', 'hooks/pre-commit'], { cwd }));
  const dir = path.dirname(hook);
  fs.mkdirSync(dir, { recursive: true });
  const block = veilBlock();

  if (!fs.existsSync(hook)) {
    fs.writeFileSync(hook, '#!/bin/sh\n' + block, { mode: 0o755 });
    return fs.chmodSync(hook, 0o755);
  }

  const existing = fs.readFileSync(hook, 'utf8');
  const start = existing.indexOf(MARK_BEGIN);
  if (start !== -1) {
    const endAt = existing.indexOf(MARK_END, start);
    const end = endAt === -1 ? existing.length : existing.indexOf('\n', endAt) + 1 || existing.length;
    fs.writeFileSync(hook, existing.slice(0, start) + block + existing.slice(end));
    return;
  }

  // A user hook without our marker: keep it as pre-commit.local and chain it.
  const local = path.join(dir, 'pre-commit.local');
  if (!fs.existsSync(local)) {
    fs.renameSync(hook, local);
    log(`kept your existing pre-commit hook as ${local}; it still runs before veil's check`);
  } else {
    let bak = path.join(dir, 'pre-commit.veil-bak');
    for (let n = 1; fs.existsSync(bak); n++) bak = path.join(dir, `pre-commit.veil-bak.${n}`);
    fs.renameSync(hook, bak);
    log(`${local} already exists, so your current pre-commit hook was moved to ${bak}. Merge it into pre-commit.local to keep running it.`);
  }
  const chain = 'd=$(dirname "$0"); if [ -x "$d/pre-commit.local" ]; then "$d/pre-commit.local" "$@" || exit 1; fi\n';
  fs.writeFileSync(hook, '#!/bin/sh\n' + chain + block, { mode: 0o755 });
  fs.chmodSync(hook, 0o755);
}

// ------------------------------------------------------------------- check

/** Parse `git diff -z --name-status` output into { status, src, dst } entries. */
function parseNameStatus(out) {
  const f = out.split('\0');
  const entries = [];
  for (let i = 0; i < f.length && f[i]; ) {
    const status = f[i++][0];
    if (status === 'R' || status === 'C') entries.push({ status, src: f[i++], dst: f[i++] });
    else {
      const p = f[i++];
      entries.push({ status, src: p, dst: p });
    }
  }
  return entries;
}

/** Read many blobs with one `git cat-file --batch`. Returns Map oid -> Buffer (missing oids absent). */
function readBlobs(oids) {
  const out = git(['cat-file', '--batch'], { input: oids.join('\n') + '\n', stdio: ['pipe', 'pipe', 'pipe'] });
  const blobs = new Map();
  let i = 0;
  while (i < out.length) {
    const nl = out.indexOf(0x0a, i);
    const header = out.subarray(i, nl).toString('utf8').split(' ');
    i = nl + 1;
    if (header[1] === 'missing' || header.length < 3) continue;
    const size = Number(header[2]);
    if (header[1] === 'blob') blobs.set(header[0], out.subarray(i, i + size));
    i += size + 1;
  }
  return blobs;
}

/** Decide what a staged protected blob needs. Returns { ok } | { rekey } | { error }. */
function inspect(policy, p, blob, allowed) {
  if (!vc.isEnvelope(blob)) {
    return { error: `plaintext staged for protected path ${p}. Run \`veil setup\` and re-add it (the veil clean filter was bypassed).` };
  }
  let env;
  try {
    env = vc.parse(blob);
  } catch (e) {
    return { error: `cannot rekey '${p}': ${e.message}` };
  }
  const want = Object.keys(recipientsFor(policy, allowed));
  if (env.path === p && sameSet(Object.keys(env.keys), want)) return { ok: true };
  return { rekey: env };
}

function reseal(policy, p, env, allowed, id) {
  if (!allowed.includes(id.name)) return { error: `cannot rekey '${p}': '${id.name}' is not in its audience (allowed: ${allowed.join(', ')})` };
  const signer = policy.keys?.[env.signer];
  const signerAllowed = fileRule(policy, env.path) || [];
  if (!signer || !vc.verify(env, signer.ed25519) || !signerAllowed.includes(env.signer)) {
    return { error: `cannot rekey '${p}': bad or unknown signature (signer '${env.signer}')` };
  }
  let pt;
  try {
    pt = vc.open(env, id);
  } catch {
    return { error: `cannot rekey '${p}': decryption failed (tampered ciphertext?)` };
  }
  if (!pt) return { error: `cannot rekey '${p}': '${id.name}' is not in its audience (no key in this envelope)` };
  const recipients = recipientsFor(policy, allowed);
  return { sealed: vc.seal({ plaintext: pt, path: p, recipients, signer: id }), recipients };
}

export function cmdPreCommit() {
  const policy = loadPolicy();
  if (!policy) return; // veil not set up here: nothing to check

  const base = tryGitStr(['rev-parse', '-q', '--verify', 'HEAD']) || gitStr(['hash-object', '-t', 'tree', '/dev/null']);
  const diff = gitStr(['diff', '--cached', '-z', '--name-status', '--no-ext-diff', '-M100%', '--diff-filter=ACMR', base]);
  const entries = parseNameStatus(diff);
  const errors = [];

  // A .gitattributes line can send a protected path to another filter (e.g. git-lfs, which
  // uploads plaintext from its pre-push hook). Check what git really resolves.
  const attrsStaged = entries.some((e) => path.posix.basename(e.dst) === '.gitattributes');
  const probe = attrsStaged
    ? gitStr(['ls-files', '-z']).split('\0').filter((p) => p && fileRule(policy, p))
    : [...new Set(entries.map((e) => e.dst).filter((p) => fileRule(policy, p)))];
  for (const r of checkResolvedFilters(probe)) {
    errors.push(`'${r.path}' resolves to filter=${r.value} (from .gitattributes); veil requires filter=veil. Run \`veil setup\` and remove the override.`);
  }

  for (const e of entries) {
    if ((e.status === 'R' || e.status === 'C') && fileRule(policy, e.src) && !fileRule(policy, e.dst)) {
      errors.push(
        `cannot rekey '${e.src}' -> '${e.dst}': '${e.dst}' matches no veil rule, so it would be left as unreadable ` +
          `ciphertext at an unprotected path. Rename it to a protected path, or decrypt it and commit the plaintext deliberately.`
      );
    }
  }
  const targets = [...new Set(entries.map((e) => e.dst).filter((p) => fileRule(policy, p)))];
  if (!targets.length) return finish(errors);

  const staged = gitStr(['--literal-pathspecs', 'ls-files', '-s', '-z', '--', ...targets])
    .split('\0')
    .filter(Boolean)
    .map((l) => {
      const tab = l.indexOf('\t');
      const [mode, oid] = l.slice(0, tab).split(' ');
      return { mode, oid, path: l.slice(tab + 1) };
    });
  const blobs = readBlobs([...new Set(staged.map((s) => s.oid))]);

  let id;
  const updates = [];
  for (const s of staged) {
    const allowed = fileRule(policy, s.path);
    const blob = blobs.get(s.oid);
    if (!blob || s.mode === '120000') {
      errors.push(`'${s.path}' is protected and must be a regular encrypted file`);
      continue;
    }
    const r = inspect(policy, s.path, blob, allowed);
    if (r.error) errors.push(r.error);
    if (!r.rekey) continue;
    id ??= loadIdentity();
    if (!id) {
      errors.push(`cannot rekey '${s.path}': no identity at ${path.join(VEIL_HOME(), 'identity.json')}. Run: veil keygen <your-name>`);
      continue;
    }
    const sealed = reseal(policy, s.path, r.rekey, allowed, id);
    if (sealed.error) errors.push(sealed.error);
    else updates.push({ ...s, ...sealed });
  }
  if (errors.length) return finish(errors);

  if (updates.length) {
    const lines = updates.map((u) => {
      const oid = gitStr(['hash-object', '-w', '--no-filters', '--stdin'], { input: u.sealed, stdio: ['pipe', 'pipe', 'pipe'] });
      return `${u.mode} ${oid}\t${u.path}\0`;
    });
    git(['update-index', '-z', '--index-info'], { input: lines.join(''), stdio: ['pipe', 'pipe', 'pipe'] });
    for (const u of updates) log(`rekeyed ${u.path} for ${Object.keys(u.recipients).join(', ')}`);
  }
  finish(errors);
}

function finish(errors) {
  if (!errors.length) return;
  for (const m of errors) log(m);
  process.exit(1);
}
