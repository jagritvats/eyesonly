// Who could read what, and when: answered from git history alone (the envelopes record
// their recipients), so it works the same with and without a server.
//
//   eyesonly audit --file <path> [--at <date|rev>] [--all-refs] [--json]
//   eyesonly audit <user> [--since <date>] [--until <date>] [--json]
//   eyesonly offboard <user> [--yes] [--checklist <out.md>]
//   eyesonly rotate <file> KEY=value... | --from-stdin
//
// The rotation checklist and every message list dotenv key NAMES only, never values.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { execFileSync } from 'node:child_process';
import * as vc from './crypto.mjs';
import * as rp from './repo-policy.mjs';
import { fileRule, writersOf } from './policy.mjs';
import { cmdPullPolicy, cmdRekey, gitDir, loadIdentity, loadPolicy, repoTop } from './client.mjs';

const log = (msg) => console.error('[eyesonly] ' + msg);
function die(msg) {
  log(msg);
  process.exit(1);
}
const git = (args, opts = {}) => execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 30, ...opts });
const tryGit = (args, opts) => {
  try {
    return git(args, opts);
  } catch {
    return null;
  }
};
const blobOf = (oid, cwd) => execFileSync('git', ['cat-file', 'blob', oid], { cwd, maxBuffer: 1 << 30, stdio: ['ignore', 'pipe', 'pipe'] });

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,38}$/i;
const DOTENV = /(^|\/)\.env(\.[^/]+)?$|\.env$/;
const day = (ts) => new Date(ts * 1000).toISOString().slice(0, 10);
const stamp = (ts) => new Date(ts * 1000).toISOString().slice(0, 16).replace('T', ' ');

function flags(args, spec) {
  const out = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') {
      out._.push(...args.slice(i + 1));
      break;
    }
    if (!a.startsWith('--')) {
      out._.push(a);
      continue;
    }
    const k = a.slice(2);
    if (!(k in spec)) die(`unknown option ${a}`);
    if (spec[k] === Boolean) out[k] = true;
    else if (i + 1 >= args.length) die(`${a} needs a value`);
    else out[k] = args[++i];
  }
  return out;
}

/** A date for git's --before/--since. A bare YYYY-MM-DD means the end of that day (UTC). */
function gitDate(s, flag) {
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return `${s}T23:59:59Z`;
  if (!Number.isNaN(Date.parse(s)) || /\b(ago|yesterday|today|now)\b/.test(s)) return s;
  die(`${flag}: '${s}' is not a date (use YYYY-MM-DD, an ISO timestamp or e.g. "2 weeks ago")`);
}
const toTs = (s, flag) => {
  const d = gitDate(s, flag);
  const t = Date.parse(d);
  if (!Number.isNaN(t)) return Math.floor(t / 1000);
  return Number(git(['log', '-1', '--format=%ct', `--before=${d}`, '--all']).trim() || 0);
};

/** Recipients of an envelope: [{ name, kid, oldKey }] (oldKey: the policy now has another key). */
function readersOf(env, policy) {
  return Object.entries(env.keys)
    .map(([name, e]) => {
      const kid = typeof e.kid === 'string' ? e.kid : null;
      const cur = policy?.keys?.[name]?.x25519;
      return { name, kid, oldKey: Boolean(kid && cur && vc.keyId(cur) !== kid) };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** Parse a blob at a protected path: { plaintext: true } or { env, readers }. */
function describe(blob, policy) {
  if (!vc.isEnvelope(blob)) return { plaintext: true, readers: [] };
  try {
    const env = vc.parse(blob);
    return { env, readers: readersOf(env, policy), bound: env.path };
  } catch (e) {
    return { invalid: e.message, readers: [] };
  }
}

const fmtReaders = (v) =>
  v.plaintext
    ? 'EVERYONE who could read the branch (committed in plaintext)'
    : v.invalid
      ? `(unreadable envelope: ${v.invalid})`
      : v.readers.map((r) => `${r.name}${r.kid ? ` [${r.kid.slice(0, 8)}${r.oldKey ? ', old key' : ''}]` : ' [no key id]'}`).join(', ') || '(nobody)';

// ---------------------------------------------------------------- audit --file

/** Plaintext of a blob for comparison: decrypted if we can, raw if it isn't an envelope, else null. */
function contentOf(oid, id, top) {
  try {
    const blob = blobOf(oid, top);
    if (!vc.isEnvelope(blob)) return blob;
    return id ? vc.open(vc.parse(blob), id) : null;
  } catch {
    return null;
  }
}

/**
 * Every path `file` had, newest first. Git's rename detection can't follow protected files:
 * a rename re-seals the envelope for the new path, so no bytes match. Instead, look at the
 * commit that added each name: a protected path deleted in that same commit is the old name
 * (certain when the decrypted contents match; otherwise only if it's the single candidate).
 */
function namesOf(file, tip, top) {
  const names = [file];
  if (!tip) return names;
  const id = loadIdentity({ required: false });
  let cur = file;
  let from = tip;
  for (let hops = 0; hops < 50 && from; hops++) {
    const added = tryGit(['log', '-1', '--diff-filter=A', '--format=%H', from, '--', cur], { cwd: top })?.trim();
    if (!added || !tryGit(['rev-parse', '--verify', '-q', `${added}^`], { cwd: top })) break;
    const gone = (tryGit(['diff-tree', '-r', '-z', '--no-renames', '--diff-filter=D', `${added}^`, added], { cwd: top }) || '')
      .split('\0')
      .filter(Boolean);
    // -z output: ":<mode> <mode> <oid> <oid> D\0<path>\0" pairs
    const deleted = [];
    for (let i = 0; i + 1 < gone.length; i += 2) deleted.push({ path: gone[i + 1], oid: gone[i].split(' ')[2] });
    const candidates = deleted.filter((d) => !names.includes(d.path) && vc.isEnvelope(blobOf(d.oid, top).subarray(0, 12)));
    if (!candidates.length) break;
    const now = tryGit(['rev-parse', `${added}:${cur}`], { cwd: top })?.trim();
    const mine = now ? contentOf(now, id, top) : null;
    const same = mine ? candidates.find((d) => contentOf(d.oid, id, top)?.equals(mine)) : null;
    const prev = same || (candidates.length === 1 ? candidates[0] : null);
    if (!prev) break;
    names.push(prev.path);
    cur = prev.path;
    from = `${added}^`;
  }
  return names;
}

/** The commit `ref` pointed at, as of `at` (a rev or a date); null if it didn't exist yet. */
function commitAt(ref, at, top) {
  if (!at) return tryGit(['rev-parse', '--verify', '-q', `${ref}^{commit}`], { cwd: top })?.trim() || null;
  return tryGit(['rev-list', '-1', '--first-parent', `--before=${gitDate(at, '--at')}`, ref], { cwd: top })?.trim() || null;
}

function versionAt(commit, names, policy, top) {
  for (const n of names) {
    const line = tryGit(['ls-tree', '-z', commit, '--', n], { cwd: top });
    const entry = line && line.split('\0').find((e) => e.endsWith(`\t${n}`));
    if (!entry) continue;
    const oid = entry.split('\t')[0].split(' ')[2];
    const intro = (tryGit(['log', '--reverse', '--format=%H %ct', `--find-object=${oid}`, commit, '--', n], { cwd: top }) || '').split('\n')[0];
    const [ih, its] = intro.split(' ');
    return { path: n, blob: oid, introduced: ih ? { commit: ih, date: stamp(Number(its)) } : null, ...describe(blobOf(oid, top), policy) };
  }
  return null;
}

function auditFile(o) {
  const top = repoTop();
  const policy = loadPolicy();
  const file = path.relative(top, path.resolve(o.file)).split(path.sep).join('/');
  if (!fileRule(policy, file)) log(`note: '${file}' isn't protected by the current policy; showing what history says anyway`);
  const def = rp.defaultRef(top);
  const rev = o.at ? tryGit(['rev-parse', '--verify', '-q', `${o.at}^{commit}`], { cwd: top })?.trim() : null;
  if (rev && o['all-refs']) die('--all-refs needs --at <date>, not a commit');

  let points;
  if (rev) points = [{ ref: o.at, commit: rev }];
  else {
    const refs = o['all-refs']
      ? git(['for-each-ref', '--format=%(refname)', 'refs/heads', 'refs/remotes', 'refs/tags'], { cwd: top }).split('\n').filter((r) => r && !r.endsWith('/HEAD'))
      : [def || 'HEAD'];
    points = refs.map((ref) => ({ ref, commit: commitAt(ref, o.at, top) })).filter((p) => p.commit);
  }
  const tip = tryGit(['rev-parse', '--verify', '-q', `${def || 'HEAD'}^{commit}`], { cwd: top })?.trim();
  const names = namesOf(file, tip, top);
  const versions = new Map();
  for (const p of points) {
    const v = versionAt(p.commit, names, policy, top);
    if (!v) continue;
    const key = `${v.path}\0${v.blob}`;
    if (!versions.has(key)) versions.set(key, { ...v, refs: [] });
    versions.get(key).refs.push({ ref: p.ref.replace(/^refs\/(heads|remotes)\//, ''), commit: p.commit });
  }
  const list = [...versions.values()];
  if (o.json) {
    const clean = list.map(({ env, ...v }) => v);
    return console.log(JSON.stringify({ file, at: o.at || null, names, versions: clean }, null, 2));
  }
  const when = o.at ? `at ${o.at}` : 'now';
  if (!list.length) return console.log(`${file}: not present ${when} on ${points.map((p) => p.ref).join(', ') || 'any ref'} (not added yet, or deleted).`);
  for (const v of list) {
    console.log(`${file} ${when}${v.path !== file ? ` (then named ${v.path})` : ''}: version ${v.blob.slice(0, 10)} on ${v.refs.map((r) => r.ref).join(', ')}`);
    if (v.introduced) console.log(`  introduced by ${v.introduced.commit.slice(0, 10)} on ${v.introduced.date}`);
    if (v.bound && v.bound !== v.path) console.log(`  envelope is bound to '${v.bound}'`);
    console.log(`  readable by: ${fmtReaders(v)}`);
  }
}

// ---------------------------------------------------------------- audit <user>

/**
 * Every (path, blob) version of a protected path in the history visible here, with the
 * first/last commit times it appeared and whether it's on the default branch tip now.
 */
function allVersions(top, policy) {
  const def = rp.defaultRef(top) || 'HEAD';
  const commits = (tryGit(['log', '--all', '--format=%H %T %ct'], { cwd: top }) || '').split('\n').filter(Boolean);
  const byTree = new Map();
  const versions = new Map();
  for (const line of commits) {
    const [, tree, ts] = line.split(' ');
    if (!byTree.has(tree)) {
      const entries = [];
      for (const e of git(['ls-tree', '-r', '-z', tree], { cwd: top }).split('\0').filter(Boolean)) {
        const tab = e.indexOf('\t');
        const file = e.slice(tab + 1);
        const [, type, oid] = e.slice(0, tab).split(' ');
        if (type === 'blob' && fileRule(policy, file)) entries.push([file, oid]);
      }
      byTree.set(tree, entries);
    }
    for (const [file, oid] of byTree.get(tree)) {
      const key = `${file}\0${oid}`;
      const t = Number(ts);
      const v = versions.get(key);
      if (!v) versions.set(key, { path: file, blob: oid, first: t, last: t, commits: 1 });
      else {
        v.first = Math.min(v.first, t);
        v.last = Math.max(v.last, t);
        v.commits++;
      }
    }
  }
  const current = new Set();
  const tip = tryGit(['rev-parse', '--verify', '-q', `${def}^{commit}`], { cwd: top })?.trim();
  if (tip) {
    for (const e of git(['ls-tree', '-r', '-z', tip], { cwd: top }).split('\0').filter(Boolean)) {
      const tab = e.indexOf('\t');
      current.add(`${e.slice(tab + 1)}\0${e.slice(0, tab).split(' ')[2]}`);
    }
  }
  for (const [key, v] of versions) {
    v.current = current.has(key);
    Object.assign(v, describe(blobOf(v.blob, top), policy));
  }
  return [...versions.values()];
}

/** What `user` could decrypt: per file, the versions with dates. Plaintext versions count. */
export function exposureOf(user, top, policy, { since, until } = {}) {
  const lo = since ? toTs(since, '--since') : -Infinity;
  const hi = until ? toTs(until, '--until') : Infinity;
  const files = new Map();
  for (const v of allVersions(top, policy)) {
    const mine = v.plaintext || v.readers.some((r) => r.name === user);
    if (!mine) continue;
    const end = v.current ? Infinity : v.last;
    if (end < lo || v.first > hi) continue;
    const r = v.readers.find((x) => x.name === user);
    if (!files.has(v.path)) files.set(v.path, []);
    files.get(v.path).push({ ...v, kid: r?.kid ?? null });
  }
  for (const list of files.values()) list.sort((a, b) => a.first - b.first);
  return files;
}

function auditUser(user, o) {
  if (!NAME_RE.test(user)) die(`invalid user name '${user}'`);
  const top = repoTop();
  const policy = loadPolicy();
  const files = exposureOf(user, top, policy, o);
  if (o.json) {
    const out = [...files].map(([file, vs]) => ({
      file,
      versions: vs.map((v) => ({ blob: v.blob, first: day(v.first), last: v.current ? null : day(v.last), current: v.current, plaintext: Boolean(v.plaintext), kid: v.kid })),
    }));
    return console.log(JSON.stringify({ user, since: o.since || null, until: o.until || null, files: out }, null, 2));
  }
  if (!files.size) return console.log(`${user} never had access to any protected file in this history${o.since || o.until ? ' in that period' : ''}.`);
  const n = [...files.values()].reduce((s, l) => s + l.length, 0);
  console.log(`${user} could decrypt these protected files at some point (${n} version${n > 1 ? 's' : ''}). Rotate the secrets inside them:`);
  for (const [file, vs] of files) {
    console.log(`  ${file}`);
    for (const v of vs) {
      const span = `${day(v.first)} -> ${v.current ? 'now (current)' : day(v.last)}`;
      console.log(`    ${v.blob.slice(0, 10)}  ${span.padEnd(28)}${v.plaintext ? ' committed in PLAINTEXT' : v.kid ? ` key ${v.kid.slice(0, 8)}` : ''}`);
    }
  }
  console.log('Only refs in this clone are scanned: fetch every branch first (git fetch --all).');
}

export function cmdAudit(args) {
  const o = flags(args, { file: String, at: String, 'all-refs': Boolean, since: String, until: String, json: Boolean });
  if (o.file) {
    if (o._.length || o.since || o.until) die('usage: eyesonly audit --file <path> [--at <date|rev>] [--all-refs] [--json]');
    return auditFile(o);
  }
  if (o.at || o['all-refs']) die('--at and --all-refs go with --file <path>');
  if (o._.length !== 1) die('usage: eyesonly audit <user> [--since <date>] [--until <date>] [--json]  |  eyesonly audit --file <path> [--at <date|rev>]');
  return auditUser(o._[0], o);
}

// ---------------------------------------------------------------- offboard

/** Key names in a dotenv text. Lenient: lines it doesn't understand are skipped. Never values. */
export function dotenvKeys(text) {
  const keys = [];
  for (const line of text.replace(/\r\n?/g, '\n').split('\n')) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    if (m && !keys.includes(m[1])) keys.push(m[1]);
  }
  return keys;
}

/** Key names per file that `user` could read, from versions the caller can decrypt. */
function checklistData(files, id, top) {
  const out = [];
  for (const [file, vs] of files) {
    const item = { file, last: vs.some((v) => v.current) ? 'current version' : day(Math.max(...vs.map((v) => v.last))), versions: vs.length, plaintext: vs.some((v) => v.plaintext), keys: null, unread: 0 };
    if (DOTENV.test(file)) {
      const names = [];
      for (const v of vs) {
        let text = null;
        try {
          const blob = blobOf(v.blob, top);
          if (!vc.isEnvelope(blob)) text = blob.toString('utf8');
          else {
            const pt = vc.open(vc.parse(blob), id);
            if (pt) text = pt.toString('utf8');
          }
        } catch {}
        if (text == null) item.unread++;
        else for (const k of dotenvKeys(text)) if (!names.includes(k)) names.push(k);
      }
      item.keys = names;
    }
    out.push(item);
  }
  return out;
}

function checklistMarkdown(user, by, items) {
  const lines = [
    `# Rotation checklist: offboarding ${user}`,
    '',
    `Generated ${new Date().toISOString().slice(0, 10)} by ${by}. ${user} could decrypt everything below at some point.`,
    'Revoking access only protects future versions: rotate each secret at its source (the provider),',
    'then commit the new value, e.g. `eyesonly rotate .env KEY=<new value>` (or `--from-stdin`).',
    '',
  ];
  for (const it of items) {
    lines.push(`## ${it.file}`, '', `Last readable by ${user}: ${it.last} · ${it.versions} version${it.versions > 1 ? 's' : ''}${it.plaintext ? ' · was committed in PLAINTEXT' : ''}`, '');
    if (it.keys && it.keys.length) for (const k of it.keys) lines.push(`- [ ] ${k}`);
    else lines.push(`- [ ] rotate everything in ${it.file}`);
    if (it.unread) lines.push('', `(${it.unread} version${it.unread > 1 ? 's' : ''} you can't decrypt: ask a reader for the key names in them)`);
    lines.push('');
  }
  return lines.join('\n');
}

async function confirm(question) {
  if (!process.stdin.isTTY) die('not a terminal: pass --yes to offboard without a prompt');
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  const answer = await new Promise((resolve) => rl.question(`${question} [y/N] `, resolve));
  rl.close();
  return /^y(es)?$/i.test(answer.trim());
}

const inAudience = (policy, user) => Object.values(policy.files || {}).some((who) => who.includes(user));

export async function cmdOffboard(args) {
  const o = flags(args, { yes: Boolean, checklist: String, remote: String });
  const user = o._[0];
  if (!user || o._.length !== 1 || !NAME_RE.test(user)) die('usage: eyesonly offboard <user> [--yes] [--checklist <out.md>]');
  const top = repoTop();
  const id = loadIdentity();
  if (user === id.name) die("you can't offboard yourself");
  let policy = loadPolicy();
  const mode = policy.mode === 'repo' ? 'repo' : 'server';

  const files = exposureOf(user, top, policy);
  const items = checklistData(files, id, top);
  if (!o.yes && !(await confirm(`Offboard ${user}: remove them from the policy, re-encrypt what you can read, and write a rotation checklist for ${items.length} file(s)?`))) die('nothing changed');

  const out = path.resolve(o.checklist || path.join(gitDir(), 'eyesonly', `offboard-${user}.md`));
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, checklistMarkdown(user, id.name, items));
  log(`rotation checklist: ${out} (${items.length} file(s); key names only, no values)`);

  if (mode === 'repo') {
    if (policy.keys?.[user] || inAudience(policy, user)) {
      const rm = await import('./repo-mode.mjs');
      rm.cmdRevoke([user]);
      policy = loadPolicy();
    } else log(`${user} is already out of the policy`);
    cmdRekey();
    if (fs.existsSync(path.join(top, rp.POLICY_FILE))) git(['add', '--', rp.POLICY_FILE], { cwd: top });
    log(`next: git commit -m "eyesonly: offboard ${user}" && git push, then rotate what the checklist lists`);
    return;
  }

  // Server mode: the server holds the policy. Refresh it; if the user is still in it, the
  // admin removes them on the server first and runs offboard again to re-encrypt.
  await cmdPullPolicy(o.remote ? ['--remote', o.remote] : []);
  policy = loadPolicy();
  if (inAudience(policy, user)) {
    const repo = policy.repo;
    log(`${user} is still in the server's policy for ${repo}. On the server, an admin runs:`);
    console.log(`  eyesonly-server user remove ${user}`);
    console.log(`  # if ${repo} has a signed policy, re-sign it:`);
    console.log(`  eyesonly-server policy manifest ${repo} > m.json && eyesonly policy-sign m.json > s.json && eyesonly-server policy attest ${repo} s.json`);
    log(`then run \`eyesonly offboard ${user} --yes\` again here to re-encrypt for the remaining readers. Their token stops working as soon as the user is removed.`);
    return;
  }
  cmdRekey();
  log(`next: git commit -m "eyesonly: offboard ${user}" && git push, then rotate what the checklist lists`);
}

// ---------------------------------------------------------------- rotate

const BARE = /^[A-Za-z0-9_./:@+,%^=-]*$/;
const quoteValue = (v) => (BARE.test(v) ? v : `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r')}"`);

/** End index (inclusive) of a KEY=VALUE line at `i`, following a quoted value across lines. */
function valueEnd(lines, i) {
  const m = lines[i].match(/^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*(["'`])(.*)$/);
  if (!m) return i;
  const q = m[1];
  const closes = (s) => {
    for (let k = 0; k < s.length; k++) {
      if (s[k] === '\\' && q === '"') k++;
      else if (s[k] === q) return true;
    }
    return false;
  };
  if (closes(m[2])) return i;
  for (let j = i + 1; j < lines.length; j++) if (closes(lines[j])) return j;
  return i;
}

/** Set keys in dotenv text, keeping comments, order and `export ` prefixes. */
export function setDotenvKeys(text, updates) {
  const eol = /\r\n/.test(text) ? '\r\n' : '\n';
  const lines = text.length ? text.replace(/\r\n/g, '\n').split('\n') : [];
  const trailing = lines.length && lines[lines.length - 1] === '';
  if (trailing) lines.pop();
  const changed = [];
  const added = [];
  const same = [];
  for (const [key, value] of updates) {
    let at = -1;
    for (let i = 0; i < lines.length; i++) {
      if (new RegExp(`^\\s*(?:export\\s+)?${key}\\s*=`).test(lines[i])) at = i;
      i = valueEnd(lines, i);
    }
    const prefix = at >= 0 && /^\s*export\s+/.test(lines[at]) ? 'export ' : '';
    const line = `${prefix}${key}=${quoteValue(value)}`;
    if (at < 0) {
      lines.push(line);
      added.push(key);
    } else {
      const end = valueEnd(lines, at);
      if (end === at && lines[at] === line) same.push(key);
      else {
        lines.splice(at, end - at + 1, line);
        changed.push(key);
      }
    }
  }
  return { text: lines.join(eol) + eol, changed, added, same };
}

function parseUpdates(pairs, where) {
  const updates = [];
  for (const p of pairs) {
    const m = p.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/);
    if (!m) die(`${where}: expected KEY=value`); // never echo it: it holds a secret
    updates.push([m[1], m[2]]);
  }
  return updates;
}

export function cmdRotate(args) {
  const o = flags(args, { 'from-stdin': Boolean });
  const [fileArg, ...pairs] = o._;
  if (!fileArg || (!pairs.length && !o['from-stdin']) || (pairs.length && o['from-stdin'])) {
    die('usage: eyesonly rotate <file> KEY=value [KEY=value...]   |   eyesonly rotate <file> --from-stdin  (KEY=value lines)');
  }
  const top = repoTop();
  const policy = loadPolicy();
  const id = loadIdentity();
  const file = path.relative(top, path.resolve(fileArg)).split(path.sep).join('/');
  const readers = fileRule(policy, file);
  if (!readers) die(`'${file}' isn't a protected file in this repo's policy`);
  const writers = writersOf(policy, file);
  if (!writers.includes(id.name)) die(`you can't write '${file}' (${readers.includes(id.name) ? 'read-only; ' : ''}writers: ${writers.join(', ') || 'nobody'})`);
  const abs = path.join(top, file);
  const current = fs.existsSync(abs) ? fs.readFileSync(abs) : Buffer.alloc(0);
  if (vc.isEnvelope(current) || vc.isCrlfEnvelope(current)) die(`'${file}' isn't decrypted in this checkout: run \`eyesonly setup\` first`);

  const updates = o['from-stdin']
    ? parseUpdates(
        fs.readFileSync(0, 'utf8').replace(/\r\n?/g, '\n').split('\n').filter((l) => l.trim() && !l.trim().startsWith('#')),
        'stdin',
      )
    : parseUpdates(pairs, 'argument');
  if (!updates.length) die('no KEY=value pairs given');

  const r = setDotenvKeys(current.toString('utf8'), updates);
  if (!r.changed.length && !r.added.length) return log(`nothing changed in ${file} (same values: ${r.same.join(', ')})`);
  fs.writeFileSync(abs, r.text);
  git(['add', '--', file], { cwd: top, stdio: ['ignore', 'pipe', 'inherit'] });
  const parts = [r.changed.length && `changed ${r.changed.join(', ')}`, r.added.length && `added ${r.added.join(', ')}`, r.same.length && `unchanged ${r.same.join(', ')}`].filter(Boolean);
  log(`${file}: ${parts.join('; ')}. Staged (encrypted); commit and push.`);
}
