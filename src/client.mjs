import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import * as attest from './attest.mjs';
import * as attrs from './attrs.mjs';
import { fileURLToPath } from 'node:url';
import * as vc from './crypto.mjs';
import { fileRule } from './policy.mjs';
import { installPreCommitHook, cmdPreCommit } from './hooks.mjs';

const CLI = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'eyesonly.mjs');
const EYESONLY_HOME = () => process.env.EYESONLY_HOME || path.join(os.homedir(), '.eyesonly');
const identityPath = () => path.join(EYESONLY_HOME(), 'identity.json');

const log = (...a) => console.error('[eyesonly]', ...a);
function die(msg) {
  log(msg);
  process.exit(1);
}

function git(args, opts = {}) {
  // Large protected blobs overflow execFileSync's 1 MiB default and would be re-sealed on every clean.
  return execFileSync('git', args, { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 30, ...opts });
}
const gitStr = (args, opts) => git(args, { encoding: 'utf8', ...opts }).trim();

function tryGit(args) {
  try {
    return git(args);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- identity

export function loadIdentity({ required = true } = {}) {
  const p = identityPath();
  if (!fs.existsSync(p)) {
    if (required) die(`no identity at ${p}. Run: eyesonly keygen <your-name>`);
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    die(`can't read your identity at ${p}: ${e.message}`);
  }
}

function cmdKeygen([name]) {
  if (!name) die('usage: eyesonly keygen <name>');
  if (!/^[a-z0-9][a-z0-9._-]{0,38}$/i.test(name)) die(`invalid name '${name}': use letters, digits, '.', '_' or '-' (max 39 characters), starting with a letter or digit`);
  const p = identityPath();
  if (fs.existsSync(p)) die(`identity already exists at ${p} (refusing to overwrite)`);
  fs.mkdirSync(EYESONLY_HOME(), { recursive: true, mode: 0o700 });
  const id = vc.generateIdentity(name);
  fs.writeFileSync(p, JSON.stringify(id, null, 2), { mode: 0o600 });
  const card = vc.publicCard(id);
  log(`created identity '${name}' (fingerprint ${vc.fingerprint(card)}) at ${p}`);
  log('send this public card to your server admin:');
  console.log(vc.encodeCard(card));
}

function cmdWhoami() {
  const id = loadIdentity();
  const card = vc.publicCard(id);
  console.log(`${id.name}  ${vc.fingerprint(card)}`);
  console.log(vc.encodeCard(card));
}

// ------------------------------------------------------------------ policy

// Eyes Only state lives in the common git dir, shared by every `git worktree`.
function gitDir() {
  const { gitDir: own, common } = attrs.gitDirs();
  if (own !== common) migrateWorktreeState(own, common);
  return common;
}

/** Older eyesonly kept state in .git/worktrees/<n>/eyesonly. Move it once; never let it override the main repo's trust. */
function migrateWorktreeState(own, common) {
  const from = path.join(own, 'eyesonly');
  const to = path.join(common, 'eyesonly');
  if (!fs.existsSync(from)) return;
  if (!fs.existsSync(to)) {
    fs.renameSync(from, to);
    return log(`moved this worktree's eyesonly state to ${to} (shared by all worktrees)`);
  }
  const trust = (d) => (fs.existsSync(path.join(d, 'trust.json')) ? fs.readFileSync(path.join(d, 'trust.json'), 'utf8') : null);
  const mine = trust(from);
  if (mine !== null && mine !== trust(to)) {
    die(`conflicting eyesonly trust in worktree and main repo; delete one (${from}) after checking which admin key is right`);
  }
  fs.rmSync(from, { recursive: true, force: true });
}
const policyPath = (dir = gitDir()) => path.join(dir, 'eyesonly', 'policy.json');

export function loadPolicy({ required = true } = {}) {
  let p;
  try {
    p = policyPath();
  } catch {
    if (required) die('not inside a git repository');
    return null;
  }
  if (!fs.existsSync(p)) {
    if (required) die('no eyesonly policy cached for this repo. Run: eyesonly setup');
    return null;
  }
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function credentialsFor(url) {
  const u = new URL(url);
  if (u.username && u.password) return { user: decodeURIComponent(u.username), pass: decodeURIComponent(u.password) };
  const r = spawnSync('git', ['credential', 'fill'], {
    input: `url=${url}\n\n`,
    encoding: 'utf8',
    env: { ...process.env, GIT_TERMINAL_PROMPT: process.env.GIT_TERMINAL_PROMPT ?? '1' },
    stdio: ['pipe', 'pipe', 'inherit'],
  });
  const kv = Object.fromEntries(
    (r.stdout || '').split('\n').filter(Boolean).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)])
  );
  if (!kv.username || !kv.password) die(`no credentials for ${u.host}`);
  return { user: kv.username, pass: kv.password };
}

async function fetchPolicy(remoteUrl) {
  if (!/^https?:\/\//.test(remoteUrl)) die(`eyesonly needs an http(s) remote, got: ${remoteUrl}`);
  const { user, pass } = credentialsFor(remoteUrl);
  const u = new URL(remoteUrl);
  u.username = '';
  u.password = '';
  u.pathname = u.pathname.replace(/\/+$/, '') + '/eyesonly/policy';
  let res;
  try {
    res = await fetch(u, { headers: { authorization: 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') } });
  } catch (e) {
    die(`can't reach ${u.host}: ${e.cause?.code || e.cause?.message || e.message}`);
  }
  if (!res.ok) die(`policy fetch failed: HTTP ${res.status} ${await res.text()}`);
  return res.json();
}

function writePolicy(policy, dir) {
  const p = policyPath(dir);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(policy, null, 2));
}

/** Fetch the policy and check it against the pinned admin key. Writes nothing. */
async function loadResolved(remoteUrl, gitDirOrNull) {
  const raw = await fetchPolicy(remoteUrl);
  const repoName = path.basename(new URL(remoteUrl).pathname);
  let r;
  try {
    r = attest.resolvePolicy(raw, {
      trust: gitDirOrNull ? attest.loadTrust(gitDirOrNull) : null,
      repoName,
      pin: process.env.EYESONLY_PIN_ADMIN,
    });
  } catch (e) {
    die(`refusing the server's policy: ${e.message}. Nothing was changed; ask your admin (if the admin set really changed, delete .git/eyesonly/trust.json to re-pin).`);
  }
  r.notes.forEach((n) => log(n));
  return r;
}

function saveResolved({ policy, trust }, dir) {
  writePolicy(policy, dir);
  if (trust) attest.saveTrust(dir || gitDir(), trust);
  attrs.pinAttributes(pinnedLines(policy), dir || gitDir()); // clone, setup and pull-policy all pin
}

function configureFilters(cwd) {
  const q = (s) => `'${s.replace(/'/g, `'\\''`)}'`;
  const base = `${q(process.execPath)} ${q(CLI)}`;
  const set = (k, v) => git(['config', '--local', k, v], { cwd });
  set('filter.eyesonly.clean', `${base} clean %f`);
  set('filter.eyesonly.smudge', `${base} smudge %f`);
  set('filter.eyesonly.required', 'true');
  set('diff.eyesonly.textconv', `${base} textconv`);
  set('diff.eyesonly.cachetextconv', 'false');
  set('merge.eyesonly.name', 'eyesonly decrypt-merge-reseal');
  set('merge.eyesonly.driver', `${base} merge-file %O %A %B %P %L`);
  installPreCommitHook(cwd);
}

/** Policy globs are root-anchored; translate them to .gitattributes lines. */
function attributeLines(policy) {
  return Object.keys(policy.files || {}).map((g) => `${g.startsWith('**/') ? g : '/' + g} filter=eyesonly diff=eyesonly merge=eyesonly`);
}

// The local pin also sets -text: with core.autocrlf=true (Git for Windows' default) git
// converts line endings before smudge, the envelope's magic line no longer matches, and the
// ciphertext would be written out as-is. It lives only in info/attributes, so committed
// .gitattributes stay the same for everyone.
const pinnedLines = (policy) => attributeLines(policy).map((l) => `${l} -text`);

function ensureAttributes(policy, cwd) {
  attrs.pinAttributes(pinnedLines(policy), attrs.commonGitDir(cwd)); // wins over any in-tree .gitattributes
  const p = path.join(cwd, '.gitattributes');
  const existing = fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '';
  // Lines written before the merge driver existed lack ` merge=eyesonly`: upgrade them in place.
  const old = (l) => l.replace(/ merge=eyesonly$/, '');
  const want = attributeLines(policy);
  let upgraded = 0;
  const lines = existing.split('\n').map((l) => {
    const t = l.trim();
    const hit = want.find((w) => w !== t && old(w) === t);
    if (!hit) return l;
    upgraded++;
    return hit;
  });
  const have = new Set(lines.map((l) => l.trim()));
  const missing = want.filter((l) => !have.has(l));
  if (!missing.length && !upgraded) return false;
  const text = lines.join('\n');
  fs.writeFileSync(p, text + (text && !text.endsWith('\n') ? '\n' : '') + missing.join('\n') + (missing.length ? '\n' : ''));
  log(`${missing.length ? `added ${missing.length}` : ''}${missing.length && upgraded ? ', ' : ''}${upgraded ? `upgraded ${upgraded}` : ''} line(s) in .gitattributes. Commit it so teammates' clients encrypt these paths too.`);
  return true;
}

function protectedFiles(policy, cwd) {
  // `-t` tags skip-worktree entries 'S': a sparse checkout must not materialize excluded secrets.
  const out = gitStr(['ls-files', '-t', '-z'], { cwd });
  return out
    .split('\0')
    .filter((e) => e && e[0] !== 'S')
    .map((e) => e.slice(2))
    .filter((f) => fileRule(policy, f));
}

function originUrl(cwd) {
  try {
    return gitStr(['config', 'remote.origin.url'], { cwd });
  } catch {
    die("this repo has no 'origin' remote. Point origin at your Eyes Only server, e.g.\n  git remote add origin https://<you>@git.example.com/<repo>.git   (or: git remote set-url origin ...)");
  }
}

function repoTop() {
  try {
    return gitStr(['rev-parse', '--show-toplevel']);
  } catch {
    die('not inside a git repository. cd into your clone first (or use `eyesonly clone <url>`).');
  }
}

async function cmdSetup() {
  const top = repoTop();
  const remote = originUrl(top);
  const resolved = await loadResolved(remote, gitDir());
  const { policy } = resolved;
  const id = loadIdentity({ required: false });
  if (id && policy.user !== id.name) log(`warning: server says you are '${policy.user}' but your identity is '${id.name}'`);
  saveResolved(resolved);
  configureFilters(top);
  ensureAttributes(policy, top);
  const files = protectedFiles(policy, top);
  // Re-smudge. `checkout-index -f` skips files whose stat matches the index (a freshly
  // pulled envelope), so remove working copies that are still envelopes first. Plaintext
  // working copies are left alone: they're already decrypted or hold local edits.
  const sealed = files.filter((f) => {
    try {
      return vc.isEnvelope(fs.readFileSync(path.join(top, f)));
    } catch {
      return true; // missing: let checkout-index restore it
    }
  });
  for (const f of sealed) fs.rmSync(path.join(top, f), { force: true });
  if (sealed.length) git(['checkout-index', '-f', '-u', '--', ...sealed], { cwd: top }); // -u: refresh index stat
  log(`ready. ${files.length} protected file(s) in this checkout.`);
}

async function cmdPullPolicy() {
  const remote = originUrl(repoTop());
  saveResolved(await loadResolved(remote, gitDir()));
  log('policy updated. Run `eyesonly rekey` if file access changed.');
}

async function cmdClone([url, dir]) {
  if (!url) die('usage: eyesonly clone <url> [dir]');
  const resolved = await loadResolved(url, null); // before cloning: a bad policy leaves nothing behind
  const { policy } = resolved;
  const id = loadIdentity({ required: false });
  if (!id) log(`warning: no identity at ${identityPath()}, so nothing will be decrypted. Run: eyesonly keygen <your-name>`);
  else if (policy.user !== id.name) log(`warning: server says you are '${policy.user}' but your identity is '${id.name}', so nothing will be decrypted`);
  dir = path.resolve(dir || path.basename(new URL(url).pathname).replace(/\.git$/, ''));
  execFileSync('git', ['clone', '--quiet', '--no-checkout', url, dir], { stdio: 'inherit' });
  saveResolved(resolved, path.join(dir, '.git'));
  configureFilters(dir);
  if (spawnSync('git', ['rev-parse', '--verify', '-q', 'HEAD'], { cwd: dir }).status !== 0) {
    // Protocol v0 can't advertise an unborn HEAD, so git falls back to init.defaultBranch
    // (often master). eyesonly-server creates every repo on main: start there too.
    git(['symbolic-ref', 'HEAD', 'refs/heads/main'], { cwd: dir });
    return log(`cloned an empty repository into ${dir} (branch main). Add files, commit and \`git push -u origin main\`; protected paths are encrypted automatically.`);
  }
  execFileSync('git', ['reset', '--quiet', '--hard', 'HEAD'], { cwd: dir, stdio: ['ignore', 'ignore', 'inherit'] });
  const files = protectedFiles(policy, dir);
  const locked = files.filter((f) => vc.isEnvelope(fs.readFileSync(path.join(dir, f))));
  log(`cloned into ${dir}: ${files.length} protected file(s), ${files.length - locked.length} decrypted, ${locked.length} locked.`);
}

// ----------------------------------------------------------------- filters

export function recipientsFor(policy, allowed) {
  const out = {};
  for (const u of allowed) if (policy.keys?.[u]) out[u] = policy.keys[u].x25519;
  return out;
}

const sameSet = (a, b) => a.length === b.length && a.every((x) => b.includes(x));

function cmdClean([file]) {
  const input = fs.readFileSync(0);
  // Already ciphertext: the working copy of someone who can't decrypt. Pass it through untouched.
  if (vc.isEnvelope(input)) return void process.stdout.write(input);

  const policy = loadPolicy();
  const allowed = fileRule(policy, file);
  if (!allowed) die(`'${file}' has filter=eyesonly in .gitattributes but no rule in the policy. Refusing to commit it in plaintext.`);
  const id = loadIdentity();
  if (!allowed.includes(id.name)) die(`'${id.name}' is not allowed to write '${file}' (allowed: ${allowed.join(', ')})`);

  const recipients = recipientsFor(policy, allowed);
  const missing = allowed.filter((u) => !recipients[u]);
  if (missing.length) log(`warning: no public key for ${missing.join(', ')}; they won't be able to read '${file}'`);

  // Don't produce a fresh ciphertext (and a noisy diff) when the plaintext hasn't changed.
  for (const ref of [`:${file}`, `HEAD:${file}`]) {
    const blob = tryGit(['cat-file', 'blob', ref]);
    if (!blob || !vc.isEnvelope(blob)) continue;
    try {
      const env = vc.parse(blob);
      if (env.path !== file || !sameSet(Object.keys(env.keys), Object.keys(recipients))) continue;
      // A recipient's key changed (set-key): re-wrap. `rekey` also re-seals pre-key-id envelopes.
      if (vc.staleRecipients(env, recipients, { strict: process.env.EYESONLY_RESEAL === '1' }).length) continue;
      const signer = policy.keys?.[env.signer];
      if (!signer || !allowed.includes(env.signer) || !vc.verify(env, signer.ed25519)) continue;
      const prev = vc.open(env, id);
      if (prev && prev.equals(input)) return void process.stdout.write(blob);
    } catch {
      /* fall through and re-seal */
    }
  }
  process.stdout.write(vc.seal({ plaintext: input, path: file, recipients, signer: id }));
}

/** Decrypt a blob if we're allowed to and its signature checks out; else explain why not. */
export function tryOpen(blob, file, policy, id) {
  let env;
  try {
    env = vc.parse(blob);
  } catch (e) {
    return { error: e.message };
  }
  if (file && env.path !== file) return { error: `envelope is bound to '${env.path}', not '${file}' (run eyesonly rekey)` };
  const allowed = policy ? fileRule(policy, env.path) || [] : [];
  const signer = policy?.keys?.[env.signer];
  if (!signer || !vc.verify(env, signer.ed25519)) return { env, error: `bad or unknown signature (signer '${env.signer}')` };
  if (!allowed.includes(env.signer)) return { env, error: `signer '${env.signer}' is not an allowed writer of '${env.path}'` };
  if (!id) return { env, error: 'no identity' };
  try {
    const pt = vc.open(env, id);
    return pt ? { env, plaintext: pt } : { env };
  } catch {
    return { env, error: 'decryption failed (tampered ciphertext?)' };
  }
}

function cmdSmudge([file]) {
  const input = fs.readFileSync(0);
  if (!vc.isEnvelope(input)) return void process.stdout.write(input);
  // A smudge failure would abort checkout (filter is required), so always emit something.
  const policy = loadPolicy({ required: false });
  if (!policy) {
    log('no policy for this checkout. Run `eyesonly setup`');
    return void process.stdout.write(input);
  }
  const r = tryOpen(input, file, policy, loadIdentity({ required: false }));
  if (r.error && r.error !== 'no identity') log(`refusing to decrypt '${file}': ${r.error}`);
  process.stdout.write(r.plaintext ?? input);
}

function cmdTextconv([file]) {
  const input = fs.readFileSync(file);
  if (!vc.isEnvelope(input)) return void process.stdout.write(input);
  const r = tryOpen(input, null, loadPolicy({ required: false }), loadIdentity({ required: false }));
  if (r.plaintext) return void process.stdout.write(r.plaintext);
  const who = r.env ? Object.keys(r.env.keys).join(', ') : '?';
  process.stdout.write(`[eyesonly: encrypted, readable by ${who}${r.error ? `; ${r.error}` : ''}]\n`);
}

// ------------------------------------------------------------ team commands

function cmdStatus() {
  const policy = loadPolicy();
  const id = loadIdentity({ required: false });
  const top = gitStr(['rev-parse', '--show-toplevel']);
  console.log(`repo ${policy.repo} as ${policy.user}${id ? '' : ' (no local identity!)'}`);
  for (const f of protectedFiles(policy, top)) {
    const allowed = fileRule(policy, f);
    const work = fs.existsSync(path.join(top, f)) ? fs.readFileSync(path.join(top, f)) : null;
    const blob = tryGit(['cat-file', 'blob', `:${f}`]);
    let state = work == null ? 'missing' : vc.isEnvelope(work) ? 'locked' : 'decrypted';
    let note = '';
    if (blob && vc.isEnvelope(blob)) {
      const env = vc.parse(blob);
      const have = Object.keys(env.keys).sort();
      const want = Object.keys(recipientsFor(policy, allowed)).sort();
      const stale = vc.staleRecipients(env, recipientsFor(policy, allowed));
      if (!sameSet(have, want)) note = `  needs rekey (encrypted for ${have.join(',')}; policy says ${want.join(',')})`;
      else if (stale.length) note = `  needs rekey (new key for ${stale.join(',')})`;
    } else if (blob) note = '  WARNING: committed in plaintext';
    console.log(`  ${state.padEnd(9)} ${f}  [${allowed.join(', ')}]${note}`);
  }
  for (const r of attrs.checkResolvedFilters(protectedFiles(policy, top), top)) {
    console.log(`warning: '${r.path}' resolves to filter=${r.value}; eyesonly requires filter=eyesonly`);
  }
}

function cmdRekey() {
  const policy = loadPolicy();
  const id = loadIdentity();
  const top = gitStr(['rev-parse', '--show-toplevel']);
  const mine = protectedFiles(policy, top).filter((f) => fileRule(policy, f).includes(id.name));
  const skipped = mine.filter((f) => vc.isEnvelope(fs.readFileSync(path.join(top, f))));
  const files = mine.filter((f) => !skipped.includes(f));
  if (skipped.length) log(`can't rekey (not decrypted here): ${skipped.join(', ')}`);
  if (!files.length) return log('nothing to rekey');
  git(['add', '--renormalize', '--', ...files], { cwd: top, stdio: ['ignore', 'inherit', 'inherit'], env: { ...process.env, EYESONLY_RESEAL: '1' } });
  log(`re-encrypted ${files.length} file(s) for the current policy. Review with \`git status\` and commit.`);
}

function cmdAudit([user]) {
  if (!user) die('usage: eyesonly audit <user>');
  const policy = loadPolicy();
  const seen = new Set();
  const exposed = new Map();
  for (const commit of gitStr(['rev-list', '--all']).split('\n').filter(Boolean)) {
    for (const entry of gitStr(['ls-tree', '-r', '-z', commit]).split('\0').filter(Boolean)) {
      const [meta, file] = entry.split('\t');
      const oid = meta.split(' ')[2];
      if (seen.has(oid) || !fileRule(policy, file)) continue;
      seen.add(oid);
      const blob = git(['cat-file', 'blob', oid]);
      if (!vc.isEnvelope(blob)) {
        exposed.set(file, (exposed.get(file) || 0) + 1);
        continue;
      }
      try {
        if (vc.parse(blob).keys[user]) exposed.set(file, (exposed.get(file) || 0) + 1);
      } catch {}
    }
  }
  if (!exposed.size) return console.log(`${user} never had access to any protected file in this history.`);
  console.log(`${user} could decrypt these protected files at some point. Rotate the secrets inside them:`);
  for (const [f, n] of exposed) console.log(`  ${f}  (${n} version${n > 1 ? 's' : ''})`);
}

// The demo is a bash script so it reads like the commands a user would type.
/** On Windows, plain `bash` may resolve to WSL's System32ash.exe; prefer Git for Windows' bash. */
function findBash() {
  if (process.platform !== 'win32') return 'bash';
  try {
    const exec = gitStr(['--exec-path']); // <git>/mingw64/libexec/git-core
    for (const rel of ['../../../bin/bash.exe', '../../../usr/bin/bash.exe']) {
      const b = path.resolve(exec, rel);
      if (fs.existsSync(b)) return b;
    }
  } catch {}
  return 'bash';
}

function cmdDemo() {
  const script = path.resolve(path.dirname(CLI), '..', 'examples', 'demo.sh');
  const r = spawnSync(findBash(), [script.split(path.sep).join('/')], { stdio: 'inherit' });
  if (r.error) die(`couldn't run the demo (needs bash, git and curl): ${r.error.message}`);
  process.exit(r.status ?? 1);
}

const USAGE = `eyesonly: per-user access control for git

  eyesonly demo                run a self-contained local demo (temp dir, two users)
  eyesonly keygen <name>       create your identity (~/.eyesonly/identity.json)
  eyesonly whoami              print your public card
  eyesonly clone <url> [dir]   clone an eyesonly repo and decrypt what you're allowed to read
  eyesonly setup               enable eyesonly in an existing clone
  eyesonly pull-policy         refresh the cached access policy from the server
  eyesonly policy-sign <file>  (admin) sign a policy manifest from eyesonly-server policy manifest
  eyesonly status              list protected files and whether you can read them
  eyesonly rekey               re-encrypt your readable files for the current policy
  eyesonly audit <user>        list secrets <user> could ever read (rotate them after offboarding)

internal (wired up by setup): clean %f | smudge %f | textconv <file> | pre-commit | merge-file`;

export async function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === '--version' || cmd === 'version') {
    const pkg = JSON.parse(fs.readFileSync(path.resolve(path.dirname(CLI), '..', 'package.json'), 'utf8'));
    return console.log(pkg.version);
  }
  const table = {
    demo: cmdDemo,
    keygen: cmdKeygen,
    whoami: cmdWhoami,
    clone: cmdClone,
    setup: cmdSetup,
    'pull-policy': cmdPullPolicy,
    'policy-sign': (a) => attest.cmdPolicySign(a),
    status: cmdStatus,
    rekey: cmdRekey,
    audit: cmdAudit,
    clean: cmdClean,
    smudge: cmdSmudge,
    textconv: cmdTextconv,
    'pre-commit': cmdPreCommit,
    'merge-file': (a) => import('./merge.mjs').then((m) => m.cmdMergeFile(a)),
  };
  if (!table[cmd]) {
    console.error(USAGE);
    process.exit(cmd ? 1 : 0);
  }
  try {
    await table[cmd](rest);
  } catch (e) {
    // No stack traces for expected failures, and never echo credentials embedded in URLs.
    const redact = (t) => String(t).replace(/(\/\/[^/:@\s]+):[^@\s]+@/g, '$1:***@');
    const detail = e.stderr?.toString().trim() || e.message;
    if (process.env.EYESONLY_DEBUG) console.error(redact(e.stack));
    die(redact(detail));
  }
}
