import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import * as attest from './attest.mjs';
import * as attrs from './attrs.mjs';
import { fileURLToPath } from 'node:url';
import * as vc from './crypto.mjs';
import { fileRule } from './policy.mjs';
import { installPreCommitHook, cmdPreCommit, HOOK_MARK } from './hooks.mjs';
import { eyesonlyHome, identityPath, identitySource, readIdentity } from './identity.mjs';

const CLI = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'eyesonly.mjs');
const EYESONLY_HOME = eyesonlyHome;

const log = (...a) => console.error('[eyesonly]', ...a);

// Inside the long-running filter process (and doctor), a failure must fail one request,
// not kill the process: die() throws instead of exiting.
class Stop extends Error {}
let throwOnDie = false;
function die(msg) {
  if (throwOnDie) throw new Stop(msg);
  log(msg);
  process.exit(1);
}

const redact = (t) => String(t).replace(/(\/\/[^/:@\s]+):[^@\s]+@/g, '$1:***@');

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

/** Look up several object names (`:path`, `HEAD:path`, ...) with one `git cat-file --batch`. null where missing or not a blob. */
function catBlobs(names) {
  if (names.some((n) => n.includes('\n'))) return names.map((n) => tryGit(['cat-file', 'blob', n]));
  let out;
  try {
    out = git(['cat-file', '--batch'], { input: names.join('\n') + '\n', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch {
    return names.map(() => null);
  }
  const res = [];
  let i = 0;
  for (let k = 0; k < names.length && i < out.length; k++) {
    const nl = out.indexOf(0x0a, i);
    const header = out.subarray(i, nl).toString('utf8').split(' ');
    i = nl + 1;
    const size = Number(header[2]);
    if (header.length !== 3 || !Number.isFinite(size)) {
      res.push(null); // "<name> missing" / "ambiguous"
      continue;
    }
    res.push(header[1] === 'blob' ? out.subarray(i, i + size) : null);
    i += size + 1;
  }
  while (res.length < names.length) res.push(null);
  return res;
}

/** Pull `--flag value` pairs out of argv. */
function takeFlags(args, names) {
  const flags = {};
  const rest = [];
  for (let i = 0; i < args.length; i++) {
    const name = names.find((n) => args[i] === `--${n}` || args[i].startsWith(`--${n}=`));
    if (!name) rest.push(args[i]);
    else if (args[i].includes('=')) flags[name] = args[i].slice(args[i].indexOf('=') + 1);
    else if (i + 1 < args.length) flags[name] = args[++i];
    else die(`--${name} needs a value`);
  }
  return { flags, rest };
}

// ---------------------------------------------------------------- identity

export function loadIdentity({ required = true } = {}) {
  let id;
  try {
    id = readIdentity();
  } catch (e) {
    die(e.message);
  }
  if (!id && required) die(`no identity at ${identityPath()}. Run: eyesonly keygen <your-name> (or set EYESONLY_IDENTITY)`);
  return id;
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

async function fetchPolicy(remoteUrl, remoteName) {
  const which = remoteName ? ` (remote '${remoteName}')` : '';
  const other = remoteName ? `. If '${remoteName}' isn't your Eyes Only server, use --remote <name>` : '';
  if (!/^https?:\/\//.test(remoteUrl)) die(`eyesonly needs an http(s) remote, got: ${redact(remoteUrl)}${which}${other}`);
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
  if (!res.ok) die(`policy fetch failed${which}: HTTP ${res.status} ${(await res.text()).trim()}${res.status === 404 || res.status === 401 ? other : ''}`);
  try {
    return await res.json();
  } catch {
    die(`policy fetch failed${which}: the server didn't answer with an Eyes Only policy${other}`);
  }
}

function writePolicy(policy, dir) {
  const p = policyPath(dir);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(policy, null, 2));
}

/** Fetch the policy and check it against the pinned admin key. Writes nothing. */
async function loadResolved(remoteUrl, gitDirOrNull, remoteName) {
  const raw = await fetchPolicy(remoteUrl, remoteName);
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

const shq = (s) => `'${s.replace(/'/g, `'\\''`)}'`;
const realOrSelf = (p) => {
  try {
    return fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
};
const samePath = (a, b) => {
  const n = (p) => realOrSelf(p).replace(/\\/g, '/');
  return process.platform === 'win32' ? n(a).toLowerCase() === n(b).toLowerCase() : n(a) === n(b);
};

/** Run a shell command line the way git runs filters and hooks (git's sh, git's PATH). */
function viaGitShell(cmdline, cwd) {
  return spawnSync('git', ['-c', `alias.eyesonly-probe=!${cmdline}`, 'eyesonly-probe'], {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30000,
  });
}

/**
 * How git should invoke this CLI. `eyesonly` from PATH survives node upgrades and package
 * moves, but only if it is this same package; otherwise (npx, a checkout) use absolute
 * node + script paths, which `eyesonly setup` rewrites if they ever move.
 */
function cliCommand(cwd) {
  const absolute = `${shq(process.execPath)} ${shq(CLI)}`;
  if (process.env.EYESONLY_ABSOLUTE_COMMANDS) return absolute;
  const r = viaGitShell('eyesonly __cli-path', cwd);
  if (r.status === 0 && r.stdout.trim() && samePath(r.stdout.trim(), CLI)) return 'eyesonly';
  return absolute;
}

function configureFilters(cwd) {
  const base = cliCommand(cwd);
  const set = (k, v) => git(['config', '--local', k, v], { cwd });
  // git prefers the long-running `process` filter; clean/smudge stay as the fallback for
  // tools that only know single-shot filters.
  set('filter.eyesonly.process', `${base} filter-process`);
  set('filter.eyesonly.clean', `${base} clean %f`);
  set('filter.eyesonly.smudge', `${base} smudge %f`);
  set('filter.eyesonly.required', 'true');
  set('diff.eyesonly.textconv', `${base} textconv`);
  set('diff.eyesonly.cachetextconv', 'false');
  set('merge.eyesonly.name', 'eyesonly decrypt-merge-reseal');
  set('merge.eyesonly.driver', `${base} merge-file %O %A %B %P %L`);
  installPreCommitHook(cwd, base);
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

/**
 * The remote that points at the Eyes Only server: `--remote <name>` (remembered in
 * `eyesonly.remote`), else the remembered one, else `origin`.
 */
function resolveRemote(cwd, flag) {
  let remembered = null;
  try {
    remembered = gitStr(['config', 'eyesonly.remote'], { cwd }) || null;
  } catch {}
  const name = flag || remembered || 'origin';
  let url;
  try {
    url = gitStr(['config', `remote.${name}.url`], { cwd });
  } catch {
    if (flag || remembered) die(`no remote named '${name}' in this repo (git remote -v lists them).`);
    die("this repo has no 'origin' remote. Point a remote at your Eyes Only server, e.g.\n  git remote add origin https://<you>@git.example.com/<repo>.git\nor keep your current origin and use: eyesonly setup --remote <name>");
  }
  if (flag && flag !== remembered) git(['config', '--local', 'eyesonly.remote', flag], { cwd });
  return { name, url };
}

function repoTop() {
  try {
    return gitStr(['rev-parse', '--show-toplevel']);
  } catch {
    die('not inside a git repository. cd into your clone first (or use `eyesonly clone <url>`).');
  }
}

async function cmdSetup(args = []) {
  const { flags } = takeFlags(args, ['remote']);
  const top = repoTop();
  const remote = resolveRemote(top, flags.remote);
  const resolved = await loadResolved(remote.url, gitDir(), remote.name);
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
  log(`ready (remote '${remote.name}'). ${files.length} protected file(s) in this checkout.`);
}

async function cmdPullPolicy(args = []) {
  const { flags } = takeFlags(args, ['remote']);
  const remote = resolveRemote(repoTop(), flags.remote);
  saveResolved(await loadResolved(remote.url, gitDir(), remote.name));
  log(`policy updated from remote '${remote.name}'. Run \`eyesonly rekey\` if file access changed.`);
}

const quietCredEnv = () => ({ ...process.env, GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'never' });

function credentialHelper(url) {
  const r = spawnSync('git', ['config', '--get-urlmatch', 'credential.helper', url], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  return r.status === 0 ? r.stdout.trim() : '';
}

/**
 * A token in the clone URL would end up in .git/config. When a credential helper is
 * configured, hand the token to it and return the URL without the password; otherwise
 * keep the URL as given and say how to avoid it.
 */
function storeToken(url) {
  const u = new URL(url);
  if (!u.password) return url;
  const bare = new URL(url);
  bare.password = '';
  const plain = bare.toString();
  if (!credentialHelper(url)) {
    log(`note: the token is saved in .git/config (remote URL). To keep it out, configure a git credential helper; see docs/existing-repos.md#keep-the-token-out-of-the-remote-url`);
    return url;
  }
  const pass = decodeURIComponent(u.password);
  spawnSync('git', ['credential', 'approve'], { input: `url=${plain}\npassword=${pass}\n\n`, env: quietCredEnv(), stdio: ['pipe', 'ignore', 'ignore'] });
  const r = spawnSync('git', ['credential', 'fill'], { input: `url=${plain}\n\n`, encoding: 'utf8', env: quietCredEnv(), stdio: ['pipe', 'pipe', 'ignore'] });
  const got = /(?:^|\n)password=([^\n]*)/.exec(r.stdout || '')?.[1];
  if (got !== pass) {
    log(`note: your credential helper didn't keep the token, so it stays in .git/config (remote URL)`);
    return url;
  }
  log(`token stored with your git credential helper (${credentialHelper(url)}); the remote URL holds only your user name`);
  return plain;
}

async function cmdClone([url, dir]) {
  if (!url) die('usage: eyesonly clone <url> [dir]');
  const resolved = await loadResolved(url, null); // before cloning: a bad policy leaves nothing behind
  const { policy } = resolved;
  const id = loadIdentity({ required: false });
  if (!id) log(`warning: no identity at ${identitySource()}, so nothing will be decrypted. Run: eyesonly keygen <your-name>`);
  else if (policy.user !== id.name) log(`warning: server says you are '${policy.user}' but your identity is '${id.name}'; files are decrypted as '${id.name}'`);
  dir = path.resolve(dir || path.basename(new URL(url).pathname).replace(/\.git$/, ''));
  execFileSync('git', ['clone', '--quiet', '--no-checkout', storeToken(url), dir], { stdio: 'inherit' });
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
  const contents = files.map((f) => fs.readFileSync(path.join(dir, f)));
  const locked = contents.filter((b) => vc.isEnvelope(b)).length;
  const crlf = contents.filter((b) => vc.isCrlfEnvelope(b)).length;
  log(`cloned into ${dir}: ${files.length} protected file(s), ${files.length - locked - crlf} decrypted, ${locked} locked.`);
  if (crlf) log(`warning: ${crlf} protected file(s) have converted line endings (core.autocrlf?). Run \`eyesonly doctor\` in the clone.`);
}

// ----------------------------------------------------------------- filters

export function recipientsFor(policy, allowed) {
  const out = {};
  for (const u of allowed) if (policy.keys?.[u]) out[u] = policy.keys[u].x25519;
  return out;
}

const sameSet = (a, b) => a.length === b.length && a.every((x) => b.includes(x));

/**
 * Ciphertext in the working tree: normally a non-reader's untouched copy, which passes
 * through. Ciphertext that matches nothing committed or staged and doesn't verify (an
 * editor appended to it, it was hand-edited, or it belongs to another path) is refused
 * here instead of at push time.
 */
async function passThroughEnvelope(input, file, lookup) {
  const policy = loadPolicy({ required: false });
  if (!policy) return input;
  const known = await lookup([`:${file}`, `HEAD:${file}`, `:2:${file}`, `:3:${file}`, `:1:${file}`]);
  if (known.some((b) => b && b.equals(input))) return input;
  // Verify against the envelope's own path, not `file`: a non-reader's `git mv` re-hashes the
  // moved envelope under its new name, and the pre-commit hook (re-seal or a clear refusal)
  // and the server own path binding. Here we only stop corrupted or forged ciphertext.
  const r = tryOpen(input, null, policy, null); // null identity: verify only, never decrypt
  if (r.error && r.error !== 'no identity') {
    die(`refusing to stage '${file}': its ciphertext was edited or isn't valid (${r.error}). If you can't read it, restore it with: git checkout -- ${file}`);
  }
  return input;
}

/** The clean filter: plaintext in, envelope out. Shared by `eyesonly clean` and the filter process. */
export async function cleanBuf(input, file, lookup = catBlobs) {
  // Line endings converted by core.autocrlf: restore the envelope exactly.
  if (vc.isCrlfEnvelope(input)) input = vc.fromCrlf(input);
  if (vc.isEnvelope(input)) return passThroughEnvelope(input, file, lookup);

  const policy = loadPolicy();
  const allowed = fileRule(policy, file);
  if (!allowed) die(`'${file}' has filter=eyesonly in .gitattributes but no rule in the policy. Refusing to commit it in plaintext.`);
  const id = loadIdentity();
  if (!allowed.includes(id.name)) die(`'${id.name}' is not allowed to write '${file}' (allowed: ${allowed.join(', ')})`);

  const recipients = recipientsFor(policy, allowed);
  const missing = allowed.filter((u) => !recipients[u]);
  if (missing.length) log(`warning: no public key for ${missing.join(', ')}; they won't be able to read '${file}'`);

  // Don't produce a fresh ciphertext (and a noisy diff) when the plaintext hasn't changed.
  for (const blob of await lookup([`:${file}`, `HEAD:${file}`])) {
    if (!blob || !vc.isEnvelope(blob)) continue;
    try {
      const env = vc.parse(blob);
      if (env.path !== file || !sameSet(Object.keys(env.keys), Object.keys(recipients))) continue;
      // A recipient's key changed (set-key): re-wrap. `rekey` also re-seals pre-key-id envelopes.
      if (vc.staleRecipients(env, recipients, { strict: process.env.EYESONLY_RESEAL === '1' }).length) continue;
      const signer = policy.keys?.[env.signer];
      if (!signer || !allowed.includes(env.signer) || !vc.verify(env, signer.ed25519)) continue;
      const prev = vc.open(env, id);
      if (prev && prev.equals(input)) return blob;
    } catch {
      /* fall through and re-seal */
    }
  }
  return vc.seal({ plaintext: input, path: file, recipients, signer: id });
}

async function cmdClean([file]) {
  process.stdout.write(await cleanBuf(fs.readFileSync(0), file));
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

let warnedCrlf = false;

/** The smudge filter: envelope in, plaintext out if we may read it. Never fails (checkout would abort). */
export function smudgeBuf(input, file) {
  if (vc.isCrlfEnvelope(input)) {
    if (!warnedCrlf) log('line endings were converted before decryption (core.autocrlf?). Run `eyesonly setup` to pin -text on protected paths.');
    warnedCrlf = true;
    input = vc.fromCrlf(input);
  }
  if (!vc.isEnvelope(input)) return input;
  const policy = loadPolicy({ required: false });
  if (!policy) {
    log('no policy for this checkout. Run `eyesonly setup`');
    return input;
  }
  let id = null;
  try {
    id = loadIdentity({ required: false });
  } catch (e) {
    if (!(e instanceof Stop)) throw e;
    log(e.message);
  }
  const r = tryOpen(input, file, policy, id);
  if (r.error && r.error !== 'no identity') log(`refusing to decrypt '${file}': ${r.error}`);
  return r.plaintext ?? input;
}

function cmdSmudge([file]) {
  process.stdout.write(smudgeBuf(fs.readFileSync(0), file));
}

async function cmdFilterProcess() {
  throwOnDie = true;
  const { runFilterProcess, BlobReader } = await import('./filterproc.mjs');
  const { gitDir: own, common } = attrs.gitDirs();
  const blobs = new BlobReader({ spawn, fs, path, gitDir: own, commonDir: common, fallback: catBlobs });
  try {
    await runFilterProcess({ clean: (input, file) => cleanBuf(input, file, (names) => blobs.get(names)), smudge: smudgeBuf, log: (m) => log(m) });
  } finally {
    blobs.stop();
  }
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
    const crlf = work != null && vc.isCrlfEnvelope(work);
    let state = work == null ? 'missing' : crlf ? 'corrupted' : vc.isEnvelope(work) ? 'locked' : 'decrypted';
    let note = crlf ? '  line endings were converted (core.autocrlf?); run `eyesonly setup`' : '';
    if (blob && vc.isEnvelope(blob)) {
      const env = vc.parse(blob);
      const have = Object.keys(env.keys).sort();
      const want = Object.keys(recipientsFor(policy, allowed)).sort();
      const stale = vc.staleRecipients(env, recipientsFor(policy, allowed));
      if (!sameSet(have, want)) note += `  needs rekey (encrypted for ${have.join(',')}; policy says ${want.join(',')})`;
      else if (stale.length) note += `  needs rekey (new key for ${stale.join(',')})`;
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

// ------------------------------------------------------------------ doctor

const canon = (v) =>
  Array.isArray(v) ? v.map(canon) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v;

/** Check this machine and clone; print what's wrong and how to fix it. Exit 1 on problems. */
async function cmdDoctor(args = []) {
  const { flags } = takeFlags(args, ['remote']);
  let problems = 0;
  const ok = (m) => console.log(`  ok    ${m}`);
  const warn = (m, fix) => console.log(`  warn  ${m}${fix ? `\n        fix: ${fix}` : ''}`);
  const fail = (m, fix) => {
    problems++;
    console.log(`  FAIL  ${m}${fix ? `\n        fix: ${fix}` : ''}`);
  };
  throwOnDie = true;
  const attempt = async (f) => {
    try {
      return { value: await f() };
    } catch (e) {
      if (e instanceof Stop) return { error: e.message };
      throw e;
    }
  };

  // git
  const gv = /(\d+)\.(\d+)/.exec(gitStr(['--version']));
  const [maj, min] = gv ? [Number(gv[1]), Number(gv[2])] : [0, 0];
  if (maj > 2 || (maj === 2 && min >= 40)) ok(`git ${maj}.${min}`);
  else warn(`git ${maj}.${min} is old; eyesonly is tested with git >= 2.40`, 'upgrade git');

  // identity
  const idr = await attempt(() => loadIdentity({ required: false }));
  const id = idr.value;
  if (idr.error) fail(idr.error, `restore ${identityPath()} from a backup, or run eyesonly keygen and ask your admin to re-register you`);
  else if (!id) fail(`no identity at ${identityPath()}`, 'eyesonly keygen <your-name>, then send the card to your admin (or set EYESONLY_HOME)');
  else ok(`identity '${id.name}' at ${identityPath()}`);

  let top;
  try {
    top = gitStr(['rev-parse', '--show-toplevel']);
  } catch {
    console.log('  (not inside a git repository: skipping repo checks)');
    process.exit(problems ? 1 : 0);
  }
  console.log(`repo ${top}`);

  // remote and credentials
  const rr = await attempt(() => resolveRemote(top, flags.remote));
  const remote = rr.value;
  if (rr.error) fail(rr.error.split('\n')[0], 'git remote add origin https://<you>@<server>/<repo>.git, or eyesonly setup --remote <name>');
  else {
    ok(`remote '${remote.name}' -> ${redact(remote.url)}`);
    let u = null;
    try {
      u = new URL(remote.url);
    } catch {}
    if (u?.password) warn(`the token is stored in .git/config (remote '${remote.name}' URL)`, 'set up a git credential helper, then: git remote set-url ' + remote.name + ' ' + redact(remote.url).replace(':***@', '@') + ' and run eyesonly pull-policy (it will ask for the token once)');
    else if (u) ok(credentialHelper(remote.url) ? `token comes from your credential helper (${credentialHelper(remote.url)})` : 'no token in the remote URL');
  }

  // policy cache vs server
  const policy = loadPolicy({ required: false });
  if (!policy) fail('no policy cached for this clone', 'eyesonly setup');
  else {
    const age = Date.now() - fs.statSync(policyPath()).mtimeMs;
    ok(`policy cached for '${policy.user}' (${Math.round(age / 3600000)}h old)`);
    if (id && policy.user !== id.name) fail(`the server knows you as '${policy.user}' but your identity is '${id.name}'`, 'use the identity and token that belong together (EYESONLY_HOME, remote URL user)');
    if (remote) {
      const sr = await attempt(() => loadResolved(remote.url, gitDir(), remote.name));
      if (sr.error) warn(`couldn't compare with the server: ${sr.error.split('\n')[0]}`);
      else if (JSON.stringify(canon(sr.value.policy)) !== JSON.stringify(canon(policy))) fail('the cached policy is out of date', 'eyesonly pull-policy && eyesonly rekey');
      else ok('cached policy matches the server');
    }
  }

  // filters, merge driver, hook
  const cfg = (k) => {
    try {
      return gitStr(['config', '--local', k], { cwd: top });
    } catch {
      return null;
    }
  };
  const process_ = cfg('filter.eyesonly.process');
  const clean = cfg('filter.eyesonly.clean');
  if (!clean || !cfg('filter.eyesonly.smudge') || cfg('filter.eyesonly.required') !== 'true' || !cfg('merge.eyesonly.driver')) {
    fail('eyesonly filters or merge driver are not configured', 'eyesonly setup');
  } else {
    const base = (process_ || clean).replace(/ (filter-process|clean %f)$/, '');
    const r = viaGitShell(`${base} --version`, top);
    if (r.status === 0) ok(`filters run (${base === 'eyesonly' ? 'eyesonly from PATH' : 'absolute path'}${process_ ? ', long-running process' : ''})`);
    else fail(`the configured filter command doesn't run: ${base}`, 'eyesonly setup (rewrites the commands for this machine)');
    if (!process_) warn('the long-running filter process is off, so every protected file starts a new process', 'eyesonly setup');
  }
  const hookPath = path.resolve(top, gitStr(['rev-parse', '--git-path', 'hooks/pre-commit'], { cwd: top }));
  if (fs.existsSync(hookPath) && fs.readFileSync(hookPath, 'utf8').includes(HOOK_MARK)) ok('pre-commit hook installed');
  else fail('eyesonly pre-commit hook is missing', 'eyesonly setup');

  // pinned attributes and what git resolves
  if (policy) {
    const pinned = readPinnedBlock(gitDir());
    const missing = pinnedLines(policy).filter((l) => !pinned.includes(l));
    if (missing.length) fail(`pinned attributes missing or outdated (${missing.length} line(s), e.g. '${missing[0]}')`, 'eyesonly pull-policy');
    else ok('attributes pinned in info/attributes (filter=eyesonly, -text)');
    const files = protectedFiles(policy, top);
    for (const r of attrs.checkResolvedFilters(files, top)) fail(`'${r.path}' resolves to filter=${r.value}`, 'remove the overriding .gitattributes line, then eyesonly setup');
    let crlf = 0;
    let lockedButReadable = 0;
    for (const f of files) {
      const p = path.join(top, f);
      if (!fs.existsSync(p)) continue;
      const b = fs.readFileSync(p);
      if (vc.isCrlfEnvelope(b)) crlf++;
      else if (id && vc.isEnvelope(b) && fileRule(policy, f).includes(id.name)) {
        try {
          if (vc.parse(b).keys[id.name]) lockedButReadable++;
        } catch {}
      }
    }
    if (crlf) fail(`${crlf} protected file(s) have converted line endings`, 'eyesonly setup');
    if (lockedButReadable) fail(`${lockedButReadable} protected file(s) you can read are still encrypted in the working tree`, 'eyesonly setup');
    if (!crlf && !lockedButReadable) ok(`${files.length} protected file(s) in the expected state`);
  }

  console.log(problems ? `${problems} problem(s) found.` : 'no problems found.');
  process.exit(problems ? 1 : 0);
}

function readPinnedBlock(dir) {
  const p = path.join(dir, 'info', 'attributes');
  if (!fs.existsSync(p)) return [];
  const t = fs.readFileSync(p, 'utf8');
  const a = t.indexOf('# >>> eyesonly (managed) >>>');
  const b = t.indexOf('# <<< eyesonly (managed) <<<');
  if (a === -1 || b === -1) return [];
  return t
    .slice(a, b)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
}

// The demo is a bash script so it reads like the commands a user would type.
/** On Windows, plain `bash` may resolve to WSL's System32 bash.exe; prefer Git for Windows' bash. */
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
  eyesonly setup [--remote <r>]        enable eyesonly in an existing clone (remote default: origin)
  eyesonly pull-policy [--remote <r>]  refresh the cached access policy from the server
  eyesonly doctor              check this machine and clone, and say how to fix problems
  eyesonly policy-sign <file>  (admin) sign a policy manifest from eyesonly-server policy manifest
  eyesonly status              list protected files and whether you can read them
  eyesonly rekey               re-encrypt your readable files for the current policy
  eyesonly audit <user>        list secrets <user> could ever read (rotate them after offboarding)
  eyesonly run [--file <path>]... [--no-override] [--] <cmd> [args...]
                               run <cmd> with your protected .env files loaded into its environment
  eyesonly env [--file <path>]... [--format dotenv|json|shell]
                               print those variables (writes secrets to stdout)

identity: EYESONLY_IDENTITY (JSON or base64 of it), else $EYESONLY_HOME/identity.json

internal (wired up by setup): filter-process | clean %f | smudge %f | textconv <file> | pre-commit | merge-file`;

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
    run: (a) => import('./run.mjs').then((m) => m.cmdRun(a)),
    env: (a) => import('./run.mjs').then((m) => m.cmdEnv(a)),
    'filter-process': cmdFilterProcess,
    doctor: cmdDoctor,
    '__cli-path': () => console.log(realOrSelf(CLI)),
  };
  if (!table[cmd]) {
    console.error(USAGE);
    process.exit(cmd ? 1 : 0);
  }
  try {
    await table[cmd](rest);
  } catch (e) {
    // No stack traces for expected failures, and never echo credentials embedded in URLs.
    const detail = e.stderr?.toString().trim() || e.message;
    if (process.env.EYESONLY_DEBUG) console.error(redact(e.stack));
    throwOnDie = false;
    die(redact(detail));
  }
}
