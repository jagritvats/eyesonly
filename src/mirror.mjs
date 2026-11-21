// Outbound mirror: push verified public refs from a Veil repo to GitHub/GitLab/Gitea.
//
//   veil-server mirror set  <repo.git> --url U --push <ref|glob>... [--allow-force]
//                           [--delete-upstream on-private] [--credential-file F] [--allow-local]
//   veil-server mirror show <repo.git>
//   veil-server mirror push <repo.git> [--trust-current]
//
// Admin CLI only (never an HTTP route). Deny by default, fail closed:
//   * only refs that are on the allowlist AND public under the current policy are eligible;
//     refs/heads/private/* never is;
//   * eligible refs are fetched into a separate staging repo (<repo>.git/veil-mirror-stage.git)
//     through upload-pack, so the stage physically lacks private objects and the upstream
//     push can't use them as thin-pack delta bases;
//   * every commit about to go upstream is re-verified (no history from a narrower-audience
//     ref, every protected path a valid signed envelope) before anything is pushed;
//   * the push uses explicit per-ref refspecs, never --mirror/--all/--tags/+, from a
//     scrubbed environment; the credential travels in GIT_CONFIG_* env, never argv or URL.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import * as vc from './crypto.mjs';
import { expand, fileRule, refRule, isSubset } from './policy.mjs';

// Local copies of trivial server.mjs helpers (importing server.mjs would be a cycle).
const DATA = () => path.resolve(process.env.VEIL_DATA || 'veil-data');
const REPO_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.git$/;
const repoDir = (name) => path.join(DATA(), 'repos', name);
const loadPolicy = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'veil.json'), 'utf8'));
function loadUsers() {
  const f = path.join(DATA(), 'users.json');
  return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')).users : {};
}

const configFile = (dir) => path.join(dir, 'veil-mirror.json');
const logFile = (dir) => path.join(dir, 'veil-mirror.log');
const stageDir = (dir) => path.join(dir, 'veil-mirror-stage.git');
const lockFile = (dir) => path.join(dir, 'veil-mirror.lock');
const PRIVATE_PREFIX = 'refs/heads/private/';
const UPSTREAM = 'refs/upstream/'; // in the stage: refs/upstream/heads/main = last oid pushed for refs/heads/main

let scrubToken = null;
const scrub = (s) => (scrubToken ? String(s).split(scrubToken).join('***') : String(s));

class MirrorError extends Error {}
const fail = (msg) => {
  throw new MirrorError(msg);
};

// ------------------------------------------------------------------ git helpers

/** A git environment built from scratch: no system/global config, no prompts. */
function baseEnv() {
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME || '/nonexistent',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
    LC_ALL: 'C',
  };
  if (process.env.SSH_AUTH_SOCK) env.SSH_AUTH_SOCK = process.env.SSH_AUTH_SOCK; // ssh:// upstreams
  return env;
}

function run(dir, args, { env = baseEnv(), buffer = false } = {}) {
  const r = spawnSync('git', ['-C', dir, ...args], { env, maxBuffer: 1 << 30, encoding: buffer ? 'buffer' : 'utf8' });
  if (r.error) fail(`can't run git: ${r.error.message}`);
  return r;
}
function git(dir, args, opts) {
  const r = run(dir, args, opts);
  if (r.status !== 0) fail(`git ${args.find((a) => !a.startsWith('-')) || ''} failed: ${scrub(r.stderr).trim()}`);
  return opts?.buffer ? r.stdout : r.stdout.trim();
}
const lines = (s) => s.split('\n').filter(Boolean);

function refMap(dir, pattern = 'refs/') {
  const m = new Map();
  for (const l of lines(git(dir, ['for-each-ref', '--format=%(objectname) %(refname)', pattern]))) {
    const i = l.indexOf(' ');
    m.set(l.slice(i + 1), l.slice(0, i));
  }
  return m;
}

// ------------------------------------------------------------------ config

function checkUrl(url, allowLocal) {
  if (typeof url !== 'string' || !url) fail('mirror url is required (--url)');
  const t = url.match(/^([A-Za-z0-9][A-Za-z0-9+._-]*)::/);
  if (t) fail(`mirror url transport not allowed: ${t[1]}`);
  if (url.startsWith('-')) fail('mirror url must not start with "-"');
  if (/[\s\x00-\x1f\x7f]/.test(url)) fail('mirror url must not contain whitespace or control characters');
  if (/^http:\/\//i.test(url)) fail('mirror url must use https:// (http:// would send the credential in clear)');
  if (/^(https|ssh):\/\//i.test(url)) {
    let u;
    try {
      u = new URL(url);
    } catch {
      fail(`mirror url is not a valid URL: ${url}`);
    }
    if (u.password || (u.protocol === 'https:' && u.username)) fail('mirror url must not embed credentials; use --credential-file');
    if (!u.hostname || u.hostname.startsWith('-')) fail('mirror url has an invalid host');
    return;
  }
  if (/^file:\/\//i.test(url) || url.startsWith('/')) {
    if (!allowLocal) fail('local mirror urls (file:// or a path) are only allowed with --allow-local');
    return;
  }
  if (/^([A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*:(?!\/\/).+$/.test(url)) return; // scp-like git@host:path
  fail(`unsupported mirror url '${url}': use https://, ssh:// or git@host:path`);
}

function checkPushList(push) {
  if (!Array.isArray(push) || !push.length) fail('a push allowlist is required (--push refs/heads/main ...)');
  for (const e of push) {
    if (typeof e !== 'string') fail('push allowlist entries must be strings');
    const glob = e.endsWith('*');
    const prefix = glob ? e.slice(0, -1) : e;
    if (e === '*' || prefix === '' || prefix === 'refs' || prefix === 'refs/') fail(`push allowlist too broad: '${e}' (name branches or a namespace, e.g. refs/tags/v*)`);
    if (!e.startsWith('refs/')) fail(`push allowlist entry '${e}' must start with refs/`);
    if (prefix.includes('*')) fail(`push allowlist entry '${e}': '*' is only allowed as a trailing glob`);
    if (glob && !prefix.slice(5).includes('/')) fail(`push allowlist too broad: '${e}' (a glob must stay inside one namespace, e.g. refs/heads/release/*)`);
    if (/[\s~^:?[\\\x00-\x1f\x7f]|\.\.|\/\/|@\{/.test(e) || e.endsWith('/') || e.endsWith('.lock')) fail(`push allowlist entry '${e}' is not a valid ref name`);
  }
}

function checkCredentialFile(file, dir) {
  if (!path.isAbsolute(file)) fail('--credential-file must be an absolute path');
  let st;
  try {
    st = fs.lstatSync(file);
  } catch {
    fail(`credential file ${file} does not exist`);
  }
  if (!st.isFile()) fail(`credential file ${file} must be a regular file (not a symlink)`);
  if ((st.mode & 0o777) !== 0o600) fail(`credential file ${file} must have mode 0600 (it has ${(st.mode & 0o777).toString(8)}); run chmod 600 ${file}`);
  const real = fs.realpathSync(file);
  const rel = path.relative(fs.realpathSync(dir), real);
  if (!rel.startsWith('..') && !path.isAbsolute(rel)) fail(`credential file must live outside the repo directory ${dir}`);
}

function readCredential(file, dir) {
  checkCredentialFile(file, dir);
  const tok = fs.readFileSync(file, 'utf8').trim();
  if (!tok || /[\r\n\x00]/.test(tok)) fail(`credential file ${file} must contain exactly one token line`);
  return tok;
}

function validateConfig(cfg, dir) {
  if (!cfg || typeof cfg !== 'object') fail('mirror config is not an object');
  checkUrl(cfg.url, cfg.allowLocal === true);
  checkPushList(cfg.push);
  if (!['never', 'on-private'].includes(cfg.deleteUpstream)) fail("deleteUpstream must be 'never' or 'on-private'");
  if (typeof cfg.allowForce !== 'boolean') fail('allowForce must be true or false');
  if (cfg.credentialFile !== undefined) checkCredentialFile(cfg.credentialFile, dir);
  return cfg;
}

function loadConfig(dir) {
  if (!fs.existsSync(configFile(dir))) fail(`no mirror configured; run: veil-server mirror set ${path.basename(dir)} --url ... --push refs/heads/main`);
  let cfg;
  try {
    cfg = JSON.parse(fs.readFileSync(configFile(dir), 'utf8'));
  } catch (e) {
    fail(`can't read ${configFile(dir)}: ${e.message}`);
  }
  return validateConfig(cfg, dir);
}

function writePrivate(file, data) {
  const tmp = file + '.tmp';
  fs.rmSync(tmp, { force: true });
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
}

function repoArg(name) {
  const dir = repoDir(name || '');
  if (!REPO_RE.test(name || '') || !fs.existsSync(path.join(dir, 'veil.json'))) fail(`no such repo '${name || ''}'`);
  return dir;
}

function cmdSet(name, args) {
  const dir = repoArg(name);
  const cfg = { url: undefined, push: [], allowForce: false, deleteUpstream: 'never', allowLocal: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const val = () => (i + 1 < args.length ? args[++i] : fail(`${a} needs a value`));
    if (a === '--url') cfg.url = val();
    else if (a === '--push') while (i + 1 < args.length && !args[i + 1].startsWith('--')) cfg.push.push(args[++i]);
    else if (a === '--allow-force') cfg.allowForce = true;
    else if (a === '--allow-local') cfg.allowLocal = true;
    else if (a === '--delete-upstream') cfg.deleteUpstream = val();
    else if (a === '--credential-file') cfg.credentialFile = val();
    else fail(`unknown option '${a}'`);
  }
  validateConfig(cfg, dir);
  if (cfg.credentialFile) readCredential(cfg.credentialFile, dir);
  const old = fs.existsSync(configFile(dir)) ? JSON.parse(fs.readFileSync(configFile(dir), 'utf8')) : null;
  if (old && old.url !== cfg.url && fs.existsSync(stageDir(dir))) {
    fs.rmSync(stageDir(dir), { recursive: true, force: true }); // its upstream records belong to the old url
    console.error('[veil] mirror url changed: reset the staging repo');
  }
  writePrivate(configFile(dir), JSON.stringify(cfg, null, 2) + '\n');
  for (const e of cfg.push) if (e.startsWith(PRIVATE_PREFIX)) console.error(`[veil] note: ${e} is under ${PRIVATE_PREFIX} and will never be mirrored`);
  console.error(`[veil] mirror for ${name} -> ${cfg.url} saved. Protect the upstream branches (see README) and run: veil-server mirror push ${name}`);
}

function cmdShow(name) {
  const dir = repoArg(name);
  const cfg = loadConfig(dir);
  const view = { ...cfg }; // credentialFile is a path; its contents are never read here
  if (fs.existsSync(stageDir(dir))) {
    view.mirrored = Object.fromEntries([...refMap(stageDir(dir), UPSTREAM)].map(([r, oid]) => ['refs/' + r.slice(UPSTREAM.length), oid]));
  }
  console.log(JSON.stringify(view, null, 2));
}

// ------------------------------------------------------------------ verification

/**
 * Returns null if `blob` is a valid envelope for `path`, else the reason.
 * Must stay equal to server.mjs hookPreReceive validateBlob minus the pusher check
 * (and minus the stale-recipient check, see below). Deduping both into src/verify.mjs
 * is a deferred follow-up.
 *
 * Stale recipients (encrypted to a since-revoked user) are not rejected here: the hook
 * enforced them when the commit was pushed, the content is ciphertext either way, and
 * rejecting would make history from before a revocation unmirrorable.
 */
export function verifyEnvelope(blob, file, policy, users, all) {
  if (!vc.isEnvelope(blob)) return 'not encrypted: plaintext';
  let env;
  try {
    env = vc.parse(blob);
  } catch (e) {
    return e.message;
  }
  if (env.path !== file) return `encrypted for path '${env.path}'`;
  const allowed = expand(policy, fileRule(policy, file), all);
  const u = Object.hasOwn(users, env.signer) ? users[env.signer] : null;
  if (!u) return `signer '${env.signer}' is not a registered user`;
  if (!allowed.has(env.signer)) return `signer '${env.signer}' may not write this file`;
  if (!vc.verify(env, u.ed25519)) return `bad signature by '${env.signer}'`;
  return null;
}

/** commits new to the upstream for `tip`, as [{ commit, tree }] */
function newCommits(stage, tip, exclude) {
  const out = git(stage, ['rev-list', '--format=%T', tip, '--not', ...exclude]);
  const res = [];
  const ls = lines(out);
  for (let i = 0; i + 1 < ls.length; i += 2) res.push({ commit: ls[i].replace(/^commit /, ''), tree: ls[i + 1] });
  return res;
}

function verifyContent(stage, ref, commits, ctx, cache) {
  for (const { commit, tree } of commits) {
    let entries = cache.trees.get(tree);
    if (!entries) {
      entries = [];
      for (const e of git(stage, ['ls-tree', '-r', '-z', tree]).split('\0').filter(Boolean)) {
        const tab = e.indexOf('\t');
        const [mode, type, oid] = e.slice(0, tab).split(' ');
        const file = e.slice(tab + 1);
        if (fileRule(ctx.policy, file)) entries.push({ file, mode, type, oid });
      }
      cache.trees.set(tree, entries);
    }
    for (const { file, mode, type, oid } of entries) {
      const key = `${oid}\0${file}`;
      if (cache.blobs.has(key)) continue;
      let reason = null;
      if (type !== 'blob' || mode === '120000') reason = 'not a regular file';
      else reason = verifyEnvelope(git(stage, ['cat-file', 'blob', oid], { buffer: true }), file, ctx.policy, ctx.users, ctx.all);
      if (reason) fail(`refusing to mirror ${ref}: '${file}' in ${commit.slice(0, 8)} is NOT a valid veil envelope (${reason})`);
      cache.blobs.add(key);
    }
  }
}

// ------------------------------------------------------------------ push

function ensureStage(dir) {
  const stage = stageDir(dir);
  if (!fs.existsSync(path.join(stage, 'HEAD'))) {
    fs.rmSync(stage, { recursive: true, force: true });
    git(dir, ['init', '--quiet', '--bare', stage]);
    fs.chmodSync(stage, 0o700);
  }
  for (const [k, v] of [
    ['transfer.fsckObjects', 'true'],
    ['core.hooksPath', '/dev/null'],
    ['core.logAllRefUpdates', 'false'],
    ['gc.auto', '0'],
  ]) {
    git(stage, ['config', k, v]);
  }
  return stage;
}

function firstMirrored(dir, ref) {
  if (!fs.existsSync(logFile(dir))) return null;
  for (const l of lines(fs.readFileSync(logFile(dir), 'utf8'))) {
    try {
      const e = JSON.parse(l);
      if (e.ref === ref && e.new) return e.ts;
    } catch {}
  }
  return null;
}

function upstreamPush(stage, cfg, token, refspecs, leases) {
  const c = [
    'protocol.allow=never',
    'protocol.https.allow=always',
    'protocol.ssh.allow=always',
    ...(cfg.allowLocal ? ['protocol.file.allow=always'] : []),
    'core.hooksPath=/dev/null',
    'push.followTags=false',
    'transfer.fsckObjects=true',
    'http.followRedirects=false', // never replay the Authorization header to another host
    'credential.helper=',
  ].flatMap((kv) => ['-c', kv]);
  const env = baseEnv();
  if (token) Object.assign(env, { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'http.extraHeader', GIT_CONFIG_VALUE_0: `Authorization: Bearer ${token}` });
  const r = run(stage, [...c, 'push', '--porcelain', '--atomic', '--no-verify', ...leases, '--', cfg.url, ...refspecs], { env });
  if (r.status === 0) return;
  const rejected = lines(r.stdout).filter((l) => l.startsWith('!\t'));
  for (const l of rejected) {
    const [, spec, summary = ''] = l.split('\t');
    const ref = spec.slice(spec.indexOf(':') + 1);
    if (/non-fast-forward|fetch first/.test(summary)) fail(`upstream rejected ${ref} (non-fast-forward); not retrying with force`);
    if (/stale info/.test(summary)) fail(`upstream ${ref} changed since the last mirror (lease failed); not forcing`);
  }
  const detail = scrub(`${r.stderr}\n${rejected.join('\n')}`).trim().split('\n').slice(-6).join('\n');
  fail(`upstream push failed; nothing was mirrored:\n${detail}`);
}

function cmdPush(name, args) {
  const dir = repoArg(name);
  const trustCurrent = args.includes('--trust-current');
  for (const a of args) if (a !== '--trust-current') fail(`unknown option '${a}'`);
  const cfg = loadConfig(dir);
  const token = cfg.credentialFile ? readCredential(cfg.credentialFile, dir) : null;
  scrubToken = token;

  let fd;
  try {
    fd = fs.openSync(lockFile(dir), 'wx', 0o600);
  } catch {
    fail(`another mirror push is running (remove ${lockFile(dir)} if it is stale)`);
  }
  fs.closeSync(fd);
  try {
    return pushLocked(dir, cfg, token, trustCurrent);
  } finally {
    fs.rmSync(lockFile(dir), { force: true });
  }
}

function pushLocked(dir, cfg, token, trustCurrent) {
  // (a) one snapshot; (b) eligibility against the policy as it is right now
  const snapshot = refMap(dir);
  const policy = loadPolicy(dir);
  const users = loadUsers();
  const all = Object.keys(users);
  const members = expand(policy, policy.members, all);
  const isPublic = (ref) => {
    if (ref.startsWith(PRIVATE_PREFIX)) return false;
    const r = refRule(policy, ref);
    return !r || isSubset(members, expand(policy, r.who, all));
  };
  const allowed = (ref) => cfg.push.some((e) => (e.endsWith('*') ? ref.startsWith(e.slice(0, -1)) : ref === e));

  const eligible = [];
  const skipped = [];
  for (const ref of snapshot.keys()) {
    if (!allowed(ref)) continue;
    if (isPublic(ref)) eligible.push(ref);
    else {
      skipped.push(ref);
      console.error(`[veil] skipping ${ref}: not public`);
    }
  }

  const stage = ensureStage(dir);
  const upstream = new Map([...refMap(stage, UPSTREAM)].map(([r, oid]) => ['refs/' + r.slice(UPSTREAM.length), oid]));
  const retire = [...upstream.keys()].filter((r) => !snapshot.has(r) || !isPublic(r));

  try {
    mirrorRefs({ dir, cfg, token, trustCurrent, snapshot, policy, users, all, isPublic, eligible, stage, upstream, retire });
  } catch (e) {
    // Fail closed and leave nothing behind: stage refs go back to what the upstream has,
    // and objects fetched for this attempt (e.g. an injected plaintext) are pruned.
    resetStage(stage, eligible);
    throw e;
  }
  if (skipped.length) fail(`${skipped.length} allowlisted ref(s) skipped because they are not public; remove them from the allowlist (veil-server mirror set)`);
}

function resetStage(stage, refs) {
  try {
    const upstream = new Map([...refMap(stage, UPSTREAM)].map(([r, oid]) => ['refs/' + r.slice(UPSTREAM.length), oid]));
    for (const r of refs) {
      if (upstream.has(r)) run(stage, ['update-ref', r, upstream.get(r)]);
      else run(stage, ['update-ref', '-d', r]);
    }
    run(stage, ['gc', '--quiet', '--prune=now']);
  } catch {}
}

function mirrorRefs({ dir, cfg, token, trustCurrent, snapshot, policy, users, all, isPublic, eligible, stage, upstream, retire }) {
  // (c) fetch only eligible refs into the stage, through upload-pack (reachable objects only)
  if (eligible.length) {
    git(stage, ['-c', 'protocol.file.allow=always', 'fetch', '--quiet', '--no-tags', '--prune', '--no-write-fetch-head', `file://${dir}`, ...eligible.map((r) => `+${r}:${r}`)]);
    const staged = refMap(stage);
    for (const r of eligible) if (staged.get(r) !== snapshot.get(r)) fail(`ref ${r} moved during mirror; retry`);
  }

  // (d) verify everything that is new to the upstream
  const exclude = [...upstream.values()];
  const updates = eligible.filter((r) => upstream.get(r) !== snapshot.get(r));
  const perRef = updates.map((ref) => ({ ref, commits: newCommits(stage, snapshot.get(ref), exclude) }));

  //  (i) no commit may come from a narrower-audience ref. Base = what the upstream already
  //      has (or, for refs never mirrored / --trust-current, their current tip: history the
  //      hook accepted) plus the tips of public refs that are not being mirrored now.
  const narrower = [...snapshot].filter(([r]) => !isPublic(r)).map(([, oid]) => oid);
  if (narrower.length && perRef.some((p) => p.commits.length)) {
    const exists = (oid) => run(dir, ['cat-file', '-e', `${oid}^{commit}`]).status === 0;
    const base = new Set();
    for (const [r, oid] of snapshot) {
      if (!isPublic(r)) continue;
      if (!updates.includes(r) || trustCurrent || !upstream.has(r)) base.add(oid);
      else if (exists(upstream.get(r))) base.add(upstream.get(r));
    }
    const secret = new Set(lines(git(dir, ['rev-list', ...narrower, '--not', ...base])));
    for (const { commit } of perRef.flatMap((p) => p.commits)) {
      if (secret.has(commit)) {
        fail(
          `commit ${commit.slice(0, 8)} is reachable only from a narrower-audience ref; not mirroring. ` +
            'If it reached a public branch legitimately (e.g. a private branch forked from public commits pushed since the last mirror), check it and re-run with --trust-current.',
        );
      }
    }
  }
  //  (ii) every protected path in every new commit is a valid, authorized envelope
  const ctx = { policy, users, all };
  const cache = { trees: new Map(), blobs: new Set() };
  for (const { ref, commits } of perRef) verifyContent(stage, ref, commits, ctx, cache);

  // (e/f) push from the stage only, explicit refspecs, atomically
  const deletions = cfg.deleteUpstream === 'on-private' ? retire : [];
  const refspecs = [...updates.map((r) => `${r}:${r}`), ...deletions.map((r) => `:${r}`)];
  const leases = cfg.allowForce ? updates.map((r) => `--force-with-lease=${r}:${upstream.get(r) || ''}`) : [];
  if (refspecs.length) upstreamPush(stage, cfg, token, refspecs, leases);

  // (g) record what the upstream now has
  const ts = new Date().toISOString();
  const log = [];
  for (const r of updates) {
    git(stage, ['update-ref', UPSTREAM + r.slice(5), snapshot.get(r)]);
    log.push({ ts, ref: r, old: upstream.get(r) || null, new: snapshot.get(r) });
    console.error(`[veil] mirrored ${r} ${(upstream.get(r) || 'new').slice(0, 8)}..${snapshot.get(r).slice(0, 8)}`);
  }
  // (h) refs that were public upstream and are now private or gone
  for (const r of retire) {
    if (deletions.includes(r)) {
      log.push({ ts, ref: r, old: upstream.get(r), new: null });
      console.error(`[veil] deleted ${r} upstream`);
    }
    console.error(
      `[veil] ${r} was public upstream since ${firstMirrored(dir, r) || 'an earlier mirror'}; the upstream keeps refs/pull/* and cached objects, so treat its content as disclosed`,
    );
    git(stage, ['update-ref', '-d', UPSTREAM + r.slice(5)]);
    if (run(stage, ['rev-parse', '-q', '--verify', r]).status === 0) git(stage, ['update-ref', '-d', r]);
  }
  if (retire.length) {
    if (!deletions.length) console.error('[veil] the upstream copy was left in place (--delete-upstream on-private removes it)');
    git(stage, ['-c', 'gc.reflogExpire=now', '-c', 'gc.reflogExpireUnreachable=now', 'gc', '--quiet', '--prune=now']);
  }
  if (log.length) fs.appendFileSync(logFile(dir), log.map((e) => JSON.stringify(e) + '\n').join(''), { mode: 0o600 });
  if (!refspecs.length) console.error('[veil] upstream is up to date');
}

// ------------------------------------------------------------------ CLI

export function cmdMirror([sub, name, ...rest]) {
  try {
    if (sub === 'set') return cmdSet(name, rest);
    if (sub === 'show') return cmdShow(name);
    if (sub === 'push') return cmdPush(name, rest);
    fail('usage: veil-server mirror set <name.git> --url U --push <ref|glob>... | show <name.git> | push <name.git>');
  } catch (e) {
    if (!(e instanceof MirrorError)) throw e;
    console.error(`[veil] ${scrub(e.message)}`);
    process.exit(1);
  }
}
