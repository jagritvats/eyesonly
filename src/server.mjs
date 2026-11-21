import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import * as attest from './attest.mjs';
import * as attrs from './attrs.mjs';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as vc from './crypto.mjs';
import { expand, fileRule, refRule, isSubset } from './policy.mjs';
import { filterUploadPackBody, DEFAULT_MAX_BODY } from './negotiate.mjs';
import * as refguard from './refguard.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER_CLI = path.resolve(HERE, '..', 'bin', 'veil-server.mjs');
const SITE = path.resolve(HERE, '..', 'site');
const DATA = () => path.resolve(process.env.VEIL_DATA || 'veil-data');
const ZERO = '0'.repeat(40);
const REPO_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.git$/;

const die = (msg) => {
  console.error(`[veil-server] ${msg}`);
  process.exit(1);
};
const sha256 = (s) => crypto.createHash('sha256').update(s).digest();

// ------------------------------------------------------------------ storage

const usersFile = () => path.join(DATA(), 'users.json');
function loadUsers() {
  return fs.existsSync(usersFile()) ? JSON.parse(fs.readFileSync(usersFile(), 'utf8')).users : {};
}
function saveUsers(users) {
  fs.mkdirSync(DATA(), { recursive: true, mode: 0o700 });
  fs.writeFileSync(usersFile() + '.tmp', JSON.stringify({ users }, null, 2), { mode: 0o600 });
  fs.renameSync(usersFile() + '.tmp', usersFile());
}
const repoDir = (name) => path.join(DATA(), 'repos', name);
const policyFile = (dir) => path.join(dir, 'veil.json');
function loadPolicy(dir) {
  return JSON.parse(fs.readFileSync(policyFile(dir), 'utf8'));
}

function validatePolicy(p) {
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

// ------------------------------------------------------------------- admin

function newToken() {
  return 'veil_' + crypto.randomBytes(24).toString('base64url');
}

function cmdUser([sub, arg]) {
  const users = loadUsers();
  if (sub === 'add') {
    const card = vc.decodeCard(arg || '');
    if (users[card.name]) die(`user '${card.name}' exists`);
    const token = newToken();
    users[card.name] = { x25519: card.x25519, ed25519: card.ed25519, tokenHash: sha256(token).toString('hex'), created: new Date().toISOString() };
    saveUsers(users);
    console.error(`added ${card.name} (fingerprint ${vc.fingerprint(card)}). Token, shown once:`);
    console.log(token);
  } else if (sub === 'token') {
    if (!users[arg]) die(`no such user '${arg}'`);
    const token = newToken();
    users[arg].tokenHash = sha256(token).toString('hex');
    saveUsers(users);
    console.log(token);
  } else if (sub === 'remove') {
    if (!users[arg]) die(`no such user '${arg}'`);
    delete users[arg];
    saveUsers(users);
    console.error(`removed ${arg}. Run \`veil audit ${arg}\` in each repo and rotate what it lists.`);
  } else if (sub === 'list') {
    for (const [n, u] of Object.entries(users)) console.log(`${n}\t${vc.fingerprint({ x25519: u.x25519, ed25519: u.ed25519 })}`);
  } else die('usage: veil-server user add <veilpub1:...> | token <name> | remove <name> | list');
}

function installHook(dir) {
  const hook = path.join(dir, 'hooks', 'pre-receive');
  fs.writeFileSync(hook, `#!/bin/sh\nexec '${process.execPath}' '${SERVER_CLI}' hook pre-receive\n`, { mode: 0o755 });
}

function cmdRepo([sub, name, ...rest]) {
  if (sub === 'create') {
    if (!REPO_RE.test(name || '')) die('repo name must look like name.git');
    const admin = rest[rest.indexOf('--admin') + 1];
    if (!rest.includes('--admin') || !loadUsers()[admin]) die('usage: veil-server repo create <name.git> --admin <existing-user>');
    const dir = repoDir(name);
    if (fs.existsSync(dir)) die('repo exists');
    fs.mkdirSync(path.dirname(dir), { recursive: true });
    execFileSync('git', ['init', '--quiet', '--bare', '-b', 'main', dir]);
    execFileSync('git', ['config', '-f', path.join(dir, 'config'), 'http.getanyfile', 'false']);
    installHook(dir);
    const policy = { members: ['*'], admins: [admin], groups: {}, files: {}, branches: {} };
    fs.writeFileSync(policyFile(dir), JSON.stringify(policy, null, 2));
    console.error(`created ${dir}`);
  } else if (sub === 'list') {
    const root = path.join(DATA(), 'repos');
    if (fs.existsSync(root)) fs.readdirSync(root).forEach((r) => console.log(r));
  } else die('usage: veil-server repo create <name.git> --admin <user> | list');
}

function cmdPolicy([sub, name, file]) {
  const dir = repoDir(name || '');
  if (!REPO_RE.test(name || '') || !fs.existsSync(dir)) die('no such repo');
  if (sub === 'show') return console.log(fs.readFileSync(policyFile(dir), 'utf8'));
  if (sub === 'set') {
    const raw = fs.readFileSync(file === '-' || !file ? 0 : file, 'utf8');
    let p;
    try {
      p = validatePolicy(JSON.parse(raw));
    } catch (e) {
      die(`invalid policy: ${e.message}`);
    }
    fs.writeFileSync(policyFile(dir) + '.tmp', JSON.stringify(p, null, 2));
    fs.renameSync(policyFile(dir) + '.tmp', policyFile(dir));
    return console.error('policy updated. Members should run `veil pull-policy && veil rekey`.');
  }
  if (sub === 'manifest') {
    const installed = loadAttestation(dir);
    const version = (installed?.manifest.version || 0) + 1;
    return console.log(attest.canonical(attest.buildManifest({ repo: name, policy: loadPolicy(dir), users: loadUsers(), version })));
  }
  if (sub === 'attest') {
    let att;
    try {
      att = JSON.parse(fs.readFileSync(file === '-' || !file ? 0 : file, 'utf8'));
    } catch (e) {
      die(`can't read signed manifest: ${e.message}`);
    }
    const policy = loadPolicy(dir);
    const users = loadUsers();
    if (!att?.manifest || typeof att.signer !== 'string') die('not a signed manifest (expected the output of `veil policy-sign`)');
    if (!expand(policy, policy.admins || [], Object.keys(users)).has(att.signer)) die(`'${att.signer}' is not an admin of ${name}`);
    const u = Object.hasOwn(users, att.signer) ? users[att.signer] : null;
    if (!u || att.signer_ed25519 !== u.ed25519 || !attest.verifyAttestation(att)) {
      die(`bad signature: not a valid signature by ${att.signer}'s registered key`);
    }
    const installed = loadAttestation(dir);
    const current = attest.buildManifest({ repo: name, policy, users, version: 0 });
    if (attest.manifestContent(att.manifest) !== attest.manifestContent(current)) {
      die(`signed manifest does not match current policy. Re-run: veil-server policy manifest ${name}`);
    }
    const v = att.manifest.version;
    if (att.manifest.v !== 1 || !Number.isInteger(v) || v < 1 || (installed && v <= installed.manifest.version)) {
      die(`version must increase (installed: ${installed?.manifest.version ?? 'none'}, signed: ${v}). Re-run: veil-server policy manifest ${name}`);
    }
    fs.writeFileSync(attestationFile(dir) + '.tmp', JSON.stringify(att, null, 2));
    fs.renameSync(attestationFile(dir) + '.tmp', attestationFile(dir));
    return console.error(`installed policy v${v} signed by ${att.signer}. Members pick it up with \`veil pull-policy\`.`);
  }
  die('usage: veil-server policy show|set <name.git> [file|-] | manifest <name.git> | attest <name.git> <signed.json>');
}

const attestationFile = (dir) => path.join(dir, 'veil-attestation.json');
function loadAttestation(dir) {
  return fs.existsSync(attestationFile(dir)) ? JSON.parse(fs.readFileSync(attestationFile(dir), 'utf8')) : null;
}

// ------------------------------------------------------------- HTTP proxy

function authenticate(req, users) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Basic ')) return null;
  const raw = Buffer.from(h.slice(6), 'base64').toString('utf8');
  const i = raw.indexOf(':');
  if (i < 1) return null;
  const name = raw.slice(0, i);
  const u = Object.hasOwn(users, name) ? users[name] : null;
  // Always hash and compare so unknown users and wrong tokens take the same path.
  const want = u ? Buffer.from(u.tokenHash, 'hex') : crypto.randomBytes(32);
  const ok = crypto.timingSafeEqual(sha256(raw.slice(i + 1)), want);
  return ok && u ? name : null;
}

function clientPolicy(repo, policy, users, user) {
  const all = Object.keys(users);
  const files = {};
  const keys = {};
  for (const [glob, who] of Object.entries(policy.files || {})) {
    files[glob] = [...expand(policy, who, all)].filter((u) => users[u]).sort();
    for (const u of files[glob]) keys[u] = { x25519: users[u].x25519, ed25519: users[u].ed25519 };
  }
  // Deliberately omits branch rules: their names would reveal private branches.
  return { repo, user, files, keys };
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', ...headers });
  res.end(body);
}

const GIT_ROUTES = [
  { method: 'GET', re: /^\/info\/refs$/, service: (q) => q.get('service') },
  { method: 'POST', re: /^\/git-upload-pack$/, service: () => 'git-upload-pack' },
  { method: 'POST', re: /^\/git-receive-pack$/, service: () => 'git-receive-pack' },
];

function handle(req, res, opts) {
  const url = new URL(req.url, 'http://veil.local');
  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
    const f = path.join(SITE, 'index.html');
    if (fs.existsSync(f)) return send(res, 200, fs.readFileSync(f), { 'content-type': 'text/html; charset=utf-8' });
  }
  if (url.pathname === '/healthz') return send(res, 200, 'ok\n');

  const m = url.pathname.match(/^\/([^/]+)(\/.*)$/);
  if (!m || !REPO_RE.test(m[1])) return send(res, 404, 'not found\n');
  const [, repo, rest] = m;
  const dir = repoDir(repo);

  const users = loadUsers();
  const user = authenticate(req, users);
  if (!user) return send(res, 401, 'authentication required\n', { 'www-authenticate': 'Basic realm="veil"' });
  // Same 404 for "doesn't exist" and "not a member" so repo names don't leak.
  if (!fs.existsSync(policyFile(dir))) return send(res, 404, 'not found\n');
  const policy = loadPolicy(dir);
  const all = Object.keys(users);
  if (!expand(policy, policy.members, all).has(user)) return send(res, 404, 'not found\n');

  if (req.method === 'GET' && rest === '/veil/policy') {
    const view = clientPolicy(repo, policy, users, user);
    const attestation = loadAttestation(dir);
    if (attestation) {
      const current = attest.buildManifest({ repo, policy, users, version: 0 });
      Object.assign(view, { attestation, attestation_stale: attest.manifestContent(current) !== attest.manifestContent(attestation.manifest || {}) });
    }
    return send(res, 200, JSON.stringify(view), { 'content-type': 'application/json' });
  }

  // Only the smart protocol is served. Dumb HTTP (GET /objects/..., /HEAD, ...) would
  // hand out any object by path and bypass ref hiding entirely.
  const route = GIT_ROUTES.find((r) => r.method === req.method && r.re.test(rest));
  const service = route?.service(url.searchParams);
  if (!route || !['git-upload-pack', 'git-receive-pack'].includes(service)) return send(res, 404, 'not found\n');
  // Early, friendly refusal for read-only members; the pre-receive hook is the real boundary.
  if (service === 'git-receive-pack' && !refguard.canWrite(policy, user, all)) return send(res, 403, '[veil] read-only access\n');

  const hidden = Object.entries(policy.branches || {})
    .filter(([, who]) => !expand(policy, who, all).has(user))
    .map(([prefix]) => prefix.replace(/\/$/, ''));

  const cfg = [
    ['http.receivepack', 'true'],
    ['http.uploadpack', 'true'],
    ['http.getanyfile', 'false'],
    ['uploadpack.allowAnySHA1InWant', 'false'],
    ['uploadpack.allowTipSHA1InWant', 'false'],
    ['uploadpack.allowReachableSHA1InWant', 'false'],
    ['uploadpack.allowFilter', 'false'],
    ['uploadpack.allowRefInWant', 'false'],
    ...hidden.map((h) => ['transfer.hideRefs', h]),
  ];
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    VEIL_DATA: DATA(),
    VEIL_USER: user,
    GIT_PROJECT_ROOT: path.join(DATA(), 'repos'),
    GIT_HTTP_EXPORT_ALL: '1',
    REMOTE_USER: user,
    REQUEST_METHOD: req.method,
    PATH_INFO: `/${repo}${rest}`,
    QUERY_STRING: url.search.slice(1),
    CONTENT_TYPE: req.headers['content-type'] || '',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_COUNT: String(cfg.length),
  };
  cfg.forEach(([k, v], i) => {
    env[`GIT_CONFIG_KEY_${i}`] = k;
    env[`GIT_CONFIG_VALUE_${i}`] = v;
  });
  if (req.headers['content-length']) env.CONTENT_LENGTH = req.headers['content-length'];
  if (req.headers['content-encoding']) env.HTTP_CONTENT_ENCODING = req.headers['content-encoding'];
  // Protocol v2 lets a client `want` any object the server has, ignoring hideRefs
  // reachability rules. Forcing v0 keeps want-validation against advertised refs.
  if (opts.allowV2 && req.headers['git-protocol']) env.GIT_PROTOCOL = req.headers['git-protocol'];

  if (service !== 'git-upload-pack' || req.method !== 'POST') return runBackend(env, res, user, repo, req);

  // Upload-pack: buffer the request and drop have/shallow lines for objects this user
  // can't see, so ACKs don't reveal whether the server holds a private commit.
  const max = Number(process.env.VEIL_MAX_UPLOAD_PACK_BODY) || DEFAULT_MAX_BODY;
  const tooBig = () => {
    send(res, 413, `[veil] upload-pack request is larger than ${max} bytes\n`, { connection: 'close' });
    req.resume(); // discard the rest; never reaches http-backend
  };
  if (Number(req.headers['content-length']) > max) return tooBig();
  const chunks = [];
  let total = 0;
  let failed = false;
  req.on('data', (c) => {
    if (failed) return;
    total += c.length;
    if (total > max) {
      failed = true;
      chunks.length = 0;
      return tooBig();
    }
    chunks.push(c);
  });
  req.on('end', () => {
    if (failed) return;
    filterUploadPackBody({ body: Buffer.concat(chunks), contentEncoding: req.headers['content-encoding'], gitDir: dir, hiddenPrefixes: hidden, maxBytes: max })
      .then((buf) => {
        env.CONTENT_LENGTH = String(buf.length);
        delete env.HTTP_CONTENT_ENCODING;
        runBackend(env, res, user, repo, buf);
      })
      .catch((e) => {
        if (!e.status) console.error(`[veil-server] upload-pack filter failed for ${user}@${repo}:`, e);
        if (!res.headersSent) send(res, e.status || 500, e.status ? `${e.message}\n` : 'internal error\n');
      });
  });

  // input: the request stream (piped through) or an already-filtered Buffer.
  function runBackend(env, res, user, repo, input) {
    const child = spawn('git', ['http-backend'], { env });
    child.stdin.on('error', () => {}); // EPIPE if the backend exits before reading everything
    if (Buffer.isBuffer(input)) child.stdin.end(input);
    else input.pipe(child.stdin);
    let head = Buffer.alloc(0);
    let started = false;
    child.stdout.on('data', (chunk) => {
      if (started) return res.write(chunk);
      head = Buffer.concat([head, chunk]);
      const sep = head.indexOf('\r\n\r\n');
      if (sep === -1) return;
      started = true;
      let status = 200;
      const headers = {};
      for (const line of head.subarray(0, sep).toString('utf8').split('\r\n')) {
        const i = line.indexOf(':');
        if (i < 0) continue;
        const k = line.slice(0, i).trim();
        const v = line.slice(i + 1).trim();
        if (k.toLowerCase() === 'status') status = parseInt(v, 10);
        else headers[k] = v;
      }
      res.writeHead(status, headers);
      const rest2 = head.subarray(sep + 4);
      if (rest2.length) res.write(rest2);
    });
    child.stderr.on('data', (d) => process.stderr.write(`[git ${user}@${repo}] ${d}`));
    child.on('close', () => {
      if (!started) send(res, 500, 'backend error\n');
      else res.end();
    });
    if (Buffer.isBuffer(input)) res.on('close', () => child.exitCode === null && child.kill());
    else input.on('aborted', () => child.kill());
  }
}

function cmdServe(args) {
  const port = Number(args[args.indexOf('--port') + 1] || process.env.PORT || 8787);
  const host = args.includes('--host') ? args[args.indexOf('--host') + 1] : '127.0.0.1';
  const opts = { allowV2: process.env.VEIL_ALLOW_PROTOCOL_V2 === '1' };
  const server = http.createServer((req, res) => {
    try {
      handle(req, res, opts);
    } catch (e) {
      console.error(e);
      if (!res.headersSent) send(res, 500, 'internal error\n');
    }
  });
  server.listen(port, host, () => console.error(`[veil-server] listening on http://${host}:${port} (data: ${DATA()})`));
}

// ----------------------------------------------------------- pre-receive

function hookPreReceive() {
  const reject = (msg) => {
    console.error(`\n[veil] REJECTED: ${msg}\n`);
    process.exit(1);
  };
  const g = (args) => execFileSync('git', args, { encoding: 'utf8', maxBuffer: 1 << 30 }).trim();
  const gBuf = (args) => execFileSync('git', args, { maxBuffer: 1 << 30 });
  const lines = (s) => s.split('\n').filter(Boolean);

  const user = process.env.VEIL_USER;
  const users = loadUsers();
  if (!user || !users[user]) reject('push did not come through the veil server (no authenticated user)');
  const policy = loadPolicy(process.cwd());
  const all = Object.keys(users);
  const members = expand(policy, policy.members, all);
  if (!members.has(user)) reject(`'${user}' is not a member of this repository`);

  const audience = (ref) => {
    const r = refRule(policy, ref);
    return r ? expand(policy, r.who, all) : members;
  };
  const refs = lines(g(['for-each-ref', '--format=%(objectname) %(refname)'])).map((l) => {
    const [oid, ref] = l.split(' ');
    return { oid, ref, aud: audience(ref) };
  });

  // --- tree checks, cached across commits
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
  const validated = new Set();
  const validateBlob = (commit, file, entry, allowed) => {
    const key = `${entry.oid}\0${file}`;
    if (validated.has(key)) return;
    const at = `'${file}' in ${commit.slice(0, 8)}`;
    if (entry.type !== 'blob' || entry.mode === '120000') reject(`${at} must be a regular encrypted file`);
    const blob = gBuf(['cat-file', 'blob', entry.oid]);
    if (!vc.isEnvelope(blob)) reject(`${at} is NOT encrypted. Refusing to store a plaintext secret. Run \`veil setup\` and recommit.`);
    let env;
    try {
      env = vc.parse(blob);
    } catch (e) {
      reject(`${at}: ${e.message}`);
    }
    if (env.path !== file) reject(`${at} is encrypted for path '${env.path}'. Run \`veil rekey\` after renaming protected files.`);
    if (!allowed.has(env.signer) || !users[env.signer] || !vc.verify(env, users[env.signer].ed25519)) {
      reject(`${at} has an invalid signature or its signer '${env.signer}' may not write it`);
    }
    const recips = new Set(Object.keys(env.keys));
    if (!isSubset(recips, allowed)) {
      reject(`${at} is encrypted to users outside the policy: ${[...recips].filter((r) => !allowed.has(r)).join(', ')}. Run \`veil pull-policy && veil rekey\`.`);
    }
    const missing = [...allowed].filter((u) => !recips.has(u));
    if (missing.length) console.error(`[veil] note: ${at} is not readable by ${missing.join(', ')} yet (veil rekey)`);
    validated.add(key);
  };
  const checkCommit = (commit) => {
    const parents = g(['rev-list', '--parents', '-n1', commit]).split(' ').slice(1);
    attrs.checkCommitAttributes({ commit, parents, policy, git: g, reject, isAdmin: expand(policy, policy.admins || [], all).has(user) });
    const mine = protectedEntries(commit);
    const theirs = parents.map(protectedEntries);
    for (const [file, entry] of mine) {
      if (theirs.length && theirs.some((t) => t.get(file)?.oid === entry.oid)) continue; // unchanged from a parent
      const allowed = expand(policy, fileRule(policy, file), all);
      if (!allowed.has(user)) reject(`'${user}' may not modify protected file '${file}' (${commit.slice(0, 8)})`);
      validateBlob(commit, file, entry, allowed);
    }
    for (const t of theirs) {
      for (const file of t.keys()) {
        if (mine.has(file)) continue;
        const allowed = expand(policy, fileRule(policy, file), all);
        if (!allowed.has(user)) reject(`'${user}' may not delete protected file '${file}' (${commit.slice(0, 8)})`);
      }
    }
  };

  const isAdmin = expand(policy, policy.admins || [], all).has(user);
  // Objects received in this push live in the quarantine dir until the hook accepts them.
  // Anything else this push references was already on the server.
  const notInQuarantine = (oids) => {
    if (!oids.length) return [];
    const q = process.env.GIT_QUARANTINE_PATH;
    if (!q) return oids; // no pack was sent at all
    const out = execFileSync('git', ['cat-file', '--batch-check=%(objectname)'], {
      input: oids.join('\n') + '\n',
      encoding: 'utf8',
      maxBuffer: 1 << 30,
      env: { ...process.env, GIT_OBJECT_DIRECTORY: q, GIT_ALTERNATE_OBJECT_DIRECTORIES: '' },
    });
    const present = new Set(lines(out).filter((l) => !l.endsWith(' missing')));
    return oids.filter((o) => !present.has(o));
  };

  let headRef = null;
  try {
    headRef = g(['symbolic-ref', '-q', 'HEAD']) || null;
  } catch {}
  for (const line of lines(fs.readFileSync(0, 'utf8'))) {
    const [oldOid, newOid, ref] = line.split(' ');
    const rule = refRule(policy, ref);
    if (rule && !expand(policy, rule.who, all).has(user)) reject(`'${user}' may not push to '${ref}'`);
    const update = { policy, all, user, oldOid, newOid, ref, headRef, git: g, reject, validate: validateBlob };
    refguard.checkRefRules(update);
    if (newOid === ZERO) continue;

    // 1. Visibility: commits newly reachable from `ref` must not come from a branch
    //    whose audience is narrower than ref's audience (e.g. private -> main merge).
    const target = audience(ref);
    const ok = refs.filter((r) => isSubset(target, r.aud)).map((r) => r.oid);
    const narrower = refs.filter((r) => !isSubset(target, r.aud)).map((r) => r.oid);
    if (narrower.length) {
      const fresh = lines(g(['rev-list', newOid, '--not', ...(oldOid !== ZERO ? [oldOid] : []), ...ok]));
      if (fresh.length) {
        const secret = new Set(lines(g(['rev-list', ...narrower, '--not', ...ok])));
        const hit = fresh.find((c) => secret.has(c));
        if (hit) reject(`pushing '${ref}' would expose commit ${hit.slice(0, 8)} from a branch with a narrower audience. Use \`git merge --squash\`.`);
      }
    }

    // 1b. Object allowlist. The check above only knows about refs that exist right now
    //     and only walks commits. Objects from a deleted private branch, or a tree/blob
    //     named directly by a tag or tree entry, are still in the object store. So every
    //     object this update makes newly visible must either have been sent in this push
    //     (the pusher already had it) or already be visible to ref's audience. Admins may
    //     resurrect orphaned objects (e.g. to restore a deleted branch).
    if (!isAdmin) {
      const peeled = g(['cat-file', '-t', `${newOid}^{}`]);
      if (peeled !== 'commit') reject(`'${ref}' must point at a commit, not a ${peeled}`);
      const newly = lines(g(['rev-list', '--objects', newOid, '--not', ...(oldOid !== ZERO ? [oldOid] : []), ...ok])).map((l) => l.split(' ')[0]);
      let stale = notInQuarantine(newly);
      // `rev-list --objects X --not Y` only excludes objects at Y's boundary, not every
      // object in Y's history, so a revert to an old blob shows up here even though the
      // audience can already see it. Settle the remaining candidates with a full walk.
      const visibleTips = [...(oldOid !== ZERO ? [oldOid] : []), ...ok];
      if (stale.length && visibleTips.length) {
        const visible = new Set(lines(g(['rev-list', '--objects', '--no-object-names', ...visibleTips])));
        stale = stale.filter((o) => !visible.has(o));
      }
      if (stale.length) {
        reject(`pushing '${ref}' would expose ${stale.length} existing object(s) its audience can't see (e.g. ${stale[0].slice(0, 8)}), such as history from a private or deleted branch. Push the content itself, or ask an admin.`);
      }
    }

    // 2. Content: every commit new to the server is checked against file rules.
    for (const commit of lines(g(['rev-list', newOid, '--not', '--all']))) checkCommit(commit);

    // 3. Ref update: the resulting tree is valid now, even if its commits already existed
    //    (a force-push or fast-forward to an old commit still encrypted to a revoked user).
    refguard.checkRefContent(update);
  }
}

// ------------------------------------------------------------------- main

const USAGE = `veil-server: auth proxy + policy enforcement for veil repos   (data dir: $VEIL_DATA, default ./veil-data)

  veil-server user add <veilpub1:...>          register a user, prints their access token
  veil-server user token <name>                rotate a user's token
  veil-server user remove <name>               offboard a user
  veil-server user list
  veil-server repo create <name.git> --admin <user>
  veil-server repo list
  veil-server policy show <name.git>
  veil-server policy set <name.git> <file|->   replace the policy (validated)
  veil-server policy manifest <name.git>       print the policy manifest for an admin to sign
  veil-server policy attest <name.git> <signed.json>   install an admin-signed manifest
  veil-server mirror set <name.git> --url U --push <ref|glob>... [--allow-force] [--delete-upstream on-private] [--credential-file F] [--allow-local]
  veil-server mirror show <name.git>           print the mirror config (credential path only)
  veil-server mirror push <name.git>           push verified public refs to the upstream (fails closed)
  veil-server serve [--port 8787] [--host 127.0.0.1]`;

export async function main([cmd, ...rest]) {
  if (cmd === 'user') return cmdUser(rest);
  if (cmd === 'repo') return cmdRepo(rest);
  if (cmd === 'policy') return cmdPolicy(rest);
  if (cmd === 'serve') return cmdServe(rest);
  if (cmd === 'mirror') return (await import('./mirror.mjs')).cmdMirror(rest);
  if (cmd === 'hook' && rest[0] === 'pre-receive') return hookPreReceive();
  console.error(USAGE);
  process.exit(cmd ? 1 : 0);
}
