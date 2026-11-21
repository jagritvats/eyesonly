import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import * as attest from './attest.mjs';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as vc from './crypto.mjs';
import { expand, refRule, isSubset } from './policy.mjs';
import { filterUploadPackBody, DEFAULT_MAX_BODY } from './negotiate.mjs';
import * as refguard from './refguard.mjs';
import { contentChecker } from './validate.mjs';
import * as store from './store.mjs';
import { OpError, DATA, REPO_RE, sha256, loadUsers, repoDir, policyFile, loadPolicy, loadAttestation, validatePolicy } from './store.mjs';
import { audit, cmdAuditLog } from './audit.mjs';
import { ADMIN_PREFIX, AuthLimiter, clientIp, handleAdmin, cmdAdminToken, cmdServerAdmin } from './admin.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SITE = path.resolve(HERE, '..', 'site');
const ZERO = '0'.repeat(40);

const die = (msg) => {
  console.error(`[eyesonly-server] ${msg}`);
  process.exit(1);
};
/** Run a store operation; report its OpError the CLI way. */
const op = (fn) => {
  try {
    return fn();
  } catch (e) {
    if (e instanceof OpError) die(e.message);
    throw e;
  }
};
const cliLog = (fields) => audit('admin', { actor: 'local-cli', via: 'cli', ...fields });

// ------------------------------------------------------------------- admin

function cmdUser([sub, arg]) {
  const users = loadUsers();
  if (sub === 'add') {
    const card = op(() => store.parseCard(arg));
    const token = op(() => store.addUser(users, card));
    cliLog({ action: 'user add', target: card.name });
    console.error(`added ${card.name} (fingerprint ${vc.fingerprint(card)}). Token, shown once:`);
    console.log(token);
  } else if (sub === 'set-key') {
    const card = op(() => store.parseCard(arg));
    const fp = op(() => store.setUserKey(users, card));
    cliLog({ action: 'user set-key', target: card.name, old_fingerprint: fp.old, new_fingerprint: fp.new });
    console.error(`replaced ${card.name}'s key: ${fp.old} -> ${fp.new} (token unchanged). Next:`);
    for (const l of store.keyChangeAdvice(card.name, users)) console.error(`  - ${l}`);
  } else if (sub === 'token') {
    const token = op(() => store.rotateUserToken(users, arg));
    cliLog({ action: 'user token', target: arg });
    console.log(token);
  } else if (sub === 'remove') {
    op(() => store.removeUser(users, arg));
    cliLog({ action: 'user remove', target: arg });
    console.error(`removed ${arg}. Run \`eyesonly audit ${arg}\` in each repo and rotate what it lists.`);
  } else if (sub === 'list') {
    for (const [n, u] of Object.entries(users)) console.log(`${n}\t${store.userFingerprint(u)}`);
  } else die('usage: eyesonly-server user add <eyesonlypub1:...> | set-key <eyesonlypub1:...> | token <name> | remove <name> | list');
}

function cmdRepo([sub, name, ...rest]) {
  if (sub === 'create') {
    if (!REPO_RE.test(name || '')) die('repo name must look like name.git');
    const admin = rest[rest.indexOf('--admin') + 1];
    if (!rest.includes('--admin') || !loadUsers()[admin]) die('usage: eyesonly-server repo create <name.git> --admin <existing-user>');
    const dir = op(() => store.createRepo(name, store.starterPolicy(admin)));
    cliLog({ action: 'repo create', target: name, repo: name, admin });
    console.error(`created ${dir}`);
  } else if (sub === 'list') {
    store.listRepos().forEach((r) => console.log(r));
  } else die('usage: eyesonly-server repo create <name.git> --admin <user> | list');
}

function cmdPolicy([sub, name, file]) {
  const dir = op(() => store.existingRepo(name));
  if (sub === 'show') return console.log(fs.readFileSync(policyFile(dir), 'utf8'));
  if (sub === 'set') {
    let p;
    try {
      p = JSON.parse(fs.readFileSync(file === '-' || !file ? 0 : file, 'utf8'));
    } catch (e) {
      die(`invalid policy: ${e.message}`);
    }
    const h = op(() => store.savePolicy(dir, p));
    cliLog({ action: 'policy set', repo: name, before: h.before, after: h.after });
    return console.error('policy updated. Members should run `eyesonly pull-policy && eyesonly rekey`.');
  }
  if (sub === 'manifest') return console.log(attest.canonical(store.nextManifest(name, dir)));
  if (sub === 'attest') {
    let att;
    try {
      att = JSON.parse(fs.readFileSync(file === '-' || !file ? 0 : file, 'utf8'));
    } catch (e) {
      die(`can't read signed manifest: ${e.message}`);
    }
    const v = op(() => store.installAttestation(name, dir, att));
    audit('attestation', { actor: 'local-cli', repo: name, version: v, signer: att.signer, via: 'cli' });
    return console.error(`installed policy v${v} signed by ${att.signer}. Members pick it up with \`eyesonly pull-policy\`.`);
  }
  die('usage: eyesonly-server policy show|set <name.git> [file|-] | manifest <name.git> | attest <name.git> <signed.json>');
}

const INIT_USAGE =
  'usage: eyesonly-server init --admin <eyesonlypub1:...> --repo <name.git> [--files .env,secrets/**] [--private-prefix refs/heads/private/] [--url https://git.example.com]';

/** One-command bootstrap: data dir, admin user, first repo and a starter policy. */
function cmdInit(args) {
  const opt = (k) => (args.includes(k) ? args[args.indexOf(k) + 1] : undefined);
  const cardArg = opt('--admin');
  const name = opt('--repo');
  if (!cardArg || !name) die(INIT_USAGE);
  const card = op(() => store.parseCard(cardArg, '--admin card'));
  if (!REPO_RE.test(name)) die('--repo must look like name.git');
  const files = (opt('--files') ?? '.env,secrets/**').split(',').map((s) => s.trim()).filter(Boolean);
  const prefix = opt('--private-prefix') ?? 'refs/heads/private/';
  let base;
  try {
    base = new URL(opt('--url') ?? 'http://127.0.0.1:8787');
    if (!/^https?:$/.test(base.protocol)) throw new Error('must be http(s)');
  } catch (e) {
    die(`invalid --url: ${e.message}`);
  }

  // Check everything before writing anything: init never clobbers an existing user or repo.
  const users = loadUsers();
  if (Object.hasOwn(users, card.name)) die(`user '${card.name}' already exists. init only bootstraps; use \`repo create\` and \`policy set\` on an existing server.`);
  if (fs.existsSync(repoDir(name))) die(`repo ${name} already exists. init only bootstraps; use \`policy set\` to change it.`);
  let policy;
  try {
    policy = validatePolicy({
      members: ['*'],
      admins: [card.name],
      groups: { core: [card.name] },
      files: Object.fromEntries(files.map((f) => [f, ['@core']])),
      branches: prefix ? { [prefix]: ['@core'] } : {},
    });
  } catch (e) {
    die(`invalid starter policy: ${e.message}`);
  }

  fs.mkdirSync(DATA(), { recursive: true, mode: 0o700 });
  const token = op(() => store.addUser(users, card));
  op(() => store.createRepo(name, policy));
  const cfg = store.loadServerConfig();
  if (!cfg.server_admins.includes(card.name)) cfg.server_admins.push(card.name);
  store.saveServerConfig(cfg);
  cliLog({ action: 'init', target: card.name, repo: name });

  const host = base.host;
  const repoUrl = (u) => `${base.protocol}//${card.name}:${u}@${host}${base.pathname.replace(/\/+$/, '')}/${name}`;
  const e = (s) => console.error(s);
  e(`initialized ${DATA()}`);
  e(`  admin   ${card.name} (fingerprint ${vc.fingerprint(card)}), server admin`);
  e(`  repo    ${name}`);
  e(`  secrets ${files.length ? files.join(', ') : '(none)'} readable by @core (${card.name})`);
  if (prefix) e(`  private ${prefix}* visible to @core only`);
  e(`Token for ${card.name}, shown once:`);
  console.log(token);
  e(`
Next:
  1. Run the server (behind TLS in production; see docs/server-deployment.md):
       eyesonly-server serve --port 8787
  2. On your machine, either clone the new repo:
       eyesonly clone ${repoUrl('<token>')}
     or push an existing repo into it:
       git remote rename origin github
       git remote add origin ${repoUrl('<token>')}
       git push -u origin --all && eyesonly setup
  3. Add a teammate: they run \`eyesonly keygen <name>\` and send you the card, then
       eyesonly-server user add <their card>         (prints their token)
     and, to let them read the secrets, add them to "core":
       eyesonly-server policy show ${name} > policy.json   # edit groups.core
       eyesonly-server policy set ${name} policy.json
  4. Or manage the server from your laptop over HTTPS (docs/admin-api.md):
       eyesonly-server admin-token create ${card.name}
       eyesonly admin --server ${base.origin} user add <their card>`);
}

// ------------------------------------------------------------- HTTP proxy

/** Git auth: { user } on success, { attempted, name } otherwise (attempted = credentials were sent). */
function authenticate(req, users) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Basic ')) return { attempted: !!h, name: null };
  const raw = Buffer.from(h.slice(6), 'base64').toString('utf8');
  const i = raw.indexOf(':');
  if (i < 1) return { attempted: true, name: null };
  const name = raw.slice(0, i).slice(0, 64);
  const u = Object.hasOwn(users, name) ? users[name] : null;
  // Always hash and compare so unknown users and wrong tokens take the same path.
  const want = u ? Buffer.from(u.tokenHash, 'hex') : crypto.randomBytes(32);
  const ok = crypto.timingSafeEqual(sha256(raw.slice(i + 1)), want);
  return ok && u ? { user: name } : { attempted: true, name };
}

/** The user name a Basic header claims, unverified (for lockout bookkeeping only). */
function basicUser(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Basic ')) return '';
  const raw = Buffer.from(h.slice(6), 'base64').toString('utf8');
  return raw.slice(0, Math.max(0, raw.indexOf(':'))).slice(0, 64);
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
  const url = new URL(req.url, 'http://eyesonly.local');
  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
    const f = path.join(SITE, 'index.html');
    if (fs.existsSync(f)) return send(res, 200, fs.readFileSync(f), { 'content-type': 'text/html; charset=utf-8' });
  }
  if (url.pathname === '/healthz') return send(res, 200, 'ok\n');
  if (url.pathname === ADMIN_PREFIX || url.pathname.startsWith(ADMIN_PREFIX + '/')) return handleAdmin(req, res, opts);

  const m = url.pathname.match(/^\/([^/]+)(\/.*)$/);
  if (!m || !REPO_RE.test(m[1])) return send(res, 404, 'not found\n');
  const [, repo, rest] = m;
  const dir = repoDir(repo);

  const users = loadUsers();
  const ip = clientIp(req);
  const claimed = basicUser(req);
  const wait = opts.limiter.retryAfter(ip, claimed);
  if (wait > 0) {
    req.resume();
    return send(res, 429, '[eyesonly] too many failed logins; try again later\n', { 'retry-after': String(Math.ceil(wait / 1000)) });
  }
  const auth = authenticate(req, users);
  const user = auth.user;
  if (!user) {
    // The first request from git carries no credentials; only wrong ones count as failures.
    if (auth.attempted) {
      const locked = opts.limiter.fail(ip, auth.name);
      audit('auth_failure', { route: 'git', ip, user: auth.name || undefined, repo });
      if (locked) audit('lockout', { route: 'git', ip, user: auth.name || undefined, ms: locked, failures: opts.limiter.max });
    }
    req.resume();
    return send(res, 401, 'authentication required\n', { 'www-authenticate': 'Basic realm="eyesonly"' });
  }
  opts.limiter.succeed(ip, user);
  // Same 404 for "doesn't exist" and "not a member" so repo names don't leak.
  if (!fs.existsSync(policyFile(dir))) return send(res, 404, 'not found\n');
  const policy = loadPolicy(dir);
  const all = Object.keys(users);
  if (!expand(policy, policy.members, all).has(user)) return send(res, 404, 'not found\n');

  if (req.method === 'GET' && rest === '/eyesonly/policy') {
    audit('policy_fetch', { user, repo, ip });
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
  if (service === 'git-receive-pack' && !refguard.canWrite(policy, user, all)) {
    if (req.method === 'POST') audit('push', { user, repo, refs: [], result: 'rejected', reason: 'read-only access' });
    return send(res, 403, '[eyesonly] read-only access\n');
  }

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
    EYESONLY_DATA: DATA(),
    EYESONLY_USER: user,
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
  const max = Number(process.env.EYESONLY_MAX_UPLOAD_PACK_BODY) || DEFAULT_MAX_BODY;
  const tooBig = () => {
    send(res, 413, `[eyesonly] upload-pack request is larger than ${max} bytes\n`, { connection: 'close' });
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
        if (!e.status) console.error(`[eyesonly-server] upload-pack filter failed for ${user}@${repo}:`, e);
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
  const port = Number((args.includes('--port') && args[args.indexOf('--port') + 1]) || process.env.PORT || 8787);
  const host = args.includes('--host') ? args[args.indexOf('--host') + 1] : '127.0.0.1';
  const opts = { allowV2: process.env.EYESONLY_ALLOW_PROTOCOL_V2 === '1', limiter: new AuthLimiter() };
  const server = http.createServer((req, res) => {
    try {
      handle(req, res, opts);
    } catch (e) {
      console.error(e);
      if (!res.headersSent) send(res, 500, 'internal error\n');
    }
  });
  server.listen(port, host, () => console.error(`[eyesonly-server] listening on http://${host}:${server.address().port} (data: ${DATA()})`));
}

// ----------------------------------------------------------- pre-receive

function hookPreReceive() {
  // Read the ref updates first so a rejection can be logged with what was pushed.
  const updates = fs
    .readFileSync(0, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => l.split(' '));
  const pushLog = (result, reason) =>
    audit('push', {
      user: process.env.EYESONLY_USER || null,
      repo: path.basename(process.cwd()),
      refs: updates.map(([o, n, r]) => ({ ref: r, old: o, new: n })),
      result,
      ...(reason ? { reason } : {}),
    });
  const reject = (msg) => {
    pushLog('rejected', msg);
    console.error(`\n[eyesonly] REJECTED: ${msg}\n`);
    process.exit(1);
  };
  const g = (args) => execFileSync('git', args, { encoding: 'utf8', maxBuffer: 1 << 30 }).trim();
  const gBuf = (args) => execFileSync('git', args, { maxBuffer: 1 << 30 });
  const lines = (s) => s.split('\n').filter(Boolean);

  const user = process.env.EYESONLY_USER;
  const users = loadUsers();
  if (!user || !users[user]) reject('push did not come through the eyesonly server (no authenticated user)');
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

  const isAdmin = expand(policy, policy.admins || [], all).has(user);
  // --- content checks (shared with `eyesonly verify`), authorized by the pusher
  const { validateBlob, checkCommit } = contentChecker({
    policy,
    users,
    g,
    gBuf,
    reject,
    isAdmin,
    authorize: (kind, file, commit, allowed) => {
      if (!allowed.has(user)) reject(`'${user}' may not ${kind} protected file '${file}' (${commit.slice(0, 8)})`);
    },
  });

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
  for (const [oldOid, newOid, ref] of updates) {
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
  pushLog('accepted');
}

// ------------------------------------------------------------------- main

const USAGE = `eyesonly-server: auth proxy + policy enforcement for eyesonly repos   (data dir: $EYESONLY_DATA, default ./eyesonly-data)

  eyesonly-server init --admin <eyesonlypub1:...> --repo <name.git> [--files .env,secrets/**] [--private-prefix refs/heads/private/] [--url URL]
                                                   bootstrap: admin user, first repo, starter policy
  eyesonly-server user add <eyesonlypub1:...>          register a user, prints their access token
  eyesonly-server user set-key <eyesonlypub1:...>      replace a user's keys (lost key, new machine); token unchanged
  eyesonly-server user token <name>                rotate a user's token
  eyesonly-server user remove <name>               offboard a user
  eyesonly-server user list
  eyesonly-server repo create <name.git> --admin <user>
  eyesonly-server repo list
  eyesonly-server policy show <name.git>
  eyesonly-server policy set <name.git> <file|->   replace the policy (validated)
  eyesonly-server policy manifest <name.git>       print the policy manifest for an admin to sign
  eyesonly-server policy attest <name.git> <signed.json>   install an admin-signed manifest
  eyesonly-server mirror set <name.git> --url U --push <ref|glob>... [--allow-force] [--delete-upstream on-private] [--credential-file F] [--allow-local]
  eyesonly-server mirror show <name.git>           print the mirror config (credential path only)
  eyesonly-server mirror push <name.git>           push verified public refs to the upstream (fails closed)
  eyesonly-server admin-token create <user> [--name <label>]   token for the admin API (docs/admin-api.md); not for git
  eyesonly-server admin-token list | revoke <id>
  eyesonly-server server-admin list | add <user> | remove <user>   who may manage every user and repo over the API
  eyesonly-server audit-log [--repo R] [--user U] [--type T] [--since DATE] [--json]
  eyesonly-server audit-log --verify               check the audit log's hash chain
  eyesonly-server serve [--port 8787] [--host 127.0.0.1]`;

export async function main([cmd, ...rest]) {
  if (cmd === 'init') return cmdInit(rest);
  if (cmd === 'user') return cmdUser(rest);
  if (cmd === 'repo') return cmdRepo(rest);
  if (cmd === 'policy') return cmdPolicy(rest);
  if (cmd === 'serve') return cmdServe(rest);
  if (cmd === 'mirror') return (await import('./mirror.mjs')).cmdMirror(rest);
  if (cmd === 'admin-token') return cmdAdminToken(rest);
  if (cmd === 'server-admin') return cmdServerAdmin(rest);
  if (cmd === 'audit-log') return cmdAuditLog(rest);
  if (cmd === 'hook' && rest[0] === 'pre-receive') return hookPreReceive();
  console.error(USAGE);
  process.exit(cmd ? 1 : 0);
}
