// Admin API: manage users, repos and policies over HTTPS without a shell on the server.
//
//   /_eyesonly/admin/v1/...   JSON in, JSON out, `Authorization: Bearer <admin token>`
//
// The prefix can't collide with a repo: repo names must match REPO_RE (start with a
// letter or digit and end in .git). Admin tokens live in their own file and only
// authenticate here; git tokens (users.json) only authenticate git. A token never works
// for the other side.
//
// Who may do what: server admins (server.json, set by `init`) everything; a repo admin
// (the repo policy's "admins") reads and changes that repo's policy and attestation.
//
// Admin routes refuse plain HTTP unless the client is on loopback, or (behind a proxy,
// with EYESONLY_TRUST_PROXY=1) the proxy says X-Forwarded-Proto: https. Bodies are capped.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import * as vc from './crypto.mjs';
import * as store from './store.mjs';
import { OpError } from './store.mjs';
import { audit } from './auditlog.mjs';

export const ADMIN_PREFIX = '/_eyesonly/admin/v1';
const TOKEN_PREFIX = 'eyesonlyadm_';

// ------------------------------------------------------------- admin tokens

const tokensFile = () => path.join(store.DATA(), 'admin-tokens.json');
function loadTokens() {
  return fs.existsSync(tokensFile()) ? JSON.parse(fs.readFileSync(tokensFile(), 'utf8')).tokens || {} : {};
}
function saveTokens(tokens) {
  fs.mkdirSync(store.DATA(), { recursive: true, mode: 0o700 });
  fs.writeFileSync(tokensFile() + '.tmp', JSON.stringify({ tokens }, null, 2), { mode: 0o600 });
  fs.renameSync(tokensFile() + '.tmp', tokensFile());
}

/** May `user` hold an admin token at all? Server admins and admins of at least one repo. */
export function mayHoldAdminToken(user, users = store.loadUsers()) {
  return store.isServerAdmin(user, users) || store.adminRepos(user, users).length > 0;
}

export function createAdminToken(user, label = '') {
  const users = store.loadUsers();
  store.getUser(users, user);
  if (!mayHoldAdminToken(user, users)) throw new OpError(`'${user}' is not a server admin or an admin of any repo`, 403);
  const id = crypto.randomBytes(4).toString('hex');
  const token = `${TOKEN_PREFIX}${id}_${crypto.randomBytes(24).toString('base64url')}`;
  const tokens = loadTokens();
  tokens[id] = { user, label: String(label).slice(0, 80), hash: store.sha256hex(token), created: new Date().toISOString() };
  saveTokens(tokens);
  return { id, token };
}

export function listAdminTokens() {
  return Object.entries(loadTokens()).map(([id, t]) => ({ id, user: t.user, label: t.label, created: t.created }));
}

export function revokeAdminToken(id) {
  const tokens = loadTokens();
  if (!Object.hasOwn(tokens, id || '')) throw new OpError(`no admin token '${id}'`, 404);
  const { user } = tokens[id];
  delete tokens[id];
  saveTokens(tokens);
  return user;
}

/** Returns the token's user, or null. Same work for unknown ids and wrong secrets. */
function checkAdminToken(raw) {
  const m = /^eyesonlyadm_([0-9a-f]{8})_[A-Za-z0-9_-]{32}$/.exec(raw || '');
  const t = m ? loadTokens()[m[1]] : null;
  const want = t ? Buffer.from(t.hash, 'hex') : crypto.randomBytes(32);
  const ok = crypto.timingSafeEqual(store.sha256(raw || ''), want);
  if (!ok || !t) return null;
  const users = store.loadUsers();
  // A token outlives nothing: removed users and users who are no longer admins lose access.
  return Object.hasOwn(users, t.user) && mayHoldAdminToken(t.user, users) ? t.user : null;
}

export function cmdAdminToken([sub, arg, ...rest]) {
  const die = (m) => {
    console.error(`[eyesonly-server] ${m}`);
    process.exit(1);
  };
  try {
    if (sub === 'create') {
      if (!arg) die('usage: eyesonly-server admin-token create <user> [--name <label>]');
      const label = rest.includes('--name') ? rest[rest.indexOf('--name') + 1] : '';
      const { id, token } = createAdminToken(arg, label);
      audit('admin', { actor: 'local-cli', action: 'admin-token create', target: arg, token_id: id, via: 'cli' });
      console.error(`admin token ${id} for ${arg}${label ? ` (${label})` : ''}. Shown once; it only works for the admin API, not for git:`);
      console.log(token);
    } else if (sub === 'list') {
      for (const t of listAdminTokens()) console.log(`${t.id}\t${t.user}\t${t.created}\t${t.label || ''}`);
    } else if (sub === 'revoke') {
      const user = revokeAdminToken(arg);
      audit('admin', { actor: 'local-cli', action: 'admin-token revoke', target: user, token_id: arg, via: 'cli' });
      console.error(`revoked admin token ${arg} (${user})`);
    } else die('usage: eyesonly-server admin-token create <user> [--name <label>] | list | revoke <id>');
  } catch (e) {
    if (e instanceof OpError) die(e.message);
    throw e;
  }
}

export function cmdServerAdmin([sub, user]) {
  const die = (m) => {
    console.error(`[eyesonly-server] ${m}`);
    process.exit(1);
  };
  const c = store.loadServerConfig();
  if (sub === 'list') return c.server_admins.forEach((u) => console.log(u));
  if (!['add', 'remove'].includes(sub) || !user) die('usage: eyesonly-server server-admin list | add <user> | remove <user>');
  if (sub === 'add') {
    if (!Object.hasOwn(store.loadUsers(), user)) die(`no such user '${user}'`);
    if (!c.server_admins.includes(user)) c.server_admins.push(user);
  } else c.server_admins = c.server_admins.filter((u) => u !== user);
  store.saveServerConfig(c);
  audit('admin', { actor: 'local-cli', action: `server-admin ${sub}`, target: user, via: 'cli' });
  console.error(`server admins: ${c.server_admins.join(', ') || '(none)'}`);
}

// ------------------------------------------------- failed-auth limiter

/**
 * In-memory backoff for failed logins, per client IP + user name, plus a looser per-IP
 * bucket so spraying many user names from one address also slows down. After
 * EYESONLY_AUTH_MAX_FAILURES failures (default 5) within the window, the key is locked
 * for EYESONLY_AUTH_LOCKOUT_MS (default 1000) doubling per further failure, capped at
 * EYESONLY_AUTH_LOCKOUT_MAX_MS (default 15 min). A success clears the key. State resets
 * when the server restarts.
 */
export class AuthLimiter {
  constructor(env = process.env) {
    this.max = Number(env.EYESONLY_AUTH_MAX_FAILURES) || 5;
    this.base = Number(env.EYESONLY_AUTH_LOCKOUT_MS) || 1000;
    this.cap = Number(env.EYESONLY_AUTH_LOCKOUT_MAX_MS) || 15 * 60 * 1000;
    this.window = 15 * 60 * 1000;
    this.keys = new Map();
  }
  #keys(ip, user) {
    return [`${ip}\0${user || ''}`, `${ip}\0*`];
  }
  /** ms until this client may try again (0 = go ahead). */
  retryAfter(ip, user, now = Date.now()) {
    const [k, ipk] = this.#keys(ip, user);
    return Math.max(0, ...[k, ipk].map((x) => (this.keys.get(x)?.until || 0) - now));
  }
  /** Record a failure; returns the lockout it triggered in ms (0 if none). */
  fail(ip, user, now = Date.now()) {
    let locked = 0;
    for (const [key, limit] of this.#keys(ip, user).map((x, i) => [x, i ? this.max * 4 : this.max])) {
      const s = this.keys.get(key);
      const st = s && now - s.last < this.window ? s : { n: 0, until: 0 };
      st.n += 1;
      st.last = now;
      if (st.n >= limit) {
        const ms = Math.min(this.cap, this.base * 2 ** (st.n - limit));
        st.until = now + ms;
        locked = Math.max(locked, ms);
      }
      this.keys.set(key, st);
    }
    if (this.keys.size > 50_000) this.#gc(now);
    return locked;
  }
  succeed(ip, user) {
    this.keys.delete(this.#keys(ip, user)[0]);
  }
  #gc(now) {
    for (const [k, v] of this.keys) if (now - v.last > this.window && v.until < now) this.keys.delete(k);
  }
}

const trustProxy = () => process.env.EYESONLY_TRUST_PROXY === '1';

/** Client address: the socket peer, or with a trusted proxy the address it appended. */
export function clientIp(req) {
  if (trustProxy() && req.headers['x-forwarded-for']) {
    const parts = String(req.headers['x-forwarded-for']).split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1];
  }
  return req.socket.remoteAddress || 'unknown';
}

const isLoopback = (a) => a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1' || /^127\./.test(a || '') || /^::ffff:127\./.test(a || '');

/** May admin credentials travel on this request? */
export function secureEnough(req) {
  if (process.env.EYESONLY_ALLOW_INSECURE_ADMIN === '1' || req.socket.encrypted) return true;
  if (trustProxy()) return String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
  return isLoopback(req.socket.remoteAddress);
}

// --------------------------------------------------------------- the API

function json(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify(body) + '\n');
}

function readJson(req) {
  const max = Number(process.env.EYESONLY_MAX_ADMIN_BODY) || 1 << 20;
  return new Promise((resolve, reject) => {
    if (Number(req.headers['content-length']) > max) {
      req.resume();
      return reject(new OpError(`request body is larger than ${max} bytes`, 413));
    }
    const chunks = [];
    let total = 0;
    let done = false;
    req.on('data', (c) => {
      if (done) return;
      total += c.length;
      if (total > max) {
        done = true;
        req.resume();
        return reject(new OpError(`request body is larger than ${max} bytes`, 413));
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      const text = Buffer.concat(chunks).toString('utf8');
      if (!text.trim()) return resolve({});
      if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) return reject(new OpError('send JSON (content-type: application/json)', 415));
      try {
        const v = JSON.parse(text);
        if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('expected a JSON object');
        resolve(v);
      } catch (e) {
        reject(new OpError(`invalid JSON body: ${e.message}`, 400));
      }
    });
    req.on('error', reject);
  });
}

const strList = (v, what) => {
  if (v == null) return [];
  const list = Array.isArray(v) ? v : [v];
  if (!list.every((x) => typeof x === 'string' && x)) throw new OpError(`${what} must be a string or a list of strings`);
  return list;
};

/** Route table: [method, regex, handler(ctx, ...captures)]. */
const ROUTES = [
  ['GET', /^\/whoami$/, ({ actor, users }) => ({ user: actor, server_admin: store.isServerAdmin(actor, users), repo_admin: store.adminRepos(actor, users) })],

  // users
  ['GET', /^\/users$/, ({ users }) => ({ users: Object.entries(users).map(([name, u]) => ({ name, fingerprint: store.userFingerprint(u), created: u.created })) })],
  [
    'POST',
    /^\/users$/,
    ({ actor, users, body, serverAdmin, log }) => {
      serverAdmin();
      const card = store.parseCard(body.card);
      const token = store.addUser(users, card);
      log({ action: 'user add', target: card.name });
      return { status: 201, body: { name: card.name, fingerprint: vc.fingerprint(card), token, note: 'git token, shown once' } };
    },
  ],
  [
    'DELETE',
    /^\/users\/([^/]+)$/,
    ({ users, serverAdmin, log }, name) => {
      serverAdmin();
      store.removeUser(users, name);
      log({ action: 'user remove', target: name });
      return { removed: name, next: `run \`eyesonly audit ${name}\` in each repo and rotate what it lists` };
    },
  ],
  [
    'PUT',
    /^\/users\/([^/]+)\/key$/,
    ({ users, body, serverAdmin, log }, name) => {
      serverAdmin();
      const card = store.parseCard(body.card);
      if (card.name !== name) throw new OpError(`card is for '${card.name}', not '${name}'`);
      const fp = store.setUserKey(users, card);
      log({ action: 'user set-key', target: name, old_fingerprint: fp.old, new_fingerprint: fp.new });
      return { name, old_fingerprint: fp.old, new_fingerprint: fp.new, next: store.keyChangeAdvice(name, users) };
    },
  ],
  [
    'POST',
    /^\/users\/([^/]+)\/token$/,
    ({ users, serverAdmin, log }, name) => {
      serverAdmin();
      const token = store.rotateUserToken(users, name);
      log({ action: 'user token', target: name });
      return { name, token, note: 'new git token, shown once; the old one stops working now' };
    },
  ],

  // repos
  ['GET', /^\/repos$/, ({ actor, users, isServerAdmin }) => ({ repos: isServerAdmin ? store.listRepos() : store.adminRepos(actor, users) })],
  [
    'POST',
    /^\/repos$/,
    ({ users, body, serverAdmin, log }) => {
      serverAdmin();
      const name = body.name;
      if (typeof name !== 'string' || !store.REPO_RE.test(name)) throw new OpError('repo name must look like name.git');
      if (typeof body.admin !== 'string' || !Object.hasOwn(users, body.admin)) throw new OpError('admin must be an existing user');
      store.createRepo(name, store.starterPolicy(body.admin));
      log({ action: 'repo create', target: name, repo: name, admin: body.admin });
      return { status: 201, body: { repo: name, admin: body.admin } };
    },
  ],
  ['GET', /^\/repos\/([^/]+)\/policy$/, ({ repoAdmin, users }, repo) => {
    const dir = repoAdmin(repo);
    return { repo, policy: store.loadPolicy(dir), attestation: store.attestationStatus(repo, dir, users) };
  }],
  [
    'PUT',
    /^\/repos\/([^/]+)\/policy$/,
    ({ repoAdmin, users, body, log }, repo) => {
      const dir = repoAdmin(repo);
      const h = store.savePolicy(dir, body.policy);
      log({ action: 'policy set', repo, before: h.before, after: h.after });
      return policyResult(repo, dir, users, ['policy replaced']);
    },
  ],
  [
    'POST',
    /^\/repos\/([^/]+)\/(grant|revoke)$/,
    ({ repoAdmin, users, body, log }, repo, verb) => {
      const dir = repoAdmin(repo);
      const policy = store.loadPolicy(dir);
      const targets = { files: strList(body.files, 'files'), branches: strList(body.branches, 'branches') };
      let changes;
      let notes = [];
      if (verb === 'grant') changes = store.grant(policy, body.principal, targets);
      else ({ changes, notes } = store.revoke(policy, body.principal, targets));
      if (!changes.length) return { repo, changed: false, notes: notes.length ? notes : [`nothing to ${verb}`], policy };
      const h = store.savePolicy(dir, policy);
      log({ action: `policy ${verb}`, target: body.principal, repo, changes, before: h.before, after: h.after });
      return { ...policyResult(repo, dir, users, changes), notes };
    },
  ],
  ['GET', /^\/repos\/([^/]+)\/attestation$/, ({ repoAdmin, users }, repo) => ({ repo, ...store.attestationStatus(repo, repoAdmin(repo), users) })],
  ['GET', /^\/repos\/([^/]+)\/manifest$/, ({ repoAdmin, users }, repo) => ({ repo, manifest: store.nextManifest(repo, repoAdmin(repo), users) })],
  [
    'POST',
    /^\/repos\/([^/]+)\/attestation$/,
    ({ actor, repoAdmin, users, body }, repo) => {
      const dir = repoAdmin(repo);
      const att = body.attestation ?? body;
      const version = store.installAttestation(repo, dir, att, users);
      audit('attestation', { actor, repo, version, signer: att.signer, via: 'api' });
      return { repo, installed: version, signer: att.signer, next: 'members pick it up with `eyesonly pull-policy`' };
    },
  ],
];

function policyResult(repo, dir, users, changes) {
  const att = store.attestationStatus(repo, dir, users);
  const out = { repo, changed: true, changes, policy: store.loadPolicy(dir), attestation: att, next: ['members run `eyesonly pull-policy && eyesonly rekey`'] };
  if (att.signed && att.stale) out.next.push(`the signed policy is now stale; clients keep using v${att.version} until an admin re-signs. ${store.resignHint(repo)}`);
  return out;
}

/**
 * Handle a request under ADMIN_PREFIX. `limiter` is the server's AuthLimiter (shared
 * with git auth). Always answers; never throws.
 */
export async function handleAdmin(req, res, { limiter }) {
  const ip = clientIp(req);
  try {
    if (!secureEnough(req)) {
      req.resume();
      return json(res, 403, { error: 'the admin API needs HTTPS (behind a TLS proxy set EYESONLY_TRUST_PROXY=1; for local testing EYESONLY_ALLOW_INSECURE_ADMIN=1)' });
    }
    const wait = limiter.retryAfter(ip, '*admin');
    if (wait > 0) {
      req.resume();
      return json(res, 429, { error: 'too many failed attempts; try again later' }, { 'retry-after': String(Math.ceil(wait / 1000)) });
    }
    const h = req.headers.authorization || '';
    const actor = h.startsWith('Bearer ') ? checkAdminToken(h.slice(7).trim()) : null;
    if (!actor) {
      req.resume();
      const locked = limiter.fail(ip, '*admin');
      audit('auth_failure', { route: 'admin', ip });
      if (locked) audit('lockout', { route: 'admin', ip, ms: locked, failures: limiter.max });
      return json(res, 401, { error: 'admin token required (Authorization: Bearer eyesonlyadm_...)' }, { 'www-authenticate': 'Bearer realm="eyesonly-admin"' });
    }
    limiter.succeed(ip, '*admin');

    const url = new URL(req.url, 'http://eyesonly.local');
    const sub = url.pathname.slice(ADMIN_PREFIX.length) || '/';
    let match = null;
    for (const [method, re, fn] of ROUTES) {
      const m = method === req.method && re.exec(sub);
      if (m) {
        match = [fn, m.slice(1).map(decodeURIComponent)];
        break;
      }
    }
    if (!match) {
      req.resume();
      return json(res, ROUTES.some(([, re]) => re.test(sub)) ? 405 : 404, { error: 'no such admin endpoint' });
    }
    const body = ['POST', 'PUT'].includes(req.method) ? await readJson(req) : (req.resume(), {});
    const users = store.loadUsers();
    const isServerAdmin = store.isServerAdmin(actor, users);
    const ctx = {
      actor,
      users,
      body,
      isServerAdmin,
      serverAdmin: () => {
        if (!isServerAdmin) throw new OpError('only a server admin can do that', 403);
      },
      // Repo admins see their repos; everyone else gets the same 404 as a missing repo.
      repoAdmin: (repo) => {
        const dir = store.existingRepo(repo);
        if (!isServerAdmin && !store.isRepoAdmin(actor, dir, users)) throw new OpError('no such repo', 404);
        return dir;
      },
      log: (fields) => audit('admin', { actor, via: 'api', ...fields }),
    };
    const [fn, captures] = match;
    const out = await fn(ctx, ...captures);
    if (out && Object.hasOwn(out, 'status') && Object.hasOwn(out, 'body')) return json(res, out.status, out.body);
    return json(res, 200, out);
  } catch (e) {
    if (e instanceof OpError) return json(res, e.status, { error: e.message });
    if (e instanceof URIError) return json(res, 400, { error: 'malformed URL escape' });
    console.error('[eyesonly-server] admin API error:', e);
    if (!res.headersSent) json(res, 500, { error: 'internal error' });
  }
}
