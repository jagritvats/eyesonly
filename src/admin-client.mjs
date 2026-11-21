// eyesonly admin: the client for the server's admin API (src/admin.mjs).
//
//   eyesonly admin --server https://git.example.com [--token-file F] <command> ...
//
// The admin token comes from --token-file or EYESONLY_ADMIN_TOKEN, never from argv (argv
// is visible to other local users and lands in shell history). The server URL comes from
// --server or EYESONLY_ADMIN_SERVER. Plain http:// is refused for anything but loopback
// unless --insecure, because the token would travel in the clear.
import fs from 'node:fs';
import * as attest from './attest.mjs';
import { readIdentity, identityPath } from './identity.mjs';
import { fetchRetry } from './net.mjs';

const USAGE = `usage: eyesonly admin [--server URL] [--token-file F] [--insecure] <command>
  (or set EYESONLY_ADMIN_SERVER and EYESONLY_ADMIN_TOKEN)

  whoami                                   who the token belongs to and what it may manage
  user list
  user add <eyesonlypub1:...>              register a user; prints their git token once
  user remove <name>
  user set-key <eyesonlypub1:...>          replace a user's keys (lost key, new machine)
  user token <name>                        rotate a user's git token; prints it once
  repo list
  repo create <name.git> --admin <user>
  grant <user|@group> --repo <name.git> [--files <glob>]... [--branches <refs/...>]...
                                           no --files/--branches: add to members
  revoke <user|@group> --repo <name.git> [--files <glob>]... [--branches <refs/...>]...
                                           no --files/--branches: remove everywhere
  policy get --repo <name.git>
  policy set <file|-> --repo <name.git>
  attestation --repo <name.git>            signed policy status
  sign --repo <name.git>                   sign the current policy with your identity and install it`;

function fail(msg) {
  console.error(`[eyesonly] ${msg}`);
  process.exit(1);
}

/** Split argv into options (with values) and positionals. Repeatable options collect. */
function parse(argv) {
  const withValue = new Set(['--server', '--token-file', '--repo', '--admin', '--files', '--branches']);
  const opts = { files: [], branches: [] };
  const pos = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--insecure') opts.insecure = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--token') fail('pass the admin token with --token-file <file> or EYESONLY_ADMIN_TOKEN, not on the command line');
    else if (withValue.has(a)) {
      const v = argv[++i];
      if (v === undefined) fail(`${a} needs a value`);
      const key = a.slice(2).replace('-file', 'File');
      if (key === 'files' || key === 'branches') opts[key].push(...v.split(',').map((s) => s.trim()).filter(Boolean));
      else opts[key] = v;
    } else pos.push(a);
  }
  return { opts, pos };
}

const isLoopbackHost = (h) => h === 'localhost' || h === '[::1]' || /^127\./.test(h);

function connection(opts) {
  const server = opts.server || process.env.EYESONLY_ADMIN_SERVER;
  if (!server) fail('which server? pass --server https://git.example.com or set EYESONLY_ADMIN_SERVER');
  let base;
  try {
    base = new URL(server);
    if (!/^https?:$/.test(base.protocol)) throw new Error('must be http(s)');
  } catch (e) {
    fail(`invalid --server: ${e.message}`);
  }
  if (base.protocol === 'http:' && !isLoopbackHost(base.hostname) && !opts.insecure) {
    fail(`refusing to send an admin token over plain http to ${base.host}; use https (or --insecure on a network you trust)`);
  }
  let token;
  if (opts.tokenFile) {
    try {
      token = fs.readFileSync(opts.tokenFile, 'utf8').trim();
    } catch (e) {
      fail(`can't read --token-file: ${e.message}`);
    }
  } else token = (process.env.EYESONLY_ADMIN_TOKEN || '').trim();
  if (!token) fail('no admin token: pass --token-file <file> or set EYESONLY_ADMIN_TOKEN (create one on the server: eyesonly-server admin-token create <you>)');
  return { base: base.origin + base.pathname.replace(/\/+$/, ''), token };
}

async function call(conn, method, route, body) {
  const url = `${conn.base}/_eyesonly/admin/v1${route}`;
  let res;
  try {
    // Only GETs are retried: a repeated POST/PUT/DELETE could apply twice.
    res = await (method === 'GET' ? fetchRetry : fetch)(url, {
      method,
      headers: { authorization: `Bearer ${conn.token}`, accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    fail(`can't reach ${new URL(url).host}: ${e.cause?.code || e.cause?.message || e.message}`);
  }
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    fail(`unexpected answer from the server (HTTP ${res.status}); is ${conn.base} an Eyes Only server with the admin API (0.5+)?`);
  }
  if (!res.ok) {
    const hint = res.status === 401 ? ' (wrong, revoked or expired admin token?)' : res.status === 429 ? ` (retry after ${res.headers.get('retry-after') || '?'}s)` : '';
    fail(`${data.error || `HTTP ${res.status}`}${hint}`);
  }
  return data;
}

const enc = encodeURIComponent;
const needRepo = (opts) => opts.repo || fail('--repo <name.git> is required');
const say = (s) => console.error(s);

function printPolicyResult(r) {
  if (!r.changed) return (r.notes || []).forEach((n) => say(n));
  say(`${r.repo}: ${r.changes.join(', ')}`);
  for (const n of [...(r.notes || []), ...(r.next || [])]) say(`  - ${n}`);
}

export async function cmdAdmin(argv) {
  const { opts, pos } = parse(argv);
  const [cmd, sub, arg] = pos;
  if (!cmd || cmd === 'help' || cmd === '--help') {
    console.error(USAGE);
    process.exit(cmd ? 0 : 1);
  }
  const conn = connection(opts);
  const out = (data, human) => (opts.json ? console.log(JSON.stringify(data, null, 2)) : human(data));

  if (cmd === 'whoami') {
    const r = await call(conn, 'GET', '/whoami');
    return out(r, () => console.log(`${r.user}${r.server_admin ? ' (server admin)' : ''}${r.repo_admin.length ? `; repo admin of ${r.repo_admin.join(', ')}` : ''}`));
  }
  if (cmd === 'user') {
    if (sub === 'list') {
      const r = await call(conn, 'GET', '/users');
      return out(r, () => r.users.forEach((u) => console.log(`${u.name}\t${u.fingerprint}`)));
    }
    if (sub === 'add') {
      const r = await call(conn, 'POST', '/users', { card: arg });
      say(`added ${r.name} (fingerprint ${r.fingerprint}). Git token, shown once:`);
      return console.log(r.token);
    }
    if (sub === 'remove') {
      const r = await call(conn, 'DELETE', `/users/${enc(arg || '')}`);
      return say(`removed ${r.removed}. Next: ${r.next}.`);
    }
    if (sub === 'set-key') {
      let name;
      try {
        name = JSON.parse(Buffer.from(String(arg).replace(/^eyesonlypub1:/, ''), 'base64url').toString('utf8')).name;
      } catch {
        fail('invalid card (expected eyesonlypub1:...)');
      }
      const r = await call(conn, 'PUT', `/users/${enc(name)}/key`, { card: arg });
      say(`replaced ${r.name}'s key: ${r.old_fingerprint} -> ${r.new_fingerprint} (token unchanged). Next:`);
      return r.next.forEach((l) => say(`  - ${l}`));
    }
    if (sub === 'token') {
      const r = await call(conn, 'POST', `/users/${enc(arg || '')}/token`);
      say(`new git token for ${r.name}, shown once (the old one stopped working):`);
      return console.log(r.token);
    }
  }
  if (cmd === 'repo') {
    if (sub === 'list') {
      const r = await call(conn, 'GET', '/repos');
      return out(r, () => r.repos.forEach((x) => console.log(x)));
    }
    if (sub === 'create') {
      if (!opts.admin) fail('usage: eyesonly admin repo create <name.git> --admin <user>');
      const r = await call(conn, 'POST', '/repos', { name: arg, admin: opts.admin });
      return say(`created ${r.repo} (admin ${r.admin})`);
    }
  }
  if (cmd === 'grant' || cmd === 'revoke') {
    if (!sub) fail(`usage: eyesonly admin ${cmd} <user|@group> --repo <name.git> [--files <glob>] [--branches <refs/...>]`);
    const r = await call(conn, 'POST', `/repos/${enc(needRepo(opts))}/${cmd}`, { principal: sub, files: opts.files, branches: opts.branches });
    return out(r, printPolicyResult);
  }
  if (cmd === 'policy') {
    const repo = needRepo(opts);
    if (sub === 'get') {
      const r = await call(conn, 'GET', `/repos/${enc(repo)}/policy`);
      return console.log(JSON.stringify(r.policy, null, 2));
    }
    if (sub === 'set') {
      let policy;
      try {
        policy = JSON.parse(fs.readFileSync(arg && arg !== '-' ? arg : 0, 'utf8'));
      } catch (e) {
        fail(`can't read the policy: ${e.message}`);
      }
      const r = await call(conn, 'PUT', `/repos/${enc(repo)}/policy`, { policy });
      return out(r, printPolicyResult);
    }
  }
  if (cmd === 'attestation') {
    const r = await call(conn, 'GET', `/repos/${enc(needRepo(opts))}/attestation`);
    return out(r, () => console.log(r.signed ? `${r.repo}: signed v${r.version} by ${r.signer}${r.stale ? ', STALE (policy changed since; re-sign)' : ', current'}` : `${r.repo}: not signed`));
  }
  if (cmd === 'sign') {
    const repo = needRepo(opts);
    let identity;
    try {
      identity = readIdentity();
    } catch (e) {
      fail(e.message);
    }
    if (!identity) fail(`no identity at ${identityPath()}. Run: eyesonly keygen <your-name> (or set EYESONLY_IDENTITY)`);
    const { manifest } = await call(conn, 'GET', `/repos/${enc(repo)}/manifest`);
    if (!attest.validManifest(manifest) || manifest.repo !== repo) fail('the server sent something that is not a policy manifest for this repo');
    say(`signing ${repo} policy v${manifest.version} as ${identity.name}: ${manifest.files.map(([g, who]) => `${g} -> ${who.join(',') || '(nobody)'}`).join('; ')}`);
    const r = await call(conn, 'POST', `/repos/${enc(repo)}/attestation`, attest.signManifest(manifest, identity));
    return say(`installed ${r.repo} policy v${r.installed} signed by ${r.signer}. Next: ${r.next}.`);
  }
  console.error(USAGE);
  process.exit(1);
}
