// Repo mode: same commands as with a server, the signed policy lives in the repo
// (.eyesonly/policy.json, see repo-policy.mjs), and any git host works (GitHub, GitLab, ssh,
// a local path). Mode detection, setup/clone/pull-policy for repo mode, and the admin
// commands init / join / grant / revoke / policy show.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import * as attest from './attest.mjs';
import * as vc from './crypto.mjs';
import * as rp from './repo-policy.mjs';
import { installPrePushHook, PRE_PUSH_MARK } from './hooks.mjs';
import { configureFilters, ensureAttributes, gitDir, loadIdentity, protectedFiles, repoTop, resmudge, saveResolved } from './client.mjs';

const log = (...a) => console.error('[eyesonly]', ...a);
function die(msg) {
  log(msg);
  process.exit(1);
}
const git = (args, opts = {}) => execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 30, ...opts }).trim();
const tryGit = (args, opts) => {
  try {
    return git(args, opts);
  } catch {
    return null;
  }
};
const isHttp = (u) => /^https?:\/\//i.test(u || '');

// ------------------------------------------------------------------ detection

/**
 * Is there an Eyes Only server behind this URL? It answers an unauthenticated policy
 * request with `401` and `WWW-Authenticate: Basic realm="eyesonly"`. Anything else
 * (GitHub, GitLab, offline, not http) is "no".
 */
export async function probeServer(url) {
  if (!isHttp(url)) return false;
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  u.username = '';
  u.password = '';
  u.pathname = u.pathname.replace(/\/+$/, '') + '/eyesonly/policy';
  try {
    const res = await fetch(u, { redirect: 'manual', signal: AbortSignal.timeout(5000) });
    return res.status === 401 && /realm="eyesonly"/i.test(res.headers.get('www-authenticate') || '');
  } catch {
    return false;
  }
}

/**
 * 'server' when origin is an Eyes Only server, else 'repo' when the default branch carries
 * a policy file. The server is checked first: otherwise a member with push access could
 * commit a policy file signed by themselves and flip new clones into repo mode.
 * A clone never switches modes silently.
 */
export async function detectMode(top, { explicit, remote = {} } = {}) {
  if (explicit && explicit !== 'repo' && explicit !== 'server') die('usage: --mode repo|server');
  const name = remote.name || 'origin';
  const url = remote.url !== undefined ? remote.url : tryGit(['config', `remote.${name}.url`], { cwd: top });
  let mode = explicit;
  if (!mode) {
    if (await probeServer(url)) mode = 'server';
    else if (rp.policyTextAt(rp.defaultRef(top, name), top) != null) mode = 'repo';
    else if (isHttp(url)) mode = 'server'; // unreachable server: keep its error messages
    else die(`no Eyes Only policy found: remote '${name}' is not an Eyes Only server and the default branch has no ${rp.POLICY_FILE}. An admin starts with \`eyesonly init\` (no server needed) or \`eyesonly-server init\`.`);
  }
  const cached = tryGit(['config', '--local', 'eyesonly.mode'], { cwd: top });
  if (cached && cached !== mode && !explicit) {
    die(`this clone was set up in ${cached} mode, but it now looks like ${mode} mode. Not switching silently; if that's intended, run \`eyesonly setup --mode ${mode}\`.`);
  }
  return mode;
}

// ------------------------------------------------------------------ resolve

/** Read, verify and trust-check the policy on the default branch of the repo at `top`. */
function resolveAt(top, gd, remote) {
  const ref = rp.defaultRef(top, remote);
  const text = rp.policyTextAt(ref, top);
  if (text == null) die(`no ${rp.POLICY_FILE} on the default branch${ref ? ` (${ref.replace(/^refs\/(remotes\/|heads\/)/, '')})` : ''}. Pull first, or ask an admin to run \`eyesonly init\`.`);
  try {
    return rp.resolveRepoPolicy(rp.parseAttestation(text), { trust: attest.loadTrust(gd), pin: process.env.EYESONLY_PIN_ADMIN });
  } catch (e) {
    die(`refusing the repo's policy: ${e.message}. Nothing was changed. If the admin set really changed, delete .git/eyesonly/trust.json to re-pin.`);
  }
}

function memberNotes(m, id) {
  if (!id) return log('warning: no identity, so nothing will be decrypted. Run: eyesonly keygen <your-name>, then eyesonly join');
  const k = m.keys[id.name];
  if (!k) return log(`you ('${id.name}') aren't in this repo's policy yet: run \`eyesonly join\` and ask an admin to grant you`);
  if (k.ed25519 !== id.ed25519.pub || k.x25519 !== id.x25519.pub) log(`warning: the policy has a different key for '${id.name}' than your identity; ask an admin to re-grant you`);
}

/** Apply a resolved repo policy to the clone at `top` (cache, trust, filters, hooks, attributes). */
function apply(top, { manifest, trust, notes }, id, { dir } = {}) {
  notes.forEach((n) => log(n));
  memberNotes(manifest, id);
  const policy = rp.cachePolicy(manifest, id?.name ?? null);
  saveResolved({ policy, trust }, dir);
  installPrePushHook(top, configureFilters(top));
  git(['config', '--local', 'eyesonly.mode', 'repo'], { cwd: top });
  return policy;
}

export function setupRepo(top, remote) {
  const resolved = resolveAt(top, gitDir(), remote);
  const policy = apply(top, resolved, loadIdentity({ required: false }));
  ensureAttributes(policy, top);
  const files = resmudge(policy, top);
  log(`ready (repo mode, policy v${resolved.manifest.version}). ${files.length} protected file(s) in this checkout.`);
}

export function pullRepoPolicy(top, remote = 'origin') {
  if (tryGit(['config', `remote.${remote}.url`], { cwd: top }) && tryGit(['fetch', '--quiet', remote], { cwd: top }) === null) {
    log(`warning: couldn't fetch ${remote}; using the policy already on the local default branch`);
  }
  const resolved = resolveAt(top, gitDir(), remote);
  apply(top, resolved, loadIdentity({ required: false }));
  log(`policy v${resolved.manifest.version} from the default branch. Run \`eyesonly rekey\` if file access changed.`);
}

/** `eyesonly doctor` checks for a repo-mode clone. */
export function doctorRepo(top, { ok, warn, fail, id, remote }) {
  const ref = rp.defaultRef(top, remote);
  const text = rp.policyTextAt(ref, top);
  if (text == null) return fail(`no ${rp.POLICY_FILE} on the default branch${ref ? ` (${ref})` : ''}`, `git pull, or ask an admin to run eyesonly init`);
  let r;
  try {
    r = rp.resolveRepoPolicy(rp.parseAttestation(text), { trust: attest.loadTrust(gitDir()), pin: process.env.EYESONLY_PIN_ADMIN });
  } catch (e) {
    return fail(`the repo's policy is refused: ${e.message}`, 'ask your admin; if the admin set really changed, delete .git/eyesonly/trust.json and run eyesonly setup');
  }
  const m = r.manifest;
  ok(`repo mode: policy v${m.version} on ${ref.replace(/^refs\/(remotes\/|heads\/)/, '')}, signed by admin ${rp.rulesOf(m).admins.join(', ')}, matches the pinned admin keys`);
  const trust = attest.loadTrust(gitDir());
  if (!trust) warn('no admin key pinned yet', 'eyesonly setup');
  const cached = (() => {
    try {
      return JSON.parse(fs.readFileSync(path.join(gitDir(), 'eyesonly', 'policy.json'), 'utf8'));
    } catch {
      return null;
    }
  })();
  if (cached && (cached.version || 0) < m.version) fail(`this clone uses policy v${cached.version || '?'}, the default branch has v${m.version}`, 'eyesonly pull-policy && eyesonly rekey');
  if (id) {
    const k = m.keys[id.name];
    if (!k) warn(`you ('${id.name}') aren't in the policy yet`, 'eyesonly join, then ask an admin to run eyesonly grant');
    else if (k.ed25519 !== id.ed25519.pub || k.x25519 !== id.x25519.pub) fail(`the policy has a different key for '${id.name}' than your identity`, 'ask an admin to re-grant you with your current card (eyesonly whoami)');
    else ok(`you ('${id.name}') are a member`);
  }
  const hook = path.resolve(top, git(['rev-parse', '--git-path', 'hooks/pre-push'], { cwd: top }));
  if (fs.existsSync(hook) && fs.readFileSync(hook, 'utf8').includes(PRE_PUSH_MARK)) ok('pre-push hook installed (runs eyesonly verify)');
  else fail('the eyesonly pre-push hook is missing', 'eyesonly setup');
}

/** A cheap hint for `eyesonly status`: the default branch has a newer policy than this clone uses. */
export function warnIfPolicyBehind(policy, top) {
  try {
    const text = rp.policyTextAt(rp.defaultRef(top), top);
    const v = text && JSON.parse(text).manifest?.version;
    if (Number.isInteger(v) && v > (policy.version || 0)) console.log(`note: the default branch has policy v${v}; run \`eyesonly pull-policy\` (then \`eyesonly rekey\` if you can read files whose audience changed)`);
  } catch {}
}

const repoNameFromUrl = (url) => url.replace(/[/\\]+$/, '').split(/[/\\:]/).pop().replace(/\.git$/, '') || 'repo';

/**
 * Clone a repo-mode repo. Returns false (and leaves nothing behind) when the default branch
 * has no policy and `fallback` is set, so the caller can try the server flow instead.
 */
export async function cloneRepo(url, dir, { fallback = false } = {}) {
  dir = path.resolve(dir || repoNameFromUrl(url));
  const existed = fs.existsSync(dir);
  execFileSync('git', ['clone', '--quiet', '--no-checkout', url, dir], { stdio: 'inherit' });
  const text = rp.policyTextAt(rp.defaultRef(dir), dir);
  if (text == null) {
    if (!existed) fs.rmSync(dir, { recursive: true, force: true });
    if (fallback) return false;
    die(`${url} has no ${rp.POLICY_FILE} on its default branch and isn't an Eyes Only server. Clone it with plain git, or ask an admin to run \`eyesonly init\`.`);
  }
  let resolved;
  try {
    resolved = rp.resolveRepoPolicy(rp.parseAttestation(text), { trust: null, pin: process.env.EYESONLY_PIN_ADMIN });
  } catch (e) {
    if (!existed) fs.rmSync(dir, { recursive: true, force: true });
    die(`refusing the repo's policy: ${e.message}. Nothing was cloned.`);
  }
  const id = loadIdentity({ required: false });
  const policy = apply(dir, resolved, id, { dir: path.join(dir, '.git') });
  if (tryGit(['rev-parse', '--verify', '-q', 'HEAD'], { cwd: dir })) {
    execFileSync('git', ['reset', '--quiet', '--hard', 'HEAD'], { cwd: dir, stdio: ['ignore', 'ignore', 'inherit'] });
  } else {
    // The host's HEAD names a branch that doesn't exist: check out the default branch we read.
    const ref = rp.defaultRef(dir);
    const branch = ref.replace(/^refs\/(remotes\/origin|heads)\//, '');
    execFileSync('git', ['checkout', '--quiet', '-B', branch, ref], { cwd: dir, stdio: ['ignore', 'ignore', 'inherit'] });
  }
  const files = protectedFiles(policy, dir);
  const locked = files.filter((f) => vc.isEnvelope(fs.readFileSync(path.join(dir, f))));
  log(`cloned into ${dir} (repo mode, policy v${resolved.manifest.version}): ${files.length} protected file(s), ${files.length - locked.length} decrypted, ${locked.length} locked.`);
  return true;
}

// ------------------------------------------------------------------ admin

function flags(args, spec) {
  const out = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
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

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,38}$/i;
const cardOf = (id) => ({ x25519: id.x25519.pub, ed25519: id.ed25519.pub });

/**
 * The policy an admin edits: the working-tree file if it verifies against the pinned trust
 * (so several grants can be chained before committing), else the default branch's.
 */
function editablePolicy(top) {
  const gd = gitDir();
  const trust = attest.loadTrust(gd);
  const p = path.join(top, rp.POLICY_FILE);
  const text = fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : rp.policyTextAt(rp.defaultRef(top), top);
  if (text == null) die(`no ${rp.POLICY_FILE} here. Start with \`eyesonly init\`.`);
  try {
    return rp.resolveRepoPolicy(rp.parseAttestation(text), { trust, pin: process.env.EYESONLY_PIN_ADMIN });
  } catch (e) {
    die(`can't edit the policy: ${e.message}`);
  }
}

/** Sign the edited rules as the next version, write the file, and refresh this clone. */
function publish(top, prev, rules, keys, id) {
  const manifest = rp.buildRepoManifest({ repo: prev.repo, version: prev.version + 1, policy: rules, keys });
  if (!rp.validRepoManifest(manifest)) die('the edited policy is inconsistent (every admin needs a key)');
  let att;
  try {
    att = rp.signRepoManifest(manifest, id);
  } catch (e) {
    die(e.message);
  }
  rp.writePolicyFile(top, att);
  // Refresh this clone's cache so `rekey` encrypts for the new audience right away, but
  // leave the pinned trust alone: it moves when the policy reaches the default branch
  // (pull-policy). A grant made on a branch that's later abandoned must not look like a
  // rollback when the admin goes back to main.
  const policy = rp.cachePolicy(manifest, id.name);
  saveResolved({ policy, trust: null });
  ensureAttributes(policy, top);
  return manifest;
}

function requireAdmin(m, id) {
  if (!m.policy.admins.includes(id.name)) die(`only admins can change the policy ('${id.name}' isn't one; admins: ${m.policy.admins.join(', ')})`);
}

export async function cmdInit(args) {
  const o = flags(args, { files: String, group: String, commit: Boolean });
  const top = repoTop();
  const remote = tryGit(['config', 'remote.origin.url'], { cwd: top });
  if (await probeServer(remote)) die(`origin (${remote.replace(/\/\/[^@/]*@/, '//')}) is an Eyes Only server: the server holds the policy. An admin runs \`eyesonly-server init\` there, and you run \`eyesonly setup\`.`);
  if (fs.existsSync(path.join(top, rp.POLICY_FILE)) || rp.policyTextAt(rp.defaultRef(top), top) != null) {
    die(`${rp.POLICY_FILE} already exists. Use \`eyesonly setup\`, or \`eyesonly grant\` / \`revoke\` to change it.`);
  }
  const id = loadIdentity();
  const group = o.group || 'core';
  if (!NAME_RE.test(group)) die(`invalid group name '${group}'`);
  const globs = (o.files || '.env,secrets/**').split(',').map((s) => s.trim()).filter(Boolean);
  if (!globs.length) die('--files needs at least one path or glob');
  const rules = { members: ['*'], admins: [id.name], groups: { [group]: [id.name] }, files: Object.fromEntries(globs.map((g) => [g, [`@${group}`]])) };
  const manifest = rp.buildRepoManifest({ repo: rp.newRepoId(), version: 1, policy: rules, keys: { [id.name]: cardOf(id) } });
  const att = rp.signRepoManifest(manifest, id);
  rp.writePolicyFile(top, att);
  const resolved = rp.resolveRepoPolicy(att, { trust: null, pin: null });
  const policy = apply(top, { ...resolved, notes: [] }, id);
  ensureAttributes(policy, top);

  // Protected files already tracked in plaintext: encrypt them now, but history keeps the old copies.
  const tracked = protectedFiles(policy, top);
  const plain = tracked.filter((f) => {
    try {
      return !vc.isEnvelope(execFileSync('git', ['cat-file', 'blob', `:${f}`], { cwd: top, maxBuffer: 1 << 30, stdio: ['ignore', 'pipe', 'ignore'] }));
    } catch {
      return false;
    }
  });
  if (plain.length) {
    git(['add', '--renormalize', '--', ...plain], { cwd: top });
    log(`encrypted ${plain.length} file(s) that were tracked in plaintext: ${plain.join(', ')}. Their old versions are still in history: rotate those secrets.`);
  }
  const fp = attest.adminFingerprint(id.ed25519.pub);
  if (o.commit) {
    git(['add', '--', rp.POLICY_FILE, '.gitattributes'], { cwd: top });
    execFileSync('git', ['commit', '-q', '-m', 'eyesonly: init (signed policy, encrypted paths)'], { cwd: top, stdio: ['ignore', 'inherit', 'inherit'] });
  }
  log(`initialized repo mode: ${globs.join(', ')} readable by @${group} (${id.name}). Admin fingerprint ${fp}`);
  log(o.commit
    ? 'committed. Push it, then teammates run: eyesonly keygen <name> && eyesonly join (and send you the card)'
    : `next: git add ${rp.POLICY_FILE} .gitattributes && git commit -m "eyesonly: init" && git push`);
  log('teammates: eyesonly keygen <name>, clone, then `eyesonly join` and send you their card; you run `eyesonly grant <name>`');
  log(`tip: protect the default branch and require \`eyesonly verify\` in CI (docs/repo-mode.md); members can pin ${fp} with EYESONLY_PIN_ADMIN`);
}

export function cmdJoin() {
  const top = repoTop();
  const id = loadIdentity();
  const card = vc.encodeCard(vc.publicCard(id));
  const rel = `${rp.REQUESTS_DIR}/${id.name}.pub`;
  fs.mkdirSync(path.join(top, rp.REQUESTS_DIR), { recursive: true });
  fs.writeFileSync(path.join(top, rel), card + '\n');
  log(`wrote ${rel} (fingerprint ${vc.fingerprint(vc.publicCard(id))}). Commit it on a branch and open a pull request, or send this card to an admin:`);
  console.log(card);
  log(`the admin runs: eyesonly grant ${id.name} --from-request   (or --card <card>)`);
}

export function cmdGrant(args) {
  const o = flags(args, { card: String, 'from-request': Boolean, group: String, files: String, admin: Boolean });
  const name = o._[0];
  if (!name || !NAME_RE.test(name)) die('usage: eyesonly grant <name> [--card <eyesonlypub1:...> | --from-request] [--group <g>] [--files <glob>] [--admin]');
  const top = repoTop();
  const id = loadIdentity();
  const { manifest: m } = editablePolicy(top);
  requireAdmin(m, id);
  const rules = structuredClone(rp.rulesOf(m));
  const keys = { ...m.keys };
  const reqPath = path.join(top, rp.REQUESTS_DIR, `${name}.pub`);

  let cardText = o.card;
  if (!cardText && (o['from-request'] || (!keys[name] && fs.existsSync(reqPath)))) {
    if (!fs.existsSync(reqPath)) die(`no request at ${rp.REQUESTS_DIR}/${name}.pub (they run \`eyesonly join\`)`);
    cardText = fs.readFileSync(reqPath, 'utf8').trim();
  }
  if (cardText) {
    let card;
    try {
      card = vc.decodeCard(cardText);
    } catch (e) {
      die(`invalid card: ${e.message}`);
    }
    if (card.name !== name) die(`that card is for '${card.name}', not '${name}'`);
    if (keys[name] && keys[name].ed25519 !== card.ed25519) log(`replacing ${name}'s key (old ${vc.fingerprint({ ...keys[name] })}, new ${vc.fingerprint(card)}); readers must rekey`);
    keys[name] = { x25519: card.x25519, ed25519: card.ed25519 };
  }
  if (!keys[name]) die(`no key for '${name}': pass --card <card>, or have them run \`eyesonly join\` and use --from-request`);

  const groups = Object.keys(rules.groups);
  let group = o.group;
  if (!group && !o.files && !o.admin && !cardText) die(`nothing to change: pass --group <g>, --files <glob> or --admin`);
  if (!group && !o.files && groups.length === 1) group = groups[0];
  const did = [];
  if (group) {
    if (!NAME_RE.test(group)) die(`invalid group name '${group}'`);
    rules.groups[group] ||= [];
    if (!rules.groups[group].includes(name)) rules.groups[group].push(name);
    did.push(`@${group}`);
  }
  if (o.files) {
    rules.files[o.files] ||= [];
    if (!rules.files[o.files].includes(name)) rules.files[o.files].push(name);
    did.push(o.files);
  }
  if (o.admin && !rules.admins.includes(name)) {
    rules.admins.push(name);
    did.push('admins');
  }
  const next = publish(top, m, rules, keys, id);
  if (fs.existsSync(reqPath)) fs.rmSync(reqPath);
  const readable = next.files.filter(([, who]) => who.includes(name)).map(([g]) => g);
  log(`granted ${name}${did.length ? ` (${did.join(', ')})` : ''}: policy v${next.version}. ${name} can read: ${readable.join(', ') || 'nothing yet'}`);
  log(`next: git add ${rp.POLICY_FILE}${fs.existsSync(path.join(top, rp.REQUESTS_DIR)) ? ` ${rp.REQUESTS_DIR}` : ''} && git commit -m "eyesonly: grant ${name}", then \`eyesonly rekey\`, commit and push`);
}

export function cmdRevoke(args) {
  const o = flags(args, { group: String });
  const name = o._[0];
  if (!name) die('usage: eyesonly revoke <name> [--group <g>]');
  const top = repoTop();
  const id = loadIdentity();
  const { manifest: m } = editablePolicy(top);
  requireAdmin(m, id);
  const rules = structuredClone(rp.rulesOf(m));
  const keys = { ...m.keys };
  const drop = (list) => list.filter((x) => x !== name);
  if (o.group) {
    if (!rules.groups[o.group]) die(`no group '${o.group}'`);
    rules.groups[o.group] = drop(rules.groups[o.group]);
  } else {
    if (!keys[name]) die(`'${name}' isn't in the policy`);
    if (rules.admins.length === 1 && rules.admins[0] === name) die(`'${name}' is the only admin; grant another admin first`);
    for (const g of Object.keys(rules.groups)) rules.groups[g] = drop(rules.groups[g]);
    for (const f of Object.keys(rules.files)) rules.files[f] = drop(rules.files[f]);
    rules.admins = drop(rules.admins);
    delete keys[name];
  }
  const next = publish(top, m, rules, keys, id);
  log(`revoked ${name}${o.group ? ` from @${o.group}` : ''}: policy v${next.version}`);
  log(`next: git add ${rp.POLICY_FILE} && git commit -m "eyesonly: revoke ${name}", then \`eyesonly rekey\`, commit and push`);
  log(`revocation isn't retroactive: rotate what ${name} could read (\`eyesonly audit ${name}\`)`);
}

export function cmdPolicy([sub]) {
  if (sub && sub !== 'show') die('usage: eyesonly policy show');
  const top = repoTop();
  const { manifest: m } = editablePolicy(top);
  const rules = rp.rulesOf(m);
  console.log(`repo ${m.repo}  policy v${m.version}`);
  console.log('admins:');
  for (const a of rules.admins) console.log(`  ${a}  ${attest.adminFingerprint(m.keys[a].ed25519)}`);
  console.log('groups:');
  for (const [g, who] of Object.entries(rules.groups)) console.log(`  @${g}: ${who.join(', ') || '(empty)'}`);
  console.log('files (first match wins):');
  for (const [glob, who] of m.files) console.log(`  ${glob}  ${JSON.stringify(rules.files[glob])} -> ${who.join(', ') || '(nobody)'}`);
  console.log('members:');
  for (const [u, k] of Object.entries(m.keys)) console.log(`  ${u}  ${vc.fingerprint(k)}`);
  const req = path.join(top, rp.REQUESTS_DIR);
  const pending = fs.existsSync(req) ? fs.readdirSync(req).filter((f) => f.endsWith('.pub')) : [];
  if (pending.length) console.log(`pending requests: ${pending.map((f) => f.slice(0, -4)).join(', ')}  (eyesonly grant <name> --from-request)`);
}
