// Where a user's identity (private keys) comes from, in this order:
//
//   1. EYESONLY_IDENTITY: the identity JSON, or base64 of it. For CI and containers,
//      where a secret is easier to pass as an environment variable than as a file.
//   2. The store recorded in $EYESONLY_HOME/config.json (no secrets in it):
//        "keychain": the OS keychain (macOS Keychain, Windows DPAPI, Linux Secret Service)
//        "file":     $EYESONLY_HOME/identity.json, mode 0600 (the default)
//   3. $EYESONLY_HOME/identity.json if it exists (identities made before config.json).
//
// The secret never goes on a command line: every backend gets it on stdin and returns
// it on stdout. Error messages never include it.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

export const eyesonlyHome = () => process.env.EYESONLY_HOME || path.join(os.homedir(), '.eyesonly');
export const identityPath = () => path.join(eyesonlyHome(), 'identity.json');
const configPath = () => path.join(eyesonlyHome(), 'config.json');
const dpapiPath = () => path.join(eyesonlyHome(), 'identity.dpapi');

const SERVICE = 'eyesonly';

const fromEnv = () => {
  const v = process.env.EYESONLY_IDENTITY;
  return v != null && v.trim() !== '' ? v.trim() : null;
};

// ------------------------------------------------------------------ config

export function readConfig() {
  try {
    const c = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
    return c && typeof c === 'object' ? c : {};
  } catch {
    return {};
  }
}

function writeConfig(c) {
  fs.mkdirSync(eyesonlyHome(), { recursive: true, mode: 0o700 });
  fs.writeFileSync(configPath() + '.tmp', JSON.stringify(c, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(configPath() + '.tmp', configPath());
}

/** 'keychain' or 'file': where this machine keeps the identity (EYESONLY_IDENTITY aside). */
export const configuredStore = () => (readConfig().store === 'keychain' ? 'keychain' : 'file');

// ---------------------------------------------------------------- backends

/** Which keychain backend this platform uses, for messages. */
export function keychainKind() {
  if (process.env.EYESONLY_KEYCHAIN_SHIM) return 'test keychain shim';
  if (process.platform === 'darwin') return 'macOS Keychain';
  if (process.platform === 'win32') return 'Windows DPAPI';
  return 'Secret Service (secret-tool)';
}

function run(cmd, args, input) {
  const r = spawnSync(cmd, args, { input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  if (r.error) return { ok: false, missing: r.error.code === 'ENOENT', err: r.error.message };
  return { ok: r.status === 0, out: r.stdout || '', err: (r.stderr || '').trim(), status: r.status };
}

// Test-only: a node script that stands in for the OS keychain, called as
// `node <shim> store|lookup|delete <account>` with the secret on stdin/stdout.
function shim(op, account, input) {
  return run(process.execPath, [process.env.EYESONLY_KEYCHAIN_SHIM, op, account], input);
}

// macOS: `security -i` reads commands from stdin, so the secret is never in argv (where
// `ps` would show it). EYESONLY_KEYCHAIN (a keychain file path) is for tests and CI.
function macKeychainArg() {
  return process.env.EYESONLY_KEYCHAIN ? ` ${JSON.stringify(process.env.EYESONLY_KEYCHAIN)}` : '';
}

// Windows: DPAPI (CurrentUser scope) through Windows PowerShell; plaintext on stdin.
const PS = ['-NoProfile', '-NonInteractive', '-Command'];
const PS_PROTECT =
  'Add-Type -AssemblyName System.Security; $s=[Console]::In.ReadToEnd();' +
  "$p=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($s),$null,'CurrentUser');" +
  '[Console]::Out.Write([Convert]::ToBase64String($p))';
const PS_UNPROTECT =
  'Add-Type -AssemblyName System.Security; $s=[Console]::In.ReadToEnd().Trim();' +
  "$b=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($s),$null,'CurrentUser');" +
  '[Console]::Out.Write([Text.Encoding]::UTF8.GetString($b))';

const unavailable = (what) =>
  new Error(`the OS keychain isn't available here (${what}). Use \`--store file\`, or set EYESONLY_IDENTITY`);

function kcStore(account, secret) {
  let r;
  if (process.env.EYESONLY_KEYCHAIN_SHIM) r = shim('store', account, secret);
  else if (process.platform === 'darwin') {
    r = run('/usr/bin/security', ['-i'], `add-generic-password -U -s ${SERVICE} -a ${account} -l eyesonly -w ${secret}${macKeychainArg()}\n`);
    if (r.ok && /error|SecKeychain/i.test(r.err)) r.ok = false;
  } else if (process.platform === 'win32') {
    r = run('powershell.exe', [...PS, PS_PROTECT], secret);
    if (r.ok) {
      fs.mkdirSync(eyesonlyHome(), { recursive: true, mode: 0o700 });
      fs.writeFileSync(dpapiPath(), r.out.trim() + '\n', { mode: 0o600 });
    }
  } else {
    r = run('secret-tool', ['store', '--label', 'eyesonly identity', 'service', SERVICE, 'account', account], secret);
    if (r.missing) throw unavailable('secret-tool not found; install libsecret-tools');
  }
  if (r.missing) throw unavailable(r.err);
  if (!r.ok) throw new Error(`couldn't save the identity to the ${keychainKind()}: ${r.err || `exit ${r.status}`}`);
}

/** Returns the stored secret, or null if there's no entry. */
function kcLookup(account) {
  let r;
  if (process.env.EYESONLY_KEYCHAIN_SHIM) r = shim('lookup', account);
  else if (process.platform === 'darwin') {
    const args = ['find-generic-password', '-s', SERVICE, '-a', account, '-w'];
    if (process.env.EYESONLY_KEYCHAIN) args.push(process.env.EYESONLY_KEYCHAIN);
    r = run('/usr/bin/security', args);
  } else if (process.platform === 'win32') {
    if (!fs.existsSync(dpapiPath())) return null;
    r = run('powershell.exe', [...PS, PS_UNPROTECT], fs.readFileSync(dpapiPath(), 'utf8'));
  } else {
    r = run('secret-tool', ['lookup', 'service', SERVICE, 'account', account]);
    if (r.missing) throw unavailable('secret-tool not found; install libsecret-tools');
    if (!r.ok && !r.err) return null; // secret-tool exits 1 silently when there's no match
  }
  if (r.missing) throw unavailable(r.err);
  if (!r.ok) {
    if (/could not be found|not found|no such|status 44/i.test(r.err) || r.status === 44) return null;
    throw new Error(`couldn't read the identity from the ${keychainKind()}: ${r.err || `exit ${r.status}`}`);
  }
  const out = r.out.trim();
  return out || null;
}

function kcDelete(account) {
  if (process.env.EYESONLY_KEYCHAIN_SHIM) return shim('delete', account).ok;
  if (process.platform === 'darwin') {
    const args = ['delete-generic-password', '-s', SERVICE, '-a', account];
    if (process.env.EYESONLY_KEYCHAIN) args.push(process.env.EYESONLY_KEYCHAIN);
    return run('/usr/bin/security', args).ok;
  }
  if (process.platform === 'win32') {
    fs.rmSync(dpapiPath(), { force: true });
    return true;
  }
  return run('secret-tool', ['clear', 'service', SERVICE, 'account', account]).ok;
}

// ----------------------------------------------------------------- reading

function check(id, where) {
  const ok = (k) => typeof k?.pub === 'string' && typeof k?.priv === 'string';
  if (!id || typeof id.name !== 'string' || !ok(id.x25519) || !ok(id.ed25519)) {
    throw new Error(`${where} is not an eyesonly identity (expected the JSON written by \`eyesonly keygen\`)`);
  }
  return id;
}

const encode = (id) => Buffer.from(JSON.stringify(id)).toString('base64');
const decodeSecret = (s, where) => {
  try {
    return check(JSON.parse(Buffer.from(s, 'base64').toString('utf8')), where);
  } catch (e) {
    if (e.message.includes('is not an eyesonly identity')) throw e;
    throw new Error(`${where} doesn't hold a readable identity`);
  }
};

/** Human-readable source, for messages: "EYESONLY_IDENTITY", the keychain entry, or the file path. */
export function identitySource() {
  if (fromEnv()) return 'EYESONLY_IDENTITY';
  const c = readConfig();
  if (c.store === 'keychain') return `${keychainKind()} (${SERVICE}/${c.account})`;
  return identityPath();
}

// One lookup per process: the long-running filter process handles many files, and a
// keychain round trip (PowerShell on Windows) costs hundreds of milliseconds.
let cache = null;
const cacheKey = () => `${fromEnv() ?? ''}\0${eyesonlyHome()}\0${process.env.EYESONLY_KEYCHAIN_SHIM ?? ''}`;

/** Returns the identity, or null if none is configured. Throws a safe Error if it's unreadable. */
export function readIdentity() {
  const key = cacheKey();
  if (cache && cache.key === key) return cache.id;
  const id = readUncached();
  cache = id ? { key, id } : null;
  return id;
}

function readUncached() {
  const env = fromEnv();
  if (env) {
    const text = env.startsWith('{') ? env : Buffer.from(env, 'base64').toString('utf8');
    let id;
    try {
      id = JSON.parse(text);
    } catch {
      // JSON.parse messages quote the input, which would print key material.
      throw new Error('EYESONLY_IDENTITY is set but is neither identity JSON nor base64 of it');
    }
    return check(id, 'EYESONLY_IDENTITY');
  }
  const c = readConfig();
  if (c.store === 'keychain') {
    const where = identitySource();
    const s = kcLookup(c.account);
    if (!s) throw new Error(`no identity in the ${where}, but ${configPath()} says it's there. Restore the keychain entry, or put a backup at ${identityPath()} and delete ${configPath()}`);
    return decodeSecret(s, where);
  }
  return readFile();
}

function readFile() {
  const p = identityPath();
  if (!fs.existsSync(p)) return null;
  let id;
  try {
    id = JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    throw new Error(`can't parse your identity at ${p} (not valid JSON)`);
  }
  return check(id, p);
}

// ----------------------------------------------------------------- writing

/** Is there already an identity on this machine (ignoring EYESONLY_IDENTITY)? Returns where, or null. */
export function existingIdentity() {
  const c = readConfig();
  if (c.store === 'keychain' && c.account) return identitySourceFor('keychain', c.account);
  return fs.existsSync(identityPath()) ? identityPath() : null;
}

const identitySourceFor = (store, account) => (store === 'keychain' ? `${keychainKind()} (${SERVICE}/${account})` : identityPath());

/** Save a new identity to `store` and record the choice. Returns where it went. */
export function saveIdentity(id, store) {
  check(id, 'identity');
  if (store === 'keychain') {
    kcStore(id.name, encode(id));
    const back = kcLookup(id.name);
    if (!back || JSON.stringify(decodeSecret(back, 'keychain')) !== JSON.stringify(id)) {
      throw new Error(`the ${keychainKind()} didn't return what was saved; nothing changed`);
    }
    writeConfig({ ...readConfig(), store: 'keychain', account: id.name });
  } else {
    fs.mkdirSync(eyesonlyHome(), { recursive: true, mode: 0o700 });
    fs.writeFileSync(identityPath() + '.tmp', JSON.stringify(id, null, 2), { mode: 0o600 });
    fs.renameSync(identityPath() + '.tmp', identityPath());
    const { store: _s, account: _a, ...rest } = readConfig();
    writeConfig({ ...rest, store: 'file' });
  }
  cache = null;
  return identitySourceFor(store, id.name);
}

/**
 * Move the identity between stores. The copy is written and read back before the old one
 * is removed, so a failed move leaves the identity where it was.
 */
export function moveIdentity(to) {
  if (fromEnv()) throw new Error('EYESONLY_IDENTITY is set; unset it to move the stored identity');
  const from = configuredStore();
  const c = readConfig();
  const id = from === 'keychain' ? decodeSecret(kcLookup(c.account) ?? '', identitySource()) : readFile();
  if (!id) throw new Error(`no identity at ${identityPath()} to move`);
  if (from === to) return { id, from, to, where: identitySource(), moved: false };
  if (to === 'file' && fs.existsSync(identityPath())) throw new Error(`${identityPath()} already exists; remove it first`);
  const where = saveIdentity(id, to);
  if (from === 'keychain') kcDelete(c.account);
  else fs.rmSync(identityPath(), { force: true });
  return { id, from, to, where, moved: true };
}

/** base64 of the identity JSON, the format EYESONLY_IDENTITY accepts. */
export const exportIdentity = (id) => encode(id);
