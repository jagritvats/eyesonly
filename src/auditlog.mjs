// Append-only audit log: $EYESONLY_DATA/audit.log, one JSON object per line, mode 0600.
//
// Every line carries `prev`, the SHA-256 of the previous line's bytes (the first line
// uses 64 zeros), so editing or deleting a line in the middle breaks the chain and
// `eyesonly-server audit-log --verify` reports where. The chain can't detect the tail
// being cut off or the last line being rewritten; record the head hash that --verify
// prints somewhere else if that matters to you.
//
// The serve process and every pre-receive hook (separate processes) append, so writers
// take a lock file around read-last-line + append. Nothing here ever logs a token,
// a card's private half or file contents: callers pass names, refs, hashes and reasons.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DATA } from './store.mjs';

const GENESIS = '0'.repeat(64);
export const auditFile = () => path.join(DATA(), 'audit.log');
const hash = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function sleepMs(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function withLock(fn) {
  const lock = auditFile() + '.lock';
  const deadline = Date.now() + 5000;
  for (;;) {
    try {
      fs.closeSync(fs.openSync(lock, 'wx', 0o600));
      break;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      try {
        // A writer that crashed mid-append leaves the lock behind; it's stale after 10 s.
        if (Date.now() - fs.statSync(lock).mtimeMs > 10_000) fs.rmSync(lock, { force: true });
      } catch {}
      if (Date.now() > deadline) throw new Error('audit log is locked (another writer is stuck?)');
      sleepMs(10);
    }
  }
  try {
    return fn();
  } finally {
    fs.rmSync(lock, { force: true });
  }
}

/** Last line of the log (without its newline), read from the end. */
function lastLine(file) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
  } catch {
    return null;
  }
  try {
    const size = fs.fstatSync(fd).size;
    let chunk = 4096;
    for (;;) {
      const start = Math.max(0, size - chunk);
      const buf = Buffer.alloc(size - start);
      fs.readSync(fd, buf, 0, buf.length, start);
      const text = buf.toString('utf8').replace(/\n+$/, '');
      const nl = text.lastIndexOf('\n');
      if (nl !== -1 || start === 0) return text.slice(nl + 1) || null;
      chunk *= 4;
    }
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Append one event. Failures to log never break the request that caused them (the
 * operator sees a warning on stderr); a missing data dir is created.
 */
export function audit(type, fields = {}) {
  try {
    fs.mkdirSync(DATA(), { recursive: true, mode: 0o700 });
    withLock(() => {
      const file = auditFile();
      const prevLine = lastLine(file);
      const prev = prevLine ? hash(Buffer.from(prevLine)) : GENESIS;
      const line = JSON.stringify({ ts: new Date().toISOString(), type, ...fields, prev });
      const fd = fs.openSync(file, 'a', 0o600);
      try {
        fs.writeSync(fd, line + '\n');
      } finally {
        fs.closeSync(fd);
      }
    });
  } catch (e) {
    console.error(`[eyesonly-server] warning: could not write the audit log: ${e.message}`);
  }
}

export function readEntries() {
  const file = auditFile();
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((raw, i) => {
      try {
        return { n: i + 1, raw, e: JSON.parse(raw) };
      } catch {
        return { n: i + 1, raw, e: null };
      }
    });
}

/** Check the hash chain. Returns { ok, lines, head } or { ok: false, line, reason }. */
export function verifyChain() {
  let prev = GENESIS;
  const entries = readEntries();
  for (const { n, raw, e } of entries) {
    if (!e) return { ok: false, line: n, reason: 'not valid JSON' };
    if (e.prev !== prev) return { ok: false, line: n, reason: 'hash chain broken (a line before it was changed, removed or inserted)' };
    prev = hash(Buffer.from(raw));
  }
  return { ok: true, lines: entries.length, head: prev };
}

const SUMMARY = {
  auth_failure: (e) => `${e.route} auth failed for ${e.user ? `'${e.user}'` : 'unknown user'} from ${e.ip}`,
  lockout: (e) => `locked out ${e.user ? `'${e.user}'` : 'unknown user'} from ${e.ip} for ${Math.round(e.ms / 1000)}s after ${e.failures} failures`,
  push: (e) => `${e.user} pushed ${e.repo}: ${(e.refs || []).map((r) => `${r.ref} ${r.old.slice(0, 8)}..${r.new.slice(0, 8)}`).join(', ') || '(no refs)'} ${e.result}${e.reason ? `: ${e.reason}` : ''}`,
  policy_fetch: (e) => `${e.user} fetched the ${e.repo} policy`,
  admin: (e) => `${e.actor} ${e.action}${e.target ? ` ${e.target}` : ''}${e.repo ? ` (${e.repo})` : ''}${e.via ? ` via ${e.via}` : ''}`,
  attestation: (e) => `${e.actor} installed ${e.repo} policy v${e.version} signed by ${e.signer}${e.via ? ` via ${e.via}` : ''}`,
};

/** eyesonly-server audit-log [--repo r] [--user u] [--since date] [--type t] [--json] [--verify] */
export function cmdAuditLog(args) {
  const opt = (k) => (args.includes(k) ? args[args.indexOf(k) + 1] : undefined);
  if (args.includes('--verify')) {
    const r = verifyChain();
    if (!r.ok) {
      console.error(`[eyesonly-server] audit log FAILED verification at line ${r.line}: ${r.reason}`);
      process.exit(1);
    }
    console.log(`ok: ${r.lines} line(s), chain intact. Head: ${r.head}`);
    return;
  }
  const repo = opt('--repo');
  const user = opt('--user');
  const type = opt('--type');
  const sinceArg = opt('--since');
  const since = sinceArg ? Date.parse(sinceArg) : null;
  if (sinceArg && Number.isNaN(since)) {
    console.error(`[eyesonly-server] --since: not a date: ${sinceArg}`);
    process.exit(1);
  }
  for (const { raw, e } of readEntries()) {
    if (!e) continue;
    if (repo && e.repo !== repo) continue;
    if (user && e.user !== user && e.actor !== user && e.target !== user) continue;
    if (type && e.type !== type) continue;
    if (since && Date.parse(e.ts) < since) continue;
    if (args.includes('--json')) console.log(raw);
    else console.log(`${e.ts}  ${(SUMMARY[e.type] || ((x) => JSON.stringify(x)))(e)}`);
  }
}
