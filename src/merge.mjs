// Merge driver for protected files: `merge.eyesonly.driver = eyesonly merge-file %O %A %B %P %L`.
//
// seal() emits a fresh ciphertext every time, so two concurrent edits to `.env` always
// conflict inside the envelope. This driver:
//   1. verifies all three sides (signature by an allowed writer, bound to this path),
//      because re-sealing a forged side under the merger's key would launder it,
//   2. decrypts them into 0600 temp files under <common git dir>/eyesonly/tmp (removed on
//      every path), runs `git merge-file` on the plaintext,
//   3. clean merge: re-seals for the file's audience, signed by the merger (exit 0);
//      conflicts: writes plaintext with conflict markers to %A (exit 1), and the user's
//      `git add` seals the resolution through the clean filter.
// On any refusal %A is left untouched (ours) and the driver exits 1, so git reports a
// conflict and the user can pick a side with `git checkout --ours/--theirs`.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import * as vc from './crypto.mjs';
import { fileRule } from './policy.mjs';
import { tryOpen, loadPolicy, loadIdentity, recipientsFor } from './client.mjs';

const log = (msg) => console.error('[eyesonly] ' + msg);
const STALE_MS = 60 * 60 * 1000;

class Refusal extends Error {}
const refuse = (msg) => {
  throw new Refusal(msg);
};

function readSide(file) {
  try {
    return fs.readFileSync(file);
  } catch {
    return Buffer.alloc(0);
  }
}

/** Decrypt one side after verifying it. Returns { plaintext, env } or { env } (not a reader). */
function openSide(name, blob, P, policy, id) {
  if (!vc.isEnvelope(blob)) {
    // Only an empty base (add/add) is acceptable without an envelope.
    if (name === 'base' && blob.length === 0) return { plaintext: blob };
    refuse(`${name} is not an eyesonly envelope`);
  }
  const r = tryOpen(blob, P, policy, id);
  if (r.error) refuse(`${name}: ${r.error}`);
  return r;
}

const isBinary = (buf) => buf.subarray(0, 8000).includes(0);

function tmpDir() {
  const common = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], { encoding: 'utf8' }).trim();
  const dir = path.join(common, 'eyesonly', 'tmp');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700); // mkdir honours umask, and the dir may predate us
  const now = Date.now();
  for (const f of fs.readdirSync(dir)) {
    const p = path.join(dir, f);
    try {
      if (now - fs.statSync(p).mtimeMs > STALE_MS) fs.unlinkSync(p);
    } catch {
      /* raced with another merge: fine */
    }
  }
  return dir;
}

/** Three-way merge of plaintexts via `git merge-file`. Temp files never outlive this call. */
function mergePlaintext(dir, ours, base, theirs, markerSize) {
  const files = [];
  try {
    const put = (buf) => {
      const p = path.join(dir, crypto.randomBytes(16).toString('hex'));
      files.push(p);
      fs.writeFileSync(p, buf, { mode: 0o600, flag: 'wx' });
      return p;
    };
    const [a, o, b] = [put(ours), put(base), put(theirs)];
    const r = spawnSync(
      'git',
      ['merge-file', '-p', `--marker-size=${markerSize}`, '-L', 'ours', '-L', 'base', '-L', 'theirs', a, o, b],
      { maxBuffer: 1 << 30 }
    );
    if (r.error || r.status == null || r.status >= 128) {
      const why = String(r.stderr || r.error?.message || '').trim();
      refuse(/binary/i.test(why) ? 'binary content; pick a side' : `git merge-file failed: ${why || 'signal ' + r.signal}`);
    }
    return { merged: r.stdout, conflicts: r.status };
  } finally {
    for (const p of files) {
      try {
        fs.unlinkSync(p);
      } catch {
        /* already gone */
      }
    }
  }
}

function mergeFile([O, A, B, P, L]) {
  const policy = loadPolicy();
  const id = loadIdentity();
  const dir = tmpDir(); // sweep leftovers from crashed merges on every run
  const allowed = fileRule(policy, P);
  if (!allowed) refuse(`'${P}' has merge=eyesonly in .gitattributes but no rule in the policy`);

  const sides = { ours: readSide(A), base: readSide(O), theirs: readSide(B) };
  const opened = {};
  for (const [name, blob] of Object.entries(sides)) opened[name] = openSide(name, blob, P, policy, id);

  if (Object.values(opened).some((s) => !s.plaintext)) {
    const readers = new Set();
    for (const s of Object.values(opened)) Object.keys(s.env?.keys || {}).forEach((u) => readers.add(u));
    refuse(
      `you are not a reader. Pick a side with \`git checkout --ours/--theirs -- ${P}\`, or ask one of: ${[...readers].sort().join(', ') || '(nobody)'}`
    );
  }
  if (!allowed.includes(id.name)) refuse(`'${id.name}' may not write '${P}'`);

  const { ours, base, theirs } = Object.fromEntries(Object.entries(opened).map(([k, v]) => [k, v.plaintext]));
  if ([ours, base, theirs].some(isBinary)) refuse('binary content; pick a side');

  const markerSize = /^\d+$/.test(L || '') && Number(L) > 0 ? Number(L) : 7;
  const { merged, conflicts } = mergePlaintext(dir, ours, base, theirs, markerSize);
  if (conflicts === 0) {
    fs.writeFileSync(A, vc.seal({ plaintext: merged, path: P, recipients: recipientsFor(policy, allowed), signer: id }));
    return 0;
  }
  // Conflicts: hand git the plaintext with markers. Smudge passes non-envelopes through,
  // and the user's `git add` runs clean, which seals the resolution.
  fs.writeFileSync(A, merged);
  log(`conflict in '${P}' (decrypted for you). Resolve it, then \`git add ${P}\` re-encrypts it.`);
  return 1;
}

export async function cmdMergeFile(args) {
  const P = args[3];
  if (args.length < 4) {
    log('usage: eyesonly merge-file %O %A %B %P [%L] (wired up by eyesonly setup)');
    process.exit(2);
  }
  let code;
  try {
    code = mergeFile(args);
  } catch (e) {
    log(`can't merge '${P}': ${e instanceof Refusal ? e.message : e.stack || e.message}`);
    code = 1;
  }
  process.exit(code);
}
