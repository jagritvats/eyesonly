// Upload-pack request filtering: closes the have-negotiation object-existence oracle.
//
// In fetch negotiation a client sends `have <sha>` and the server ACKs the shas it
// holds. Without filtering, anyone who knows (or guesses) a SHA can learn whether a
// private commit exists on the server. The proxy parses the pkt-line body, drops every
// have/shallow line whose object is not a commit reachable from the refs this user can
// see, and forwards the rest byte-for-byte. A dropped have looks exactly like a have
// for an object the server never had.

import zlib from 'node:zlib';
import { spawn } from 'node:child_process';

export const DEFAULT_MAX_BODY = 10 * 1024 * 1024;

export class NegotiateError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
const bad = (msg) => new NegotiateError(400, `[eyesonly] ${msg}`);

// ------------------------------------------------------------- pkt-lines

const SPECIAL = { 0: 'flush', 1: 'delim', 2: 'end' };

export function parsePktLines(buf) {
  const out = [];
  let i = 0;
  while (i < buf.length) {
    if (i + 4 > buf.length) throw bad('malformed pkt-line (truncated length header)');
    const hex = buf.toString('latin1', i, i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw bad('malformed pkt-line (length is not hex)');
    const len = parseInt(hex, 16);
    if (SPECIAL[len]) {
      out.push({ type: SPECIAL[len] });
      i += 4;
      continue;
    }
    if (len === 3) throw bad('malformed pkt-line (invalid length 0003)');
    if (i + len > buf.length) throw bad('malformed pkt-line (length runs past the end of the body)');
    out.push({ type: 'data', payload: buf.subarray(i + 4, i + len) });
    i += len;
  }
  return out;
}

const CODES = { flush: '0000', delim: '0001', end: '0002' };

export function serializePktLines(pkts) {
  const parts = [];
  for (const p of pkts) {
    if (p.type === 'data') {
      parts.push(Buffer.from((p.payload.length + 4).toString(16).padStart(4, '0'), 'latin1'), p.payload);
    } else parts.push(Buffer.from(CODES[p.type], 'latin1'));
  }
  return Buffer.concat(parts);
}

// --------------------------------------------------------- classification

const OID_LINE = /^(have|shallow) ([0-9a-f]{40}|[0-9a-f]{64})\n?$/;

/** Returns { kind: 'oid', sha } for have/shallow lines, { kind: 'pass' } otherwise; throws on bad lines. */
export function classify(payload) {
  const s = payload.toString('latin1');
  if (s.startsWith('have ') || s.startsWith('shallow ')) {
    const m = s.match(OID_LINE);
    if (!m) throw bad(`malformed '${s.split(' ')[0]}' line (expected 40 or 64 lowercase hex digits)`);
    return { kind: 'oid', sha: m[2] };
  }
  if (s.startsWith('deepen-not ')) throw bad('deepen-not is not supported by eyesonly (it resolves ref names, hidden ones included). Use --depth or --shallow-since.');
  return { kind: 'pass' };
}

// ----------------------------------------------------------- reachability

function run(gitDir, args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn('git', ['--git-dir', gitDir, ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.stdin.on('error', () => {}); // EPIPE if git exits early; reported via the exit code
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) return resolve(Buffer.concat(out).toString('utf8'));
      reject(new Error(`git ${args[0]} failed (${code}): ${Buffer.concat(err).toString('utf8').trim()}`));
    });
    child.stdin.end(input || '');
  });
}
const lines = (s) => s.split('\n').filter(Boolean);

const isHidden = (ref, hiddenPrefixes) => hiddenPrefixes.some((p) => ref === p || ref.startsWith(p + '/'));

/** Returns the subset of `shas` that are commits reachable from refs visible to the user. */
export async function visibleHaves({ gitDir, shas, hiddenPrefixes = [] }) {
  const keep = new Set();
  const unique = [...new Set(shas)];
  if (!unique.length) return keep;

  const tips = lines(await run(gitDir, ['for-each-ref', '--format=%(objectname) %(refname)']))
    .map((l) => l.split(' '))
    .filter(([, ref]) => !isHidden(ref, hiddenPrefixes))
    .map(([oid]) => oid);
  if (!tips.length) return keep;

  const commits = lines(await run(gitDir, ['cat-file', '--batch-check=%(objectname) %(objecttype)'], unique.join('\n') + '\n'))
    .map((l) => l.split(' '))
    .filter(([, type]) => type === 'commit')
    .map(([oid]) => oid);
  if (!commits.length) return keep;

  // Commits reachable from the haves but not from any visible tip: the invisible part.
  const input = [...commits, '--not', ...new Set(tips)].join('\n') + '\n';
  const invisible = new Set(lines(await run(gitDir, ['rev-list', '--stdin'], input)));
  for (const c of commits) if (!invisible.has(c)) keep.add(c);
  return keep;
}

// ------------------------------------------------------------ request body

function decode(body, contentEncoding, maxBytes) {
  const enc = String(contentEncoding || 'identity').trim().toLowerCase();
  if (enc === 'identity' || enc === '') return body;
  if (enc !== 'gzip' && enc !== 'x-gzip') throw new NegotiateError(400, `[eyesonly] unsupported Content-Encoding '${enc}' (use gzip or none)`);
  try {
    return zlib.gunzipSync(body, { maxOutputLength: maxBytes });
  } catch (e) {
    if (e.code === 'ERR_BUFFER_TOO_LARGE' || e instanceof RangeError) {
      throw new NegotiateError(413, `[eyesonly] upload-pack request is larger than ${maxBytes} bytes once decompressed`);
    }
    throw bad('upload-pack request body is not valid gzip');
  }
}

/** Parses an upload-pack request, drops have/shallow lines for invisible objects, re-serializes it. */
export async function filterUploadPackBody({ body, contentEncoding, gitDir, hiddenPrefixes = [], maxBytes = DEFAULT_MAX_BODY }) {
  if (body.length > maxBytes) throw new NegotiateError(413, `[eyesonly] upload-pack request is larger than ${maxBytes} bytes`);
  const raw = decode(body, contentEncoding, maxBytes);
  if (!raw.length) throw bad('empty upload-pack request');
  const pkts = parsePktLines(raw);
  const tagged = pkts.map((p) => ({ p, c: p.type === 'data' ? classify(p.payload) : { kind: 'pass' } }));
  const shas = tagged.filter((t) => t.c.kind === 'oid').map((t) => t.c.sha);
  if (!shas.length) return raw;
  const keep = await visibleHaves({ gitDir, shas, hiddenPrefixes });
  return serializePktLines(tagged.filter((t) => t.c.kind === 'pass' || keep.has(t.c.sha)).map((t) => t.p));
}
