// git's long-running filter process protocol, version 2 (gitattributes(5), "Long Running
// Filter Process"). One node process serves every clean/smudge of a git command instead of
// one process per file.
//
// Only `clean` and `smudge` are advertised. `delay` is never offered: delayed checkout is
// what CVE-2021-21300 abused, and nothing here needs it.
//
// The per-file logic is passed in (the same functions the single-shot `eyesonly clean` and
// `eyesonly smudge` commands use), so both modes enforce exactly the same rules.

const MAX_DATA = 65516; // LARGE_PACKET_DATA_MAX
export const CAPABILITIES = ['clean', 'smudge'];

const FLUSH = Symbol('flush');

/** Incremental pkt-line reader over a readable stream. */
function pktReader(stream) {
  let buf = Buffer.alloc(0);
  let ended = false;
  let waiting = null;
  const wake = () => {
    const w = waiting;
    waiting = null;
    w?.();
  };
  stream.on('data', (c) => {
    buf = buf.length ? Buffer.concat([buf, c]) : c;
    wake();
  });
  stream.on('end', () => {
    ended = true;
    wake();
  });
  stream.on('error', () => {
    ended = true;
    wake();
  });

  async function need(n) {
    while (buf.length < n) {
      if (ended) return false;
      await new Promise((r) => (waiting = r));
    }
    return true;
  }

  /** Returns a Buffer, FLUSH, or null at a clean EOF between packets. */
  async function read() {
    if (!(await need(4))) {
      if (buf.length) throw new Error('truncated pkt-line header');
      return null;
    }
    const len = parseInt(buf.subarray(0, 4).toString('latin1'), 16);
    if (Number.isNaN(len)) throw new Error('bad pkt-line length');
    if (len === 0) {
      buf = buf.subarray(4);
      return FLUSH;
    }
    if (len < 4) throw new Error(`unsupported pkt-line ${len}`);
    if (!(await need(len))) throw new Error('truncated pkt-line');
    const data = buf.subarray(4, len);
    buf = buf.subarray(len);
    return data;
  }

  /** Text lines up to a flush, without trailing LFs. null at EOF. */
  async function readList() {
    const out = [];
    for (;;) {
      const p = await read();
      if (p === null) {
        if (out.length) throw new Error('EOF inside a pkt-line list');
        return null;
      }
      if (p === FLUSH) return out;
      out.push(p.toString('utf8').replace(/\n$/, ''));
    }
  }

  /** Binary content up to a flush. */
  async function readContent() {
    const parts = [];
    for (;;) {
      const p = await read();
      if (p === null) throw new Error('EOF inside content');
      if (p === FLUSH) return Buffer.concat(parts);
      parts.push(p);
    }
  }

  return { readList, readContent };
}

const hdr = (n) => n.toString(16).padStart(4, '0');
const textPkt = (s) => {
  const b = Buffer.from(s + '\n', 'utf8');
  return Buffer.concat([Buffer.from(hdr(b.length + 4), 'latin1'), b]);
};
const flushPkt = Buffer.from('0000', 'latin1');
function contentPkts(buf) {
  const out = [];
  for (let i = 0; i < buf.length; i += MAX_DATA) {
    const part = buf.subarray(i, i + MAX_DATA);
    out.push(Buffer.from(hdr(part.length + 4), 'latin1'), part);
  }
  return out;
}

function writer(stream) {
  return async (parts) => {
    if (!stream.write(Buffer.concat(parts))) await new Promise((r) => stream.once('drain', r));
  };
}

/**
 * A long-lived `git cat-file --batch` for blob lookups (`:path`, `HEAD:path`, ...).
 * cat-file reads the index once, and one filter process can outlive several index and
 * HEAD updates (a rebase runs every pick in one git process), so it is restarted whenever
 * the index, HEAD or refs change on disk.
 */
export class BlobReader {
  constructor({ spawn, fs, path, gitDir, commonDir, fallback }) {
    Object.assign(this, { spawn, fs, path, gitDir, commonDir, fallback });
    this.proc = null;
    this.key = null;
    this.buf = Buffer.alloc(0);
    this.dead = false;
    this.waiting = null;
  }

  stamp(p) {
    try {
      const s = this.fs.statSync(p);
      return `${s.mtimeMs}:${s.size}:${s.ino}`;
    } catch {
      return '-';
    }
  }

  stateKey() {
    const { fs, path } = this;
    const index = process.env.GIT_INDEX_FILE ? path.resolve(process.env.GIT_INDEX_FILE) : path.join(this.gitDir, 'index');
    let head = '';
    try {
      head = fs.readFileSync(path.join(this.gitDir, 'HEAD'), 'utf8').trim();
    } catch {}
    const ref = head.startsWith('ref: ') ? this.stamp(path.join(this.commonDir, head.slice(5))) : '';
    return [this.stamp(index), head, ref, this.stamp(path.join(this.commonDir, 'packed-refs'))].join('|');
  }

  start() {
    this.buf = Buffer.alloc(0);
    this.dead = false;
    const p = this.spawn('git', ['cat-file', '--batch'], { stdio: ['pipe', 'pipe', 'ignore'] });
    p.stdout.on('data', (c) => {
      this.buf = this.buf.length ? Buffer.concat([this.buf, c]) : c;
      this.wake();
    });
    p.on('close', () => {
      this.dead = true;
      this.wake();
    });
    p.stdin.on('error', () => {});
    this.proc = p;
  }

  stop() {
    if (!this.proc) return;
    this.proc.stdin.end();
    this.proc = null;
  }

  wake() {
    const w = this.waiting;
    this.waiting = null;
    w?.();
  }

  async need(test) {
    while (!test()) {
      if (this.dead) throw new Error('git cat-file exited');
      await new Promise((r) => (this.waiting = r));
    }
  }

  async readOne() {
    await this.need(() => this.buf.indexOf(0x0a) !== -1);
    const nl = this.buf.indexOf(0x0a);
    const header = this.buf.subarray(0, nl).toString('utf8');
    this.buf = this.buf.subarray(nl + 1);
    const f = header.split(' ');
    const size = Number(f[2]);
    if (f.length !== 3 || !Number.isFinite(size) || / (missing|ambiguous)$/.test(header)) return null;
    await this.need(() => this.buf.length >= size + 1);
    const data = Buffer.from(this.buf.subarray(0, size));
    this.buf = this.buf.subarray(size + 1);
    return f[1] === 'blob' ? data : null;
  }

  /** Same contract as the client's catBlobs(): a Buffer or null per name. */
  async get(names) {
    if (names.some((n) => n.includes('\n'))) return this.fallback(names);
    const key = this.stateKey();
    if (!this.proc || this.dead || key !== this.key) {
      this.stop();
      this.start();
      this.key = key;
    }
    try {
      this.proc.stdin.write(names.join('\n') + '\n');
      const out = [];
      for (let i = 0; i < names.length; i++) out.push(await this.readOne());
      return out;
    } catch {
      this.stop();
      return this.fallback(names);
    }
  }
}

const kv = (lines) =>
  Object.fromEntries(lines.filter((l) => l.includes('=')).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));

/**
 * Serve git until it closes stdin.
 * @param {{ clean: (input: Buffer, path: string) => Buffer | Promise<Buffer>, smudge: (input: Buffer, path: string) => Buffer | Promise<Buffer>, log: (msg: string) => void }} handlers
 */
export async function runFilterProcess({ clean, smudge, log }, input = process.stdin, output = process.stdout) {
  const r = pktReader(input);
  const write = writer(output);

  const hello = await r.readList();
  if (!hello || hello[0] !== 'git-filter-client' || !hello.includes('version=2')) {
    throw new Error(`unexpected filter handshake: ${JSON.stringify(hello)}`);
  }
  await write([textPkt('git-filter-server'), textPkt('version=2'), flushPkt]);

  const offered = (await r.readList()) || [];
  const caps = CAPABILITIES.filter((c) => offered.includes(`capability=${c}`));
  await write([...caps.map((c) => textPkt(`capability=${c}`)), flushPkt]);

  const handlers = { clean, smudge };
  for (;;) {
    const head = await r.readList();
    if (head === null) return; // git is done
    const req = kv(head);
    const content = await r.readContent();
    let out = null;
    try {
      if (!caps.includes(req.command)) throw new Error(`unsupported filter command '${req.command}'`);
      out = await handlers[req.command](content, req.pathname);
    } catch (e) {
      log(e?.message || String(e));
    }
    if (!Buffer.isBuffer(out)) {
      await write([textPkt('status=error'), flushPkt]);
      continue;
    }
    // status, content, then an empty list: "status unchanged" (success).
    await write([textPkt('status=success'), flushPkt, ...contentPkts(out), flushPkt, flushPkt]);
  }
}
