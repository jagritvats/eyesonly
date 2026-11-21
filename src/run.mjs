// eyesonly run / eyesonly env: load protected dotenv files into a process's environment.
//
// Values come from the staged (index) blob, falling back to HEAD, decrypted with the same
// verifying tryOpen as the smudge filter. The working tree isn't read, so this works in a
// checkout that keeps ciphertext on disk, and a hand-edited working copy can't inject values.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { fileRule } from './policy.mjs';
import { loadIdentity, loadPolicy, tryOpen } from './client.mjs';

const log = (msg) => console.error('[eyesonly] ' + msg);
function die(msg) {
  log(msg);
  process.exit(1);
}

const git = (args, opts = {}) => execFileSync('git', args, { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 30, ...opts });
const tryGit = (args, opts) => {
  try {
    return git(args, opts);
  } catch {
    return null;
  }
};

const DOTENV = /^\.env(\..+)?$/;

// ------------------------------------------------------------------ parsing

/** Parse dotenv text: KEY=VALUE, `export `, quotes, # comments. No interpolation. */
export function parseDotenv(text, where) {
  const out = {};
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const at = `${where}:${i + 1}`;
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) die(`${at}: not a KEY=VALUE line`); // never echo the line: it may hold a secret
    const [, key] = m;
    let rest = m[2];
    const q = rest[0];
    if (q === '"' || q === "'" || q === '`') {
      // Quoted values may span lines; take everything up to the matching unescaped quote.
      let body = rest.slice(1);
      let end = closingQuote(body, q);
      while (end < 0 && i + 1 < lines.length) {
        body += '\n' + lines[++i];
        end = closingQuote(body, q);
      }
      if (end < 0) die(`${at}: unterminated ${q} quote`);
      const after = body.slice(end + 1).trim();
      if (after && !after.startsWith('#')) die(`${at}: unexpected text after the closing quote`);
      body = body.slice(0, end);
      out[key] = q === '"' ? unescapeDouble(body) : body;
    } else {
      out[key] = rest.replace(/\s+#.*$/, '').trim();
    }
  }
  return out;
}

function closingQuote(s, q) {
  for (let i = 0; i < s.length; i++) {
    if (q === '"' && s[i] === '\\') {
      i++;
      continue;
    }
    if (s[i] === q) return i;
  }
  return -1;
}

const unescapeDouble = (s) => s.replace(/\\([nrt"\\])/g, (_, c) => ({ n: '\n', r: '\r', t: '\t', '"': '"', '\\': '\\' })[c]);

// ------------------------------------------------------------------ loading

function parseArgs(argv, { allowCommand }) {
  const opts = { files: [], override: true, format: 'dotenv', command: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      opts.command = argv.slice(i + 1);
      break;
    } else if (a === '--file' || a === '-f') {
      if (!argv[i + 1]) die(`${a} needs a path`);
      opts.files.push(argv[++i]);
    } else if (a === '--no-override') opts.override = false;
    else if (a === '--format' && !allowCommand) opts.format = argv[++i];
    else if (a.startsWith('-')) die(`unknown option ${a}`);
    else if (allowCommand) {
      opts.command = argv.slice(i);
      break;
    } else die(`unexpected argument ${a}`);
  }
  return opts;
}

/** Index blob for `file`, or HEAD's if it isn't staged. */
function committedBlob(file, cwd) {
  return tryGit(['cat-file', 'blob', `:${file}`], { cwd }) ?? tryGit(['cat-file', 'blob', `HEAD:${file}`], { cwd });
}

/**
 * Decrypt and parse the selected dotenv files. Explicit --file paths must all be readable;
 * by default, protected .env / .env.* files the user can't read are skipped with a note.
 * Any forged, moved or tampered envelope aborts the whole load: nothing partial is returned.
 */
export function loadVars(files) {
  const policy = loadPolicy();
  const id = loadIdentity();
  let top;
  try {
    top = git(['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
  } catch {
    die('not inside a git repository. cd into your clone first.');
  }
  const explicit = files.length > 0;
  const rel = (f) => path.relative(top, path.resolve(f)).split(path.sep).join('/');
  const selected = explicit
    ? files.map(rel)
    : git(['ls-files', '-z'], { cwd: top, encoding: 'utf8' })
        .split('\0')
        .filter((f) => f && fileRule(policy, f) && DOTENV.test(path.posix.basename(f)))
        .sort();
  if (!selected.length) die('no protected .env files in this repo. Pick files with --file <path>.');

  const vars = {};
  const loaded = [];
  for (const f of selected) {
    const readers = fileRule(policy, f);
    if (!readers) die(`'${f}' isn't a protected file in this repo's policy`);
    const blob = committedBlob(f, top);
    if (!blob) die(`'${f}' isn't committed or staged`);
    const r = tryOpen(blob, f, policy, id);
    if (r.error) die(`refusing to load '${f}': ${r.error}`);
    if (!r.plaintext) {
      const msg = `you are not a reader of '${f}' (readers: ${readers.join(', ')})`;
      if (explicit) die(msg + '. Nothing was loaded.');
      log(`skipping ${f}: ${msg}`);
      continue;
    }
    warnIfUnstaged(top, f, r.plaintext);
    Object.assign(vars, parseDotenv(r.plaintext.toString('utf8'), f));
    loaded.push(f);
  }
  if (!loaded.length) die(`you can't read any of: ${selected.join(', ')}. Nothing was loaded.`);
  return { vars, loaded };
}

function warnIfUnstaged(top, f, plaintext) {
  try {
    const work = fs.readFileSync(path.join(top, f));
    if (!work.subarray(0, 11).equals(Buffer.from('EYESONLY-V1')) && !work.equals(plaintext)) {
      log(`note: ${f} has unstaged edits; using the staged version (git add it to use your edits)`);
    }
  } catch {}
}

// ----------------------------------------------------------------- commands

export function cmdEnv(argv) {
  const opts = parseArgs(argv, { allowCommand: false });
  const { vars } = loadVars(opts.files);
  log('warning: printing secrets to stdout');
  const fmt = {
    dotenv: () => Object.entries(vars).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join('\n'),
    json: () => JSON.stringify(vars, null, 2),
    shell: () => Object.entries(vars).map(([k, v]) => `export ${k}='${v.replace(/'/g, `'\\''`)}'`).join('\n'),
  }[opts.format];
  if (!fmt) die(`unknown --format '${opts.format}' (dotenv, json or shell)`);
  console.log(fmt());
}

export function cmdRun(argv) {
  const opts = parseArgs(argv, { allowCommand: true });
  if (!opts.command.length) die('usage: eyesonly run [--file <path>]... [--no-override] [--] <command> [args...]');
  const { vars, loaded } = loadVars(opts.files);
  const env = opts.override ? { ...process.env, ...vars } : { ...vars, ...process.env };
  log(`loaded ${Object.keys(vars).length} variable(s) from ${loaded.join(', ')}`);

  const [cmd, ...args] = opts.command;
  const child = spawnCommand(cmd, args, env);
  const forward = (sig) => () => child.kill(sig);
  const signals = ['SIGINT', 'SIGTERM', 'SIGHUP'];
  const handlers = signals.map((s) => [s, forward(s)]);
  for (const [s, h] of handlers) process.on(s, h);
  child.on('error', (e) => die(`can't run '${cmd}': ${e.code === 'ENOENT' ? 'command not found' : e.message}`));
  child.on('exit', (code, signal) => {
    for (const [s, h] of handlers) process.off(s, h);
    if (signal) {
      process.kill(process.pid, signal); // die the same way the child did
      setTimeout(() => process.exit(128 + (os.constants.signals[signal] || 1)), 100); // e.g. Windows
      return;
    }
    process.exit(code ?? 1);
  });
}

// On Windows, .cmd/.bat shims (npm, npx, yarn) can't be spawned without a shell since
// Node's CVE-2024-27980 fix, so resolve them and run them through cmd.exe explicitly.
function spawnCommand(cmd, args, env) {
  const opts = { stdio: 'inherit', env };
  if (process.platform !== 'win32') return spawn(cmd, args, opts);
  const resolved = whichWin(cmd, env);
  if (!resolved || !/\.(cmd|bat)$/i.test(resolved)) return spawn(resolved || cmd, args, opts);
  const quote = (a) => (/^[\w./:=@\\-]+$/.test(a) ? a : `"${a.replace(/"/g, '""')}"`);
  const line = [resolved, ...args].map(quote).join(' ');
  return spawn(env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', `"${line}"`], { ...opts, windowsVerbatimArguments: true });
}

function whichWin(cmd, env) {
  const exts = (env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';');
  const hasExt = path.extname(cmd) !== '';
  const dirs = cmd.includes('/') || cmd.includes('\\') ? [''] : (env.PATH || env.Path || '').split(path.delimiter);
  for (const d of dirs) {
    for (const e of hasExt ? [''] : exts) {
      const p = path.resolve(d, cmd + e);
      if (fs.existsSync(p) && fs.statSync(p).isFile()) return p;
    }
  }
  return null;
}
