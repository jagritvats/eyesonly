// Attribute pinning: keep protected paths on filter=eyesonly no matter what the tree says.
//
// The eyesonly filter used to be wired only through the in-tree .gitattributes, which any
// member can edit. A later `.env filter=lfs` line or a nested `secrets/.gitattributes`
// wins over it, and git would hand the plaintext to that other filter (git-lfs uploads
// it from its pre-push hook, before the eyesonly server sees anything).
//
// - Client: `$GIT_COMMON_DIR/info/attributes` takes precedence over every in-tree file,
//   so `pinAttributes` writes the eyesonly lines there, in a managed block.
// - Client: `checkResolvedFilters` asks git what a path really resolves to (pre-commit,
//   eyesonly status).
// - Server: `checkCommitAttributes` refuses commits whose .gitattributes / .lfsconfig
//   changes would redirect a protected path, for clients that never ran `eyesonly setup`.
//
// Must not import client.mjs or hooks.mjs (both import this file).
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileRule } from './policy.mjs';

const BEGIN = '# >>> eyesonly (managed) >>>';
const END = '# <<< eyesonly (managed) <<<';

function run(args, opts = {}) {
  return execFileSync('git', args, { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', maxBuffer: 1 << 30, ...opts });
}

const real = (p) => {
  try {
    return fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
};

/** { gitDir, common }: this worktree's git dir and the repository's common git dir, both absolute. */
export function gitDirs(cwd) {
  const [own, common] = run(['rev-parse', '--absolute-git-dir', '--git-common-dir'], { cwd }).split('\n');
  return { gitDir: real(own), common: real(path.resolve(cwd || process.cwd(), common)) };
}

/** The common git dir (shared by every worktree), absolute. `--git-common-dir` may print a relative path. */
export function commonGitDir(cwd) {
  return gitDirs(cwd).common;
}

// ------------------------------------------------------------------ client

/**
 * Write `lines` (client attributeLines(policy)) into <common>/info/attributes between the
 * eyesonly markers. Everything outside the block is kept byte for byte (CRLF included). The
 * block is rewritten on every call and moved to the end, so it wins over earlier lines and
 * globs removed from the policy disappear.
 */
export function pinAttributes(lines, gitCommonDir) {
  const p = path.join(gitCommonDir, 'info', 'attributes');
  fs.mkdirSync(path.dirname(p), { recursive: true });
  let rest = fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '';
  const start = rest.indexOf(BEGIN);
  if (start !== -1) {
    const endAt = rest.indexOf(END, start);
    const lineEnd = (i) => {
      const nl = rest.indexOf('\n', i);
      return nl === -1 ? rest.length : nl + 1;
    };
    // A block without its end marker: drop only the begin line, never the user's lines after it.
    rest = rest.slice(0, start) + rest.slice(endAt === -1 ? lineEnd(start) : lineEnd(endAt));
  }
  if (rest && !rest.endsWith('\n')) rest += '\n';
  const block = [BEGIN, '# written by eyesonly from the repo policy; edits inside this block are overwritten', ...lines, END].join('\n') + '\n';
  const next = rest + block;
  if (fs.existsSync(p) && fs.readFileSync(p, 'utf8') === next) return false;
  const tmp = `${p}.eyesonly-tmp-${process.pid}`;
  fs.writeFileSync(tmp, next);
  fs.renameSync(tmp, p);
  return true;
}

/** Parse `git check-attr -z` output into [{ path, value }]. */
function parseCheckAttr(out) {
  const f = out.split('\0');
  const res = [];
  for (let i = 0; i + 2 < f.length; i += 3) res.push({ path: f[i], value: f[i + 2] });
  return res;
}

/** [{ path, value }] for every path whose resolved filter is not `eyesonly` (value may be 'unspecified', 'unset', 'set', 'lfs', ...). */
export function checkResolvedFilters(paths, cwd) {
  if (!paths.length) return [];
  const out = run(['check-attr', '-z', '--stdin', 'filter'], { cwd, input: paths.join('\0') + '\0', stdio: ['pipe', 'pipe', 'pipe'] });
  return parseCheckAttr(out).filter((r) => r.value !== 'eyesonly');
}

// ------------------------------------------------------------------ server

const MIN_GIT = [2, 40];
let gitVersionOk = null;
// Keys git-lfs reads from .lfsconfig that decide where objects are sent.
const LFS_ENDPOINT_RE = '^(lfs\\.(url|pushurl)|remote\\..*\\.(lfsurl|lfspushurl)|url\\..*\\.(insteadof|pushinsteadof))$';

// One sample path per policy glob: "**/" becomes "x/", "*" and "?" become "x".
// Globs with character classes are best effort (a sample that does not match its glob is dropped).
function globSamples(policy) {
  const out = [];
  for (const g of Object.keys(policy.files || {})) {
    const s = g.replace(/\*\*\//g, 'x/').replace(/\*\*/g, 'x').replace(/[*?]/g, 'x');
    out.push(s);
    if (g.startsWith('**/')) out.push(s.slice(2)); // `**/` also matches at the root
  }
  return out;
}

const isAttrFile = (p) => path.posix.basename(p).toLowerCase() === '.gitattributes';
const isLfsConfig = (p) => p.toLowerCase() === '.lfsconfig';

/**
 * Pre-receive check for one commit new to the server. Only does work when the commit
 * changes a `.gitattributes` (any depth) or `.lfsconfig`. `git(args)` returns stdout as a
 * string and throws on a non-zero exit; `reject(msg)` must not return.
 */
export function checkCommitAttributes({ commit, parents, policy, git, reject, isAdmin }) {
  const short = commit.slice(0, 8);
  const nul = (s) => s.split('\0').filter(Boolean);
  const touched = new Set();
  if (!parents.length) nul(git(['diff-tree', '-r', '-z', '--name-only', '--no-commit-id', '--root', commit])).forEach((p) => touched.add(p));
  for (const parent of parents) nul(git(['diff-tree', '-r', '-z', '--name-only', '--no-renames', parent, commit])).forEach((p) => touched.add(p));
  const attrFiles = [...touched].filter(isAttrFile);
  const lfsTouched = [...touched].some(isLfsConfig);
  // Protected paths added or changed here are probed too: an earlier commit may have
  // planted a redirect (e.g. `secrets/**/*.pem filter=lfs`) that none of the sample
  // paths matched, and this is the commit where a file finally lands under it.
  const protTouched = [...touched].filter((p) => fileRule(policy, p));
  if (!attrFiles.length && !lfsTouched && !protTouched.length) return;

  // Case-insensitive filesystems (macOS, Windows) read `.GitAttributes` as `.gitattributes`;
  // git check-attr --source does not. Refuse the ambiguity instead of guessing.
  for (const p of [...touched].filter((p) => isAttrFile(p) || isLfsConfig(p))) {
    const base = path.posix.basename(p);
    if (base !== '.gitattributes' && p !== '.lfsconfig') reject(`commit ${short} adds '${p}': attribute and LFS config files must be named exactly .gitattributes / .lfsconfig`);
  }

  if (gitVersionOk === null) {
    const m = /(\d+)\.(\d+)/.exec(git(['version'])) || [];
    const [maj, min] = [Number(m[1]), Number(m[2])];
    gitVersionOk = maj > MIN_GIT[0] || (maj === MIN_GIT[0] && min >= MIN_GIT[1]);
  }
  if (!gitVersionOk) reject(`server git too old for attribute checks (need >= ${MIN_GIT.join('.')})`);

  if (attrFiles.length || protTouched.length) checkFilters({ commit, parents, policy, git, reject, attrFiles, extra: protTouched, short, nul });
  if (lfsTouched && !isAdmin) checkLfsConfig({ commit, parents, git, reject });
}

function checkFilters({ commit, parents, policy, git, reject, attrFiles, extra = [], short, nul }) {
  const probes = new Set(extra);
  if (attrFiles.length) nul(git(['ls-tree', '-r', '-z', '--name-only', commit])).filter((p) => fileRule(policy, p)).forEach((p) => probes.add(p));
  const samples = globSamples(policy);
  for (const s of samples) probes.add(s);
  // A nested .gitattributes only affects its own subtree: probe that directory too.
  for (const f of attrFiles) {
    const dir = path.posix.dirname(f);
    if (dir === '.') continue;
    for (const s of ['x', ...samples.map((x) => path.posix.basename(x))]) probes.add(`${dir}/${s}`);
  }
  const list = [...probes].filter((p) => fileRule(policy, p));
  if (!list.length) return;

  const resolve = (rev, paths) => {
    const res = [];
    for (let i = 0; i < paths.length; i += 500) {
      res.push(...parseCheckAttr(git(['check-attr', `--source=${rev}`, '-z', 'filter', '--', ...paths.slice(i, i + 500)])));
    }
    return res;
  };
  const now = resolve(commit, list);
  for (const r of now) {
    if (r.value !== 'eyesonly' && r.value !== 'unspecified') {
      reject(`commit ${short} sets filter=${r.value} on protected path '${r.path}'. Protected paths must keep filter=eyesonly; remove that .gitattributes line.`);
    }
  }
  // `!filter` (back to unspecified) on a path that was filter=eyesonly is a downgrade too.
  const unspec = now.filter((r) => r.value === 'unspecified').map((r) => r.path);
  for (const parent of unspec.length ? parents : []) {
    for (const r of resolve(parent, unspec)) {
      if (r.value === 'eyesonly') reject(`commit ${short} sets filter=unspecified on protected path '${r.path}' (it was filter=eyesonly). Keep the eyesonly line in .gitattributes.`);
    }
  }
}

function checkLfsConfig({ commit, parents, git, reject }) {
  const endpoints = (rev) => {
    if (!git(['ls-tree', rev, '--', '.lfsconfig'])) return '';
    try {
      return git(['config', '--blob', `${rev}:.lfsconfig`, '--get-regexp', LFS_ENDPOINT_RE]);
    } catch (e) {
      if (e.status === 1) return ''; // no matching key
      return null; // unparseable: git-lfs may read it differently, so fail closed
    }
  };
  const mine = endpoints(commit);
  if (mine === '') return;
  if (mine !== null && parents.some((p) => endpoints(p) === mine)) return; // endpoints unchanged
  reject(`only admins may change .lfsconfig endpoints (lfs.url, remote.*.lfsurl, url.*.insteadOf)${mine === null ? '; .lfsconfig could not be parsed' : ''}`);
}
