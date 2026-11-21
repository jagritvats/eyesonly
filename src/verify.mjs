// eyesonly verify / pre-push: the server's content checks, run by anyone (CI, the pre-push
// hook) against the policy committed in the repo. Repo mode only.
//
// For a range base..head:
//   - The policy at `base` (the reviewed default branch) is the starting point.
//   - Every commit that changes .eyesonly/policy.json must carry a policy signed by an admin
//     of its first parent's policy (or base's), for the same repo id, with a higher version.
//     Removing the policy file is refused: it would switch enforcement off.
//   - Every commit is checked with the policy in its own tree (accepted above), using the
//     same checks as the server's pre-receive hook (src/validate.mjs).
//   - The head tree is checked in full, so plaintext that predates the range is caught too.
//
// What it can't know without a server: who pushed. Changes are attributed to envelope
// signers (a forged or unauthorized envelope fails), and deletions are reported, not refused.
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import * as attest from './attest.mjs';
import * as rp from './repo-policy.mjs';
import { contentChecker, gitRunner } from './validate.mjs';
import { refRule } from './policy.mjs';

const ZERO = /^0{40}$|^0{64}$/;
const log = (msg) => console.error('[eyesonly] ' + msg);

class Rejection extends Error {}

const tryGit = (args, cwd) => {
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 1 << 30 }).trim();
  } catch {
    return null;
  }
};
const commitOf = (rev, cwd) => (rev ? tryGit(['rev-parse', '--verify', '-q', `${rev}^{commit}`], cwd) : null);
const policyOid = (commit, cwd) => tryGit(['rev-parse', '--verify', '-q', `${commit}:${rp.POLICY_FILE}`], cwd);

/** Is `att` a valid successor of `prev`: signed by one of prev's admins, same repo, newer? */
function checkSuccessor(att, prev) {
  if (!attest.verifyAttestation(att)) throw new Error('policy signature invalid');
  const m = att.manifest;
  if (!rp.validRepoManifest(m)) throw new Error('policy is malformed or inconsistent');
  if (!m.policy.admins.includes(att.signer) || m.keys[att.signer]?.ed25519 !== att.signer_ed25519) {
    throw new Error(`policy is signed by '${att.signer}', who is not an admin in it`);
  }
  if (!prev.policy.admins.includes(att.signer) || prev.keys[att.signer]?.ed25519 !== att.signer_ed25519) {
    throw new Error(`policy change signed by '${att.signer}', who was not an admin before it`);
  }
  if (m.repo !== prev.repo) throw new Error(`policy belongs to a different repo (id ${m.repo}, expected ${prev.repo})`);
  if (m.version <= prev.version) throw new Error(`policy version ${m.version} doesn't increase (was ${prev.version})`);
  return m;
}

/**
 * Verify the commits reachable from `head` and not from `base` / `exclude`.
 * Returns { errors, notes, checked, policy } (policy: false when no policy applies at all).
 */
export function verifyRange({ base = null, head = 'HEAD', exclude = [], cwd = process.cwd() } = {}) {
  const { g, gBuf } = gitRunner(cwd);
  const errors = [];
  const notes = [];
  const errorSet = new Set();
  const fail = (msg) => {
    if (!errorSet.has(msg)) errorSet.add(msg) && errors.push(msg);
  };
  const headC = commitOf(head, cwd);
  if (!headC) throw new Error(`unknown revision '${head}'`);
  const baseC = base ? commitOf(base, cwd) : null;
  if (base && !baseC) throw new Error(`base commit '${base}' isn't in this clone. Fetch full history (in GitHub Actions: actions/checkout with fetch-depth: 0).`);

  const accepted = new Map(); // policy blob oid -> manifest
  const refused = new Set();
  let baseM = null;
  if (baseC) {
    const oid = policyOid(baseC, cwd);
    if (oid) {
      try {
        baseM = rp.resolveRepoPolicy(rp.parseAttestation(g(['cat-file', 'blob', oid])), { trust: null, pin: null }).manifest;
        accepted.set(oid, baseM);
      } catch (e) {
        fail(`the policy at the base (${baseC.slice(0, 8)}) is invalid: ${e.message}`);
      }
    }
  }

  const checkers = new Map();
  const checkerFor = (oid) => {
    if (!checkers.has(oid)) {
      const m = accepted.get(oid);
      checkers.set(oid, contentChecker({
        policy: rp.rulesOf(m),
        users: m.keys,
        g,
        gBuf,
        reject: (msg) => {
          throw new Rejection(msg);
        },
        authorize: (kind, file, commit) => {
          if (kind === 'delete') notes.push(`'${file}' deleted in ${commit.slice(0, 8)} (who did it can't be checked without a server)`);
        },
        note: (msg) => notes.push(msg.replace(/^\[eyesonly\] note: /, '')),
      }));
    }
    return checkers.get(oid);
  };

  const commits = (g(['rev-list', '--reverse', '--topo-order', headC, ...(baseC || exclude.length ? ['--not', ...(baseC ? [baseC] : []), ...exclude] : [])]) || '').split('\n').filter(Boolean);
  let anyPolicy = accepted.size > 0;
  for (const c of commits) {
    const oid = policyOid(c, cwd);
    const parent = tryGit(['rev-parse', '--verify', '-q', `${c}^1`], cwd);
    const parentOid = parent ? policyOid(parent, cwd) : null;
    if (!oid) {
      if (parentOid && accepted.has(parentOid)) fail(`commit ${c.slice(0, 8)} deletes ${rp.POLICY_FILE}, which would turn off enforcement. Admins change the policy with eyesonly grant/revoke.`);
      continue; // no policy in this commit: nothing to enforce
    }
    anyPolicy = true;
    if (refused.has(oid)) continue;
    if (!accepted.has(oid)) {
      const prev = (parentOid && accepted.get(parentOid)) || baseM;
      try {
        const text = g(['cat-file', 'blob', oid]);
        const att = rp.parseAttestation(text);
        if (prev) accepted.set(oid, checkSuccessor(att, prev));
        else {
          // The policy's first appearance: nothing earlier to check it against.
          const m = rp.resolveRepoPolicy(att, { trust: null, pin: null }).manifest;
          accepted.set(oid, m);
          notes.push(`${rp.POLICY_FILE} first appears in ${c.slice(0, 8)}, signed by ${att.signer} (${attest.adminFingerprint(att.signer_ed25519)})`);
        }
      } catch (e) {
        refused.add(oid);
        fail(`${rp.POLICY_FILE} in ${c.slice(0, 8)}: ${e.message}`);
        continue;
      }
    }
    try {
      checkerFor(oid).checkCommit(c);
    } catch (e) {
      if (!(e instanceof Rejection)) throw e;
      fail(e.message);
    }
  }

  // The resulting tree must be valid as a whole, whatever its history.
  const headOid = policyOid(headC, cwd);
  if (headOid && accepted.has(headOid)) {
    try {
      checkerFor(headOid).checkTree(headC);
    } catch (e) {
      if (!(e instanceof Rejection)) throw e;
      fail(e.message);
    }
  }
  return { errors, notes, checked: commits.length, policy: anyPolicy, head: headC, base: baseC };
}

function report(r, { what }) {
  for (const n of [...new Set(r.notes)]) log(`note: ${n}`);
  for (const e of r.errors) console.error(`[eyesonly] REJECTED: ${e}`);
  if (!r.policy) {
    log(`no ${rp.POLICY_FILE} in ${what}: nothing to verify`);
    return true;
  }
  if (r.errors.length) return false;
  log(`verified ${r.checked} commit(s) in ${what}: protected files are valid envelopes from allowed writers${r.checked ? '' : ' (no new commits)'}`);
  return true;
}

function run(fn) {
  try {
    return fn();
  } catch (e) {
    log(e.message);
    process.exit(1);
  }
}

/** A pushed ref that names a private branch under the policy at `rev` (CI: the base). */
function privateRefError(ref, rev, cwd = process.cwd()) {
  const text = rp.policyTextAt(rev, cwd);
  if (!text) return null;
  let m;
  try {
    m = JSON.parse(text).manifest;
  } catch {
    return null;
  }
  const rule = refRule({ branches: Object.fromEntries(m?.branches || []) }, ref);
  return rule ? `'${ref.replace(/^refs\/heads\//, '')}' is a private branch (${rule.prefix.replace(/^refs\/heads\//, '')}*) pushed to the host in plaintext. Delete it there, treat its contents as disclosed, and use eyesonly branch push.` : null;
}

/** eyesonly verify [<base> [<head>]] | --range <base>..<head> [--ref <ref>] [--sealed [<remote>]] */
export async function cmdVerify(args) {
  let base = null;
  let head = 'HEAD';
  let ref = null;
  let sealed = null;
  const rest = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--ref') ref = args[++i] || null;
    else if (args[i] === '--sealed') sealed = args[i + 1] && !args[i + 1].startsWith('-') ? args[++i] : '';
    else if (args[i] === '--range') {
      const r = args[++i] || '';
      const m = /^(.*?)\.\.(.+)$/.exec(r);
      if (!m) run(() => {
        throw new Error('usage: eyesonly verify --range <base>..<head>');
      });
      base = m[1] || null;
      head = m[2];
    } else rest.push(args[i]);
  }
  if (rest[0]) base = rest[0];
  if (rest[1]) head = rest[1];
  if (base && ZERO.test(base)) base = null; // new branch in a push event: fall back below
  if (!base) {
    base = tryGit(['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}']) || rp.defaultRef(process.cwd());
    if (base && commitOf(base) === commitOf(head)) base = null;
  }
  const what = base ? `${base.replace(/^refs\/(remotes\/|heads\/)/, '')}..${head}` : `the history of ${head}`;
  const r = run(() => verifyRange({ base, head }));
  let ok = report(r, { what });
  if (ref) {
    const full = ref.startsWith('refs/') ? ref : `refs/heads/${ref}`;
    const err = privateRefError(full, base || rp.defaultRef(process.cwd()));
    if (err) {
      console.error(`[eyesonly] REJECTED: ${err}`);
      ok = false;
    }
  }
  if (sealed !== null) {
    const { verifySealedRefs } = await import('./branches.mjs');
    const s = run(() => verifySealedRefs(process.cwd(), sealed || null));
    for (const e of s.errors) console.error(`[eyesonly] REJECTED: ${e}`);
    if (s.errors.length) ok = false;
    else log(`checked ${s.checked} sealed branch ref(s): each is one encrypted envelope bound to its ref`);
  }
  process.exit(ok ? 0 : 1);
}

/** The pre-push hook: verify each pushed ref's new commits. stdin: <lref> <loid> <rref> <roid> lines. */
export async function cmdPrePush() {
  if (tryGit(['config', '--local', 'eyesonly.mode']) !== 'repo') return;
  let input = '';
  try {
    input = fs.readFileSync(0, 'utf8');
  } catch {
    input = '';
  }
  const lines = input.split('\n').filter(Boolean);
  const { prePushChecks } = await import('./branches.mjs');
  const guard = run(() => prePushChecks(process.cwd(), lines));
  for (const e of guard) console.error(`[eyesonly] REJECTED: ${e}`);
  let ok = !guard.length;
  for (const line of lines) {
    const [lref, loid, rref, roid] = line.split(' ');
    if (!loid || ZERO.test(loid)) continue; // deleting a ref
    if (rref?.startsWith('refs/eyesonly/')) continue; // sealed branches: shape-checked above
    const known = roid && !ZERO.test(roid) && commitOf(roid) ? roid : null;
    // Commits already on any remote-tracking branch were pushed (and checked) before.
    const base = known || rp.defaultRef(process.cwd());
    const r = run(() => verifyRange({ base, head: loid, exclude: ['--remotes'] }));
    ok = report(r, { what: `${lref.replace(/^refs\/heads\//, '')} (outgoing)` }) && ok;
  }
  if (!ok) {
    log('push blocked: fix the commits above (CI runs the same check). To push anyway: git push --no-verify');
    process.exit(1);
  }
}
