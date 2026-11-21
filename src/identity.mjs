// Where a user's identity (private keys) comes from.
//
//   1. EYESONLY_IDENTITY: the identity JSON, or base64 of it. For CI and containers,
//      where a secret is easier to pass as an environment variable than as a file.
//   2. $EYESONLY_HOME/identity.json (default ~/.eyesonly/identity.json).
//
// Error messages never include the value: it holds private keys.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const eyesonlyHome = () => process.env.EYESONLY_HOME || path.join(os.homedir(), '.eyesonly');
export const identityPath = () => path.join(eyesonlyHome(), 'identity.json');

const fromEnv = () => {
  const v = process.env.EYESONLY_IDENTITY;
  return v != null && v.trim() !== '' ? v.trim() : null;
};

/** Human-readable source, for messages: "EYESONLY_IDENTITY" or the file path. */
export const identitySource = () => (fromEnv() ? 'EYESONLY_IDENTITY' : identityPath());

function check(id, where) {
  const ok = (k) => typeof k?.pub === 'string' && typeof k?.priv === 'string';
  if (!id || typeof id.name !== 'string' || !ok(id.x25519) || !ok(id.ed25519)) {
    throw new Error(`${where} is not an eyesonly identity (expected the JSON written by \`eyesonly keygen\`)`);
  }
  return id;
}

/** Returns the identity, or null if none is configured. Throws a safe Error if it's unreadable. */
export function readIdentity() {
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
