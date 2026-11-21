// Eyes Only envelope format (EYESONLY-V1).
//
//   content:  AES-256-GCM(DEK, plaintext, AAD = "eyesonly-v1\0" + path)
//   wrapping: per recipient, X25519(ephemeral, recipient) -> HKDF-SHA256 -> KEK
//             AES-256-GCM(KEK, DEK, AAD = "eyesonly-wrap\0" + recipient)
//   signing:  Ed25519 over the canonical JSON of every field except `sig`
//
// Binding the path into the AAD means a ciphertext can't be moved from one
// protected file to another. The signature means only a known writer can
// produce an envelope, so a stranger can't swap in a secret encrypted to the team.
import crypto from 'node:crypto';

export const MAGIC = 'EYESONLY-V1\n';
export const CARD_PREFIX = 'eyesonlypub1:';
const MAGIC_BUF = Buffer.from(MAGIC);

const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s) => Buffer.from(s, 'base64');
// Node accepts truncated GCM tags (down to 4 bytes) unless authTagLength is set.
const GCM = { authTagLength: 16 };
const tag16 = (t) => {
  if (t.length !== 16) throw new Error('malformed envelope: bad auth tag length');
  return t;
};

export const pubKey = (s) => crypto.createPublicKey({ key: unb64(s), format: 'der', type: 'spki' });
export const privKey = (s) => crypto.createPrivateKey({ key: unb64(s), format: 'der', type: 'pkcs8' });

export function generateIdentity(name) {
  const x = crypto.generateKeyPairSync('x25519');
  const e = crypto.generateKeyPairSync('ed25519');
  const exp = (kp) => ({
    pub: b64(kp.publicKey.export({ type: 'spki', format: 'der' })),
    priv: b64(kp.privateKey.export({ type: 'pkcs8', format: 'der' })),
  });
  return { version: 1, name, x25519: exp(x), ed25519: exp(e) };
}

export function publicCard(identity) {
  return { name: identity.name, x25519: identity.x25519.pub, ed25519: identity.ed25519.pub };
}

export function encodeCard(card) {
  return CARD_PREFIX + Buffer.from(JSON.stringify(card)).toString('base64url');
}

export function decodeCard(s) {
  if (!s.startsWith(CARD_PREFIX)) throw new Error('not an eyesonly public card (expected eyesonlypub1:...)');
  const card = JSON.parse(Buffer.from(s.slice(CARD_PREFIX.length), 'base64url').toString('utf8'));
  pubKey(card.x25519); // validates
  pubKey(card.ed25519);
  if (!/^[a-z0-9][a-z0-9._-]{0,38}$/i.test(card.name)) throw new Error('invalid user name in card');
  return card;
}

export function fingerprint(card) {
  const h = crypto.createHash('sha256').update(card.x25519).update('\0').update(card.ed25519).digest('hex');
  return h.slice(0, 16).match(/.{4}/g).join(':');
}

function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

const signedBytes = (env) => {
  const { sig, ...rest } = env;
  return Buffer.from(canonical(rest));
};

function kek(shared, epkDer, rpkDer) {
  return Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.concat([epkDer, rpkDer]), 'eyesonly-wrap-v1', 32));
}

export function isEnvelope(buf) {
  return buf.length >= MAGIC_BUF.length && buf.subarray(0, MAGIC_BUF.length).equals(MAGIC_BUF);
}

/**
 * @param {object} o
 * @param {Buffer} o.plaintext
 * @param {string} o.path        repo-relative path the envelope is bound to
 * @param {Record<string,string>} o.recipients  name -> x25519 public key (b64 spki)
 * @param {object} o.signer      full identity of the writer
 */
export function seal({ plaintext, path, recipients, signer }) {
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', dek, iv, GCM);
  c.setAAD(Buffer.from('eyesonly-v1\0' + path));
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  const tag = c.getAuthTag();

  const eph = crypto.generateKeyPairSync('x25519');
  const epkDer = eph.publicKey.export({ type: 'spki', format: 'der' });
  const keys = {};
  for (const name of Object.keys(recipients).sort()) {
    const rpkDer = unb64(recipients[name]);
    const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: pubKey(recipients[name]) });
    const wiv = crypto.randomBytes(12);
    const wc = crypto.createCipheriv('aes-256-gcm', kek(shared, epkDer, rpkDer), wiv, GCM);
    wc.setAAD(Buffer.from('eyesonly-wrap\0' + name));
    const wrapped = Buffer.concat([wc.update(dek), wc.final(), wc.getAuthTag()]);
    keys[name] = { iv: b64(wiv), key: b64(wrapped) };
  }

  const env = { v: 1, path, signer: signer.name, epk: b64(epkDer), iv: b64(iv), tag: b64(tag), ct: b64(ct), keys };
  env.sig = b64(crypto.sign(null, signedBytes(env), privKey(signer.ed25519.priv)));
  return Buffer.from(MAGIC + JSON.stringify(env, null, 1) + '\n');
}

export function parse(buf) {
  if (!isEnvelope(buf)) throw new Error('not an eyesonly envelope');
  const env = JSON.parse(buf.subarray(MAGIC_BUF.length).toString('utf8'));
  for (const f of ['path', 'signer', 'epk', 'iv', 'tag', 'ct', 'sig']) {
    if (typeof env[f] !== 'string') throw new Error(`malformed envelope: missing ${f}`);
  }
  if (env.v !== 1 || !env.keys || typeof env.keys !== 'object') throw new Error('malformed envelope');
  return env;
}

export function verify(env, signerEd25519Pub) {
  try {
    return crypto.verify(null, signedBytes(env), pubKey(signerEd25519Pub), unb64(env.sig));
  } catch {
    return false;
  }
}

/** Returns plaintext, or null if `identity` is not a recipient. Throws on tampering. */
export function open(env, identity) {
  const entry = env.keys[identity.name];
  if (!entry) return null;
  const shared = crypto.diffieHellman({ privateKey: privKey(identity.x25519.priv), publicKey: pubKey(env.epk) });
  const wrapped = unb64(entry.key);
  if (wrapped.length !== 32 + 16) throw new Error('malformed envelope: bad wrapped key length');
  const wd = crypto.createDecipheriv('aes-256-gcm', kek(shared, unb64(env.epk), unb64(identity.x25519.pub)), unb64(entry.iv), GCM);
  wd.setAAD(Buffer.from('eyesonly-wrap\0' + identity.name));
  wd.setAuthTag(wrapped.subarray(32));
  const dek = Buffer.concat([wd.update(wrapped.subarray(0, 32)), wd.final()]);

  const d = crypto.createDecipheriv('aes-256-gcm', dek, unb64(env.iv), GCM);
  d.setAAD(Buffer.from('eyesonly-v1\0' + env.path));
  d.setAuthTag(tag16(unb64(env.tag)));
  return Buffer.concat([d.update(unb64(env.ct)), d.final()]);
}
