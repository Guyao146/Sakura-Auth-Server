import crypto from 'node:crypto';
import { getSetting, setSetting } from '../models/settings.js';

let signingKey = null;

/** 首次启动生成 RSA-2048 签名密钥并持久化到 settings 表;之后复用 */
export function initKeys() {
  const raw = getSetting('signing_key');
  if (raw) {
    signingKey = JSON.parse(raw);
    return;
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const kid = crypto.createHash('sha256').update(`${jwk.n}:${jwk.e}`).digest('base64url').slice(0, 16);
  signingKey = {
    kid,
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicJwk: { kty: jwk.kty, n: jwk.n, e: jwk.e },
  };
  setSetting('signing_key', JSON.stringify(signingKey));
}

export const getSigningKey = () => signingKey;

/** RFC 7517 JWKS 文档 */
export function jwks() {
  return {
    keys: [{ use: 'sig', alg: 'RS256', kid: signingKey.kid, ...signingKey.publicJwk }],
  };
}

export function privateKeyObject() {
  return crypto.createPrivateKey(signingKey.privatePem);
}

export function publicKeyObject() {
  return crypto.createPublicKey({ key: signingKey.publicJwk, format: 'jwk' });
}
