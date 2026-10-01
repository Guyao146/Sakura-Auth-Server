import { getDb } from '../core/db.js';
import { randomToken, sha256hex, nowSec } from '../core/crypto.js';

/** 创建授权码,返回明文 code;库里只存哈希。launchVerifier:门户代发 PKCE 的 verifier(IdP 委托) */
export function create({ clientId, userId, redirectUri, scope, codeChallenge, codeChallengeMethod, nonce, authTime, launchVerifier, ttl }) {
  const code = randomToken(32);
  getDb().prepare(
    `INSERT INTO auth_codes
       (code_hash, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, auth_time, launch_verifier, expires_at, used)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`
  ).run(sha256hex(code), clientId, userId, redirectUri, scope, codeChallenge || null,
    codeChallengeMethod || null, nonce || null, authTime || null, launchVerifier || null, nowSec() + ttl);
  return code;
}

export const byCode = (code) => getDb().prepare('SELECT * FROM auth_codes WHERE code_hash = ?').get(sha256hex(code));

export const markUsed = (codeHash) =>
  getDb().prepare('UPDATE auth_codes SET used = 1 WHERE code_hash = ?').run(codeHash);
