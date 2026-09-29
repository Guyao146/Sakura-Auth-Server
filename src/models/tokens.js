import { getDb } from '../core/db.js';
import { randomToken, sha256hex, nowSec } from '../core/crypto.js';

/** 插入 access(jti=随机 id)或 refresh(id=token 哈希)令牌记录 */
export function insert({ id, kind, clientId, userId, scope, authTime, nonce, expiresAt }) {
  getDb().prepare(
    `INSERT INTO tokens (id, kind, client_id, user_id, scope, auth_time, nonce, revoked, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`
  ).run(id, kind, clientId, userId, scope, authTime || null, nonce || null, nowSec(), expiresAt);
}

export const byId = (id) => getDb().prepare('SELECT * FROM tokens WHERE id = ?').get(id);

export const revokeById = (id) => getDb().prepare('UPDATE tokens SET revoked = 1 WHERE id = ?').run(id);

export function revokeForClient(clientId) {
  getDb().prepare('UPDATE tokens SET revoked = 1 WHERE client_id = ?').run(clientId);
}

/** 有效 = 未吊销且未过期 */
export function isLive(row) {
  return row && !row.revoked && row.expires_at > nowSec();
}

export const countActive = () =>
  getDb().prepare("SELECT COUNT(*) AS n FROM tokens WHERE kind = 'access' AND revoked = 0 AND expires_at > ?")
    .get(nowSec()).n;

/** access token 存储键 = jti;refresh token 存储键 = sha256(明文) */
export const accessKey = (jti) => jti;
export const refreshKey = (token) => sha256hex(token);
export const newRefreshToken = () => randomToken(32);
export const newJti = () => randomToken(16);
