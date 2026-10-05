import { getDb } from '../core/db.js';
import { randomToken, sha256hex, nowSec } from '../core/crypto.js';

/** 插入 access(jti=随机 id)或 refresh(id=token 哈希)令牌记录;chainId:同轮换链共用(见 revokeByChain) */
export function insert({ id, kind, clientId, userId, scope, authTime, nonce, expiresAt, chainId }) {
  getDb().prepare(
    `INSERT INTO tokens (id, kind, client_id, user_id, scope, auth_time, nonce, chain_id, revoked, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`
  ).run(id, kind, clientId, userId, scope, authTime || null, nonce || null, chainId || null, nowSec(), expiresAt);
}

export const byId = (id) => getDb().prepare('SELECT * FROM tokens WHERE id = ?').get(id);

export const revokeById = (id) => getDb().prepare('UPDATE tokens SET revoked = 1 WHERE id = ?').run(id);

/** 吊销同一轮换链上的全部令牌(RFC 7009:撤 refresh 级联撤链上 access);chain_id 为 NULL 的旧令牌不受影响 */
export const revokeByChain = (chainId) =>
  getDb().prepare('UPDATE tokens SET revoked = 1 WHERE chain_id = ?').run(chainId);

export function revokeForClient(clientId) {
  getDb().prepare('UPDATE tokens SET revoked = 1 WHERE client_id = ?').run(clientId);
}

/** 吊销某用户在某应用下的全部令牌(用户撤销授权时用) */
export function revokeForClientUser(clientId, userId) {
  return getDb().prepare('UPDATE tokens SET revoked = 1 WHERE client_id = ? AND user_id = ?').run(clientId, userId);
}

/** 吊销某用户的全部令牌(改密/重置/禁用账号时用) */
export function revokeForUser(userId) {
  getDb().prepare('UPDATE tokens SET revoked = 1 WHERE user_id = ?').run(userId);
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
/** 轮换链 ID:授权码换首对令牌时生成,刷新时沿用 */
export const newChainId = () => randomToken(12);
