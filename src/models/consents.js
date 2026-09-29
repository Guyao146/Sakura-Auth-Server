import { getDb } from '../core/db.js';
import { nowSec } from '../core/crypto.js';

export const get = (userId, clientId) =>
  getDb().prepare('SELECT * FROM consents WHERE user_id = ? AND client_id = ?').get(userId, clientId);

/** 记录/合并已授权 scope */
export function grant(userId, clientId, scope) {
  getDb().prepare(
    `INSERT INTO consents (user_id, client_id, scope, granted_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id, client_id) DO UPDATE SET scope = excluded.scope, granted_at = excluded.granted_at`
  ).run(userId, clientId, scope, nowSec());
}

/** 已授权 scope 是否覆盖本次请求的全部 scope */
export function covers(userId, clientId, requestedScopes) {
  const row = get(userId, clientId);
  if (!row) return false;
  const granted = new Set(row.scope.split(/\s+/).filter(Boolean));
  return requestedScopes.every((s) => granted.has(s));
}
