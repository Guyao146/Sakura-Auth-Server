import { getDb } from '../core/db.js';
import { randomToken, sha256hex, nowSec } from '../core/crypto.js';

const TTL = 14 * 86400; // 实际 TTL 取运行时配置,见 create()

export function byIdHash(idHash) {
  return getDb().prepare('SELECT * FROM sessions WHERE id_hash = ?').get(idHash);
}

/** 创建会话;返回放 cookie 的明文 id */
export function create(userId, csrf, ttl) {
  const sid = randomToken(32);
  const now = nowSec();
  getDb().prepare('INSERT INTO sessions (id_hash, user_id, csrf, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(sha256hex(sid), userId, csrf, now, now + (ttl || TTL));
  return sid;
}

export function remove(idHash) {
  getDb().prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
}

export function removeByUser(userId) {
  getDb().prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
}

export const count = () => getDb().prepare('SELECT COUNT(*) AS n FROM sessions WHERE expires_at > ?').get(nowSec()).n;
