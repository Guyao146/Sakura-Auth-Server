/** 密码重置令牌(邮件找回密码):只存哈希、一次性、30 分钟有效 */
import { getDb } from '../core/db.js';
import { randomToken, sha256hex, nowSec } from '../core/crypto.js';

const TTL = 30 * 60; // 30 分钟

/** 为用户生成一枚明文 token(仅此一次返回),库里只存 sha256 */
export function create(userId) {
  const token = randomToken(32); // 32B base64url
  getDb().prepare('INSERT INTO reset_tokens (code_hash, user_id, expires_at, used_at) VALUES (?, ?, ?, NULL)')
    .run(sha256hex(token), userId, nowSec() + TTL);
  return token;
}

/** 非消费查询:token 未用且未过期时返回其记录,否则 null(GET 重置页用) */
export function lookup(token) {
  if (!token) return null;
  const row = getDb().prepare('SELECT * FROM reset_tokens WHERE code_hash = ?').get(sha256hex(String(token)));
  if (!row || row.used_at || row.expires_at <= nowSec()) return null;
  return row;
}

/** 消费一枚 token:一次性、未过期才标记 used 并返回 userId,否则 null */
export function consume(token) {
  if (!token) return null;
  const db = getDb();
  const h = sha256hex(String(token));
  const r = db.prepare('UPDATE reset_tokens SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?')
    .run(nowSec(), h, nowSec());
  if (!r.changes) return null;
  return db.prepare('SELECT user_id FROM reset_tokens WHERE code_hash = ?').get(h).user_id;
}

export const clearFor = (userId) =>
  getDb().prepare('DELETE FROM reset_tokens WHERE user_id = ?').run(userId);
