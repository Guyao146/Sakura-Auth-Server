import { getDb } from '../core/db.js';
import { randomToken, sha256hex, nowSec } from '../core/crypto.js';

const TTL = 14 * 86400; // 实际 TTL 取运行时配置,见 create()

export function byIdHash(idHash) {
  return getDb().prepare('SELECT * FROM sessions WHERE id_hash = ?').get(idHash);
}

/** 创建会话;meta 可携带设备信息 {ip, ua};返回放 cookie 的明文 id */
export function create(userId, csrf, ttl, meta = {}) {
  const sid = randomToken(32);
  const now = nowSec();
  getDb().prepare('INSERT INTO sessions (id_hash, user_id, csrf, created_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(sha256hex(sid), userId, csrf, now, now + (ttl || TTL),
      String(meta.ip || ''), String(meta.ua || ''));
  return sid;
}

export function remove(idHash) {
  getDb().prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
}

/** 用户存活会话列表(新会话在前;同秒内按插入先后倒序),附 ua 别名便于展示 */
export function listForUser(userId) {
  return getDb()
    .prepare('SELECT * FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC, rowid DESC')
    .all(userId, nowSec())
    .map((row) => ({ ...row, ua: row.user_agent }));
}

/** 撤销指定会话(带 user_id 双条件防越权);返回是否删除了记录 */
export function removeByIdHash(idHash, userId) {
  return getDb().prepare('DELETE FROM sessions WHERE id_hash = ? AND user_id = ?')
    .run(idHash, userId).changes > 0;
}

/** 撤销某用户除 keepIdHash 外的全部会话;返回删除条数 */
export function removeAllOther(userId, keepIdHash) {
  return getDb().prepare('DELETE FROM sessions WHERE user_id = ? AND id_hash <> ?')
    .run(userId, keepIdHash).changes;
}

export function removeByUser(userId) {
  getDb().prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
}

export const count = () => getDb().prepare('SELECT COUNT(*) AS n FROM sessions WHERE expires_at > ?').get(nowSec()).n;
