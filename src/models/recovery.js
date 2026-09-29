/** 一次性恢复代码(2FA 开启时生成,每枚只能用一次) */
import { getDb } from '../core/db.js';
import { randomBytes } from 'node:crypto';
import { sha256hex, nowSec } from '../core/crypto.js';

const normalize = (code) => String(code || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
const hash = (code) => sha256hex(normalize(code));

/** 生成 count 枚人类友好代码(如 ab12-cd34),返回明文列表(仅此一次) */
export function createBatch(userId, count = 8) {
  const codes = Array.from({ length: count }, () => {
    const raw = randomBytes(4).toString('hex');
    return `${raw.slice(0, 4)}-${raw.slice(4)}`;
  });
  const stmt = getDb().prepare('INSERT OR IGNORE INTO recovery_codes (code_hash, user_id, used_at) VALUES (?, ?, NULL)');
  for (const c of codes) stmt.run(hash(c), userId);
  return codes;
}

/** 消费一枚恢复代码:未用过则标记并返回 true */
export function consume(userId, code) {
  if (!code || normalize(code).length < 6) return false;
  const row = getDb().prepare('SELECT * FROM recovery_codes WHERE code_hash = ? AND user_id = ?').get(hash(code), userId);
  if (!row || row.used_at) return false;
  getDb().prepare('UPDATE recovery_codes SET used_at = ? WHERE code_hash = ?').run(nowSec(), row.code_hash);
  return true;
}

export function clearFor(userId) {
  getDb().prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId);
}

export const countValid = (userId) =>
  getDb().prepare('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL').get(userId).n;
