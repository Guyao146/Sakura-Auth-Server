/** 操作审计日志:登录/授权/关键管理动作留痕(滚动保留最新 5000 条,不参与过期清理) */
import { getDb } from '../core/db.js';
import { nowSec, randomToken } from '../core/crypto.js';

const MAX_ROWS = 5000;

/** 写入一条审计记录;超过上限时删除最旧的溢出部分(保留最新 5000 条) */
export function log({ actor = 'anonymous', action, detail = '', ip = '' }) {
  if (!action) return;
  getDb()
    .prepare('INSERT INTO audit_logs (id, ts, actor, action, detail, ip) VALUES (?, ?, ?, ?, ?, ?)')
    .run(randomToken(12), nowSec(), String(actor || 'anonymous'), String(action), String(detail ?? ''), String(ip || ''));
  const n = getDb().prepare('SELECT COUNT(*) AS n FROM audit_logs').get().n;
  if (n > MAX_ROWS) {
    const excess = n - MAX_ROWS;
    getDb()
      .prepare('DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs ORDER BY ts ASC, rowid ASC LIMIT ?)')
      .run(excess);
  }
}

/** 按时间倒序列出:可选 action 精确过滤、actor/detail 关键词 LIKE 过滤 */
export function list({ limit = 200, action = '', q = '' } = {}) {
  const conds = [];
  const params = [];
  if (action) {
    conds.push('action = ?');
    params.push(String(action));
  }
  const kw = String(q || '').trim();
  if (kw) {
    conds.push('(actor LIKE ? OR detail LIKE ?)');
    const like = `%${kw}%`;
    params.push(like, like);
  }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  return getDb()
    .prepare(`SELECT * FROM audit_logs ${where} ORDER BY ts DESC, rowid DESC LIMIT ?`)
    .all(...params, Math.max(1, Number(limit) || 200));
}

export const count = () => getDb().prepare('SELECT COUNT(*) AS n FROM audit_logs').get().n;

/** 已出现过的动作代码(管理端筛选下拉用,按字母序) */
export const distinctActions = () =>
  getDb().prepare('SELECT DISTINCT action FROM audit_logs ORDER BY action').all().map((r) => r.action);

/** 清空全部审计记录(管理端危险操作) */
export function clear() {
  getDb().prepare('DELETE FROM audit_logs').run();
}
