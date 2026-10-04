/** 操作审计日志:登录/授权/关键管理动作留痕(滚动保留最新 5000 条,不参与过期清理) */
import { getDb } from '../core/db.js';
import { nowSec, randomToken } from '../core/crypto.js';

const MAX_ROWS = 5000;

/** 写入一条审计记录;每次写入后按需收敛到上限 5000 条(不依赖进程内计数,
 *  重启及其它连接写入后也能正确收敛;COUNT/DELETE 走同一索引,成本可控) */
export function log({ actor = 'anonymous', action, detail = '', ip = '' }) {
  if (!action) return;
  const db = getDb();
  db.prepare('INSERT INTO audit_logs (id, ts, actor, action, detail, ip) VALUES (?, ?, ?, ?, ?, ?)')
    .run(randomToken(12), nowSec(), String(actor || 'anonymous'), String(action), String(detail ?? ''), String(ip || ''));
  // 保持严格上限;不依赖进程内计数,重启及其它连接写入后也能正确收敛。
  const n = db.prepare('SELECT COUNT(*) AS n FROM audit_logs').get().n;
  if (n > MAX_ROWS) {
    const excess = n - MAX_ROWS;
    db
      .prepare('DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs ORDER BY ts ASC, rowid ASC LIMIT ?)')
      .run(excess);
  }
}

/** 组装筛选条件:action 精确匹配 + actor/detail 关键词 LIKE(list/listPaged 共用) */
function buildWhere(action = '', q = '') {
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
  return { where: conds.length ? `WHERE ${conds.join(' AND ')}` : '', params };
}

/** 按时间倒序列出:可选 action 精确过滤、actor/detail 关键词 LIKE 过滤 */
export function list({ limit = 200, action = '', q = '' } = {}) {
  const { where, params } = buildWhere(action, q);
  return getDb()
    .prepare(`SELECT * FROM audit_logs ${where} ORDER BY ts DESC, rowid DESC LIMIT ?`)
    .all(...params, Math.max(1, Number(limit) || 200));
}

/** 分页列出(page 从 1 起):返回 { rows, total, pages, page },page 越界自动收敛到有效页码 */
export function listPaged({ page = 1, perPage = 50, action = '', q = '' } = {}) {
  const size = Math.max(1, Number(perPage) || 50);
  const { where, params } = buildWhere(action, q);
  const total = getDb().prepare(`SELECT COUNT(*) AS n FROM audit_logs ${where}`).get(...params).n;
  const pages = Math.max(1, Math.ceil(total / size));
  const cur = Math.min(Math.max(1, Math.floor(Number(page) || 1)), pages);
  const rows = getDb()
    .prepare(`SELECT * FROM audit_logs ${where} ORDER BY ts DESC, rowid DESC LIMIT ? OFFSET ?`)
    .all(...params, size, (cur - 1) * size);
  return { rows, total, pages, page: cur };
}

export const count = () => getDb().prepare('SELECT COUNT(*) AS n FROM audit_logs').get().n;

/** 已出现过的动作代码(管理端筛选下拉用,按字母序) */
export const distinctActions = () =>
  getDb().prepare('SELECT DISTINCT action FROM audit_logs ORDER BY action').all().map((r) => r.action);

/** 清空全部审计记录(管理端危险操作) */
export function clear() {
  getDb().prepare('DELETE FROM audit_logs').run();
}
