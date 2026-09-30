/** 权限组与组成员关系:groups claim 与应用访问控制的唯一数据源 */
import { getDb } from '../core/db.js';
import { randomToken, nowSec } from '../core/crypto.js';

export const byId = (id) => getDb().prepare('SELECT * FROM groups WHERE id = ?').get(id);

export const byName = (name) => getDb().prepare('SELECT * FROM groups WHERE name = ?').get(name);

/** 组列表,附带成员数 */
export const list = () =>
  getDb().prepare(
    `SELECT g.*, (SELECT COUNT(*) FROM group_members m WHERE m.group_id = g.id) AS member_count
     FROM groups g ORDER BY g.created_at ASC, g.name ASC`
  ).all();

export function create({ name, description = '' }) {
  const id = randomToken(12);
  getDb().prepare('INSERT INTO groups (id, name, description, created_at) VALUES (?, ?, ?, ?)')
    .run(id, String(name).trim(), String(description || '').trim(), nowSec());
  return byId(id);
}

/** 按名取组,不存在则自动创建(setUserGroups / 播种共用) */
export function ensureByName(name) {
  const cur = byName(name);
  if (cur) return cur;
  getDb().prepare('INSERT OR IGNORE INTO groups (id, name, description, created_at) VALUES (?, ?, ?, ?)')
    .run(randomToken(12), name, '', nowSec());
  return byName(name);
}

export function rename(id, name) {
  getDb().prepare('UPDATE groups SET name = ? WHERE id = ?').run(String(name).trim(), id);
  return byId(id);
}

/** 删除组并级联解除成员关系;同步清理 user_groups 镜像文本,避免重启播种时复活 */
export function remove(id) {
  const db = getDb();
  const g = byId(id);
  if (!g) return;
  db.prepare('DELETE FROM group_members WHERE group_id = ?').run(id);
  db.prepare('DELETE FROM groups WHERE id = ?').run(id);
  const rows = db.prepare('SELECT id, user_groups FROM users WHERE user_groups LIKE ?').all(`%${g.name}%`);
  const upd = db.prepare('UPDATE users SET user_groups = ? WHERE id = ?');
  for (const u of rows) {
    const rest = String(u.user_groups).split(/[\s,]+/).filter((n) => n && n !== g.name).join(' ');
    upd.run(rest, u.id);
  }
}

/** 用户所属组名数组(按组名字典序稳定输出) */
export const membersOf = (userId) =>
  getDb().prepare(
    `SELECT g.name FROM groups g JOIN group_members m ON m.group_id = g.id
     WHERE m.user_id = ? ORDER BY g.name ASC`
  ).all(userId).map((r) => r.name);

/** 规整输入:数组或字符串均可,按空白/逗号再拆分并去重 */
const cleanNames = (names) =>
  [...new Set((Array.isArray(names) ? names : [names]).flatMap((n) => String(n).split(/[\s,]+/)).filter(Boolean))];

/** 重建某用户的组成员关系;不存在的组自动创建 */
export function setUserGroups(userId, names = []) {
  const clean = cleanNames(names);
  const db = getDb();
  db.prepare('DELETE FROM group_members WHERE user_id = ?').run(userId);
  const ins = db.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)');
  for (const name of clean) {
    const g = ensureByName(name);
    if (g) ins.run(g.id, userId);
  }
  return clean;
}
