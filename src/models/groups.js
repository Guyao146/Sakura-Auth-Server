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

/** 更新组名与描述;重命名时同步 user_groups 镜像文本,避免重启播种时复活旧组名 */
export function update(id, { name, description }) {
  const cur = byId(id);
  if (!cur) return;
  const newName = String(name).trim();
  getDb().prepare('UPDATE groups SET name = ?, description = ? WHERE id = ?')
    .run(newName, description !== undefined ? String(description).trim() : cur.description, id);
  if (newName !== cur.name) {
    const db = getDb();
    const rows = db.prepare('SELECT id, user_groups FROM users WHERE user_groups LIKE ?').all(`%${cur.name}%`);
    const upd = db.prepare('UPDATE users SET user_groups = ? WHERE id = ?');
    for (const u of rows) {
      const rest = String(u.user_groups).split(/[\s,]+/).map((n) => (n === cur.name ? newName : n)).filter(Boolean).join(' ');
      upd.run(rest, u.id);
    }
  }
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

/** 一次性取全部成员关系(userId → [组名]),列表页用它消除 N+1 */
export const membersOfAll = () => {
  const map = new Map();
  for (const r of getDb().prepare(
    `SELECT m.user_id AS uid, g.name AS name
     FROM group_members m JOIN groups g ON g.id = m.group_id
     ORDER BY g.name ASC`
  ).all()) {
    if (!map.has(r.uid)) map.set(r.uid, []);
    map.get(r.uid).push(r.name);
  }
  return map;
};

/** 用户所属组名数组(按组名字典序稳定输出) */
export const membersOf = (userId) =>
  getDb().prepare(
    `SELECT g.name FROM groups g JOIN group_members m ON m.group_id = g.id
     WHERE m.user_id = ? ORDER BY g.name ASC`
  ).all(userId).map((r) => r.name);

/** 组成员用户列表(JOIN users,仅取展示字段;按用户名字典序稳定输出) */
export const listMembers = (groupId) =>
  getDb().prepare(
    `SELECT u.id, u.username, u.name, u.email, u.is_admin, u.disabled
     FROM group_members m JOIN users u ON u.id = m.user_id
     WHERE m.group_id = ? ORDER BY u.username ASC`
  ).all(groupId);

/** 加入单个成员(幂等:已存在不重复写入) */
export const addMember = (groupId, userId) =>
  getDb().prepare('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)').run(groupId, userId);

/** 移除单个成员(幂等:不存在时无操作) */
export const removeMember = (groupId, userId) =>
  getDb().prepare('DELETE FROM group_members WHERE group_id = ? AND user_id = ?').run(groupId, userId);

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
