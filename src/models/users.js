import { getDb } from '../core/db.js';
import { randomToken } from '../core/crypto.js';
import { nowSec } from '../core/crypto.js';

export const byId = (id) => getDb().prepare('SELECT * FROM users WHERE id = ?').get(id);

export const byUsername = (username) =>
  getDb().prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username);

export const list = () => getDb().prepare('SELECT * FROM users ORDER BY created_at ASC').all();

export const count = () => getDb().prepare('SELECT COUNT(*) AS n FROM users').get().n;

export const adminCount = () => getDb().prepare('SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND disabled = 0').get().n;

export function create({ username, passwordHash, name = '', email = '', userGroups = '', isAdmin = false }) {
  const id = randomToken(12);
  const now = nowSec();
  getDb().prepare(
    `INSERT INTO users (id, username, name, email, user_groups, password_hash, is_admin, disabled, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`
  ).run(id, username, name, email, userGroups, passwordHash, isAdmin ? 1 : 0, now, now);
  return byId(id);
}

/** 只更新传入的字段;passwordHash 传 null 表示不改密码 */
export function update(id, { name, email, userGroups, passwordHash = null, isAdmin, disabled }) {
  const cur = byId(id);
  if (!cur) return;
  getDb().prepare(
    `UPDATE users SET name = ?, email = ?, user_groups = ?, password_hash = ?, is_admin = ?, disabled = ?, updated_at = ?
     WHERE id = ?`
  ).run(
    name !== undefined ? name : cur.name,
    email !== undefined ? email : cur.email,
    userGroups !== undefined ? userGroups : cur.user_groups,
    passwordHash || cur.password_hash,
    isAdmin !== undefined ? (isAdmin ? 1 : 0) : cur.is_admin,
    disabled !== undefined ? (disabled ? 1 : 0) : cur.disabled,
    nowSec(), id
  );
}

export function remove(id) {
  const db = getDb();
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM consents WHERE user_id = ?').run(id);
  db.prepare("DELETE FROM tokens WHERE user_id = ?").run(id);
  db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM group_members WHERE user_id = ?').run(id);
}

/* ---- 两步验证(TOTP) ---- */
export const setTotpSecret = (id, secret) =>
  getDb().prepare('UPDATE users SET totp_secret = ?, updated_at = ? WHERE id = ?').run(secret, nowSec(), id);

export const enableTotp = (id) =>
  getDb().prepare('UPDATE users SET totp_enabled = 1, updated_at = ? WHERE id = ?').run(nowSec(), id);

export const clearTotp = (id) =>
  getDb().prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0, updated_at = ? WHERE id = ?').run(nowSec(), id);

/* ---- Microsoft 账号绑定 ---- */
export const byMicrosoftSub = (sub) =>
  getDb().prepare('SELECT * FROM users WHERE ms_sub = ?').get(sub);

export function bindMicrosoft(id, sub, email = '') {
  getDb().prepare('UPDATE users SET ms_sub = ?, ms_email = ?, updated_at = ? WHERE id = ?')
    .run(sub, email || '', nowSec(), id);
}

export const unbindMicrosoft = (id) =>
  getDb().prepare('UPDATE users SET ms_sub = NULL, ms_email = NULL, updated_at = ? WHERE id = ?').run(nowSec(), id);
