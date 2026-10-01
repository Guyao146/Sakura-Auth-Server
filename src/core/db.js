import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { config } from './config.js';
import { logger } from './logger.js';
import { nowSec, randomToken } from './crypto.js';

let db = null;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name          TEXT NOT NULL DEFAULT '',
  email         TEXT NOT NULL DEFAULT '',
  user_groups   TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  is_admin      INTEGER NOT NULL DEFAULT 0,
  disabled      INTEGER NOT NULL DEFAULT 0,
  totp_secret   TEXT,
  totp_enabled  INTEGER NOT NULL DEFAULT 0,
  ms_sub        TEXT,
  ms_email      TEXT,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
  client_id       TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  secret_hash     TEXT,
  redirect_uris   TEXT NOT NULL DEFAULT '[]',
  scopes          TEXT NOT NULL DEFAULT '',
  token_auth      TEXT NOT NULL DEFAULT 'client_secret_basic',
  pkce_required   INTEGER NOT NULL DEFAULT 0,
  require_consent INTEGER NOT NULL DEFAULT 1,
  allowed_groups  TEXT NOT NULL DEFAULT '[]',
  description     TEXT NOT NULL DEFAULT '',
  logo_url        TEXT NOT NULL DEFAULT '',
  created_at      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id_hash    TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  csrf       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash             TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL,
  user_id               TEXT NOT NULL,
  redirect_uri          TEXT NOT NULL,
  scope                 TEXT NOT NULL,
  code_challenge        TEXT,
  code_challenge_method TEXT,
  nonce                 TEXT,
  auth_time             INTEGER,
  launch_verifier       TEXT,
  expires_at            INTEGER NOT NULL,
  used                  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens (
  id         TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  client_id  TEXT NOT NULL,
  user_id    TEXT,
  scope      TEXT NOT NULL,
  auth_time  INTEGER,
  nonce      TEXT,
  replaced_by TEXT,
  revoked    INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_user  ON tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_client ON tokens(client_id);
CREATE TABLE IF NOT EXISTS consents (
  user_id    TEXT NOT NULL,
  client_id  TEXT NOT NULL,
  scope      TEXT NOT NULL,
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, client_id)
);
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_codes (
  code_hash TEXT PRIMARY KEY,
  user_id   TEXT NOT NULL,
  used_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(user_id);
CREATE TABLE IF NOT EXISTS reset_tokens (
  code_hash  TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_reset_tokens_user ON reset_tokens(user_id);
CREATE TABLE IF NOT EXISTS groups (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
  group_id TEXT NOT NULL,
  user_id  TEXT NOT NULL,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);
CREATE TABLE IF NOT EXISTS audit_logs (
  id     TEXT PRIMARY KEY,
  ts     INTEGER NOT NULL,
  actor  TEXT NOT NULL DEFAULT 'anonymous',
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  ip     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts DESC);
`;

/** 老库平滑迁移:补列/补表,幂等 */
function migrate() {
  const cols = db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
  if (!cols.includes('totp_secret')) db.exec('ALTER TABLE users ADD COLUMN totp_secret TEXT');
  if (!cols.includes('totp_enabled')) db.exec('ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0');
  if (!cols.includes('ms_sub')) db.exec('ALTER TABLE users ADD COLUMN ms_sub TEXT');
  if (!cols.includes('ms_email')) db.exec('ALTER TABLE users ADD COLUMN ms_email TEXT');
  const ccols = db.prepare('PRAGMA table_info(clients)').all().map((c) => c.name);
  if (!ccols.includes('allowed_groups')) {
    db.exec("ALTER TABLE clients ADD COLUMN allowed_groups TEXT NOT NULL DEFAULT '[]'");
  }
  if (!ccols.includes('description')) {
    db.exec("ALTER TABLE clients ADD COLUMN description TEXT NOT NULL DEFAULT ''");
  }
  if (!ccols.includes('logo_url')) {
    db.exec("ALTER TABLE clients ADD COLUMN logo_url TEXT NOT NULL DEFAULT ''");
  }
  const acols = db.prepare('PRAGMA table_info(auth_codes)').all().map((c) => c.name);
  if (!acols.includes('launch_verifier')) {
    db.exec('ALTER TABLE auth_codes ADD COLUMN launch_verifier TEXT');
  }
  seedGroupsFromUserGroups();
}

/**
 * 数据播种:把 users.user_groups 的旧式自由文本(空白/逗号分隔)拆分为组名,
 * 自动建组并写入成员关系。幂等(INSERT OR IGNORE),重复运行不重复建。
 * 返回本次写入的成员关系条数。
 */
export function seedGroupsFromUserGroups() {
  const rows = db.prepare("SELECT id, user_groups FROM users WHERE TRIM(user_groups) <> ''").all();
  if (!rows.length) return 0;
  const now = nowSec();
  const insGroup = db.prepare("INSERT OR IGNORE INTO groups (id, name, description, created_at) VALUES (?, ?, '', ?)");
  const getGroup = db.prepare('SELECT id FROM groups WHERE name = ?');
  const insMember = db.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)');
  let seeded = 0;
  for (const row of rows) {
    const names = new Set(String(row.user_groups).split(/[\s,]+/).filter(Boolean));
    for (const name of names) {
      let g = getGroup.get(name);
      if (!g) {
        insGroup.run(randomToken(12), name, now);
        g = getGroup.get(name);
      }
      if (g) {
        insMember.run(g.id, row.id);
        seeded++;
      }
    }
  }
  if (seeded) logger.info('已从 user_groups 文本播种权限组成员关系', { relations: seeded });
  return seeded;
}

export function initDb() {
  fs.mkdirSync(config.dataDir, { recursive: true });
  db = new DatabaseSync(config.dbFile);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  migrate();
  logger.info('数据库已就绪', { file: config.dbFile });
  return db;
}

export const getDb = () => db;

/** 定期清理过期会话/授权码/令牌 */
export function purgeExpired() {
  const now = nowSec();
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM auth_codes WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM tokens WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM reset_tokens WHERE expires_at < ?').run(now);
}
