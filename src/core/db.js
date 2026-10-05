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
  health_url      TEXT NOT NULL DEFAULT '',
  created_at      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id_hash    TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  csrf       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip         TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
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
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_codes_client ON auth_codes(client_id);
CREATE TABLE IF NOT EXISTS tokens (
  id         TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  client_id  TEXT NOT NULL,
  user_id    TEXT,
  scope      TEXT NOT NULL,
  auth_time  INTEGER,
  nonce      TEXT,
  replaced_by TEXT,
  chain_id   TEXT,
  revoked    INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_user  ON tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_client ON tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at);
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
CREATE INDEX IF NOT EXISTS idx_reset_tokens_expires ON reset_tokens(expires_at);
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
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  name        TEXT NOT NULL DEFAULT 'Passkey',
  public_key  TEXT NOT NULL,
  counter     INTEGER NOT NULL DEFAULT 0,
  transports  TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);
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
function migrate(hadGroups) {
  const cols = db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
  if (!cols.includes('totp_secret')) db.exec('ALTER TABLE users ADD COLUMN totp_secret TEXT');
  if (!cols.includes('totp_enabled')) db.exec('ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0');
  if (!cols.includes('ms_sub')) db.exec('ALTER TABLE users ADD COLUMN ms_sub TEXT');
  if (!cols.includes('ms_email')) db.exec('ALTER TABLE users ADD COLUMN ms_email TEXT');
  // ms_sub 索引须在列补齐之后建(老库 users 无该列);微软联邦登录按 ms_sub 查用户
  db.exec('CREATE INDEX IF NOT EXISTS idx_users_ms_sub ON users(ms_sub);');
  if (!cols.includes('credential_version')) db.exec('ALTER TABLE users ADD COLUMN credential_version INTEGER NOT NULL DEFAULT 0');
  // 数据库级递增也覆盖脚本/直接 SQL,避免同一秒内改密或禁用再启用的 ABA 竞态。
  db.exec(`CREATE TRIGGER IF NOT EXISTS users_credential_version
    AFTER UPDATE OF password_hash, disabled, is_admin, totp_secret, totp_enabled, ms_sub ON users
    WHEN OLD.password_hash IS NOT NEW.password_hash OR OLD.disabled IS NOT NEW.disabled
      OR OLD.is_admin IS NOT NEW.is_admin OR OLD.totp_secret IS NOT NEW.totp_secret
      OR OLD.totp_enabled IS NOT NEW.totp_enabled OR OLD.ms_sub IS NOT NEW.ms_sub
    BEGIN UPDATE users SET credential_version = credential_version + 1 WHERE id = NEW.id; END;`);
  const ccols = db.prepare('PRAGMA table_info(clients)').all().map((c) => c.name);
  if (!ccols.includes('access_mode')) {
    db.exec("ALTER TABLE clients ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'auto'");
  }
  if (!ccols.includes('allowed_groups')) {
    db.exec("ALTER TABLE clients ADD COLUMN allowed_groups TEXT NOT NULL DEFAULT '[]'");
  }
  if (!ccols.includes('description')) {
    db.exec("ALTER TABLE clients ADD COLUMN description TEXT NOT NULL DEFAULT ''");
  }
  if (!ccols.includes('logo_url')) {
    db.exec("ALTER TABLE clients ADD COLUMN logo_url TEXT NOT NULL DEFAULT ''");
  }
  if (!ccols.includes('health_url')) {
    db.exec("ALTER TABLE clients ADD COLUMN health_url TEXT NOT NULL DEFAULT ''");
  }
  const acols = db.prepare('PRAGMA table_info(auth_codes)').all().map((c) => c.name);
  if (!acols.includes('launch_verifier')) {
    db.exec('ALTER TABLE auth_codes ADD COLUMN launch_verifier TEXT');
  }
  // tokens 表补链 ID 列:同一授权会话签发的令牌对共用 chain_id,
  // refresh 吊销按链级联撤 access(RFC 7009);老库幂等补列,旧行 NULL = 无链(仅可单独撤销)
  const tcols = db.prepare('PRAGMA table_info(tokens)').all().map((c) => c.name);
  if (!tcols.includes('auth_time')) db.exec('ALTER TABLE tokens ADD COLUMN auth_time INTEGER');
  if (!tcols.includes('nonce')) db.exec('ALTER TABLE tokens ADD COLUMN nonce TEXT');
  if (!tcols.includes('replaced_by')) db.exec('ALTER TABLE tokens ADD COLUMN replaced_by TEXT');
  if (!tcols.includes('chain_id')) {
    db.exec('ALTER TABLE tokens ADD COLUMN chain_id TEXT');
  }
  // 会话表补设备信息列(登录 IP / User-Agent),老库平滑迁移
  const scols = db.prepare('PRAGMA table_info(sessions)').all().map((c) => c.name);
  if (!scols.includes('ip')) {
    db.exec("ALTER TABLE sessions ADD COLUMN ip TEXT NOT NULL DEFAULT ''");
  }
  if (!scols.includes('user_agent')) {
    db.exec("ALTER TABLE sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''");
  }
  if (!db.prepare("SELECT 1 FROM settings WHERE key = 'groups_migrated_v2'").get()) {
    // 已有关系表就是权威数据;只对尚无关系表的老库导入旧字段,不能复活已撤销成员。
    transaction(() => {
      if (!hadGroups) { seedGroupsFromUserGroups(); seedDefaultAdminGroup(); }
      db.prepare("INSERT INTO settings (key, value) VALUES ('groups_migrated_v2', '1')").run();
    });
  }
  db.exec('CREATE INDEX IF NOT EXISTS idx_tokens_chain ON tokens(chain_id)');
  // 修复旧版 counter | 0 遗留的负值,恢复为 WebAuthn uint32。
  db.exec('UPDATE webauthn_credentials SET counter = counter + 4294967296 WHERE counter < 0');
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

/**
 * 默认组播种:确保名为 admin 的组存在,且所有 is_admin=1 的用户默认是 admin 组成员。
 * 仅在种子阶段(初始化/迁移)保证;之后成员关系以用户编辑页的勾选为准,编辑不回填此默认。
 * 幂等可重复运行;返回本次新增的成员关系条数。
 */
export function seedDefaultAdminGroup() {
  const getGroup = db.prepare('SELECT id FROM groups WHERE name = ?');
  let g = getGroup.get('admin');
  if (!g) {
    db.prepare("INSERT OR IGNORE INTO groups (id, name, description, created_at) VALUES (?, 'admin', ?, ?)")
      .run(randomToken(12), '管理员默认组(管理员用户自动加入)', nowSec());
    g = getGroup.get('admin');
  }
  if (!g) return 0;
  const admins = db.prepare('SELECT id FROM users WHERE is_admin = 1').all();
  const ins = db.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)');
  let added = 0;
  for (const u of admins) added += ins.run(g.id, u.id).changes;
  if (added) logger.info('已为管理员播种默认 admin 组成员关系', { relations: added });
  return added;
}

export function initDb() {
  const synchronous = (process.env.SQLITE_SYNCHRONOUS || 'FULL').trim().toUpperCase();
  if (!['FULL', 'NORMAL'].includes(synchronous)) throw new Error('SQLITE_SYNCHRONOUS 仅支持 FULL 或 NORMAL');
  fs.mkdirSync(config.dataDir, { recursive: true });
  db = new DatabaseSync(config.dbFile);
  db.exec('PRAGMA journal_mode = WAL;');
  // 认证数据默认优先持久性;只有显式选择 NORMAL 才接受断电/系统崩溃时丢失已提交事务的风险。
  db.exec(`PRAGMA synchronous = ${synchronous};`);
  db.exec('PRAGMA foreign_keys = ON;');
  // 并发写(smoke 多进程/双实例误配)时等待而非立即 SQLITE_BUSY 报错
  db.exec('PRAGMA busy_timeout = 5000;');
  const hadGroups = !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'group_members'").get();
  db.exec(SCHEMA);
  migrate(hadGroups);
  logger.info('数据库已就绪', { file: config.dbFile, synchronous });
  return db;
}

export const getDb = () => db;

/** 仅用于同步数据库操作,不要在事务内 await。 */
export function transaction(fn) {
  db.exec('SAVEPOINT sakura_write');
  try {
    const result = fn();
    db.exec('RELEASE sakura_write');
    return result;
  } catch (err) {
    db.exec('ROLLBACK TO sakura_write; RELEASE sakura_write');
    throw err;
  }
}

/** 定期清理过期会话/授权码/令牌 */
export function purgeExpired() {
  const now = nowSec();
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM auth_codes WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM tokens WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM reset_tokens WHERE expires_at < ?').run(now);
}
