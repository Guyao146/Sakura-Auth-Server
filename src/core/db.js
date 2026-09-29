import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { config } from './config.js';
import { logger } from './logger.js';
import { nowSec } from './crypto.js';

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
`;

/** 老库平滑迁移:补列/补表,幂等 */
function migrate() {
  const cols = db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
  if (!cols.includes('totp_secret')) db.exec('ALTER TABLE users ADD COLUMN totp_secret TEXT');
  if (!cols.includes('totp_enabled')) db.exec('ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0');
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
}
