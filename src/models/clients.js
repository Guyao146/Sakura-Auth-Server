import { getDb } from '../core/db.js';
import { randomToken, nowSec } from '../core/crypto.js';

export const byId = (clientId) => getDb().prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId);

export const list = () => getDb().prepare('SELECT * FROM clients ORDER BY created_at ASC').all();

export const count = () => getDb().prepare('SELECT COUNT(*) AS n FROM clients').get().n;

/** redirectUris: string[];scopes: 空格分隔;public=true 时无密钥(token_auth=none);
 *  allowedGroups: 可访问的权限组名数组,空数组 = 不限制 */
export function create({ name, redirectUris, scopes, isPublic, pkceRequired, requireConsent = true, secretHash = null, allowedGroups = [] }) {
  const clientId = 'app-' + randomToken(9);
  getDb().prepare(
    `INSERT INTO clients (client_id, name, secret_hash, redirect_uris, scopes, token_auth, pkce_required, require_consent, allowed_groups, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    clientId, name, secretHash, JSON.stringify(redirectUris), scopes,
    isPublic ? 'none' : 'client_secret_basic',
    pkceRequired ? 1 : 0, requireConsent ? 1 : 0, JSON.stringify(allowedGroups || []), nowSec()
  );
  return byId(clientId);
}

export function update(clientId, { name, redirectUris, scopes, pkceRequired, requireConsent, allowedGroups, secretHash = null }) {
  const cur = byId(clientId);
  if (!cur) return;
  getDb().prepare(
    `UPDATE clients SET name = ?, redirect_uris = ?, scopes = ?, pkce_required = ?, require_consent = ?, allowed_groups = ?
     ${secretHash ? ', secret_hash = ?' : ''} WHERE client_id = ?`
  ).run(
    name ?? cur.name,
    redirectUris ?? cur.redirect_uris,
    scopes ?? cur.scopes,
    pkceRequired !== undefined ? (pkceRequired ? 1 : 0) : cur.pkce_required,
    requireConsent !== undefined ? (requireConsent ? 1 : 0) : cur.require_consent,
    allowedGroups !== undefined ? JSON.stringify(allowedGroups || []) : cur.allowed_groups,
    ...(secretHash ? [secretHash] : []),
    clientId
  );
}

export function remove(clientId) {
  const db = getDb();
  db.prepare('DELETE FROM clients WHERE client_id = ?').run(clientId);
  db.prepare('DELETE FROM tokens WHERE client_id = ?').run(clientId);
  db.prepare('DELETE FROM auth_codes WHERE client_id = ?').run(clientId);
  db.prepare('DELETE FROM consents WHERE client_id = ?').run(clientId);
  // 客户端不产生组成员关系(组限制以 allowed_groups 内联存储),无需额外清理
}

/** 解析后的视图字段(redirect_uris 数组) */
export function withUris(client) {
  return {
    ...client,
    uriList: JSON.parse(client.redirect_uris || '[]'),
    scopeList: (client.scopes || '').split(/\s+/).filter(Boolean),
    allowedGroupList: allowedGroupNames(client),
  };
}

/** 安全解析 allowed_groups(JSON 组名数组);空数组 = 不限制 */
export function allowedGroupNames(client) {
  try {
    const v = JSON.parse(client.allowed_groups || '[]');
    return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
  } catch {
    return [];
  }
}
