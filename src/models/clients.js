import { getDb } from '../core/db.js';
import { randomToken, nowSec } from '../core/crypto.js';

export const byId = (clientId) => getDb().prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId);

export const list = () => getDb().prepare('SELECT * FROM clients ORDER BY created_at ASC').all();

export const count = () => getDb().prepare('SELECT COUNT(*) AS n FROM clients').get().n;

/** redirectUris: string[];scopes: 空格分隔;public=true 时无密钥(token_auth=none) */
export function create({ name, redirectUris, scopes, isPublic, pkceRequired, requireConsent = true, secretHash = null }) {
  const clientId = 'app-' + randomToken(9);
  getDb().prepare(
    `INSERT INTO clients (client_id, name, secret_hash, redirect_uris, scopes, token_auth, pkce_required, require_consent, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    clientId, name, secretHash, JSON.stringify(redirectUris), scopes,
    isPublic ? 'none' : 'client_secret_basic',
    pkceRequired ? 1 : 0, requireConsent ? 1 : 0, nowSec()
  );
  return byId(clientId);
}

export function update(clientId, { name, redirectUris, scopes, pkceRequired, requireConsent, secretHash = null }) {
  const cur = byId(clientId);
  if (!cur) return;
  getDb().prepare(
    `UPDATE clients SET name = ?, redirect_uris = ?, scopes = ?, pkce_required = ?, require_consent = ?
     ${secretHash ? ', secret_hash = ?' : ''} WHERE client_id = ?`
  ).run(
    name ?? cur.name,
    redirectUris ?? cur.redirect_uris,
    scopes ?? cur.scopes,
    pkceRequired !== undefined ? (pkceRequired ? 1 : 0) : cur.pkce_required,
    requireConsent !== undefined ? (requireConsent ? 1 : 0) : cur.require_consent,
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
}

/** 解析后的视图字段(redirect_uris 数组) */
export function withUris(client) {
  return { ...client, uriList: JSON.parse(client.redirect_uris || '[]'), scopeList: (client.scopes || '').split(/\s+/).filter(Boolean) };
}
