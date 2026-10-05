/** WebAuthn 凭据(Passkey):id 为 base64url(credentialId),public_key 为 base64url(COSE 公钥) */
import { getDb } from '../core/db.js';
import { nowSec } from '../core/crypto.js';

/** 每用户凭据上限(超出后注册被拒) */
const counterValue = (n) => {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error('无效 WebAuthn 计数器');
  return n;
};

export const MAX_PER_USER = 8;

export function create({ id, userId, name, publicKey, counter = 0, transports = '' }) {
  getDb().prepare(
    'INSERT INTO webauthn_credentials (id, user_id, name, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).run(id, userId, name || 'Passkey', publicKey, counterValue(counter), transports || '', nowSec());
}

export const listForUser = (userId) =>
  getDb().prepare('SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC, id').all(userId);

export const byId = (id) =>
  getDb().prepare('SELECT * FROM webauthn_credentials WHERE id = ?').get(id);

export function updateCounter(id, counter) {
  getDb().prepare('UPDATE webauthn_credentials SET counter = ? WHERE id = ?').run(counterValue(counter), id);
}

/** 双条件删除(id + user_id),防止越权删除他人凭据;返回是否删除了行 */
export function remove(id, userId) {
  return getDb().prepare('DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?').run(id, userId).changes > 0;
}

export const countForUser = (userId) =>
  getDb().prepare('SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = ?').get(userId).n;
