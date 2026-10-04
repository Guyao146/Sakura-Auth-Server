import crypto from 'node:crypto';
import { privateKeyObject, publicKeyObject, getSigningKey } from './keys.js';
import { nowSec } from './crypto.js';

/** RS256 JWT 签发;自动补 iat/exp/kid */
export function signJwt(payload, ttl) {
  const now = nowSec();
  const header = { alg: 'RS256', typ: 'JWT', kid: getSigningKey().kid };
  const body = { iat: now, exp: now + ttl, ...payload };
  const h = Buffer.from(JSON.stringify(header)).toString('base64url');
  const p = Buffer.from(JSON.stringify(body)).toString('base64url');
  const sig = crypto.createSign('RSA-SHA256').update(`${h}.${p}`).sign(privateKeyObject(), 'base64url');
  return `${h}.${p}.${sig}`;
}

/** 验签 + 过期检查;失败返回 null。ignoreExp 用于吊销检测场景 */
export function verifyJwt(token, { ignoreExp = false } = {}) {
  try {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) return null;
    const [h, p, sig] = parts;
    const header = JSON.parse(Buffer.from(h, 'base64url').toString());
    if (header.alg !== 'RS256') return null;
    const ok = crypto.createVerify('RSA-SHA256').update(`${h}.${p}`)
      .verify(publicKeyObject(), sig, 'base64url');
    if (!ok) return null;
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    // 本服务签发的 JWT 必须有有效 exp;ignoreExp 仅跳过时间比较,不放松结构校验。
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)
      || !Number.isFinite(payload.exp)) return null;
    const now = nowSec();
    if (!ignoreExp && payload.exp <= now) return null;
    if (payload.nbf !== undefined && (!Number.isFinite(payload.nbf) || payload.nbf > now)) return null;
    return payload;
  } catch {
    return null;
  }
}

export const decodeHeader = (token) => {
  try { return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString()); } catch { return null; }
};
