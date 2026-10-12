import crypto from 'node:crypto';
import { setCookie, clearCookie } from './http.js';
import { getSigningKey } from './keys.js';
import { nowSec } from './crypto.js';

/**
 * 「一键登录」记住态:无状态签名 cookie(登录页 One-Tap 风格气泡的免密回归令牌)。
 * 载荷 { uid, cv(credential_version), exp },HMAC 派生自本库 RSA 签名密钥并加域分隔,
 * 不落库、无独立密钥;改密/重置/禁用会 bump credential_version,旧令牌自动失效。
 * 仅在用户显式勾选「记住我」时签发(最保守策略),有效期 30 天。
 */

export const TAP_COOKIE = 'sakura-tap';
export const TAP_TTL = 30 * 86400;
const PENDING_TTL = 5 * 60; // 与二步验证中间态一致

let keyCache = null;
const hmacKey = () => {
  if (!keyCache) keyCache = crypto.createHash('sha256')
    .update(getSigningKey().privatePem)
    .update('sakura-tap-v1')
    .digest();
  return keyCache;
};

const b64u = (buf) => Buffer.from(buf).toString('base64url');

/** 签发记住令牌(登录成功且用户勾选「记住我」时调用) */
export function signTap(user, ttl = TAP_TTL) {
  const payload = b64u(JSON.stringify({ uid: user.id, cv: user.credential_version, exp: nowSec() + ttl }));
  const sig = b64u(crypto.createHmac('sha256', hmacKey()).update(payload).digest());
  return `${payload}.${sig}`;
}

/**
 * 校验令牌的签名与时效(不查库):返回 { uid, cv, exp } 或 null。
 * 用户级校验(存在/未禁用/credential_version 未变)由调用方用模型完成,
 * 保持 core 层不反向依赖 models。
 */
export function verifyTapSig(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 2) return null;
    const [payload, sig] = parts;
    const expected = b64u(crypto.createHmac('sha256', hmacKey()).update(payload).digest());
    const sigBuf = Buffer.from(sig);
    if (sigBuf.length !== Buffer.from(expected).length
      || !crypto.timingSafeEqual(sigBuf, Buffer.from(expected))) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!data.uid || !Number.isFinite(data.exp) || data.exp <= nowSec()) return null;
    return data;
  } catch {
    return null;
  }
}

/** 写入 / 清除记住 cookie(HttpOnly、SameSite=Lax;https 部署自动 Secure) */
export function setTapCookie(res, token, secure, maxAge = TAP_TTL) {
  setCookie(res, TAP_COOKIE, token, { maxAge, secure, sameSite: 'Lax', httpOnly: true });
}

export function clearTapCookie(res, secure) {
  clearCookie(res, TAP_COOKIE, secure);
}
