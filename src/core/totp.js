/** RFC 6238 TOTP(RFC 4648 base32 / HMAC-SHA1 / 6 位 / 30 秒步长) */
import crypto from 'node:crypto';
import { timingSafeEqStr } from './crypto.js';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const c of clean) {
    value = (value << 5) | B32.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** 新密钥:20 字节随机 → base32(兼容主流验证器 App) */
export const generateSecret = () => base32Encode(crypto.randomBytes(20));

function hotp(key, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(buf).digest();
  const off = h[h.length - 1] & 0x0f;
  const n = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(n % 1_000_000).padStart(6, '0');
}

/** 当前时间步的验证码(测试/调试用) */
export function currentCode(secretB32, now = Date.now() / 1000) {
  return hotp(base32Decode(secretB32), Math.floor(now / 30));
}

/** 校验 6 位验证码,允许 ±1 步时钟漂移 */
export function verifyTotp(secretB32, token, { window = 1, now = Date.now() / 1000 } = {}) {
  const target = String(token || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(target) || !secretB32) return false;
  const key = base32Decode(secretB32);
  const t = Math.floor(now / 30);
  for (let i = -window; i <= window; i++) {
    if (timingSafeEqStr(hotp(key, t + i), target)) return true;
  }
  return false;
}

/** 验证器 App 的扫码/手动添加地址 */
export function otpauthUri({ secret, username, issuer }) {
  const label = encodeURIComponent(`${issuer}:${username}`);
  const q = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: '6', period: '30' });
  return `otpauth://totp/${label}?${q.toString()}`;
}
