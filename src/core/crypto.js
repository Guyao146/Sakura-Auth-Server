import crypto from 'node:crypto';

export const nowSec = () => Math.floor(Date.now() / 1000);

/** 生成 base64url 随机 token(约 bytes*4/3 字符) */
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

export const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

export const sha256b64url = (s) => crypto.createHash('sha256').update(s).digest('base64url');

/** 字符串恒时比较,避免时序侧信道 */
export function timingSafeEqStr(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) {
    // 长度不同也要做一次比较,消耗相近时间
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

export const randomHex = (bytes = 8) => crypto.randomBytes(bytes).toString('hex');
