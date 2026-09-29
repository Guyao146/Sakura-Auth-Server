import crypto from 'node:crypto';

const N = 16384, R = 8, P = 1, KEYLEN = 64;

/** scrypt 口令哈希,格式:scrypt$N$r$p$salt$hash(base64url) */
export function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(pw), salt, KEYLEN, { N, r: R, p: P });
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

export function verifyPassword(pw, stored) {
  try {
    const [scheme, n, r, p, salt, hash] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const expected = Buffer.from(hash, 'base64url');
    const actual = crypto.scryptSync(String(pw), Buffer.from(salt, 'base64url'), expected.length, {
      N: Number(n), r: Number(r), p: Number(p),
    });
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}
