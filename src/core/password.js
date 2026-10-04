import crypto from 'node:crypto';

const N = 16384, R = 8, P = 1, KEYLEN = 64;
/** 并发上限:scrypt 在 libuv 线程池执行,显式限流防止认证风暴排挤其它 I/O 与请求处理 */
const MAX_CONCURRENT = 8;
let running = 0;
const pending = [];

/** 异步 scrypt;超过并发上限的请求在进程内排队,scryptSync 会阻塞事件循环,这里不再使用 */
function scryptAsync(password, salt, keylen, options) {
  return new Promise((resolve, reject) => {
    const run = () => crypto.scrypt(password, salt, keylen, options, (err, derived) => {
      running--;
      const next = pending.shift();
      if (next) { running++; next(); }
      if (err) reject(err); else resolve(derived);
    });
    if (running < MAX_CONCURRENT) { running++; run(); }
    else pending.push(run);
  });
}

/** 占位哈希:用户名不存在时仍做一次等价计算,避免通过响应快慢枚举用户名 */
const DUMMY_PASSWORD = 'dummy-password-for-constant-timing';
let dummyHashCache = null;
async function dummyHash() {
  if (!dummyHashCache) dummyHashCache = await hashPassword(DUMMY_PASSWORD);
  return dummyHashCache;
}

/** scrypt 口令哈希,格式:scrypt$N$r$p$salt$hash(base64url) */
export async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = await scryptAsync(String(pw), salt, KEYLEN, { N, r: R, p: P });
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

/**
 * 校验口令哈希;失败或哈希格式非法返回 false(不抛异常)。
 * user 为 null 时改用占位哈希做完整计算,使「用户不存在」与「密码错误」的耗时基本一致。
 */
export async function verifyUserPassword(user, password) {
  const stored = (user && user.password_hash) || (await dummyHash());
  if (!(await verifyPassword(password, stored))) return false;
  return !!user;
}

export async function verifyPassword(pw, stored) {
  try {
    const [scheme, n, r, p, salt, hash] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const expected = Buffer.from(hash, 'base64url');
    const actual = await scryptAsync(String(pw), Buffer.from(salt, 'base64url'), expected.length, {
      N: Number(n), r: Number(r), p: Number(p),
    });
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

/** 同步兜底:仅用于回归对比与诊断脚本,禁止用于请求路径(会阻塞事件循环) */
export function verifyPasswordSync(pw, stored) {
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
