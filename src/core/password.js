import crypto from 'node:crypto';

const N = 16384, R = 8, P = 1, KEYLEN = 64;
/** 并发上限:scrypt 在 libuv 线程池执行,显式限流防止认证风暴排挤其它 I/O 与请求处理 */
const MAX_CONCURRENT = 8, MAX_PENDING = 64;
let running = 0;
const pending = [];

/** 异步 scrypt;超过并发上限的请求在进程内排队,scryptSync 会阻塞事件循环,这里不再使用 */
function scryptAsync(password, salt, keylen, options) {
  return new Promise((resolve, reject) => {
    const busy = () => Object.assign(new Error('Authentication queue busy'), { status: 503, code: 'auth_busy' });
    const run = () => {
      const done = (err, derived) => {
        running--;
        if (err) reject(err); else resolve(derived);
        const next = pending.shift();
        if (next) { clearTimeout(next.timer); running++; next.run(); }
      };
      try { crypto.scrypt(password, salt, keylen, options, done); }
      catch (err) { done(err); }
    };
    if (running < MAX_CONCURRENT) { running++; run(); }
    else if (pending.length >= MAX_PENDING) reject(busy());
    else {
      const entry = { run, timer: null };
      entry.timer = setTimeout(() => {
        const i = pending.indexOf(entry);
        if (i !== -1) { pending.splice(i, 1); reject(busy()); }
      }, 10000);
      pending.push(entry);
    }
  });
}

/** 占位哈希:用户名不存在时仍做一次等价计算,避免通过响应快慢枚举用户名 */
const DUMMY_PASSWORD = 'dummy-password-for-constant-timing';
let dummyHashCache = null;
async function dummyHash() {
  if (!dummyHashCache) dummyHashCache = hashPassword(DUMMY_PASSWORD).catch((err) => { dummyHashCache = null; throw err; });
  return dummyHashCache;
}

/** scrypt 口令哈希,格式:scrypt$N$r$p$salt$hash(base64url) */
export async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = await scryptAsync(String(pw), salt, KEYLEN, { N, r: R, p: P });
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

/**
 * 校验口令哈希;失败或哈希格式非法返回 false,队列过载时抛出 503 错误。
 * user 为 null 时改用占位哈希做完整计算,使「用户不存在」与「密码错误」的耗时基本一致。
 */
export async function verifyUserPassword(user, password) {
  const stored = (user && user.password_hash) || (await dummyHash());
  if (!(await verifyPassword(password, stored))) return false;
  return !!user;
}

/** 只接受本项目实际签发过的 scrypt 参数,避免畸形存储值触发资源放大。 */
function parseHash(stored) {
  const parts = String(stored).split('$');
  const [scheme, n, r, p, salt, hash] = parts;
  if (parts.length !== 6 || scheme !== 'scrypt' || Number(n) !== N || Number(r) !== R || Number(p) !== P
      || !/^[A-Za-z0-9_-]{22}$/.test(salt) || !/^[A-Za-z0-9_-]{86}$/.test(hash)) return null;
  return { salt: Buffer.from(salt, 'base64url'), expected: Buffer.from(hash, 'base64url') };
}

export async function verifyPassword(pw, stored) {
  const parsed = parseHash(stored);
  if (!parsed) return false;
  try {
    const actual = await scryptAsync(String(pw), parsed.salt, KEYLEN, { N, r: R, p: P });
    return crypto.timingSafeEqual(parsed.expected, actual);
  } catch (err) {
    if (err.code === 'auth_busy') throw err;
    return false;
  }
}

/** 同步兜底:仅供诊断/回归使用,禁止在请求路径使用。 */
export function verifyPasswordSync(pw, stored) {
  const parsed = parseHash(stored);
  if (!parsed) return false;
  try {
    const actual = crypto.scryptSync(String(pw), parsed.salt, KEYLEN, { N, r: R, p: P });
    return crypto.timingSafeEqual(parsed.expected, actual);
  } catch { return false; }
}
