import crypto from 'node:crypto';
import * as users from '../../models/users.js';
import * as sessions from '../../models/sessions.js';
import * as recovery from '../../models/recovery.js';
import { hashPassword, verifyPassword } from '../../core/password.js';
import { randomToken, sha256hex, timingSafeEqStr, nowSec } from '../../core/crypto.js';
import { verifyTotp } from '../../core/totp.js';
import { getSigningKey } from '../../core/keys.js';
import { setCookie, clearCookie, redirect, sendHtml } from '../../core/http.js';
import { hiddenInputs } from '../../views/components.js';
import { escapeHtml as esc } from '../../core/util.js';
import { getRuntime } from '../../core/runtime.js';
import { logger } from '../../core/logger.js';
import { safeNext } from '../../core/util.js';
import { loginPage, twofaPage } from '../../views/auth.js';
import { errorPage } from '../../views/error.js';
import { record } from '../audit.js';
import { sendMail } from '../../core/smtp.js';
import { fmtTime } from '../../core/util.js';

/* 登录失败限流:同 IP+用户名 5 次失败锁定 60 秒;另设 IP 级总失败上限(防同 IP 换用户名绕过) */
const MAX_FAILS = 5, LOCK_SEC = 60, MAX_ATTEMPT_KEYS = 5000;
const MAX_IP_FAILS = 20, IP_WINDOW = 600; // IP 级:20 次失败 / 10 分钟
const attempts = new Map();
const ipFails = new Map();

function failKey(ctx, username) {
  const ip = ctx.req.socket.remoteAddress || '?';
  return `${ip}|${String(username || '').toLowerCase()}`;
}

/** 惰性清理:删除已过锁定期的计数,并对 Map 硬上限兜底(防内存无限增长) */
function pruneAttempts() {
  if (attempts.size === 0) return;
  const now = Date.now();
  if (attempts.size > 64) {
    for (const [k, v] of attempts) {
      if (now - v.first > LOCK_SEC * 1000) attempts.delete(k);
    }
  }
  while (attempts.size > MAX_ATTEMPT_KEYS) {
    attempts.delete(attempts.keys().next().value);
  }
}

function isLocked(ctx, username) {
  pruneAttempts();
  const ip = ctx.req.socket.remoteAddress || '?';
  // 两级判定:用户名级(5 次/60s)+ IP 级(20 次失败/10 分钟,换用户名无法绕过)
  const ipRec = ipFails.get(ip);
  if (ipRec && ipRec.count >= MAX_IP_FAILS && Date.now() - ipRec.first < IP_WINDOW * 1000) return true;
  const rec = attempts.get(failKey(ctx, username));
  return rec && rec.count >= MAX_FAILS && Date.now() - rec.first < LOCK_SEC * 1000;
}

/** 记一次凭据失败(限流计数 + 审计;web 与 /api 登录共用,action 可区分两步验证失败) */
function recordFail(ctx, username, action = 'auth.login_failed') {
  pruneAttempts();
  const ip = ctx.req.socket.remoteAddress || '?';
  const ipRec = ipFails.get(ip);
  if (!ipRec || Date.now() - ipRec.first > IP_WINDOW * 1000) ipFails.set(ip, { count: 1, first: Date.now() });
  else ipRec.count += 1;
  const key = failKey(ctx, username);
  const rec = attempts.get(key);
  if (!rec || Date.now() - rec.first > LOCK_SEC * 1000) attempts.set(key, { count: 1, first: Date.now() });
  else rec.count += 1;
  record(ctx, action, String(username || ''), { actor: String(username || '') || 'anonymous' });
}

function clearFails(ctx, username) {
  attempts.delete(failKey(ctx, username));
  ipFails.delete(ctx.req.socket.remoteAddress || '?');
}

/* 未知用户名的时序均衡:对固定 Dummy 哈希执行一次等价 scrypt,
 * 消除「用户存在性」响应时间差异,并强制枚举者每次都付出计算成本 */
const DUMMY_HASH = hashPassword('sakuraid-dummy-timing-equalizer');

export { isLocked, recordFail, clearFails };

/* 二步验证的中间态:把「密码已通过的用户」签成短时 HMAC 令牌(5 分钟),不落会话 */
let hmacKeyCache = null;
const hmacKey = () => {
  if (!hmacKeyCache) hmacKeyCache = crypto.createHash('sha256').update(getSigningKey().privatePem).digest();
  return hmacKeyCache;
};
const b64u = (buf) => Buffer.from(buf).toString('base64url');

function signPending(userId, ttl = 300) {
  const payload = b64u(JSON.stringify({ uid: userId, exp: nowSec() + ttl }));
  const sig = b64u(crypto.createHmac('sha256', hmacKey()).update(payload).digest());
  return `${payload}.${sig}`;
}

function verifyPending(token) {
  try {
    const [payload, sig] = String(token || '').split('.');
    if (!payload || !sig) return null;
    const expected = b64u(crypto.createHmac('sha256', hmacKey()).update(payload).digest());
    if (!timingSafeEqStr(sig, expected)) return null;
    const { uid, exp } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!uid || exp <= nowSec()) return null;
    return uid;
  } catch {
    return null;
  }
}

/** GET /login */
export function showLogin(ctx, { err, username = '' } = {}) {
  if (ctx.session) return redirect(ctx.res, safeNext(ctx.query.get('next'), '') || '/apps');
  let csrf = ctx.cookies.csrf;
  if (!csrf) {
    csrf = randomToken(18);
    setCookie(ctx.res, 'csrf', csrf, { maxAge: 600, secure: ctx.runtime.secureCookies });
  }
  const nextRaw = ctx.query.get('next') || '';
  sendHtml(ctx.res, err ? 401 : 200, loginPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName,
    csrf, next: safeNext(nextRaw, ''), err, username,
    msg: ctx.query.get('msg') || '',
    allowRegister: ctx.runtime.allowRegister,
  }));
}

/** POST /login —— 第一因子:密码 */
export function handleLogin(ctx) {
  const body = ctx.body || {};
  const next = safeNext(body.next, '');
  const cookieCsrf = ctx.cookies.csrf || '';
  if (!cookieCsrf || typeof body._csrf !== 'string' || body._csrf !== cookieCsrf) {
    return showLogin(ctx, { err: '页面已过期,请重新提交。' });
  }
  if (isLocked(ctx, body.username)) {
    return showLogin(ctx, { err: '失败次数过多,请 1 分钟后再试。', username: body.username });
  }
  const user = body.username ? users.byUsername(String(body.username)) : null;
  const pw = typeof body.password === 'string' ? body.password : '';
  // 未知用户对 Dummy 哈希也执行一次等价 scrypt:消除存在性时序差异,强制枚举者每次都付出计算成本
  const ok = user && !user.disabled && pw !== '' && verifyPassword(pw, user.password_hash);
  if (!ok) {
    if (!user) verifyPassword(pw || 'x', DUMMY_HASH);
    recordFail(ctx, body.username);
    logger.warn('登录失败', { username: String(body.username || '') });
    return showLogin(ctx, { err: '用户名或密码不正确。', username: body.username });
  }

  // 已开启两步验证:先不出会话,进入第二因子
  if (user.totp_enabled && user.totp_secret) {
    return sendHtml(ctx.res, 200, twofaPage({
      theme: ctx.theme, siteName: ctx.runtime.siteName,
      csrf: cookieCsrf, pending: signPending(user.id), next,
      username: user.username,
    }));
  }
  return finishLogin(ctx, user, next, cookieCsrf);
}

/** POST /login/2fa —— 第二因子:TOTP 或恢复代码 */
export function handleTwoFa(ctx) {
  const b = ctx.body || {};
  const cookieCsrf = ctx.cookies.csrf || '';
  if (!cookieCsrf || typeof b._csrf !== 'string' || b._csrf !== cookieCsrf) {
    return redirect(ctx.res, '/login');
  }
  const uid = verifyPending(b.pending);
  const user = uid ? users.byId(uid) : null;
  if (!user || user.disabled || !user.totp_enabled || !user.totp_secret) {
    return redirect(ctx.res, '/login');
  }
  const next = safeNext(b.next, '');
  if (isLocked(ctx, user.username)) {
    return redirect(ctx.res, '/login?err=' + encodeURIComponent('失败次数过多,请 1 分钟后再试。'));
  }
  const code = typeof b.code === 'string' ? b.code.trim() : '';
  const okTotp = verifyTotp(user.totp_secret, code);
  const okRecovery = !okTotp && recovery.consume(user.id, code);
  if (!okTotp && !okRecovery) {
    recordFail(ctx, user.username, 'auth.2fa_failed');
    logger.warn('两步验证失败', { username: user.username });
    return sendHtml(ctx.res, 401, twofaPage({
      theme: ctx.theme, siteName: ctx.runtime.siteName,
      csrf: cookieCsrf, pending: signPending(user.id), next,
      username: user.username, err: '验证码不正确,请重试。',
    }));
  }
  if (okRecovery) logger.info('恢复代码已使用', { username: user.username });
  clearFails(ctx, user.username);
  return finishLogin(ctx, user, next, cookieCsrf);
}

/** 从请求提取会话设备信息(IP / User-Agent),各登录入口统一传给 startSession 落库 */
export function sessionMeta(ctx) {
  return {
    ip: ctx.req.socket.remoteAddress || '',
    ua: String(ctx.req.headers['user-agent'] || ''),
  };
}

/**
 * 新设备登录提醒:历史会话中未出现过相同 IP + User-Agent 时视为新设备,
 * 向用户邮箱 fire-and-forget 发送提醒(未配置邮箱则跳过;发信失败只记日志,不影响登录)。
 * 独立函数 + startSession 末尾单行调用,便于并行改动共存;sid 用于排除本次刚建的会话。
 */
async function checkNewDevice(res, user, meta, sid) {
  try {
    const ip = String(meta.ip || '');
    const ua = String(meta.ua || '');
    if (!user.email) return; // 无邮箱无法通知,直接跳过
    const idHash = sha256hex(sid); // 本次登录刚建的会话不算历史
    const known = sessions.listForUser(user.id)
      .some((s) => s.id_hash !== idHash && s.ip === ip && s.user_agent === ua);
    if (known) return;
    await sendMail({
      to: user.email,
      subject: '新设备登录提醒',
      text: [
        `您的账号 ${user.username} 刚刚在一台新设备上登录。`,
        '',
        `站点:${getRuntime().siteName}`,
        `用户名:${user.username}`,
        `时间:${fmtTime(nowSec())}`,
        `IP:${ip || '(未知)'}`,
        `设备:${ua || '(未知)'}`,
        '',
        '如非本人操作,请立即登录并修改密码,必要时联系管理员。',
      ].join('\n'),
    });
    record({ req: res.req, user }, 'auth.new_device', `ip=${ip} ua=${ua.slice(0, 120)}`, { actor: user.username });
  } catch (err) {
    logger.warn('新设备登录提醒发送失败(不影响登录)', { username: user.username, error: err?.message });
  }
}

/** 建立会话并写入 sid cookie(清除 csrf cookie);供 web 登录与 JSON API 共用,返回明文 sid。
 *  meta 可选 {ip, ua},用于会话管理页展示登录设备信息。 */
export function startSession(res, user, secureCookies, meta = {}) {
  const rt = getRuntime();
  const sid = sessions.create(user.id, randomToken(24), rt.sessionTtl, meta);
  const secure = secureCookies ?? rt.secureCookies;
  setCookie(res, 'sid', sid, { maxAge: rt.sessionTtl, secure });
  clearCookie(res, 'csrf', secure);
  // 登录成功审计:web 表单、/api 登录与 Microsoft 登录都经此处,统一留痕一次
  record({ req: res.req, user }, 'auth.login', user.username, { actor: user.username });
  logger.info('登录成功', { username: user.username });
  checkNewDevice(res, user, meta, sid).catch(() => {}); // 新设备登录提醒(fire-and-forget,失败不影响登录)
  return sid;
}

function finishLogin(ctx, user, next, cookieCsrf) {
  startSession(ctx.res, user, undefined, sessionMeta(ctx));
  redirect(ctx.res, next || '/apps');
}

/** 登录失败/受限时统一 403 页:显示当前身份,避免「我是谁、怎么切换」的困惑 */
export function forbidden(ctx, message) {
  let extra = '';
  if (ctx.user) {
    const initial = (String(ctx.user.name || ctx.user.username).trim()[0] || '?').toUpperCase();
    extra = `
      <div class="identity">
        <span class="avatar">${esc(initial)}</span>
        <span>当前登录:<b style="color:var(--text)">${esc(ctx.user.name || ctx.user.username)}</b>(<span>${esc(ctx.user.username)}</span>${ctx.user.is_admin ? ' · 管理员' : ' · 普通用户'})</span>
      </div>
      <form method="post" action="/logout">
        ${hiddenInputs({ _csrf: ctx.session.csrf })}
        <div class="actions" style="margin-top:var(--s3)">
          <button class="btn btn-primary" type="submit">退出并切换账号</button>
        </div>
      </form>`;
  }
  sendHtml(ctx.res, 403, errorPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName,
    title: '没有访问权限', message: message || '该页面需要管理员权限,当前账号无权访问。',
    extra,
  }));
}
