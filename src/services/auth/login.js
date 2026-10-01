import crypto from 'node:crypto';
import * as users from '../../models/users.js';
import * as sessions from '../../models/sessions.js';
import * as recovery from '../../models/recovery.js';
import { verifyPassword } from '../../core/password.js';
import { randomToken, timingSafeEqStr, nowSec } from '../../core/crypto.js';
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

/* 登录失败限流:同 IP+用户名 5 次失败锁定 60 秒 */
const MAX_FAILS = 5, LOCK_SEC = 60;
const attempts = new Map();

function failKey(ctx, username) {
  const ip = ctx.req.socket.remoteAddress || '?';
  return `${ip}|${String(username || '').toLowerCase()}`;
}

function isLocked(ctx, username) {
  const rec = attempts.get(failKey(ctx, username));
  return rec && rec.count >= MAX_FAILS && Date.now() - rec.first < LOCK_SEC * 1000;
}

function recordFail(ctx, username) {
  const key = failKey(ctx, username);
  const rec = attempts.get(key);
  if (!rec || Date.now() - rec.first > LOCK_SEC * 1000) attempts.set(key, { count: 1, first: Date.now() });
  else rec.count += 1;
}

function clearFails(ctx, username) {
  attempts.delete(failKey(ctx, username));
}

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
  if (ctx.session) return redirect(ctx.res, safeNext(ctx.query.get('next')));
  let csrf = ctx.cookies.csrf;
  if (!csrf) {
    csrf = randomToken(18);
    setCookie(ctx.res, 'csrf', csrf, { maxAge: 600, secure: ctx.runtime.secureCookies });
  }
  const nextRaw = ctx.query.get('next') || '';
  sendHtml(ctx.res, err ? 401 : 200, loginPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName,
    csrf, next: safeNext(nextRaw, ''), err, username,
    allowRegister: ctx.runtime.allowRegister,
  }));
}

/** POST /login —— 第一因子:密码 */
export function handleLogin(ctx) {
  const body = ctx.body || {};
  const next = safeNext(body.next);
  const cookieCsrf = ctx.cookies.csrf || '';
  if (!cookieCsrf || typeof body._csrf !== 'string' || body._csrf !== cookieCsrf) {
    return showLogin(ctx, { err: '页面已过期,请重新提交。' });
  }
  if (isLocked(ctx, body.username)) {
    return showLogin(ctx, { err: '失败次数过多,请 1 分钟后再试。', username: body.username });
  }
  const user = body.username ? users.byUsername(String(body.username)) : null;
  const ok = user && !user.disabled && typeof body.password === 'string' && verifyPassword(body.password, user.password_hash);
  if (!ok) {
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
  const next = safeNext(b.next);
  if (isLocked(ctx, user.username)) {
    return redirect(ctx.res, '/login?err=' + encodeURIComponent('失败次数过多,请 1 分钟后再试。'));
  }
  const code = typeof b.code === 'string' ? b.code.trim() : '';
  const okTotp = verifyTotp(user.totp_secret, code);
  const okRecovery = !okTotp && recovery.consume(user.id, code);
  if (!okTotp && !okRecovery) {
    recordFail(ctx, user.username);
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

/** 建立会话并写入 sid cookie(清除 csrf cookie);供 web 登录与 JSON API 共用,返回明文 sid */
export function startSession(res, user, secureCookies) {
  const rt = getRuntime();
  const sid = sessions.create(user.id, randomToken(24), rt.sessionTtl);
  const secure = secureCookies ?? rt.secureCookies;
  setCookie(res, 'sid', sid, { maxAge: rt.sessionTtl, secure });
  clearCookie(res, 'csrf', secure);
  logger.info('登录成功', { username: user.username });
  return sid;
}

function finishLogin(ctx, user, next, cookieCsrf) {
  startSession(ctx.res, user);
  redirect(ctx.res, next || '/');
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
