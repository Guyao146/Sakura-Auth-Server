import * as users from '../../models/users.js';
import * as sessions from '../../models/sessions.js';
import { hashPassword } from '../../core/password.js';
import { randomToken } from '../../core/crypto.js';
import { setCookie, clearCookie, redirect, sendHtml } from '../../core/http.js';
import { getRuntime } from '../../core/runtime.js';
import { logger } from '../../core/logger.js';
import { USERNAME_RE } from '../../core/util.js';
import { registerPage } from '../../views/auth.js';
import { record } from '../audit.js';

/* 注册限流:同 IP 1 分钟内最多 5 次提交 */
const MAX_SUBMITS = 5, WINDOW_SEC = 60;
const submits = new Map();

function limited(ctx) {
  const key = ctx.req.socket.remoteAddress || '?';
  const rec = submits.get(key);
  if (!rec || Date.now() - rec.first > WINDOW_SEC * 1000) {
    submits.set(key, { count: 1, first: Date.now() });
    return false;
  }
  rec.count += 1;
  return rec.count > MAX_SUBMITS;
}

/** 回显时只保留非敏感字段,密码不回填 */
const pickValues = (b = {}) => ({
  username: typeof b.username === 'string' ? b.username : '',
  name: typeof b.name === 'string' ? b.name : '',
  email: typeof b.email === 'string' ? b.email : '',
});

/** GET /register —— 开关关闭时不可用 */
export function showRegister(ctx, { err, values } = {}) {
  if (!ctx.runtime.allowRegister) return redirect(ctx.res, '/login');
  if (ctx.session) return redirect(ctx.res, '/apps');
  let csrf = ctx.cookies.csrf;
  if (!csrf) {
    csrf = randomToken(18);
    setCookie(ctx.res, 'csrf', csrf, { maxAge: 600, secure: ctx.runtime.secureCookies });
  }
  sendHtml(ctx.res, err ? 400 : 200, registerPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName, csrf, err, values,
  }));
}

/** POST /register —— 校验通过后直接建立会话并进入首页 */
export function handleRegister(ctx) {
  const rt = getRuntime();
  if (!rt.allowRegister) return redirect(ctx.res, '/login');
  const b = ctx.body || {};
  if (limited(ctx)) {
    logger.warn('注册限流触发', { ip: ctx.req.socket.remoteAddress || '?' });
    return showRegister(ctx, { err: '注册尝试过于频繁,请 1 分钟后再试。', values: pickValues(b) });
  }
  const cookieCsrf = ctx.cookies.csrf || '';
  if (!cookieCsrf || typeof b._csrf !== 'string' || b._csrf !== cookieCsrf) {
    return showRegister(ctx, { err: '页面已过期,请重新提交。', values: pickValues(b) });
  }
  const username = String(b.username || '').trim();
  if (!USERNAME_RE.test(username)) {
    return showRegister(ctx, { err: '用户名需为 2-64 位字母数字与 _.@-。', values: pickValues(b) });
  }
  if (users.byUsername(username)) {
    return showRegister(ctx, { err: '用户名已存在。', values: pickValues(b) });
  }
  if (typeof b.password !== 'string' || b.password.length < 8) {
    return showRegister(ctx, { err: '密码至少 8 位。', values: pickValues(b) });
  }
  if (b.password !== b.password2) {
    return showRegister(ctx, { err: '两次输入的密码不一致。', values: pickValues(b) });
  }
  // 自助注册的账号永远不是管理员
  const user = users.create({
    username,
    passwordHash: hashPassword(b.password),
    name: String(b.name || '').trim(),
    email: String(b.email || '').trim(),
    isAdmin: false,
  });
  const sid = sessions.create(user.id, randomToken(24), rt.sessionTtl);
  setCookie(ctx.res, 'sid', sid, { maxAge: rt.sessionTtl, secure: rt.secureCookies });
  clearCookie(ctx.res, 'csrf', rt.secureCookies);
  record(ctx, 'auth.register', user.username, { actor: user.username });
  logger.info('新用户注册', { username: user.username });
  redirect(ctx.res, '/apps');
}
