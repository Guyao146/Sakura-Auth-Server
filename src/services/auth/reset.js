/** 邮件找回密码:申请重置链接 + 凭 token 设置新密码(防枚举、防 CSRF) */
import * as users from '../../models/users.js';
import * as sessions from '../../models/sessions.js';
import * as resets from '../../models/resets.js';
import { getDb } from '../../core/db.js';
import { sendMail } from '../../core/smtp.js';
import { getRuntime } from '../../core/runtime.js';
import { setCookie, sendHtml } from '../../core/http.js';
import { randomToken } from '../../core/crypto.js';
import { hashPassword } from '../../core/password.js';
import { logger } from '../../core/logger.js';
import { forgotPasswordPage, resetPasswordPage, resetDonePage } from '../../views/auth.js';
import { errorPage } from '../../views/error.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/* 按 IP 简单限流:1 分钟最多 3 次申请(Map 即可,进程内;带惰性过期清理与硬上限) */
const WINDOW_MS = 60 * 1000, MAX_PER_WINDOW = 3, MAX_KEYS = 5000;
const hits = new Map();

/** 惰性清理:删除已过窗口的计数,并对 Map 硬上限兜底(参照 login.js pruneAttempts 模式) */
function pruneHits() {
  if (hits.size === 0) return;
  const now = Date.now();
  if (hits.size > 64) {
    for (const [k, v] of hits) {
      if (now - v.first > WINDOW_MS) hits.delete(k);
    }
  }
  while (hits.size > MAX_KEYS) {
    hits.delete(hits.keys().next().value);
  }
}

function rateLimited(ctx) {
  pruneHits();
  const ip = ctx.req.socket.remoteAddress || '?';
  const rec = hits.get(ip);
  if (!rec || Date.now() - rec.first > WINDOW_MS) {
    hits.set(ip, { first: Date.now(), count: 1 });
    return false;
  }
  rec.count += 1;
  return rec.count > MAX_PER_WINDOW;
}

/** 仅供冒烟/单元测试观察与驱动限流状态;不参与业务流程 */
export const _rateLimitInternal = { map: hits, prune: pruneHits, maxKeys: MAX_KEYS };

/** 双提交 cookie 的 CSRF:没有则下发(与登录页同一枚 csrf cookie) */
function ensureCsrf(ctx) {
  let csrf = ctx.cookies.csrf;
  if (!csrf) {
    csrf = randomToken(18);
    setCookie(ctx.res, 'csrf', csrf, { maxAge: 600, secure: ctx.runtime.secureCookies });
  }
  return csrf;
}

/** GET /forgot-password */
export function showForgot(ctx, { err, msg, email = '' } = {}) {
  const csrf = ensureCsrf(ctx);
  sendHtml(ctx.res, 200, forgotPasswordPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName, csrf, err, msg, email,
  }));
}

/** POST /forgot-password —— 无论邮箱是否存在都渲染同一段通用提示(防枚举) */
export async function handleForgot(ctx) {
  const b = ctx.body || {};
  const cookieCsrf = ctx.cookies.csrf || '';
  if (!cookieCsrf || typeof b._csrf !== 'string' || b._csrf !== cookieCsrf) {
    return showForgot(ctx, { err: '页面已过期,请重新提交。' });
  }
  if (rateLimited(ctx)) {
    return showForgot(ctx, { err: '请求过于频繁,请 1 分钟后再试。' });
  }
  const email = String(b.email || '').trim();
  if (!EMAIL_RE.test(email)) {
    return showForgot(ctx, { err: '请输入有效的邮箱地址。', email });
  }

  const user = getDb()
    .prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE AND disabled = 0')
    .get(email);
  if (user) {
    const rt = getRuntime();
    const token = resets.create(user.id);
    const link = `${rt.issuer}/reset-password?token=${encodeURIComponent(token)}`;
    try {
      await sendMail({
        to: user.email,
        subject: `${rt.siteName}密码重置`,
        text: [
          `你好,${user.username}:`,
          '',
          '我们收到了重置你账号密码的请求。请点击下面的链接设置新密码(30 分钟内有效):',
          '',
          link,
          '',
          '如果这不是你本人的操作,请忽略本邮件,你的密码不会被更改。',
          '',
          `—— ${rt.siteName}`,
        ].join('\n'),
      });
      logger.info('密码重置邮件已处理', { username: user.username });
    } catch (err) {
      // 发信失败不向页面泄露细节,只记日志(页面提示保持一致)
      logger.error('重置邮件发送失败', { to: user.email, err: err.stack || String(err) });
    }
  }

  // 统一提示:不区分邮箱是否存在(不回显邮箱,保证两种情况页面逐字节一致)
  showForgot(ctx, {
    msg: '如果该邮箱已注册,重置链接已发送,请在 30 分钟内查收邮件(注意垃圾箱)。',
  });
}

/** GET /reset-password?token=... —— token 有效才渲染新密码表单 */
export function showReset(ctx, { err, token } = {}) {
  const tokenStr = String(token || ctx.query.get('token') || '');
  if (!resets.lookup(tokenStr)) {
    return sendHtml(ctx.res, 400, errorPage({
      theme: ctx.theme, siteName: ctx.runtime.siteName,
      title: '链接无效',
      message: '重置链接无效、已使用或已过期。请返回登录页重新发起「找回密码」。',
    }));
  }
  const csrf = ensureCsrf(ctx);
  sendHtml(ctx.res, 200, resetPasswordPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName, csrf, token: tokenStr, err,
  }));
}

/** POST /reset-password —— 校验通过后改密、消费 token、清掉全部会话 */
export function handleReset(ctx) {
  const b = ctx.body || {};
  const cookieCsrf = ctx.cookies.csrf || '';
  if (!cookieCsrf || typeof b._csrf !== 'string' || b._csrf !== cookieCsrf) {
    return showReset(ctx, { token: String(b.token || ''), err: '页面已过期,请重新提交。' });
  }
  const token = String(b.token || '');
  const { password, password2 } = b;
  if (typeof password !== 'string' || password.length < 8) {
    return showReset(ctx, { token, err: '新密码至少 8 位。' });
  }
  if (password !== password2) {
    return showReset(ctx, { token, err: '两次输入的新密码不一致。' });
  }

  const userId = resets.consume(token); // 一次性:先消费,防止重放
  const user = userId ? users.byId(userId) : null;
  if (!user || user.disabled) {
    return sendHtml(ctx.res, 400, errorPage({
      theme: ctx.theme, siteName: ctx.runtime.siteName,
      title: '链接无效',
      message: '重置链接无效、已使用或已过期。请返回登录页重新发起「找回密码」。',
    }));
  }

  users.update(user.id, { passwordHash: hashPassword(password) });
  sessions.removeByUser(user.id);
  logger.info('密码已通过邮件重置,全部会话已清除', { username: user.username });
  sendHtml(ctx.res, 200, resetDonePage({ theme: ctx.theme, siteName: ctx.runtime.siteName }));
}
