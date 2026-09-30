import * as users from '../../models/users.js';
import * as recovery from '../../models/recovery.js';
import * as consents from '../../models/consents.js';
import * as tokens from '../../models/tokens.js';
import { hashPassword, verifyPassword } from '../../core/password.js';
import { generateSecret, otpauthUri, verifyTotp } from '../../core/totp.js';
import { qrSvg } from '../../core/qr.js';
import { getRuntime } from '../../core/runtime.js';
import { sendHtml, redirect } from '../../core/http.js';
import { accountPage, recoveryCodesPage, authorizationsPage } from '../../views/auth.js';
import { scopeItems } from '../../views/components.js';
import { logger } from '../../core/logger.js';

/** 账号页 2FA 区块的状态组装 */
function twoFaState(user) {
  const rt = getRuntime();
  const otpauth = user.totp_secret
    ? otpauthUri({ secret: user.totp_secret, username: user.username, issuer: rt.siteName })
    : null;
  // 待确认密钥阶段生成扫码二维码;内容超长等异常时降级为无二维码,不阻塞账号页
  let qr = null;
  if (otpauth && !user.totp_enabled) {
    try { qr = qrSvg(otpauth); } catch { qr = null; }
  }
  return {
    enabled: !!user.totp_enabled,
    pendingSecret: user.totp_secret && !user.totp_enabled ? user.totp_secret : null,
    secret: user.totp_secret || null,
    otpauth,
    qr,
    recoveryLeft: recovery.countValid(user.id),
    recoveryCodes: null,
  };
}

/** GET /account */
export function showAccount(ctx, { msg, err } = {}) {
  sendHtml(ctx.res, 200, accountPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName, user: ctx.user,
    csrf: ctx.session.csrf, msg, err, twoFa: twoFaState(ctx.user),
  }));
}

/** POST /account —— 修改自己的密码 */
export function handleChangePassword(ctx) {
  const b = ctx.body || {};
  if (b._csrf !== ctx.session.csrf) return showAccount(ctx, { err: '页面已过期,请重试。' });
  const { current, password, password2 } = b;
  if (typeof current !== 'string' || !verifyPassword(current, ctx.user.password_hash)) {
    return showAccount(ctx, { err: '当前密码不正确。' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return showAccount(ctx, { err: '新密码至少 8 位。' });
  }
  if (password !== password2) {
    return showAccount(ctx, { err: '两次输入的新密码不一致。' });
  }
  users.update(ctx.user.id, { passwordHash: hashPassword(password) });
  logger.info('用户修改了密码', { username: ctx.user.username });
  showAccount(ctx, { msg: '密码已修改。' });
}

/* ---- 两步验证管理 ---- */

/** POST /account/2fa/start —— 验密码后生成待确认密钥 */
export function startTwoFa(ctx) {
  const b = ctx.body || {};
  if (b._csrf !== ctx.session.csrf) return showAccount(ctx, { err: '页面已过期,请重试。' });
  if (ctx.user.totp_enabled) return showAccount(ctx, { msg: '两步验证已开启。' });
  if (typeof b.password !== 'string' || !verifyPassword(b.password, ctx.user.password_hash)) {
    return showAccount(ctx, { err: '当前密码不正确。' });
  }
  users.setTotpSecret(ctx.user.id, generateSecret());
  logger.info('开始设置两步验证', { username: ctx.user.username });
  ctx.user = users.byId(ctx.user.id); // 重读,让页面拿到刚生成的待确认密钥
  showAccount(ctx);
}

/** POST /account/2fa/confirm —— 首次验证码通过则激活并发恢复代码 */
export function confirmTwoFa(ctx) {
  const b = ctx.body || {};
  if (b._csrf !== ctx.session.csrf) return showAccount(ctx, { err: '页面已过期,请重试。' });
  const fresh = users.byId(ctx.user.id);
  if (!fresh.totp_secret || fresh.totp_enabled) return showAccount(ctx, { err: '当前没有待确认的两步验证设置。' });
  if (!verifyTotp(fresh.totp_secret, b.code)) {
    return showAccount(ctx, { err: '验证码不正确,请确认 App 时间与密钥无误后重试。' });
  }
  users.enableTotp(fresh.id);
  const codes = recovery.createBatch(fresh.id, 8);
  logger.info('两步验证已开启', { username: fresh.username });
  sendHtml(ctx.res, 200, recoveryCodesPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName, user: fresh, codes,
  }));
}

/** POST /account/2fa/disable —— 验密码后关闭并清除恢复代码 */
export function disableTwoFa(ctx) {
  const b = ctx.body || {};
  if (b._csrf !== ctx.session.csrf) return showAccount(ctx, { err: '页面已过期,请重试。' });
  if (typeof b.password !== 'string' || !verifyPassword(b.password, ctx.user.password_hash)) {
    return showAccount(ctx, { err: '当前密码不正确。' });
  }
  users.clearTotp(ctx.user.id);
  recovery.clearFor(ctx.user.id);
  logger.info('两步验证已关闭', { username: ctx.user.username });
  ctx.user = users.byId(ctx.user.id);
  showAccount(ctx, { msg: '两步验证已关闭。' });
}

/* ---- 我的授权(查看/撤销已记住的应用授权) ---- */

/** GET /account/apps */
export function showAuthorizations(ctx, { msg, err } = {}) {
  const list = consents.listForUser(ctx.user.id).map((row) => ({
    ...row,
    scopeItems: scopeItems(row.scope.split(/\s+/).filter(Boolean)),
  }));
  sendHtml(ctx.res, 200, authorizationsPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName, user: ctx.user,
    csrf: ctx.session.csrf, list, msg, err,
  }));
}

/** POST /account/apps/revoke —— 撤销授权并级联吊销该应用的现有令牌 */
export function revokeAuthorization(ctx) {
  const b = ctx.body || {};
  if (b._csrf !== ctx.session.csrf) {
    return redirect(ctx.res, '/account/apps?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
  const row = consents.get(ctx.user.id, String(b.client_id || ''));
  if (!row) {
    return redirect(ctx.res, '/account/apps?err=' + encodeURIComponent('该授权不存在或已被撤销。'));
  }
  consents.revoke(ctx.user.id, row.client_id);
  tokens.revokeForClientUser(row.client_id, ctx.user.id);
  logger.info('用户撤销了应用授权', { username: ctx.user.username, client_id: row.client_id });
  redirect(ctx.res, '/account/apps?msg=' + encodeURIComponent('已撤销该应用的授权,其现有访问令牌一并失效。'));
}
