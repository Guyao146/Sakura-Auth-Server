import * as users from '../../models/users.js';
import * as recovery from '../../models/recovery.js';
import * as consents from '../../models/consents.js';
import * as tokens from '../../models/tokens.js';
import * as sessions from '../../models/sessions.js';
import { hashPassword, verifyPassword } from '../../core/password.js';
import { invalidateUserCredentials } from './credentials.js';
import { generateSecret, otpauthUri, verifyTotp } from '../../core/totp.js';
import { qrSvg } from '../../core/qr.js';
import { getRuntime } from '../../core/runtime.js';
import { sendHtml, redirect, clearCookie } from '../../core/http.js';
import { accountPage, recoveryCodesPage, authorizationsPage, sessionsPage } from '../../views/auth.js';
import { scopeItems } from '../../views/components.js';
import { logger } from '../../core/logger.js';
import { record } from '../audit.js';

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
    cur: ctx.url.pathname + ctx.url.search,
  }));
}

/** POST /account —— 修改自己的密码 */
export async function handleChangePassword(ctx) {
  const b = ctx.body || {};
  if (b._csrf !== ctx.session.csrf) return showAccount(ctx, { err: '页面已过期,请重试。' });
  const { current, password, password2 } = b;
  if (typeof current !== 'string' || !(await verifyPassword(current, ctx.user.password_hash))) {
    return showAccount(ctx, { err: '当前密码不正确。' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return showAccount(ctx, { err: '新密码至少 8 位。' });
  }
  if (password !== password2) {
    return showAccount(ctx, { err: '两次输入的新密码不一致。' });
  }
  users.update(ctx.user.id, { passwordHash: await hashPassword(password) });
  // 统一凭据失效:吊销令牌、删除未使用授权码、清除其它设备会话(保留当前会话)
  invalidateUserCredentials(ctx.user.id, { keepSession: ctx.session.id_hash });
  record(ctx, 'account.password_changed');
  logger.info('用户修改了密码', { username: ctx.user.username });
  showAccount(ctx, { msg: '密码已修改,其它设备需要重新登录。' });
}

/* ---- 两步验证管理 ---- */

/** POST /account/2fa/start —— 验密码后生成待确认密钥 */
export async function startTwoFa(ctx) {
  const b = ctx.body || {};
  if (b._csrf !== ctx.session.csrf) return showAccount(ctx, { err: '页面已过期,请重试。' });
  if (ctx.user.totp_enabled) return showAccount(ctx, { msg: '两步验证已开启。' });
  if (typeof b.password !== 'string' || !(await verifyPassword(b.password, ctx.user.password_hash))) {
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
  record(ctx, 'account.2fa_enabled', fresh.username);
  logger.info('两步验证已开启', { username: fresh.username });
  sendHtml(ctx.res, 200, recoveryCodesPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName, user: fresh, codes,
  }));
}

/** POST /account/2fa/disable —— 验密码后关闭并清除恢复代码 */
export async function disableTwoFa(ctx) {
  const b = ctx.body || {};
  if (b._csrf !== ctx.session.csrf) return showAccount(ctx, { err: '页面已过期,请重试。' });
  if (typeof b.password !== 'string' || !(await verifyPassword(b.password, ctx.user.password_hash))) {
    return showAccount(ctx, { err: '当前密码不正确。' });
  }
  users.clearTotp(ctx.user.id);
  recovery.clearFor(ctx.user.id);
  record(ctx, 'account.2fa_disabled');
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
    cur: ctx.url.pathname + ctx.url.search,
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
  record(ctx, 'oauth.consent_revoked', row.client_id);
  logger.info('用户撤销了应用授权', { username: ctx.user.username, client_id: row.client_id });
  redirect(ctx.res, '/account/apps?msg=' + encodeURIComponent('已撤销该应用的授权,其现有访问令牌一并失效。'));
}

/* ---- 登录会话管理(查看/撤销已登录设备) ---- */

/** GET /account/sessions —— 登录会话列表,当前会话行带 is_current 标记 */
export function showSessions(ctx, { msg, err } = {}) {
  const list = sessions.listForUser(ctx.user.id).map((row) => ({
    ...row,
    is_current: row.id_hash === ctx.session.id_hash,
  }));
  sendHtml(ctx.res, 200, sessionsPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName, user: ctx.user,
    csrf: ctx.session.csrf, list, msg, err,
    cur: ctx.url.pathname + ctx.url.search,
  }));
}

/** POST /account/sessions/revoke {id_hash, _csrf} —— 撤销指定会话(仅限自己的)。
 *  撤销当前会话等同登出:清 cookie 并回登录页;其它会话回列表页带提示。 */
export function revokeSession(ctx) {
  const b = ctx.body || {};
  if (typeof b._csrf !== 'string' || b._csrf !== ctx.session.csrf) {
    return redirect(ctx.res, '/account/sessions?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
  const target = typeof b.id_hash === 'string' ? b.id_hash : '';
  const removed = target ? sessions.removeByIdHash(target, ctx.user.id) : false;
  if (!removed) {
    return redirect(ctx.res, '/account/sessions?err=' + encodeURIComponent('该会话不存在或已被撤销。'));
  }
  record(ctx, 'account.session_revoked', target);
  logger.info('用户撤销了登录会话', { username: ctx.user.username });
  if (target === ctx.session.id_hash) {
    clearCookie(ctx.res, 'sid', getRuntime().secureCookies);
    return redirect(ctx.res, '/login?msg=' + encodeURIComponent('已撤销当前会话,请重新登录。'));
  }
  return redirect(ctx.res, '/account/sessions?msg=' + encodeURIComponent('已撤销该会话,对应设备下次访问需重新登录。'));
}

/** POST /account/sessions/revoke-others {_csrf} —— 撤销当前会话以外的全部会话 */
export function revokeOtherSessions(ctx) {
  const b = ctx.body || {};
  if (typeof b._csrf !== 'string' || b._csrf !== ctx.session.csrf) {
    return redirect(ctx.res, '/account/sessions?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
  const removed = sessions.removeAllOther(ctx.user.id, ctx.session.id_hash);
  record(ctx, 'account.session_revoked_others', String(removed));
  logger.info('用户撤销了其它全部登录会话', { username: ctx.user.username, count: removed });
  return redirect(ctx.res, '/account/sessions?msg='
    + encodeURIComponent(`已撤销其它 ${removed} 个会话,对应设备下次访问需重新登录。`));
}
