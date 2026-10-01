import * as users from '../../models/users.js';
import { verifyPassword, hashPassword } from '../../core/password.js';
import { randomToken, sha256b64url, nowSec } from '../../core/crypto.js';
import { setCookie, redirect, sendHtml } from '../../core/http.js';
import { buildAuthUrl, exchangeCode, verifyIdToken } from '../../core/msal.js';
import { USERNAME_RE } from '../../core/util.js';
import { getRuntime } from '../../core/runtime.js';
import { logger } from '../../core/logger.js';
import { msLinkPage } from '../../views/auth.js';
import { errorPage } from '../../views/error.js';
import { startSession } from './login.js';

/**
 * Microsoft 账号登录与绑定(OIDC 联邦):
 * GET  /auth/microsoft          发起授权(带 ?bind=1 时为已登录用户的绑定模式)
 * GET  /auth/microsoft/callback 授权码回调:绑定 / 登录 / 渲染关联页
 * POST /auth/microsoft/link     关联页表单 A:已有本地账号绑定并登录
 * POST /auth/microsoft/register 关联页表单 B:注册新号并绑定(自助注册开启时)
 * POST /auth/microsoft/unbind   已登录用户解绑
 */

/* 授权 state 与关联令牌的内存暂存(容量上限 500,淘汰最旧;TTL 10 分钟) */
const MAX_STASH = 500;
const STASH_TTL = 600;
const authStashes = new Map(); // state → { exp, verifier, bindUserId }
const linkTokens = new Map();  // linkToken → { exp, sub, email, name }

function stashPut(map, key, value) {
  if (map.size >= MAX_STASH) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
  map.set(key, value);
}

/** 取出并删除(一次性);过期视为无效 */
function stashTake(map, key) {
  const v = map.get(key);
  if (!v) return null;
  map.delete(key);
  return v.exp > nowSec() ? v : null;
}

/** 只窥视不删除(密码错了允许重试),成功路径再显式删除 */
function stashPeek(map, key) {
  const v = map.get(key);
  if (!v) return null;
  if (v.exp <= nowSec()) {
    map.delete(key);
    return null;
  }
  return v;
}

const msFail = (ctx, message) => sendHtml(ctx.res, 400, errorPage({
  theme: ctx.theme, siteName: ctx.runtime.siteName,
  title: 'Microsoft 登录失败', message,
}));

/** GET /auth/microsoft —— 生成 state/PKCE 并 302 到 Microsoft 授权页 */
export function startAuth(ctx) {
  const ms = ctx.runtime.msOAuth;
  if (!ms.enabled) return redirect(ctx.res, '/login?err=' + encodeURIComponent('未启用 Microsoft 登录。'));
  if (!ms.clientId) return redirect(ctx.res, '/login?err=' + encodeURIComponent('Microsoft 登录未配置完整,请联系管理员。'));
  const state = randomToken(16);
  const verifier = randomToken(48);
  // ?bind=1 且当前已登录:进入绑定模式,回调后绑定到当前会话用户
  const bindUserId = ctx.session && ctx.query.get('bind') === '1' ? ctx.user.id : null;
  stashPut(authStashes, state, { exp: nowSec() + STASH_TTL, verifier, bindUserId });
  return redirect(ctx.res, buildAuthUrl({
    tenant: ms.tenant, clientId: ms.clientId, redirectUri: ms.redirectUri,
    state, codeChallenge: sha256b64url(verifier), authority: ms.authority,
  }));
}

/** GET /auth/microsoft/callback —— 换 token、验 id_token,再分流 */
export async function callback(ctx) {
  const ms = ctx.runtime.msOAuth;
  if (!ms.enabled) return redirect(ctx.res, '/login?err=' + encodeURIComponent('未启用 Microsoft 登录。'));
  const entry = stashTake(authStashes, ctx.query.get('state') || '');
  if (!entry) return msFail(ctx, '登录会话无效或已过期,请重新发起 Microsoft 登录。');
  try {
    const tokenRes = await exchangeCode({
      tenant: ms.tenant, clientId: ms.clientId, clientSecret: ms.clientSecret,
      redirectUri: ms.redirectUri, code: ctx.query.get('code') || '',
      codeVerifier: entry.verifier, authority: ms.authority,
    });
    const identity = await verifyIdToken(tokenRes.id_token, {
      clientId: ms.clientId, tenant: ms.tenant, authority: ms.authority,
    });
    return finishCallback(ctx, entry, identity);
  } catch (err) {
    logger.warn('Microsoft 回调处理失败', { err: String(err.message || err) });
    return msFail(ctx, `${err.message || '身份验证未通过,请重试。'}`);
  }
}

function finishCallback(ctx, entry, identity) {
  // 绑定模式:发起时已登录,且回调时会话仍是同一位用户
  if (entry.bindUserId && ctx.session && ctx.user && ctx.user.id === entry.bindUserId) {
    const holder = users.byMicrosoftSub(identity.sub);
    if (holder && holder.id !== ctx.user.id) {
      return redirect(ctx.res, '/account?err=' + encodeURIComponent('该 Microsoft 账号已绑定其他用户。'));
    }
    users.bindMicrosoft(ctx.user.id, identity.sub, identity.email);
    logger.info('绑定 Microsoft 账号', { username: ctx.user.username, ms_email: identity.email });
    return redirect(ctx.res, '/account?msg=' + encodeURIComponent(`已绑定 Microsoft 账号${identity.email ? `(${identity.email})` : ''}。`));
  }
  // 登录模式:sub 已绑定 → 直接建会话
  const local = users.byMicrosoftSub(identity.sub);
  if (local) {
    if (local.disabled) return msFail(ctx, '该账号已被禁用,请联系管理员。');
    startSession(ctx.res, local);
    return redirect(ctx.res, '/apps');
  }
  // 未绑定:签发一次性关联令牌,渲染「关联本地账号」页
  const linkToken = randomToken(16);
  stashPut(linkTokens, linkToken, {
    exp: nowSec() + STASH_TTL, sub: identity.sub, email: identity.email, name: identity.name,
  });
  let csrf = ctx.cookies.csrf;
  if (!csrf) {
    csrf = randomToken(18);
    setCookie(ctx.res, 'csrf', csrf, { maxAge: 600, secure: ctx.runtime.secureCookies });
  }
  return sendHtml(ctx.res, 200, msLinkPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName,
    csrf, linkToken, msEmail: identity.email || identity.preferred_username || identity.name || '',
    allowRegister: ctx.runtime.allowRegister,
  }));
}

/** POST /auth/microsoft/link —— 已有本地账号:验密码 → 绑定 → 建会话 */
export function link(ctx) {
  const ms = ctx.runtime.msOAuth;
  if (!ms.enabled) return redirect(ctx.res, '/login?err=' + encodeURIComponent('未启用 Microsoft 登录。'));
  const b = ctx.body || {};
  const stateVal = typeof b.state === 'string' ? b.state : '';
  const entry = stashPeek(linkTokens, stateVal); // 校验失败保留,成功后才消费(一次性)
  if (!entry) return msFail(ctx, '关联会话无效或已过期,请重新发起 Microsoft 登录。');
  const rerender = (err, status = 401) => sendHtml(ctx.res, status, msLinkPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName, csrf: ctx.cookies.csrf || '',
    linkToken: stateVal, msEmail: entry.email || entry.name || '',
    allowRegister: ctx.runtime.allowRegister,
    err, values: { username: typeof b.username === 'string' ? b.username : '' },
  }));
  const cookieCsrf = ctx.cookies.csrf || '';
  if (!cookieCsrf || typeof b._csrf !== 'string' || b._csrf !== cookieCsrf) {
    return rerender('页面已过期,请重新提交。', 400);
  }
  const username = String(b.username || '').trim();
  const user = username ? users.byUsername(username) : null;
  const okPwd = user && !user.disabled && typeof b.password === 'string' && verifyPassword(b.password, user.password_hash);
  if (!okPwd) {
    logger.warn('Microsoft 关联失败:密码校验未通过', { username });
    return rerender('用户名或密码不正确。');
  }
  const holder = users.byMicrosoftSub(entry.sub);
  if (holder && holder.id !== user.id) return rerender('该 Microsoft 账号已绑定其他用户。');
  linkTokens.delete(stateVal);
  users.bindMicrosoft(user.id, entry.sub, entry.email);
  startSession(ctx.res, user);
  logger.info('Microsoft 账号已关联本地账号并登录', { username: user.username });
  return redirect(ctx.res, '/apps');
}

/** POST /auth/microsoft/register —— 注册新号(永远非管理员)→ 绑定 → 建会话 */
export function registerNew(ctx) {
  const rt = getRuntime();
  if (!rt.msOAuth.enabled) return redirect(ctx.res, '/login?err=' + encodeURIComponent('未启用 Microsoft 登录。'));
  const b = ctx.body || {};
  const stateVal = typeof b.state === 'string' ? b.state : '';
  const entry = stashPeek(linkTokens, stateVal);
  if (!entry) return msFail(ctx, '关联会话无效或已过期,请重新发起 Microsoft 登录。');
  const rerender = (err, status = 400) => sendHtml(ctx.res, status, msLinkPage({
    theme: ctx.theme, siteName: rt.siteName, csrf: ctx.cookies.csrf || '',
    linkToken: stateVal, msEmail: entry.email || entry.name || '',
    allowRegister: rt.allowRegister,
    err, values: { username: typeof b.username === 'string' ? b.username : '', name: typeof b.name === 'string' ? b.name : '' },
  }));
  const cookieCsrf = ctx.cookies.csrf || '';
  if (!cookieCsrf || typeof b._csrf !== 'string' || b._csrf !== cookieCsrf) {
    return rerender('页面已过期,请重新提交。');
  }
  const username = String(b.username || '').trim();
  if (!USERNAME_RE.test(username)) return rerender('用户名需为 2-64 位字母数字与 _.@-。');
  if (users.byUsername(username)) return rerender('用户名已存在。');
  if (typeof b.password !== 'string' || b.password.length < 8) return rerender('密码至少 8 位。');
  if (b.password !== b.password2) return rerender('两次输入的密码不一致。');
  const holder = users.byMicrosoftSub(entry.sub);
  if (holder) return rerender('该 Microsoft 账号已绑定其他用户。');
  linkTokens.delete(stateVal);
  const user = users.create({
    username,
    passwordHash: hashPassword(b.password),
    name: String(b.name || '').trim(),
    email: entry.email || '',
    isAdmin: false,
  });
  users.bindMicrosoft(user.id, entry.sub, entry.email);
  startSession(ctx.res, user);
  logger.info('Microsoft 关联注册新用户', { username: user.username });
  return redirect(ctx.res, '/apps');
}

/** POST /auth/microsoft/unbind —— 已登录用户解绑(会话 CSRF) */
export function unbind(ctx) {
  if (ctx.body?._csrf !== ctx.session.csrf) {
    return redirect(ctx.res, '/account?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
  if (!ctx.user.ms_sub) {
    return redirect(ctx.res, '/account?err=' + encodeURIComponent('当前账号未绑定 Microsoft 账号。'));
  }
  users.unbindMicrosoft(ctx.user.id);
  logger.info('解绑 Microsoft 账号', { username: ctx.user.username });
  return redirect(ctx.res, '/account?msg=' + encodeURIComponent('已解绑 Microsoft 账号。'));
}
