import { freshIdentity, requireCurrentSession } from './state.js';

import * as users from '../../models/users.js';
import { verifyUserPassword, hashPassword } from '../../core/password.js';
import { randomToken, sha256b64url, nowSec } from '../../core/crypto.js';
import { redirect, sendHtml, setCookie } from '../../core/http.js';
import { buildAuthUrl, exchangeCode, verifyIdToken } from '../../core/google-oidc.js';
import { USERNAME_RE, safeNext } from '../../core/util.js';
import { getRuntime } from '../../core/runtime.js';
import { logger } from '../../core/logger.js';
import { googleLinkPage } from '../../views/auth.js';
import { errorPage } from '../../views/error.js';
import { startSession, sessionMeta } from './login.js';
import { record } from '../audit.js';

/**
 * Google 账号登录与绑定(OIDC 联邦):
 * GET  /auth/google          发起授权(带 ?bind=1 时为已登录用户的绑定模式)
 * GET  /auth/google/callback 授权码回调:绑定 / 登录 / 渲染关联页
 * POST /auth/google/link     关联页表单 A:已有本地账号绑定并登录
 * POST /auth/google/register 关联页表单 B:注册新号并绑定(自助注册开启时)
 * POST /auth/google/unbind   已登录用户解绑
 */

/* 授权 state 与关联令牌的内存暂存(容量上限 500,淘汰最旧;TTL 10 分钟) */
const MAX_STASH = 500;
const STASH_TTL = 600;
const authStashes = new Map(); // state → { exp, verifier, bindUserId }
const linkTokens = new Map();  // linkToken → { exp, sub, email, name }

function stashPut(map, key, value) {
  const now = nowSec();
  for (const [k, v] of map) if (v.exp <= now) map.delete(k); // 先清过期,防占坑挤掉有效项
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

const googleFail = (ctx, message) => sendHtml(ctx.res, 400, errorPage({
  theme: ctx.theme, siteName: ctx.runtime.siteName,
  title: 'Google 登录失败', message,
}));

/**
 * authority / token / jwks 端点合法性:用于 fetch 与 URL 拼接前防御性校验,
 * 必须是 http(s) 形态(默认端点见 core/google-oidc.js;自托管或联调可覆盖)。
 */
const ENDPOINT_RE = /^https?:\/\/[a-zA-Z0-9.[\]_-]+(:\d+)?(\/[^\s]*)?$/;
export const isValidGoogleEndpoint = (s) => ENDPOINT_RE.test(String(s || '').trim());

/** GET /auth/google —— 生成 state/PKCE 并 302 到 Google 授权页 */
export function startAuth(ctx) {
  const g = ctx.runtime.googleOAuth;
  if (!g.enabled) return redirect(ctx.res, '/login?err=' + encodeURIComponent('未启用 Google 登录。'));
  if (!g.clientId) return redirect(ctx.res, '/login?err=' + encodeURIComponent('Google 登录未配置完整,请联系管理员。'));
  if (!isValidGoogleEndpoint(g.authority) || !isValidGoogleEndpoint(g.tokenEndpoint) || !isValidGoogleEndpoint(g.jwksUri)) {
    return redirect(ctx.res, '/login?err=' + encodeURIComponent('Google 端点配置不合法,请联系管理员检查设置。'));
  }
  const state = randomToken(16);
  const verifier = randomToken(48);
  // ?bind=1 且当前已登录:进入绑定模式,回调后绑定到当前会话用户
  const bindUserId = ctx.session && ctx.query.get('bind') === '1' ? ctx.user.id : null;
  // 授权链路续流:登录页气泡/应用入口带过来的 next,回调后原样回跳(不落库,随令牌暂存)
  const next = safeNext(ctx.query.get('next'), '');
  stashPut(authStashes, state, { exp: nowSec() + STASH_TTL, verifier, bindUserId, next });
  return redirect(ctx.res, buildAuthUrl({
    clientId: g.clientId, redirectUri: g.redirectUri,
    state, codeChallenge: sha256b64url(verifier), authority: g.authority,
  }));
}

/** GET /auth/google/callback —— 换 token、验 id_token,再分流 */
export async function callback(ctx) {
  const g = ctx.runtime.googleOAuth;
  if (!g.enabled) return redirect(ctx.res, '/login?err=' + encodeURIComponent('未启用 Google 登录。'));
  const entry = stashTake(authStashes, ctx.query.get('state') || '');
  if (!entry) return googleFail(ctx, '登录会话无效或已过期,请重新发起 Google 登录。');
  try {
    const tokenRes = await exchangeCode({
      clientId: g.clientId, clientSecret: g.clientSecret,
      redirectUri: g.redirectUri, code: ctx.query.get('code') || '',
      codeVerifier: entry.verifier, tokenEndpoint: g.tokenEndpoint,
    });
    const identity = await verifyIdToken(tokenRes.id_token, {
      clientId: g.clientId, authority: g.authority, jwksUri: g.jwksUri,
    });
    if (ctx.session) requireCurrentSession(ctx);
    return finishCallback(ctx, entry, identity);
  } catch (err) {
    logger.warn('Google 回调处理失败', { err: String(err.message || err) });
    return googleFail(ctx, `${err.message || '身份验证未通过,请重试。'}`);
  }
}

function finishCallback(ctx, entry, identity) {
  // 绑定模式:发起时已登录,且回调时会话仍是同一位用户
  if (entry.bindUserId && ctx.session && ctx.user && ctx.user.id === entry.bindUserId) {
    // 已绑定过则拒绝重复绑定:换绑必须先在账号页显式解绑,防止直接访问 ?bind=1 静默覆盖
    if (ctx.user.google_sub) {
      return redirect(ctx.res, '/account?err=' + encodeURIComponent('当前账号已绑定 Google 账号,请先解绑后再重新绑定。'));
    }
    const holder = users.byGoogleSub(identity.sub);
    if (holder && holder.id !== ctx.user.id) {
      return redirect(ctx.res, '/account?err=' + encodeURIComponent('该 Google 账号已绑定其他用户。'));
    }
    users.bindGoogle(ctx.user.id, identity.sub, identity.email);
    record(ctx, 'auth.google_linked', identity.email || '');
    logger.info('绑定 Google 账号', { username: ctx.user.username, google_email: identity.email });
    return redirect(ctx.res, '/account?msg=' + encodeURIComponent(`已绑定 Google 账号${identity.email ? `(${identity.email})` : ''}。`));
  }
  // 已绑定:直接登录(与密码登录同等待遇,不合并上游 id_token 的任何 claim)
  const local = users.byGoogleSub(identity.sub);
  if (local) {
    if (local.disabled) return googleFail(ctx, '该账号已被禁用,请联系管理员。');
    startSession(ctx.res, local, undefined, sessionMeta(ctx));
    return redirect(ctx.res, entry.next || '/apps');
  }
  // 未绑定:发一次性 linkToken 并渲染关联页(表单 A 绑定已有号 / 表单 B 注册新号)
  const linkToken = randomToken(24);
  stashPut(linkTokens, linkToken, { exp: nowSec() + STASH_TTL, sub: identity.sub, email: identity.email, name: identity.name, next: entry.next });
  // 双提交 CSRF:发起链路全程是 302,从未访问过会下发 csrf 的页面,这里补发一枚
  let csrf = ctx.cookies.csrf;
  if (!csrf) {
    csrf = randomToken(18);
    setCookie(ctx.res, 'csrf', csrf, { maxAge: 600, secure: ctx.runtime.secureCookies });
  }
  record(ctx, 'auth.google_link_prompt', identity.email || '');
  return sendHtml(ctx.res, 200, googleLinkPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName,
    csrf, linkToken,
    googleEmail: identity.email || identity.name || '',
    allowRegister: getRuntime().allowRegister,
  }));
}

/** POST /auth/google/link —— 已有本地账号:验密码 → 绑定 → 建会话 */
export async function link(ctx) {
  const rt = getRuntime();
  if (!rt.googleOAuth.enabled) return redirect(ctx.res, '/login?err=' + encodeURIComponent('未启用 Google 登录。'));
  const b = ctx.body || {};
  const stateVal = typeof b.state === 'string' ? b.state : '';
  const entry = stashPeek(linkTokens, stateVal);
  if (!entry) return googleFail(ctx, '关联会话无效或已过期,请重新发起 Google 登录。');
  const rerender = (err, values = {}, status = 400) => sendHtml(ctx.res, status, googleLinkPage({
    theme: ctx.theme, siteName: rt.siteName, csrf: ctx.cookies.csrf || '',
    linkToken: stateVal, googleEmail: entry.email || entry.name || '',
    allowRegister: rt.allowRegister, err, values,
  }));
  const cookieCsrf = ctx.cookies.csrf || '';
  if (!cookieCsrf || typeof b._csrf !== 'string' || b._csrf !== cookieCsrf) {
    return rerender('页面已过期,请重新提交。');
  }
  const username = String(b.username || '').trim();
  const user = username ? users.byUsername(username) : null;
  const okPwd = user ? await verifyUserPassword(user, b.password) : false;
  const clean = freshIdentity(user);
  if (!okPwd || !clean || !user || stashPeek(linkTokens, stateVal) !== entry) {
    logger.warn('Google 关联失败:密码校验未通过', { username });
    return rerender('用户名或密码不正确。', { username });
  }
  const holder = users.byGoogleSub(entry.sub);
  if (holder && holder.id !== user.id) return rerender('该 Google 账号已绑定其他用户。', { username });
  linkTokens.delete(stateVal);
  users.bindGoogle(user.id, entry.sub, entry.email);
  startSession(ctx.res, user, undefined, sessionMeta(ctx));
  record(ctx, 'auth.google_linked', entry.email || '', { actor: user.username });
  logger.info('Google 账号已关联本地账号并登录', { username: user.username });
  return redirect(ctx.res, entry.next || '/apps');
}

/** POST /auth/google/register —— 注册新号(永远非管理员)→ 绑定 → 建会话 */
export async function registerNew(ctx) {
  const rt = getRuntime();
  if (!rt.googleOAuth.enabled) return redirect(ctx.res, '/login?err=' + encodeURIComponent('未启用 Google 登录。'));
  const b = ctx.body || {};
  const stateVal = typeof b.state === 'string' ? b.state : '';
  const entry = stashPeek(linkTokens, stateVal);
  if (!entry) return googleFail(ctx, '关联会话无效或已过期,请重新发起 Google 登录。');
  const rerender = (err, status = 400) => sendHtml(ctx.res, status, googleLinkPage({
    theme: ctx.theme, siteName: rt.siteName, csrf: ctx.cookies.csrf || '',
    linkToken: stateVal, googleEmail: entry.email || entry.name || '',
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
  const holder = users.byGoogleSub(entry.sub);
  if (holder) return rerender('该 Google 账号已绑定其他用户。');
  const passwordHash = await hashPassword(b.password);
  if (!getRuntime().allowRegister || !getRuntime().googleOAuth.enabled) return rerender('注册已关闭。');
  if (users.byUsername(username) || users.byGoogleSub(entry.sub)
      || stashPeek(linkTokens, stateVal) !== entry) return rerender('关联状态已变化,请重新开始。');
  linkTokens.delete(stateVal);
  const user = users.create({
    username,
    passwordHash,
    name: String(b.name || '').trim(),
    email: entry.email || '',
    isAdmin: false,
  });
  users.bindGoogle(user.id, entry.sub, entry.email);
  startSession(ctx.res, user, undefined, sessionMeta(ctx));
  record(ctx, 'auth.google_registered', entry.email || '', { actor: user.username });
  logger.info('Google 关联注册新用户', { username: user.username });
  return redirect(ctx.res, entry.next || '/apps');
}

/** POST /auth/google/unbind —— 已登录用户解绑(会话 CSRF) */
export function unbind(ctx) {
  if (ctx.body?._csrf !== ctx.session.csrf) {
    return redirect(ctx.res, '/account?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
  if (!ctx.user.google_sub) {
    return redirect(ctx.res, '/account?err=' + encodeURIComponent('当前账号未绑定 Google 账号。'));
  }
  const googleEmail = ctx.user.google_email || '';
  users.unbindGoogle(ctx.user.id);
  record(ctx, 'auth.google_unlinked', googleEmail);
  logger.info('解绑 Google 账号', { username: ctx.user.username });
  return redirect(ctx.res, '/account?msg=' + encodeURIComponent('已解绑 Google 账号。'));
}
