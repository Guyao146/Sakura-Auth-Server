/** UniLink OIDC 回登：只接受已存在的本地 sub，不按邮箱匹配、不创建用户。 */
import crypto from 'node:crypto';
import * as users from '../../models/users.js';
import * as recovery from '../../models/recovery.js';
import * as settings from '../../models/settings.js';
import { getRuntime, updateRuntime } from '../../core/runtime.js';
import { randomToken, sha256b64url, timingSafeEqStr, nowSec } from '../../core/crypto.js';
import { verifyTotp } from '../../core/totp.js';
import { sendHtml, redirect, setCookie, clearCookie } from '../../core/http.js';
import { escapeHtml as esc, safeNext } from '../../core/util.js';
import { authPage, adminPage } from '../../views/layout.js';
import { hiddenInputs } from '../../views/components.js';
import { startSession, sessionMeta, isLocked, recordFail, clearFails } from './login.js';
import { record } from '../audit.js';

const pending = new Map(), factors = new Map();
const COOKIE = 'unilink_flow', FACTOR_COOKIE = 'unilink_factor';
const LIMIT = 200, TTL = 300;
let inflight = 0;

function put(map, key, value) {
  for (const [k, v] of map) if (v.exp <= nowSec()) map.delete(k);
  if (map.size >= LIMIT) throw new Error('扫码请求繁忙，请稍后重试');
  map.set(key, { ...value, exp: nowSec() + TTL });
}
const fingerprint = c => sha256b64url(JSON.stringify(c));
const cookie = (ctx, name, value) => setCookie(ctx.res, name, value, {
  maxAge: TTL, httpOnly: true, sameSite: 'Lax', secure: ctx.runtime.secureCookies,
});
function fail(ctx, message, status = 400) {
  return sendHtml(ctx.res, status, authPage({ theme: ctx.theme, siteName: ctx.runtime.siteName,
    title: 'UniLink 扫码登录', content: `<h3>无法完成登录</h3><p>${esc(message)}</p><a href="/login">返回登录</a>` }));
}
function validIssuer(text) {
  const u = new URL(text);
  if (u.username || u.password || u.search || u.hash ||
      (u.protocol !== 'https:' && !(u.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(u.hostname)))) {
    throw new Error('扫码服务必须使用 HTTPS，HTTP 仅限本机测试');
  }
  return u.href.replace(/\/+$/, '');
}

/** 限时、限体积且不跟随重定向，避免凭据转发到另一个端点。 */
async function jsonRequest(url, options = {}) {
  const res = await fetch(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(8000) });
  if (!res.ok) { await res.body?.cancel(); throw new Error('扫码服务请求失败'); }
  const reader = res.body.getReader(), chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 65536) throw new Error('扫码服务响应过大');
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function verifyToken(token, keys, c, nonce) {
  if (typeof token !== 'string' || token.length > 32768) throw new Error('无效 ID token');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(p => !/^[A-Za-z0-9_-]+$/.test(p))) throw new Error('无效 JWT');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  if (header.alg !== 'RS256') throw new Error('签名算法不允许');
  const key = keys.keys?.find(k => k.kid === header.kid && k.kty === 'RSA' && (!k.use || k.use === 'sig'));
  if (!key || !crypto.verify('RSA-SHA256', Buffer.from(parts.slice(0, 2).join('.')),
      crypto.createPublicKey({ key, format: 'jwk' }), Buffer.from(parts[2], 'base64url'))) {
    throw new Error('ID token 签名无效');
  }
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  const now = nowSec();
  if (claims.iss !== c.issuer || claims.aud !== c.clientId || claims.nonce !== nonce ||
      !Number.isFinite(claims.exp) || claims.exp <= now ||
      !Number.isFinite(claims.iat) || claims.iat > now + 30 ||
      (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now)) ||
      typeof claims.sub !== 'string' || !claims.sub) throw new Error('ID token 声明校验失败');
  return claims;
}

export function start(ctx) {
  const c = ctx.runtime.unilink;
  if (!c?.enabled || !c.issuer || !c.clientSecret) return fail(ctx, '尚未启用 UniLink');
  const state = randomToken(24), browser = randomToken(32), nonce = randomToken(24), verifier = randomToken(48);
  try {
    put(pending, state, { browser: sha256b64url(browser), nonce, verifier,
      config: fingerprint(c), next: safeNext(ctx.query.get('next'), '/apps') });
  } catch { return fail(ctx, '扫码请求繁忙，请稍后重试', 503); }
  cookie(ctx, COOKIE, browser);
  const url = new URL(`${c.issuer}/authorize`);
  url.search = new URLSearchParams({ response_type: 'code', client_id: c.clientId,
    redirect_uri: c.redirectUri, scope: 'openid', state, nonce,
    code_challenge: sha256b64url(verifier), code_challenge_method: 'S256' });
  return redirect(ctx.res, url.href);
}

export async function callback(ctx) {
  const c = ctx.runtime.unilink;
  if (!c?.enabled) return fail(ctx, '扫码登录未启用');
  const state = ctx.query.get('state') || '', entry = pending.get(state);
  if (!entry || entry.exp <= nowSec() || entry.config !== fingerprint(c) ||
      !timingSafeEqStr(entry.browser, sha256b64url(ctx.cookies[COOKIE] || ''))) {
    return fail(ctx, '登录会话无效、过期或浏览器不匹配');
  }
  pending.delete(state);
  clearCookie(ctx.res, COOKIE, ctx.runtime.secureCookies);
  if (ctx.query.has('error') || !ctx.query.get('code')) return fail(ctx, '登录已取消');
  if (inflight >= 8) return fail(ctx, '服务繁忙，请重新扫码', 503);
  inflight++;
  try {
    const tokens = await jsonRequest(`${c.issuer}/token`, { method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', client_id: c.clientId,
        client_secret: c.clientSecret, redirect_uri: c.redirectUri,
        code: ctx.query.get('code'), code_verifier: entry.verifier }) });
    const claims = verifyToken(tokens.id_token, await jsonRequest(`${c.issuer}/jwks`), c, entry.nonce);
    if (fingerprint(getRuntime().unilink) !== entry.config) return fail(ctx, '配置已变化，请重新扫码');
    // sub 必须来自同一 SakuraID 实例的 /userinfo；无匹配则拒绝，绝不按邮箱猜测。
    const user = users.byId(claims.sub);
    if (!user || user.disabled) return fail(ctx, '用户不存在或已禁用', 403);
    if (user.totp_enabled) {
      const id = randomToken(32), csrf = randomToken(24);
      put(factors, id, { uid: user.id, csrf, next: entry.next, config: entry.config });
      cookie(ctx, FACTOR_COOKIE, id);
      return factorPage(ctx, csrf);
    }
    startSession(ctx.res, user, undefined, sessionMeta(ctx));
    record(ctx, 'auth.unilink_login', '', { actor: user.username });
    return redirect(ctx.res, entry.next);
  } catch {
    // 不把 token、上游原始响应或密钥写进日志/页面。
    return fail(ctx, '扫码服务验证失败，请检查服务地址、客户端密钥与回调配置');
  } finally { inflight--; }
}

function factorPage(ctx, csrf, error = '') {
  return sendHtml(ctx.res, 200, authPage({ theme: ctx.theme, siteName: ctx.runtime.siteName,
    title: '两步验证', content: `<h3>扫码已确认，请完成两步验证</h3><p>${esc(error)}</p>
    <form method="post" action="/auth/unilink/2fa">${hiddenInputs({ _csrf: csrf })}
    <label>验证码或恢复代码</label><input name="code" required autocomplete="one-time-code">
    <button class="btn btn-primary">验证并登录</button></form>` }));
}
export function secondFactor(ctx) {
  const id = ctx.cookies[FACTOR_COOKIE] || '', entry = factors.get(id);
  if (!entry || entry.exp <= nowSec() || entry.config !== fingerprint(ctx.runtime.unilink) ||
      !timingSafeEqStr(String(ctx.body?._csrf || ''), entry.csrf)) return fail(ctx, '验证会话已失效');
  const user = users.byId(entry.uid);
  if (!user || user.disabled || !user.totp_enabled || !user.totp_secret) return fail(ctx, '账号状态变化，请重新登录');
  if (isLocked(ctx, user.username)) return fail(ctx, '失败次数过多，请稍后重试', 429);
  const code = String(ctx.body?.code || '').trim();
  if (!verifyTotp(user.totp_secret, code) && !recovery.consume(user.id, code)) {
    recordFail(ctx, user.username, 'auth.unilink_2fa_failed');
    return factorPage(ctx, entry.csrf, '验证码不正确');
  }
  factors.delete(id);
  clearCookie(ctx.res, FACTOR_COOKIE, ctx.runtime.secureCookies);
  clearFails(ctx, user.username);
  startSession(ctx.res, user, undefined, sessionMeta(ctx));
  record(ctx, 'auth.unilink_login', '', { actor: user.username });
  return redirect(ctx.res, entry.next);
}

export function settingsPage(ctx, error = '') {
  const c = ctx.runtime.unilink;
  return sendHtml(ctx.res, 200, adminPage({ theme: ctx.theme, siteName: ctx.runtime.siteName,
    user: ctx.user, cur: '/admin/unilink', title: 'UniLink 扫码登录', content: `
    <h2>UniLink 扫码登录</h2><p>${esc(error)}</p>
    <p>仅连接使用本 SakuraID 作为身份服务的 UniLink 实例。二维码服务具有认证权限，请只配可信地址。</p>
    <form method="post" action="/admin/unilink">${hiddenInputs({ _csrf: ctx.session.csrf })}
    <label><input type="checkbox" name="enabled" value="1"${c.enabled ? ' checked' : ''}>启用扫码登录</label>
    <label>UniLink 服务地址</label><input name="issuer" value="${esc(c.issuer)}" placeholder="https://gateway.example.com">
    <label>扫码客户端 ID</label><input name="client_id" value="${esc(c.clientId)}" required>
    <label>扫码客户端密钥（留空不改）</label><input type="password" name="client_secret" autocomplete="new-password">
    <p>回调地址：<code>${esc(c.redirectUri)}</code></p>
    <p>手机端另建公开 OAuth 客户端，开启 PKCE，注册 unilink://auth/callback；不要将上述密钥填到手机。</p>
    <button class="btn btn-primary">保存</button></form>` }));
}
export function saveSettings(ctx) {
  if (!timingSafeEqStr(String(ctx.body?._csrf || ''), ctx.session.csrf)) return fail(ctx, 'CSRF 校验失败', 403);
  try {
    const b = ctx.body, enabled = b.enabled === '1';
    const issuer = b.issuer ? validIssuer(String(b.issuer).trim()) : '';
    const secret = String(b.client_secret || '') || ctx.runtime.unilink.clientSecret;
    const clientId = String(b.client_id || '').trim();
    if (enabled && (!issuer || !clientId || secret.length < 24)) throw new Error('请填完整配置，密钥至少 24 位');
    updateRuntime({ unilink_enabled: enabled ? '1' : '0', unilink_issuer: issuer,
      unilink_client_id: clientId, unilink_client_secret: secret }, settings.setSetting);
    pending.clear(); factors.clear();
    record(ctx, 'admin.unilink_updated', '');
    return redirect(ctx.res, '/admin/unilink');
  } catch (e) { return settingsPage(ctx, e.message); }
}