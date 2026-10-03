import * as clients from '../../models/clients.js';
import * as codes from '../../models/codes.js';
import * as consents from '../../models/consents.js';
import * as groups from '../../models/groups.js';
import { getRuntime } from '../../core/runtime.js';
import { redirect, sendHtml } from '../../core/http.js';
import { filterScopes } from './issue.js';
import { consumeLaunch } from '../portal.js';
import { errorPage } from '../../views/error.js';
import { consentPage, accessDeniedPage } from '../../views/auth.js';
import { record } from '../audit.js';

const REPLAY_FIELDS = ['response_type', 'client_id', 'redirect_uri', 'scope', 'state',
  'code_challenge', 'code_challenge_method', 'nonce', 'prompt', 'sim_group'];

/** 校验 client + redirect_uri;不合法时返回需要直接渲染的错误 */
function resolveClient(clientId, redirectUri) {
  if (!clientId) return { error: '缺少 client_id 参数。' };
  const client = clients.byId(clientId);
  if (!client) return { error: `应用不存在:client_id 无效。` };
  const uriList = JSON.parse(client.redirect_uris || '[]');
  if (!redirectUri || !uriList.includes(redirectUri)) {
    return { error: 'redirect_uri 未在该应用的注册列表中,已拒绝请求。' };
  }
  return { client, uriList };
}

function buildRedirect(uri, params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') q.set(k, v);
  return uri + (uri.includes('?') ? '&' : '?') + q.toString();
}

// 错误重定向必须传真实响应对象:传 null 会让 redirect() 内部 setHeader 抛错,错误重定向整体失效
const errRedirect = (res, uri, obj) => redirect(res, buildRedirect(uri, obj));

/** RFC 7636 §4.1:code_challenge 长度 43-128,字符集限 base64url 字母表(S256 输出天然满足) */
const CHALLENGE_RE = /^[A-Za-z0-9\-_]{43,128}$/;

/** prompt 参数是否包含 none(OIDC Core §3.1.2.1,空格分隔多值) */
const promptNone = (prompt) => String(prompt || '').split(/\s+/).includes('none');

/**
 * 应用按权限组限制访问:allowed_groups 非空且用户不属于其中任何组时,
 * 直接渲染 403 风格拒绝页(不重定向回 redirect_uri,避免向不可信方泄露)。
 */
function denyIfNotAllowed(ctx, client) {
  const allowed = clients.allowedGroupNames(client);
  if (!allowed.length) return false;
  const mine = groups.membersOf(ctx.user.id);
  if (allowed.some((name) => mine.includes(name))) return false;
  // 管理员模拟:应用详情「模拟启动」携带 sim_group 时放行(launch 层已审计)
  const simGroup = ctx.query.get('sim_group') || (ctx.body && ctx.body.sim_group) || '';
  if (simGroup && ctx.user.is_admin && groups.byName(simGroup)) return false;
  sendHtml(ctx.res, 403, accessDeniedPage({
    theme: ctx.theme, siteName: getRuntime().siteName, clientName: client.name, requiredGroups: allowed,
  }));
  return true;
}

/** GET /authorize —— 授权码入口:校验 → 登录检查 → 同意检查 → 签发 code */
export function authorizeGet(ctx) {
  const q = ctx.query;
  const clientId = q.get('client_id') || '';
  const redirectUri = q.get('redirect_uri') || '';
  const resolved = resolveClient(clientId, redirectUri);
  if (resolved.error) {
    // 此时无法安全重定向,只能渲染错误页(RFC 6749 §4.1.2.1)
    sendHtml(ctx.res, 400, errorPage({ theme: ctx.theme, title: '无效的授权请求', message: resolved.error }));
    return;
  }
  const client = resolved.client;
  const state = q.get('state') || '';
  const bad = (error, description) =>
    errRedirect(ctx.res, redirectUri, { error, error_description: description, state });

  if (q.get('response_type') !== 'code') return bad('unsupported_response_type', '仅支持 response_type=code');

  const scopeList = filterScopes(q.get('scope'), client.scopes);
  const challenge = q.get('code_challenge') || '';
  const challengeMethod = q.get('code_challenge_method') || '';

  if (challenge) {
    // 携带即校验格式(先于 pkce_required 判定),非法格式不允许进入后续流程
    if (!CHALLENGE_RE.test(challenge)) {
      return bad('invalid_request', 'code_challenge 格式非法(须为 43-128 位 base64url 字符)');
    }
    if (!['S256', 'plain'].includes(challengeMethod)) {
      return bad('invalid_request', 'code_challenge_method 仅支持 S256 或 plain');
    }
  } else if (client.pkce_required) {
    return bad('invalid_request', '该应用已强制要求 PKCE,请携带 code_challenge');
  }

  const prompt = q.get('prompt') || '';
  if (!ctx.session) {
    // OIDC Core §3.1.2.1:prompt=none 要求不得出现任何交互,未登录回跳 login_required
    if (promptNone(prompt)) {
      return bad('login_required', 'prompt=none 要求已有登录会话');
    }
    const next = ctx.url.pathname + ctx.url.search;
    return redirect(ctx.res, '/login?next=' + encodeURIComponent(next));
  }

  // 登录后、同意页之前:按应用可访问权限组拦截
  if (denyIfNotAllowed(ctx, client)) return;

  const remembered = consents.covers(ctx.user.id, client.client_id, scopeList);
  if (client.require_consent && (!remembered || prompt.includes('consent'))) {
    // prompt=none:需要用户确认授权但无记住授权时回跳 consent_required
    if (promptNone(prompt)) {
      return bad('consent_required', 'prompt=none 要求已完成授权确认');
    }
    return sendHtml(ctx.res, 200, consentPage({
      theme: ctx.theme, siteName: ctx.runtime.siteName, user: ctx.user, client: clients.withUris(client),
      scopeList, csrf: ctx.session.csrf, replay: replayFromQuery(q), remember: true,
    }));
  }

  issueCode(ctx, { client, redirectUri, scopeList, challenge, challengeMethod, state, nonce: q.get('nonce') });
}

/** POST /authorize —— 同意页提交(approve / deny) */
export function authorizePost(ctx) {
  const body = ctx.body || {};
  if (!ctx.session) {
    const next = '/authorize?' + new URLSearchParams(pickReplay(body)).toString();
    return redirect(ctx.res, '/login?next=' + encodeURIComponent(next));
  }
  if (body._csrf !== ctx.session.csrf) {
    return sendHtml(ctx.res, 403, errorPage({ theme: ctx.theme, title: '表单已过期', message: 'CSRF 校验失败,请返回重新发起授权。' }));
  }
  const resolved = resolveClient(body.client_id || '', body.redirect_uri || '');
  if (resolved.error) {
    return sendHtml(ctx.res, 400, errorPage({ theme: ctx.theme, title: '无效的授权请求', message: resolved.error }));
  }
  const redirectUri = body.redirect_uri;
  const state = body.state || '';
  const bad = (error, description) => errRedirect(ctx.res, redirectUri, { error, error_description: description, state });

  // 同意页提交同样校验(防止绕过 GET 直接 POST approve)
  if (denyIfNotAllowed(ctx, resolved.client)) return;

  if (body.response_type !== 'code') return bad('unsupported_response_type', '仅支持 response_type=code');
  const client = resolved.client;
  const scopeList = filterScopes(body.scope, client.scopes);

  // 与 GET 一致的 PKCE 约束:防止绕过授权页直接 POST 发码跳过强制 PKCE / 伪造 method 或格式
  if (!body.code_challenge && client.pkce_required) {
    return bad('invalid_request', '该应用已强制要求 PKCE,请携带 code_challenge');
  }
  if (body.code_challenge) {
    if (!CHALLENGE_RE.test(body.code_challenge)) {
      return bad('invalid_request', 'code_challenge 格式非法(须为 43-128 位 base64url 字符)');
    }
    if (!['S256', 'plain'].includes(body.code_challenge_method || '')) {
      return bad('invalid_request', 'code_challenge_method 仅支持 S256 或 plain');
    }
  }

  if (body.decision !== 'approve') {
    return errRedirect(ctx.res, redirectUri, { error: 'access_denied', error_description: '用户拒绝了授权', state });
  }
  if (body.remember === 'on') consents.grant(ctx.user.id, client.client_id, scopeList.join(' '));
  record(ctx, 'oauth.consent_granted', `${client.client_id} ${scopeList.join(' ')}`);

  issueCode(ctx, {
    client, redirectUri, scopeList,
    challenge: body.code_challenge || '', challengeMethod: body.code_challenge_method || '',
    state, nonce: body.nonce,
  });
}

function issueCode(ctx, { client, redirectUri, scopeList, challenge, challengeMethod, state, nonce }) {
  // 门户代发的 PKCE:verifier 由服务端暂存,随授权码落库供令牌交换使用
  let launchVerifier = null;
  try {
    launchVerifier = consumeLaunch(ctx.session.id_hash, client.client_id);
  } catch { /* 非门户启动,忽略 */ }
  // 管理员 sim 旁路直连审计:launch 层发起的模拟启动已在 portal.launch 留痕且必有 stash 命中,
  // 此处仅当无 stash(即直连 /authorize 携带合法 sim_group)时补一条,避免与 launch 层重复;
  // 简单判定的已知边界:非 PKCE 应用的门户代发不产生 stash,会与 launch 层各记一条(去重交由读者)。
  const simGroup = ctx.query.get('sim_group') || (ctx.body && ctx.body.sim_group) || '';
  if (simGroup && ctx.user.is_admin && groups.byName(simGroup) && !launchVerifier) {
    record(ctx, 'admin.simulate_launch', `应用「${client.name}」· 模拟组「${simGroup}」`);
  }
  const code = codes.create({
    clientId: client.client_id,
    userId: ctx.user.id,
    redirectUri,
    scope: scopeList.join(' '),
    codeChallenge: challenge || null,
    codeChallengeMethod: challenge ? (challengeMethod || 'plain') : null,
    nonce: nonce || null,
    authTime: ctx.session.created_at,
    launchVerifier: challenge ? launchVerifier : null,
    ttl: getRuntime().authCodeTtl,
  });
  redirect(ctx.res, buildRedirect(redirectUri, { code, state }));
}

const pickReplay = (q) => Object.fromEntries(REPLAY_FIELDS.map((f) => [f, q.get ? q.get(f) || '' : q[f] || '']));
const replayFromQuery = (q) => pickReplay(q);
