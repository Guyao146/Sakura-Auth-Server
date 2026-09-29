import * as clients from '../../models/clients.js';
import * as codes from '../../models/codes.js';
import * as consents from '../../models/consents.js';
import { getRuntime } from '../../core/runtime.js';
import { redirect, sendHtml } from '../../core/http.js';
import { filterScopes } from './issue.js';
import { errorPage } from '../../views/error.js';
import { consentPage } from '../../views/auth.js';

const REPLAY_FIELDS = ['response_type', 'client_id', 'redirect_uri', 'scope', 'state',
  'code_challenge', 'code_challenge_method', 'nonce', 'prompt'];

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

const errRedirect = (uri, obj) => redirect(null, buildRedirect(uri, obj));

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
    errRedirect(redirectUri, { error, error_description: description, state });

  if (q.get('response_type') !== 'code') return bad('unsupported_response_type', '仅支持 response_type=code');

  const scopeList = filterScopes(q.get('scope'), client.scopes);
  const challenge = q.get('code_challenge') || '';
  const challengeMethod = q.get('code_challenge_method') || '';

  if (challenge) {
    if (!['S256', 'plain'].includes(challengeMethod)) {
      return bad('invalid_request', 'code_challenge_method 仅支持 S256 或 plain');
    }
  } else if (client.pkce_required) {
    return bad('invalid_request', '该应用已强制要求 PKCE,请携带 code_challenge');
  }

  if (!ctx.session) {
    const next = ctx.url.pathname + ctx.url.search;
    return redirect(ctx.res, '/login?next=' + encodeURIComponent(next));
  }

  const prompt = q.get('prompt') || '';
  const remembered = consents.covers(ctx.user.id, client.client_id, scopeList);
  if (client.require_consent && (!remembered || prompt.includes('consent'))) {
    return sendHtml(ctx.res, 200, consentPage({
      theme: ctx.theme, user: ctx.user, client: clients.withUris(client),
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
  const bad = (error, description) => errRedirect(redirectUri, { error, error_description: description, state });

  if (body.response_type !== 'code') return bad('unsupported_response_type', '仅支持 response_type=code');
  const client = resolved.client;
  const scopeList = filterScopes(body.scope, client.scopes);

  if (body.decision !== 'approve') {
    return errRedirect(redirectUri, { error: 'access_denied', error_description: '用户拒绝了授权', state });
  }
  if (body.remember === 'on') consents.grant(ctx.user.id, client.client_id, scopeList.join(' '));

  issueCode(ctx, {
    client, redirectUri, scopeList,
    challenge: body.code_challenge || '', challengeMethod: body.code_challenge_method || '',
    state, nonce: body.nonce,
  });
}

function issueCode(ctx, { client, redirectUri, scopeList, challenge, challengeMethod, state, nonce }) {
  const code = codes.create({
    clientId: client.client_id,
    userId: ctx.user.id,
    redirectUri,
    scope: scopeList.join(' '),
    codeChallenge: challenge || null,
    codeChallengeMethod: challenge ? (challengeMethod || 'plain') : null,
    nonce: nonce || null,
    authTime: ctx.session.created_at,
    ttl: getRuntime().authCodeTtl,
  });
  redirect(ctx.res, buildRedirect(redirectUri, { code, state }));
}

const pickReplay = (q) => Object.fromEntries(REPLAY_FIELDS.map((f) => [f, q.get ? q.get(f) || '' : q[f] || '']));
const replayFromQuery = (q) => pickReplay(q);
