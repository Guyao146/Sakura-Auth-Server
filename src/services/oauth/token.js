import * as clients from '../../models/clients.js';
import * as users from '../../models/users.js';
import * as codes from '../../models/codes.js';
import * as tokens from '../../models/tokens.js';
import { getDb } from '../../core/db.js';
import { verifyPassword } from '../../core/password.js';
import { sha256b64url, timingSafeEqStr, nowSec } from '../../core/crypto.js';
import { sendJson } from '../../core/http.js';
import { filterScopes, issueFull, issueAccessToken, mintIdToken } from './issue.js';

const bad = (ctx, error, description, status = 400) =>
  sendJson(ctx.res, status, { error, error_description: description });

/**
 * RFC 6749 §2.3.1 客户端认证:HTTP Basic 或表单 client_id/client_secret。
 * 公开客户端(token_auth=none)不带密钥。失败返回 null 并已写出 401。
 */
export function authenticateClient(ctx) {
  const body = ctx.body || {};
  let id = body.client_id || null;
  let secret = body.client_secret || null;
  const header = ctx.req.headers['authorization'];
  if (header && header.startsWith('Basic ')) {
    try {
      const dec = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const i = dec.indexOf(':');
      id = dec.slice(0, i) || id;
      secret = dec.slice(i + 1) || secret;
    } catch { /* 非法 base64 时回落到表单参数 */ }
  }
  if (!id) { bad(ctx, 'invalid_client', '缺少 client_id', 401); return null; }
  const client = clients.byId(id);
  if (!client) { bad(ctx, 'invalid_client', 'client_id 无效', 401); return null; }

  if (client.token_auth === 'none') {
    if (secret) { bad(ctx, 'invalid_client', '公开客户端不应携带客户端密钥', 401); return null; }
    return client;
  }
  if (!secret || !client.secret_hash || !verifyPassword(secret, client.secret_hash)) {
    bad(ctx, 'invalid_client', '客户端认证失败', 401);
    return null;
  }
  return client;
}

/** PKCE 校验:S256=sha256(verifier) base64url;plain=原文 */
function pkceOk(verifier, challenge, method) {
  if (typeof verifier !== 'string' || verifier.length < 43 || verifier.length > 128) return false;
  return method === 'S256'
    ? timingSafeEqStr(sha256b64url(verifier), challenge)
    : timingSafeEqStr(verifier, challenge);
}

/** POST /token —— authorization_code / refresh_token / client_credentials */
export function tokenPost(ctx) {
  ctx.res.setHeader('Cache-Control', 'no-store');
  ctx.res.setHeader('Pragma', 'no-cache');
  const body = ctx.body || {};
  const client = authenticateClient(ctx);
  if (!client) return;

  switch (body.grant_type) {
    case 'authorization_code': return grantAuthorizationCode(ctx, client, body);
    case 'refresh_token': return grantRefreshToken(ctx, client, body);
    case 'client_credentials': return grantClientCredentials(ctx, client, body);
    default: return bad(ctx, 'unsupported_grant_type', '仅支持 authorization_code / refresh_token / client_credentials');
  }
}

function grantAuthorizationCode(ctx, client, body) {
  const fail = (d) => bad(ctx, 'invalid_grant', d);
  if (!body.code) return fail('缺少 code');
  if (!body.redirect_uri) return bad(ctx, 'invalid_request', '缺少 redirect_uri');
  const row = codes.byCode(body.code);
  if (!row) return fail('授权码不存在');
  if (row.used) return fail('授权码已使用');
  if (row.expires_at <= nowSec()) return fail('授权码已过期');
  if (row.client_id !== client.client_id) return fail('授权码不属于该客户端');
  if (row.redirect_uri !== body.redirect_uri) return fail('redirect_uri 与授权请求不一致');

  if (row.code_challenge) {
    // 标准 PKCE:应用自行发起,必须携带正确 verifier;
    // 门户代发(IdP-initiated)的授权码,verifier 由服务端随码落库,允许无 verifier 换取
    const fallback = row.launch_verifier;
    if (!body.code_verifier && fallback) {
      if (!pkceOk(fallback, row.code_challenge, row.code_challenge_method)) {
        return fail('PKCE 校验失败');
      }
    } else {
      if (!body.code_verifier) return fail('缺少 PKCE code_verifier');
      if (!pkceOk(body.code_verifier, row.code_challenge, row.code_challenge_method)) {
        return fail('PKCE 校验失败');
      }
    }
  }

  codes.markUsed(row.code_hash);
  const user = users.byId(row.user_id);
  if (!user || user.disabled) return fail('用户不可用');

  const scope = row.scope.split(/\s+/).filter(Boolean);
  const res = issueFull({
    client, user, scope,
    authTime: row.auth_time,
    nonce: row.nonce,
    withRefresh: scope.includes('offline_access'),
    withIdToken: scope.includes('openid'),
  });
  return sendJson(ctx.res, 200, res);
}

function grantRefreshToken(ctx, client, body) {
  const fail = (d) => bad(ctx, 'invalid_grant', d);
  if (!body.refresh_token) return fail('缺少 refresh_token');
  const row = tokens.byId(tokens.refreshKey(body.refresh_token));
  if (!row || row.kind !== 'refresh') return fail('refresh_token 无效');
  if (row.revoked || row.expires_at <= nowSec()) return fail('refresh_token 已失效');
  if (row.client_id !== client.client_id) return fail('refresh_token 不属于该客户端');

  const user = row.user_id ? users.byId(row.user_id) : null;
  if (row.user_id && (!user || user.disabled)) return fail('用户不可用');

  const original = row.scope.split(/\s+/).filter(Boolean);
  const requested = filterScopes(body.scope || '', original.join(' '));
  const scope = requested.length ? requested : original;
  const authTime = row.auth_time;

  // 轮换:新 refresh 立即签发,旧的标记作废并记录 replaced_by 轮换链
  const newRefresh = tokens.newRefreshToken();
  const newHash = tokens.refreshKey(newRefresh);
  tokens.insert({
    id: newHash, kind: 'refresh', clientId: client.client_id,
    userId: row.user_id, scope: scope.join(' '), authTime,
    expiresAt: nowSec() + ctx.runtime.refreshTokenTtl,
  });
  getDb().prepare('UPDATE tokens SET revoked = 1, replaced_by = ? WHERE id = ?').run(newHash, row.id);

  const { access_token, expiresIn } = issueAccessToken({ client, user, scope, authTime });
  const res = {
    access_token, token_type: 'Bearer', expires_in: expiresIn,
    scope: scope.join(' '), refresh_token: newRefresh,
  };
  const idToken = mintIdToken({ client, user, scope, authTime, nonce: row.nonce, accessToken: access_token });
  if (idToken) res.id_token = idToken;
  return sendJson(ctx.res, 200, res);
}

function grantClientCredentials(ctx, client, body) {
  if (client.token_auth === 'none') {
    return bad(ctx, 'unauthorized_client', '公开客户端不支持 client_credentials');
  }
  const scope = filterScopes(body.scope || '', client.scopes);
  const res = issueFull({ client, user: null, scope, withRefresh: false, withIdToken: false });
  return sendJson(ctx.res, 200, res);
}
