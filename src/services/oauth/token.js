import * as clients from '../../models/clients.js';
import * as users from '../../models/users.js';
import * as codes from '../../models/codes.js';
import * as tokens from '../../models/tokens.js';
import { getDb } from '../../core/db.js';
import { verifyPassword } from '../../core/password.js';
import { sha256b64url, timingSafeEqStr, nowSec } from '../../core/crypto.js';
import { sendJson } from '../../core/http.js';
import { logger } from '../../core/logger.js';
import { record } from '../audit.js';
import { filterScopes, issueFull, issueAccessToken, mintIdToken } from './issue.js';

const bad = (ctx, error, description, status = 400, headers = {}) =>
  sendJson(ctx.res, status, { error, error_description: description }, headers);

/** Basic 凭证按 RFC 6749 §2.3.1 是 application/x-www-form-urlencoded 编码,需先解码;非法编码原样返回 */
const safeDecodeComponent = (s) => { try { return decodeURIComponent(s); } catch { return s; } };

/**
 * RFC 6749 §2.3.1 客户端认证:HTTP Basic 或表单 client_id/client_secret。
 * 公开客户端(token_auth=none)不带密钥。失败返回 null 并已写出 401。
 */
export async function authenticateClient(ctx) {
  const body = ctx.body || {};
  let id = body.client_id || null;
  let secret = body.client_secret || null;
  const header = ctx.req.headers['authorization'];
  const viaBasic = !!(header && header.startsWith('Basic '));
  // RFC 6749 §2.3.1:客户端每次请求只可使用一种认证方式;
  // 同时携带 Authorization Basic 头与表单 client_secret 属于重复认证,直接拒绝
  if (viaBasic && secret) {
    bad(ctx, 'invalid_request', '不得同时使用 Basic 认证头与表单 client_secret(RFC 6749 §2.3.1)');
    return null;
  }
  // RFC 6749 §5.2:客户端经 Authorization 头认证失败时,401 必须携带对应方案的 WWW-Authenticate
  const challenge = viaBasic ? { 'WWW-Authenticate': 'Basic realm="oauth2"' } : {};
  if (viaBasic) {
    try {
      const dec = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const i = dec.indexOf(':');
      // Basic 的用户名/密码为表单编码,先解码再比对(纯 ASCII 值解码后不变)
      id = safeDecodeComponent(dec.slice(0, i)) || id;
      secret = safeDecodeComponent(dec.slice(i + 1)) || secret;
    } catch { /* 非法 base64 时回落到表单参数 */ }
  }
  if (!id) { bad(ctx, 'invalid_client', '缺少 client_id', 401, challenge); return null; }
  const client = clients.byId(id);
  if (!client) { bad(ctx, 'invalid_client', 'client_id 无效', 401, challenge); return null; }

  if (client.token_auth === 'none') {
    if (secret) { bad(ctx, 'invalid_client', '公开客户端不应携带客户端密钥', 401, challenge); return null; }
    return client;
  }
  if (!secret || !client.secret_hash || !(await verifyPassword(secret, client.secret_hash))) {
    bad(ctx, 'invalid_client', '客户端认证失败', 401, challenge);
    return null;
  }
  const fresh = clients.byId(client.client_id);
  if (!fresh || fresh.secret_hash !== client.secret_hash || fresh.token_auth !== client.token_auth) {
    bad(ctx, 'invalid_client', '客户端凭据已变化', 401, challenge);
    return null;
  }
  return fresh;
}

/** PKCE 校验:verifier 长度/字符集受限(RFC 7636 §4.1);S256=sha256(verifier) base64url;plain=原文 */
function pkceOk(verifier, challenge, method) {
  if (typeof verifier !== 'string' || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return false;
  if (!['S256', 'plain'].includes(method)) return false;
  return method === 'S256'
    ? timingSafeEqStr(sha256b64url(verifier), challenge)
    : timingSafeEqStr(verifier, challenge);
}

/** POST /token —— authorization_code / refresh_token / client_credentials */
export async function tokenPost(ctx) {
  ctx.res.setHeader('Cache-Control', 'no-store');
  ctx.res.setHeader('Pragma', 'no-cache');
  const body = ctx.body || {};
  const client = await authenticateClient(ctx);
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

  const user = users.byId(row.user_id);
  if (!user || user.disabled) return fail('用户不可用');

  const scope = row.scope.split(/\s+/).filter(Boolean);
  // 消费授权码 + 签发令牌放一个事务:避免中途失败留下「已用未发」或「已发未记」状态
  const db = getDb();
  let res;
  db.exec('BEGIN');
  try {
    codes.markUsed(row.code_hash);
    res = issueFull({
      client, user, scope,
      authTime: row.auth_time,
      nonce: row.nonce,
      withRefresh: scope.includes('offline_access'),
      withIdToken: scope.includes('openid'),
    });
    db.exec('COMMIT');
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch { /* 连接异常时保留原始错误 */ }
    throw err;
  }
  return sendJson(ctx.res, 200, res);
}

function grantRefreshToken(ctx, client, body) {
  const fail = (d) => bad(ctx, 'invalid_grant', d);
  if (!body.refresh_token) return fail('缺少 refresh_token');
  const row = tokens.byId(tokens.refreshKey(body.refresh_token));
  if (!row || row.kind !== 'refresh') return fail('refresh_token 无效');
  if (row.client_id !== client.client_id) return fail('refresh_token 不属于该客户端');
  if (row.revoked) {
    // 轮换链重放:已作废的刷新令牌再次出现,按令牌泄漏处理,作废其下游整条轮换链
    // 无 chain_id 的遗留令牌无法准确关联 access,保守撤销该客户端/用户的全部令牌。
    const revoked = row.chain_id ? tokens.revokeByChain(row.chain_id).changes
      : tokens.revokeForClientUser(row.client_id, row.user_id).changes;
    record(ctx, 'oauth.refresh_replay', `${row.client_id} revoked=${revoked}`);
    logger.warn('刷新令牌重放:已作废整条轮换链', { client_id: row.client_id, revoked });
    return fail('refresh_token 已失效');
  }
  if (row.expires_at <= nowSec()) return fail('refresh_token 已失效');

  const user = row.user_id ? users.byId(row.user_id) : null;
  if (row.user_id && (!user || user.disabled)) return fail('用户不可用');

  const original = row.scope.split(/\s+/).filter(Boolean);
  let scope = original;
  if (body.scope !== undefined) {
    if (typeof body.scope !== 'string') return bad(ctx, 'invalid_scope', 'scope 必须是字符串');
    const requested = [...new Set(body.scope.trim().split(/\s+/).filter(Boolean))];
    if (!requested.length || requested.some((s) => !original.includes(s))) {
      return bad(ctx, 'invalid_scope', 'scope 必须是原授权范围的非空子集');
    }
    scope = requested;
  }
  const authTime = row.auth_time;

  // 轮换:新 refresh 立即签发,旧的标记作废并记录 replaced_by 轮换链;两者同事务
  // 新令牌沿用旧令牌的 chain_id;遗留 NULL 链重放时按客户端/用户保守撤销。
  const chainId = row.chain_id || null;
  const newRefresh = tokens.newRefreshToken();
  const newHash = tokens.refreshKey(newRefresh);
  const db = getDb();
  let res;
  db.exec('BEGIN');
  try {
    tokens.insert({
      id: newHash, kind: 'refresh', clientId: client.client_id,
      userId: row.user_id, scope: scope.join(' '), authTime, nonce: row.nonce,
      expiresAt: nowSec() + ctx.runtime.refreshTokenTtl, chainId,
    });
    db.prepare('UPDATE tokens SET revoked = 1, replaced_by = ? WHERE id = ?').run(newHash, row.id);
    const { access_token, expiresIn } = issueAccessToken({ client, user, scope, authTime, chainId });
    res = {
      access_token, token_type: 'Bearer', expires_in: expiresIn,
      scope: scope.join(' '), refresh_token: newRefresh,
    };
    const idToken = mintIdToken({ client, user, scope, authTime, nonce: row.nonce, accessToken: access_token });
    if (idToken) res.id_token = idToken;
    db.exec('COMMIT');
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch { /* 连接异常时保留原始错误 */ }
    throw err;
  }

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
