import crypto from 'node:crypto';
import { signJwt } from '../../core/jwt.js';
import { getRuntime } from '../../core/runtime.js';
import * as tokens from '../../models/tokens.js';
import * as groups from '../../models/groups.js';
import { SCOPES } from '../../core/config.js';
import { nowSec } from '../../core/crypto.js';

/** 请求 scope 与客户端允许 scope 取交集(按 SCOPES 顺序稳定输出) */
export function filterScopes(requested, allowed) {
  const req = new Set(String(requested || '').split(/\s+/).filter(Boolean));
  const allow = new Set(String(allowed || '').split(/\s+/).filter(Boolean));
  return Object.keys(SCOPES).filter((s) => req.has(s) && allow.has(s));
}

/** 按 scope 构造用户 claims(userinfo 与 id_token 共用) */
export function claimsFor(user, scopeList) {
  const s = new Set(scopeList);
  const claims = { sub: user.id };
  if (s.has('profile')) {
    claims.preferred_username = user.username;
    claims.name = user.name || user.username;
    claims.updated_at = user.updated_at;
  }
  if (s.has('email')) {
    claims.email = user.email || '';
    claims.email_verified = false;
  }
  if (s.has('groups')) {
    // 组名来自组成员关系表;users.user_groups 文本列已弃用(仅作镜像保留)
    claims.groups = groups.membersOf(user.id);
  }
  return claims;
}

/** 签发 access token(JWT)并落库;返回响应所需字段 */
export function issueAccessToken({ client, user, scope, authTime }) {
  const rt = getRuntime();
  const jti = tokens.newJti();
  const exp = nowSec() + rt.accessTokenTtl;
  const payload = {
    iss: rt.issuer,
    sub: user ? user.id : client.client_id,
    aud: client.client_id,
    client_id: client.client_id,
    scope: scope.join(' '),
    jti,
  };
  if (authTime) payload.auth_time = authTime;
  const access_token = signJwt(payload, rt.accessTokenTtl);
  tokens.insert({
    id: jti, kind: 'access', clientId: client.client_id, userId: user ? user.id : null,
    scope: scope.join(' '), authTime, expiresAt: exp,
  });
  return { access_token, expiresIn: rt.accessTokenTtl };
}

/** 签发 opaque refresh token(落库存哈希) */
export function issueRefreshToken({ client, user, scope }) {
  const rt = getRuntime();
  const token = tokens.newRefreshToken();
  tokens.insert({
    id: tokens.refreshKey(token), kind: 'refresh', clientId: client.client_id,
    userId: user ? user.id : null, scope: scope.join(' '),
    expiresAt: nowSec() + rt.refreshTokenTtl,
  });
  return token;
}

/** OIDC Core §3.1.3.6:at_hash = access token SHA-256 摘要左半(16 字节)的 base64url 编码(22 字符) */
const atHash = (accessToken) =>
  crypto.createHash('sha256').update(accessToken).digest().subarray(0, 16).toString('base64url');

/** OIDC id_token:openid scope 时返回 */
export function mintIdToken({ client, user, scope, authTime, nonce, accessToken }) {
  if (!scope.includes('openid') || !user) return null;
  const rt = getRuntime();
  const claims = claimsFor(user, scope);
  const payload = {
    iss: rt.issuer,
    aud: client.client_id,
    client_id: client.client_id,
    auth_time: authTime,
    at_hash: atHash(accessToken),
    ...claims,
  };
  if (nonce) payload.nonce = nonce;
  return signJwt(payload, rt.accessTokenTtl);
}

/** 组装 RFC 6749 token 响应体 */
export function issueFull({ client, user, scope, authTime, nonce, withRefresh, withIdToken }) {
  const { access_token, expiresIn } = issueAccessToken({ client, user, scope, authTime });
  const res = {
    access_token,
    token_type: 'Bearer',
    expires_in: expiresIn,
    scope: scope.join(' '),
  };
  if (withRefresh) res.refresh_token = issueRefreshToken({ client, user, scope });
  if (withIdToken) res.id_token = mintIdToken({ client, user, scope, authTime, nonce, accessToken: access_token });
  return res;
}
