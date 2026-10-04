import * as users from '../../models/users.js';
import * as tokens from '../../models/tokens.js';
import { verifyJwt } from '../../core/jwt.js';
import { sendJson } from '../../core/http.js';
import { claimsFor } from './issue.js';

const unauthorized = (ctx) => {
  sendJson(ctx.res, 401, { error: 'invalid_token' }, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
};

function extractToken(ctx) {
  // RFC 6750 §2.3:查询参数与编码体参数是 SHOULD NOT 的次要传递方式,统一收紧为只认
  // Authorization: Bearer 头(避免令牌泄入 URL/日志/Referer);其余载体一律 401
  const header = ctx.req.headers['authorization'];
  if (header && header.startsWith('Bearer ')) return header.slice(7).trim();
  return null;
}

/** GET/POST /userinfo —— Bearer access token → 用户 claims */
export function userinfo(ctx) {
  const token = extractToken(ctx);
  if (!token) return unauthorized(ctx);
  const payload = verifyJwt(token);
  if (!payload) return unauthorized(ctx);
  const row = tokens.byId(payload.jti);
  if (!tokens.isLive(row) || row.kind !== 'access') return unauthorized(ctx);
  const user = row.user_id ? users.byId(row.user_id) : null;
  if (!user || user.disabled) return unauthorized(ctx);
  const scope = row.scope.split(/\s+/).filter(Boolean);
  sendJson(ctx.res, 200, claimsFor(user, scope));
}
