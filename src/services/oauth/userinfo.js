import * as users from '../../models/users.js';
import * as tokens from '../../models/tokens.js';
import { verifyJwt } from '../../core/jwt.js';
import { sendJson } from '../../core/http.js';
import { claimsFor } from './issue.js';

const unauthorized = (ctx) => {
  sendJson(ctx.res, 401, { error: 'invalid_token' }, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
};

function extractToken(ctx) {
  const header = ctx.req.headers['authorization'];
  if (header && header.startsWith('Bearer ')) return header.slice(7).trim();
  if (ctx.body && ctx.body.access_token) return String(ctx.body.access_token);
  if (ctx.query.get('access_token')) return ctx.query.get('access_token');
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
