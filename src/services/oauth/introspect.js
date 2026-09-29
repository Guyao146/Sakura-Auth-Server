import * as tokens from '../../models/tokens.js';
import { verifyJwt } from '../../core/jwt.js';
import * as users from '../../models/users.js';
import { sendJson } from '../../core/http.js';
import { authenticateClient } from './token.js';
import { nowSec } from '../../core/crypto.js';

/** POST /introspect —— RFC 7662 令牌内省(仅机密客户端) */
export function introspectPost(ctx) {
  const client = authenticateClient(ctx);
  if (!client) return;
  if (client.token_auth === 'none') {
    return sendJson(ctx.res, 401, { error: 'invalid_client' });
  }
  const token = ctx.body?.token || '';
  const row = lookup(token);
  if (!row || !tokens.isLive(row)) {
    return sendJson(ctx.res, 200, { active: false });
  }
  const user = row.user_id ? users.byId(row.user_id) : null;
  sendJson(ctx.res, 200, {
    active: true,
    scope: row.scope,
    client_id: row.client_id,
    token_type: row.kind === 'refresh' ? 'refresh_token' : 'Bearer',
    exp: row.expires_at,
    iat: row.created_at,
    ...(user ? { sub: user.id, username: user.username } : { sub: row.client_id }),
  });
}

/** POST /revoke —— RFC 7009 令牌吊销;按 RFC 语义即使未找到也返回 200 */
export function revokePost(ctx) {
  const client = authenticateClient(ctx);
  if (!client) return;
  const token = ctx.body?.token || '';
  const row = lookup(token);
  if (row && row.client_id === client.client_id) tokens.revokeById(row.id);
  sendJson(ctx.res, 200, {});
}

function lookup(token) {
  if (!token) return null;
  if (token.split('.').length === 3) {
    const payload = verifyJwt(token, { ignoreExp: true });
    if (payload?.jti) return tokens.byId(payload.jti);
    return null;
  }
  return tokens.byId(tokens.refreshKey(token));
}
