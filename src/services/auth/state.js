import * as users from '../../models/users.js';
import * as sessions from '../../models/sessions.js';
import { nowSec } from '../../core/crypto.js';

/** await 后重新验证凭据快照;版本号覆盖禁用再启用、MFA 及管理员权限变更。 */
export function freshIdentity(snapshot) {
  if (!snapshot) return null;
  const fresh = users.byId(snapshot.id);
  return fresh && !fresh.disabled && fresh.credential_version === snapshot.credential_version
    && fresh.password_hash === snapshot.password_hash ? fresh : null;
}

/** 已认证写请求在读取请求体/计算密码后再次核对会话。 */
export function requireCurrentSession(ctx, admin = false) {
  const fresh = freshIdentity(ctx.user);
  const session = ctx.session && sessions.byIdHash(ctx.session.id_hash);
  if (!fresh || !session || session.user_id !== fresh.id || session.expires_at <= nowSec()
      || session.csrf !== ctx.session.csrf || (admin && !fresh.is_admin)) {
    throw Object.assign(new Error('认证状态已变化,请重新登录'), { status: 401 });
  }
  ctx.user = fresh;
  return fresh;
}
