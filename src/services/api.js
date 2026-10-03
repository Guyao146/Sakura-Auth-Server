/** JSON API 套件:心跳 / 会话状态 / 登录 / 登出 / 可见应用 / 应用健康注册表。
 *  全部返回 JSON 且 Cache-Control: no-store;登录态由处理器自行判定,
 *  未登录不重定向(区别于 auth 路由选项),便于脚本与非浏览器客户端调用。 */
import * as users from '../models/users.js';
import * as sessions from '../models/sessions.js';
import * as groups from '../models/groups.js';
import * as recovery from '../models/recovery.js';
import * as clients from '../models/clients.js';
import * as tokens from '../models/tokens.js';
import * as portal from './portal.js';
import * as appHealth from './app-health.js';
import { getDb } from '../core/db.js';
import { config } from '../core/config.js';
import { getRuntime } from '../core/runtime.js';
import { sendJson, clearCookie } from '../core/http.js';
import { verifyJwt } from '../core/jwt.js';
import { verifyTotp } from '../core/totp.js';
import { verifyPassword, hashPassword } from '../core/password.js';
import { isLocked, recordFail, clearFails, startSession, sessionMeta } from './auth/login.js';

const NO_STORE = { 'Cache-Control': 'no-store' };
// 未知用户名的时序均衡 Dummy 哈希(与 web 登录同策略)
const DUMMY_HASH = hashPassword('sakuraid-dummy-timing-equalizer');

/** JSON API 深度防御:cookie 会话的写操作要求显式 X-Requested-With 头。
 *  第一道防线是 cookie 的 SameSite=Lax(跨站 POST 不携带);此头为第二道,
 *  防未来 SameSite 策略变化或同站子域发起的请求。Bearer 令牌路径不受影响。 */
const requiresAjaxGuard = (ctx) => ctx.req.headers['x-requested-with'] !== 'JSON';

/** 用户公开信息:groups 由组成员关系表驱动,与 userinfo 的 groups claim 同源 */
const userPayload = (user) => ({
  username: user.username,
  name: user.name,
  email: user.email,
  groups: groups.membersOf(user.id),
  is_admin: !!user.is_admin,
  totp_enabled: !!(user.totp_enabled && user.totp_secret),
});

/** GET /api/heartbeat —— 匿名探活(CORS 开放,供监控跨域拉取) */
export function heartbeat(ctx) {
  let db = 'ok';
  try { getDb().prepare('SELECT 1').get(); } catch { db = 'error'; }
  const rt = getRuntime();
  sendJson(ctx.res, 200, {
    ok: true,
    status: 'alive',
    site_name: rt.siteName,
    issuer: rt.issuer,
    version: config.version,
    uptime_sec: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    db,
  }, NO_STORE);
}

/** GET /api/session —— 当前登录状态 */
export function session(ctx) {
  if (!ctx.user) return sendJson(ctx.res, 200, { authenticated: false }, NO_STORE);
  sendJson(ctx.res, 200, { authenticated: true, user: userPayload(ctx.user) }, NO_STORE);
}

/** POST /api/login —— JSON 或表单 {username, password, totp_code?};
 *  复用 web 登录的限流与凭据校验规则 */
export function login(ctx) {
  const b = ctx.body || {};
  const username = typeof b.username === 'string' ? b.username.trim() : '';
  const password = typeof b.password === 'string' ? b.password : '';
  if (!username || !password) return sendJson(ctx.res, 400, { error: 'bad_request' }, NO_STORE);

  if (isLocked(ctx, username)) return sendJson(ctx.res, 401, { error: 'rate_limited' }, NO_STORE);

  const user = users.byUsername(username);
  // 未知用户对 Dummy 哈希也执行一次等价 scrypt(时序均衡,与 web 登录同策略)
  const ok = user && !user.disabled && verifyPassword(password, user.password_hash);
  if (!ok) {
    if (!user) verifyPassword(password, DUMMY_HASH);
    recordFail(ctx, username);
    return sendJson(ctx.res, 401, { error: 'invalid_credentials' }, NO_STORE);
  }

  // 已开启两步验证:TOTP 或恢复代码均可(与 web 登录同规则;仅提交了错误验证码才记失败)
  if (user.totp_enabled && user.totp_secret) {
    const code = typeof b.totp_code === 'string' ? b.totp_code.trim() : '';
    const okTotp = verifyTotp(user.totp_secret, code);
    const okRecovery = !okTotp && recovery.consume(user.id, code);
    if (!okTotp && !okRecovery) {
      if (code) recordFail(ctx, username);
      return sendJson(ctx.res, 401, { error: 'totp_required' }, NO_STORE);
    }
  }

  clearFails(ctx, username);
  startSession(ctx.res, user, undefined, sessionMeta(ctx));
  return sendJson(ctx.res, 200, { ok: true, user: userPayload(user) }, NO_STORE);
}

/** POST /api/logout —— 销毁当前会话并清 cookie;未登录同样返回 ok(幂等) */
export function logout(ctx) {
  if (requiresAjaxGuard(ctx)) return sendJson(ctx.res, 403, { error: 'ajax_header_required' }, NO_STORE);
  if (ctx.session) sessions.remove(ctx.session.id_hash);
  clearCookie(ctx.res, 'sid', getRuntime().secureCookies);
  sendJson(ctx.res, 200, { ok: true }, NO_STORE);
}

/* ---- 登录会话自助管理(JSON API):列表 / 撤销指定 / 撤销其它 ---- */

/** GET /api/sessions —— 当前用户的登录会话列表。
 *  id_hash 仅返回前 8 位(sha256 摘要前缀,供撤销定位,不暴露完整摘要)。 */
export function listSessions(ctx) {
  if (!ctx.user) return sendJson(ctx.res, 401, { error: 'unauthenticated' }, NO_STORE);
  const list = sessions.listForUser(ctx.user.id).map((s) => ({
    id_hash: s.id_hash.slice(0, 8),
    created_at: s.created_at,
    expires_at: s.expires_at,
    ip: s.ip || '',
    ua: s.ua || '',
    is_current: s.id_hash === ctx.session.id_hash,
  }));
  sendJson(ctx.res, 200, {
    authenticated: true,
    current: ctx.session.id_hash.slice(0, 8),
    sessions: list,
  }, NO_STORE);
}

/** 在用户存活会话中解析撤销目标:完整 id_hash 或唯一前缀(≥8 位)均可 */
function resolveSessionTarget(userId, target) {
  const rows = sessions.listForUser(userId);
  const exact = rows.find((s) => s.id_hash === target);
  if (exact) return exact;
  if (target.length < 8) return null; // 过短前缀不做匹配,避免歧义
  const prefixed = rows.filter((s) => s.id_hash.startsWith(target));
  return prefixed.length === 1 ? prefixed[0] : null;
}

/** POST /api/sessions/revoke {id_hash} —— 撤销自己的指定会话(全值或列表返回的前缀均可)。
 *  撤销当前会话时 cookie 一并失效,返回 {ok:true, current_revoked:true}。 */
export function revokeSession(ctx) {
  if (requiresAjaxGuard(ctx)) return sendJson(ctx.res, 403, { error: 'ajax_header_required' }, NO_STORE);
  if (!ctx.user) return sendJson(ctx.res, 401, { error: 'unauthenticated' }, NO_STORE);
  const target = typeof ctx.body?.id_hash === 'string' ? ctx.body.id_hash.trim() : '';
  const row = target ? resolveSessionTarget(ctx.user.id, target) : null;
  if (!row) return sendJson(ctx.res, 404, { error: 'not_found' }, NO_STORE);
  sessions.removeByIdHash(row.id_hash, ctx.user.id);
  const currentRevoked = row.id_hash === ctx.session.id_hash;
  if (currentRevoked) clearCookie(ctx.res, 'sid', getRuntime().secureCookies);
  sendJson(ctx.res, 200, { ok: true, current_revoked: currentRevoked }, NO_STORE);
}

/** POST /api/sessions/revoke-others —— 撤销当前会话以外的全部会话 */
export function revokeOtherSessions(ctx) {
  if (requiresAjaxGuard(ctx)) return sendJson(ctx.res, 403, { error: 'ajax_header_required' }, NO_STORE);
  if (!ctx.user) return sendJson(ctx.res, 401, { error: 'unauthenticated' }, NO_STORE);
  const revoked = sessions.removeAllOther(ctx.user.id, ctx.session.id_hash);
  sendJson(ctx.res, 200, { ok: true, revoked }, NO_STORE);
}

/** GET /api/apps —— 当前用户可见的应用列表(复用门户的可见性过滤) */
export function apps(ctx) {
  if (!ctx.user) return sendJson(ctx.res, 401, { error: 'unauthenticated' }, NO_STORE);
  const list = portal.visibleApps(ctx.user).map((c) => ({
    client_id: c.client_id,
    name: c.name,
    type: c.token_auth === 'none' ? 'public' : 'confidential',
    scopes: c.scopeList,
  }));
  sendJson(ctx.res, 200, { apps: list }, NO_STORE);
}

/** Bearer 访问令牌校验:任何存活的 access 令牌均可(含 client_credentials 的机器身份) */
function bearerLive(ctx) {
  const header = ctx.req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) return false;
  const payload = verifyJwt(header.slice(7).trim());
  if (!payload) return false;
  const row = tokens.byId(payload.jti);
  return !!row && row.kind === 'access' && tokens.isLive(row);
}

/** GET /api/registry —— 应用健康状态注册表(应用读取其它应用的状态)。
 *  认证(任一):Bearer 访问令牌(机器身份,client_credentials 令牌也可)或管理员会话;
 *  未认证 → 401 unauthenticated。CORS 与 /api/heartbeat 一致。 */
export function registry(ctx) {
  const isAdmin = !!(ctx.user && ctx.user.is_admin);
  if (!isAdmin && !bearerLive(ctx)) {
    return sendJson(ctx.res, 401, { error: 'unauthenticated' }, NO_STORE);
  }
  const apps = clients.list().map((c) => {
    const w = clients.withUris(c);
    const h = appHealth.get(c.client_id);
    return {
      client_id: c.client_id,
      name: c.name,
      type: c.token_auth === 'none' ? 'public' : 'confidential',
      status: h?.status || 'unknown',
      latency_ms: h?.latencyMs ?? null,
      checked_at: h?.checkedAt || null,
      health_url: w.healthUrl || '',
    };
  });
  sendJson(ctx.res, 200, { apps }, NO_STORE);
}
