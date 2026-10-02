/** 应用门户:普通用户可见的应用列表与统一登录入口(IdP-initiated SSO) */
import * as clients from '../models/clients.js';
import * as groups from '../models/groups.js';
import { getRuntime } from '../core/runtime.js';
import { randomToken, sha256b64url } from '../core/crypto.js';
import { sendHtml, redirect, setCookie } from '../core/http.js';
import { portalPage } from '../views/portal.js';
import { forbidden } from './auth/login.js';
import { record } from './audit.js';

/* 启动参数暂存:门户代发的 PKCE,verifier 留在服务端(单实例内存),发码时写入授权码记录 */
const launchStash = new Map();

/** 用户可见的应用:应用未限制组,或用户属于任一限制组 */
export function visibleApps(user) {
  const mine = new Set(groups.membersOf(user.id));
  return clients.list().map((c) => clients.withUris(c))
    .filter((c) => !c.allowedGroupList.length || c.allowedGroupList.some((g) => mine.has(g)));
}

/** GET /apps */
export function showPortal(ctx, { msg, err } = {}) {
  // 视图切换:格子/条状,偏好记忆在 cookie(365 天)
  const q = ctx.query.get('view');
  let view = ctx.cookies.portal_view === 'list' ? 'list' : 'grid';
  if (q === 'grid' || q === 'list') {
    view = q;
    setCookie(ctx.res, 'portal_view', view, {
      maxAge: 365 * 86400, httpOnly: false, secure: ctx.runtime.secureCookies,
    });
  }
  // 顶栏:左侧视图切换(所有用户),右侧管理后台(仅管理员)
  const toggle = `<div class="seg-group">
      <a class="seg${view === 'grid' ? ' active' : ''}" href="/apps?view=grid">格子显示</a>
      <a class="seg${view === 'list' ? ' active' : ''}" href="/apps?view=list">条状显示</a>
    </div>`;
  const actions = `${toggle}${ctx.user.is_admin ? '<a class="btn btn-primary" href="/admin">管理后台</a>' : ''}`;
  sendHtml(ctx.res, 200, portalPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName, user: ctx.user,
    list: visibleApps(ctx.user), msg, err, view,
    cur: ctx.url.pathname + ctx.url.search,
    actions,
  }));
}

/** GET /apps/launch/:clientId —— 组装授权参数并跳转 /authorize */
export function launch(ctx) {
  const app = clients.withUris(clients.byId(ctx.params.clientId) || { uriList: [] });
  if (!app.client_id || !app.uriList.length) {
    return redirect(ctx.res, '/apps?err=' + encodeURIComponent('应用不存在或未配置回调地址。'));
  }
  // 管理员模拟启动:携带 sim_group(须为真实存在的组)时跳过组限制检查,受限应用也放行,
  // 用于以所选权限组的视角验证授权链路(真实身份不变,动作计入审计);
  // 普通用户或组名不存在时忽略该参数,照常执行组限制。
  let simGroup = '';
  const requested = ctx.query.get('sim_group');
  if (requested && ctx.user.is_admin) simGroup = groups.byName(requested)?.name || '';
  if (simGroup) {
    record(ctx, 'admin.simulate_launch', `应用「${app.name}」· 模拟组「${simGroup}」`);
  } else {
    const mine = groups.membersOf(ctx.user.id);
    if (app.allowedGroupList.length && !app.allowedGroupList.some((g) => mine.includes(g))) {
      return forbidden({ res: ctx.res, theme: ctx.theme, runtime: ctx.runtime, session: ctx.session, user: ctx.user },
        `应用「${app.name}」仅对特定权限组开放,你不在所需组内。`);
    }
  }
  const params = new URLSearchParams({
    client_id: app.client_id,
    redirect_uri: app.uriList[0],
    response_type: 'code',
    scope: app.scopeList.join(' ') || 'openid',
    state: randomToken(12),
    nonce: randomToken(12),
  });
  if (app.pkce_required) {
    // 门户代发 PKCE:verifier 暂存于服务端,authorize 发码时写入授权码记录,
    // 应用回调后凭 code 即可正常换取令牌(IdP-initiated 委托)
    const verifier = randomToken(48);
    if (launchStash.size > 500) launchStash.delete(launchStash.keys().next().value);
    launchStash.set(ctx.session.id_hash, { verifier, clientId: app.client_id });
    params.set('code_challenge', sha256b64url(verifier));
    params.set('code_challenge_method', 'S256');
  }
  redirect(ctx.res, '/authorize?' + params.toString());
}

/** authorize 发码时消费该会话的门户启动记录;无则返回 null */
export const consumeLaunch = (sessionIdHash, clientId) => {
  const rec = launchStash.get(sessionIdHash);
  if (!rec || rec.clientId !== clientId) return null;
  launchStash.delete(sessionIdHash);
  return rec.verifier;
};
