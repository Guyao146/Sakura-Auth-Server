/** 应用门户:普通用户可见的应用列表与统一登录入口(IdP-initiated SSO) */
import * as clients from '../models/clients.js';
import * as groups from '../models/groups.js';
import { getRuntime } from '../core/runtime.js';
import { randomToken, sha256b64url } from '../core/crypto.js';
import { sendHtml, redirect } from '../core/http.js';
import { portalPage } from '../views/portal.js';
import { forbidden } from './auth/login.js';

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
  sendHtml(ctx.res, 200, portalPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName, user: ctx.user,
    list: visibleApps(ctx.user), msg, err,
    cur: ctx.url.pathname + ctx.url.search,
  }));
}

/** GET /apps/launch/:clientId —— 组装授权参数并跳转 /authorize */
export function launch(ctx) {
  const app = clients.withUris(clients.byId(ctx.params.clientId) || { uriList: [] });
  if (!app.client_id || !app.uriList.length) {
    return redirect(ctx.res, '/apps?err=' + encodeURIComponent('应用不存在或未配置回调地址。'));
  }
  const mine = groups.membersOf(ctx.user.id);
  if (app.allowedGroupList.length && !app.allowedGroupList.some((g) => mine.includes(g))) {
    return forbidden({ res: ctx.res, theme: ctx.theme, runtime: ctx.runtime, session: ctx.session, user: ctx.user },
      `应用「${app.name}」仅对特定权限组开放,你不在所需组内。`);
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
