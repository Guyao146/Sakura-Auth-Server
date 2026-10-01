import * as users from '../../models/users.js';
import * as clients from '../../models/clients.js';
import * as groups from '../../models/groups.js';
import * as sessions from '../../models/sessions.js';
import * as tokens from '../../models/tokens.js';
import * as recovery from '../../models/recovery.js';
import { getRuntime, updateRuntime } from '../../core/runtime.js';
import * as settingsApi from '../../models/settings.js';
import { hashPassword } from '../../core/password.js';
import { randomToken } from '../../core/crypto.js';
import { splitLines, redirectUri as validUri } from '../../core/util.js';
import { SCOPES, DEFAULT_CLIENT_SCOPES } from '../../core/config.js';
import { sendHtml, redirect } from '../../core/http.js';
import { logger } from '../../core/logger.js';
import { dashboardPage, groupsPage, usersPage, userFormPage, appsPage, appFormPage, appDetailPage, secretRevealPage } from '../../views/admin.js';

const CSRF = (ctx) => ctx.session.csrf;

/* ---------------- 控制台首页 ---------------- */
export function showDashboard(ctx) {
  const rt = getRuntime();
  sendHtml(ctx.res, 200, dashboardPage({
    theme: ctx.theme, siteName: rt.siteName, user: ctx.user,
    cur: ctx.url.pathname + ctx.url.search,
    stats: { users: users.count(), clients: clients.count(), activeTokens: tokens.countActive(), sessions: sessions.count() },
    issuer: rt.issuer,
    allowRegister: rt.allowRegister,
    msOAuth: rt.msOAuth,
    csrf: CSRF(ctx),
    msg: ctx.query.get('msg'), err: ctx.query.get('err'),
  }));
}

/* ---------------- 自助注册开关 ---------------- */
export function toggleRegister(ctx) {
  const rt = getRuntime();
  if (ctx.body?._csrf !== CSRF(ctx)) {
    return redirect(ctx.res, '/admin?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
  const next = rt.allowRegister ? '0' : '1';
  updateRuntime({ allow_register: next }, settingsApi.setSetting);
  redirect(ctx.res, '/admin?msg=' + encodeURIComponent(next === '1' ? '已开启自助注册。' : '已关闭自助注册。'));
}

/* ---------------- Microsoft 登录配置 ---------------- */
export function saveMsOAuth(ctx) {
  const b = ctx.body || {};
  if (b._csrf !== CSRF(ctx)) {
    return redirect(ctx.res, '/admin?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
  const fields = {
    ms_enabled: b.ms_enabled === '1' ? '1' : '0',
    ms_client_id: String(b.ms_client_id || '').trim(),
    ms_tenant: String(b.ms_tenant || '').trim() || 'common',
  };
  const secret = String(b.ms_client_secret || '');
  if (secret) fields.ms_client_secret = secret; // 留空 = 保留已保存的密钥
  const authority = String(b.ms_authority || '').trim();
  if (authority) fields.ms_authority = authority.replace(/\/+$/, ''); // 默认由向导/测试直接指定,常规表单不展示
  updateRuntime(fields, settingsApi.setSetting);
  logger.info('管理员更新了 Microsoft 登录配置', { enabled: fields.ms_enabled });
  redirect(ctx.res, '/admin?msg=' + encodeURIComponent('Microsoft 登录设置已保存。'));
}

/* ---------------- 权限组管理 ---------------- */
export function listGroups(ctx) {
  sendHtml(ctx.res, 200, groupsPage({
    theme: ctx.theme, siteName: getRuntime().siteName, user: ctx.user,
    cur: ctx.url.pathname + ctx.url.search, list: groups.list(), csrf: CSRF(ctx),
    msg: ctx.query.get('msg'), err: ctx.query.get('err'),
  }));
}

export function createGroup(ctx) {
  const b = ctx.body || {};
  const back = (e) => redirect(ctx.res, '/admin/groups?err=' + encodeURIComponent(e));
  if (b._csrf !== CSRF(ctx)) return back('页面已过期,请重试。');
  const name = String(b.name || '').trim();
  const description = String(b.description || '').trim();
  if (!name || name.length > 40) return back('组名必填且不超过 40 字。');
  if (/\s/.test(name)) return back('组名不能包含空白字符。');
  if (groups.byName(name)) return back(`权限组 ${name} 已存在。`);
  groups.create({ name, description });
  redirect(ctx.res, '/admin/groups?msg=' + encodeURIComponent(`权限组 ${name} 已创建。`));
}

export function deleteGroup(ctx) {
  const back = (e) => redirect(ctx.res, '/admin/groups?err=' + encodeURIComponent(e));
  if (ctx.body?._csrf !== CSRF(ctx)) return back('页面已过期,请重试。');
  const g = groups.byId(ctx.params.id);
  if (!g) return back('权限组不存在。');
  groups.remove(g.id);
  redirect(ctx.res, '/admin/groups?msg=' + encodeURIComponent(`权限组 ${g.name} 已删除,成员关系已解除。`));
}

/* ---------------- 用户管理 ---------------- */
export function listUsers(ctx) {
  const list = users.list().map((u) => ({ ...u, groupNames: groups.membersOf(u.id), _csrf: CSRF(ctx) }));
  sendHtml(ctx.res, 200, usersPage({
    theme: ctx.theme, siteName: getRuntime().siteName, user: ctx.user,
    cur: ctx.url.pathname + ctx.url.search, list,
    msg: ctx.query.get('msg'), err: ctx.query.get('err'),
  }));
}

export function newUserForm(ctx) {
  sendHtml(ctx.res, 200, userFormPage({
    theme: ctx.theme, siteName: getRuntime().siteName, user: ctx.user,
    cur: ctx.url.pathname, target: null, isNew: true, err: ctx.query.get('err'),
    allGroups: groups.list(),
    values: { username: '', name: '', email: '', groupSet: new Set(), is_admin: false, disabled: false },
  }));
}

export function createUser(ctx) {
  const b = ctx.body || {};
  const username = String(b.username || '').trim();
  if (!/^[a-zA-Z0-9_.@-]{2,64}$/.test(username)) {
    return redirect(ctx.res, '/admin/users/new?err=' + encodeURIComponent('用户名需为 2-64 位字母数字与 _.@-。'));
  }
  if (typeof b.password !== 'string' || b.password.length < 8) {
    return redirect(ctx.res, '/admin/users/new?err=' + encodeURIComponent('初始密码至少 8 位。'));
  }
  if (users.byUsername(username)) {
    return redirect(ctx.res, '/admin/users/new?err=' + encodeURIComponent('用户名已存在。'));
  }
  const groupNames = collectGroupNames(b);
  const created = users.create({
    username, passwordHash: hashPassword(b.password),
    name: String(b.name || '').trim(), email: String(b.email || '').trim(),
    userGroups: groupNames.join(' '), isAdmin: b.is_admin === '1',
  });
  if (groupNames.length) groups.setUserGroups(created.id, groupNames);
  redirect(ctx.res, '/admin/users?msg=' + encodeURIComponent(`用户 ${created.username} 已创建。`));
}

export function userDetail(ctx) {
  const target = users.byId(ctx.params.id);
  if (!target) return redirect(ctx.res, '/admin/users?err=' + encodeURIComponent('用户不存在。'));
  sendHtml(ctx.res, 200, userFormPage({
    theme: ctx.theme, siteName: getRuntime().siteName, user: ctx.user,
    cur: ctx.url.pathname, target: target.id, isNew: false, err: ctx.query.get('err'),
    allGroups: groups.list(),
    values: {
      username: target.username, name: target.name, email: target.email,
      groupSet: new Set(groups.membersOf(target.id)), is_admin: !!target.is_admin, disabled: !!target.disabled,
      totp_enabled: !!target.totp_enabled,
      _csrf: CSRF(ctx),
    },
  }));
}

export function updateUser(ctx) {
  const b = ctx.body || {};
  const target = users.byId(ctx.params.id);
  if (!target) return redirect(ctx.res, '/admin/users?err=' + encodeURIComponent('用户不存在。'));
  if (b._csrf !== CSRF(ctx)) return redirect(ctx.res, '/admin/users?err=' + encodeURIComponent('页面已过期,请重试。'));

  const self = target.id === ctx.user.id;
  const willAdmin = b.is_admin === '1';
  const willDisabled = b.disabled === '1';
  if (self && (willDisabled || !willAdmin)) {
    return redirect(ctx.res, `/admin/users/${target.id}?err=` + encodeURIComponent('不能禁用自己或移除自己的管理员权限。'));
  }
  if (!willAdmin && target.is_admin && users.adminCount() <= 1) {
    return redirect(ctx.res, `/admin/users/${target.id}?err=` + encodeURIComponent('系统至少保留一名可用管理员。'));
  }
  let passwordHash = null;
  if (typeof b.password === 'string' && b.password.length > 0) {
    if (b.password.length < 8) {
      return redirect(ctx.res, `/admin/users/${target.id}?err=` + encodeURIComponent('新密码至少 8 位。'));
    }
    passwordHash = hashPassword(b.password);
  }
  if (b.totp_reset === '1' && target.totp_enabled) {
    users.clearTotp(target.id);
    recovery.clearFor(target.id);
  }
  const groupNames = collectGroupNames(b);
  // user_groups 文本列保留为成员关系的镜像,便于人工排查;claims/授权一律读关系表
  users.update(target.id, {
    name: String(b.name || '').trim(), email: String(b.email || '').trim(),
    userGroups: groupNames.join(' '),
    passwordHash, isAdmin: willAdmin, disabled: willDisabled,
  });
  groups.setUserGroups(target.id, groupNames);
  redirect(ctx.res, '/admin/users?msg=' + encodeURIComponent(`用户 ${target.username} 已更新。`));
}

export function deleteUser(ctx) {
  const target = users.byId(ctx.params.id);
  if (!target) return redirect(ctx.res, '/admin/users?err=' + encodeURIComponent('用户不存在。'));
  if (ctx.body?._csrf !== CSRF(ctx)) return redirect(ctx.res, '/admin/users?err=' + encodeURIComponent('页面已过期,请重试。'));
  if (target.id === ctx.user.id) {
    return redirect(ctx.res, '/admin/users?err=' + encodeURIComponent('不能删除当前登录的账号。'));
  }
  if (target.is_admin && users.adminCount() <= 1) {
    return redirect(ctx.res, '/admin/users?err=' + encodeURIComponent('系统至少保留一名可用管理员。'));
  }
  users.remove(target.id);
  redirect(ctx.res, '/admin/users?msg=' + encodeURIComponent(`用户 ${target.username} 已删除。`));
}

/* ---------------- 应用(客户端)管理 ---------------- */

function collectScopes(body) {
  const raw = Array.isArray(body.scopes) ? body.scopes : [body.scopes];
  return (raw || []).filter((s) => typeof s === 'string' && SCOPES[s]);
}

/** 表单 → 组名数组:优先 groups 复选框(可多值),否则兼容旧版 user_groups 自由文本 */
function collectGroupNames(body) {
  const raw = Array.isArray(body.groups) ? body.groups : body.groups !== undefined ? [body.groups] : [];
  if (raw.length) {
    return [...new Set(raw.flatMap((v) => String(v).split(/[\s,]+/)).filter(Boolean))];
  }
  return [...new Set(String(body.user_groups || '').trim().split(/[\s,]+/).filter(Boolean))];
}

/** 表单 → 应用可访问组名数组(只保留真实存在的组;空数组 = 不限制) */
function collectAllowedGroups(body) {
  const raw = Array.isArray(body.allowed_groups) ? body.allowed_groups : body.allowed_groups ? [body.allowed_groups] : [];
  const wanted = new Set(raw.flatMap((v) => String(v).split(/[\s,]+/)).filter(Boolean));
  const known = new Set(groups.list().map((g) => g.name));
  return [...wanted].filter((n) => known.has(n));
}

function validateAppInput(b) {
  const name = String(b.name || '').trim();
  if (!name || name.length > 40) return { error: '应用名称必填且不超过 40 字。' };
  const uris = splitLines(b.redirect_uris);
  if (!uris.length) return { error: '至少填写一个重定向地址。' };
  for (const u of uris) {
    if (!validUri(u)) return { error: `重定向地址不合法:${u}` };
  }
  const scopes = collectScopes(b);
  if (!scopes.length) return { error: '至少勾选一个 scope。' };
  return { name, uris, scopes };
}

export function listApps(ctx) {
  const rt = getRuntime();
  const list = clients.list().map((c) => ({ ...c, _csrf: CSRF(ctx) }));
  sendHtml(ctx.res, 200, appsPage({
    theme: ctx.theme, siteName: rt.siteName, user: ctx.user,
    cur: ctx.url.pathname + ctx.url.search, list, issuer: rt.issuer,
    msg: ctx.query.get('msg'), err: ctx.query.get('err'),
  }));
}

export function newAppForm(ctx, { err, values } = {}) {
  sendHtml(ctx.res, 200, appFormPage({
    theme: ctx.theme, siteName: getRuntime().siteName, user: ctx.user,
    cur: ctx.url.pathname, err, allGroups: groups.list(),
    values: values || {
      name: '', client_type: 'confidential', redirect_uris: '',
      scopeSet: new Set(DEFAULT_CLIENT_SCOPES.split(/\s+/)),
      allowedGroupSet: new Set(),
      pkce_required: true, require_consent: true,
    },
  }));
}

export function createApp(ctx) {
  const b = ctx.body || {};
  const v = validateAppInput(b);
  const allowedGroups = collectAllowedGroups(b);
  if (v.error) {
    return newAppForm(ctx, {
      err: v.error,
      values: { ...b, scopeSet: new Set(collectScopes(b)), allowedGroupSet: new Set(allowedGroups) },
    });
  }
  const isPublic = b.client_type === 'public';
  const pkce = isPublic || b.pkce_required === '1';
  let secret = null, secretHash = null;
  if (!isPublic) {
    secret = randomToken(24);
    secretHash = hashPassword(secret);
  }
  const app = clients.create({
    name: v.name, redirectUris: v.uris, scopes: v.scopes.join(' '),
    isPublic, pkceRequired: pkce, requireConsent: b.require_consent === '1',
    secretHash, allowedGroups,
  });
  if (secret) {
    return sendHtml(ctx.res, 200, secretRevealPage({
      theme: ctx.theme, siteName: getRuntime().siteName, user: ctx.user,
      cur: '/admin/apps', app: clients.withUris(app), secret, issuer: getRuntime().issuer, isNew: true,
    }));
  }
  redirect(ctx.res, `/admin/apps/${app.client_id}?msg=` + encodeURIComponent('公开客户端已创建,无需密钥。'));
}

export function appDetail(ctx) {
  const app = clients.byId(ctx.params.id);
  if (!app) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('应用不存在。'));
  sendHtml(ctx.res, 200, appDetailPage({
    theme: ctx.theme, siteName: getRuntime().siteName, user: ctx.user,
    cur: ctx.url.pathname, allGroups: groups.list(),
    app: { ...clients.withUris(app), _csrf: CSRF(ctx) },
    issuer: getRuntime().issuer,
    msg: ctx.query.get('msg'), err: ctx.query.get('err'),
  }));
}

export function updateApp(ctx) {
  const b = ctx.body || {};
  const app = clients.byId(ctx.params.id);
  if (!app) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('应用不存在。'));
  if (b._csrf !== CSRF(ctx)) return redirect(ctx.res, `/admin/apps/${app.client_id}?err=` + encodeURIComponent('页面已过期,请重试。'));
  const v = validateAppInput(b);
  if (v.error) return redirect(ctx.res, `/admin/apps/${app.client_id}?err=` + encodeURIComponent(v.error));
  clients.update(app.client_id, {
    name: v.name, redirectUris: JSON.stringify(v.uris), scopes: v.scopes.join(' '),
    pkceRequired: app.token_auth === 'none' ? true : b.pkce_required === '1',
    requireConsent: b.require_consent === '1',
    allowedGroups: collectAllowedGroups(b),
  });
  redirect(ctx.res, `/admin/apps/${app.client_id}?msg=` + encodeURIComponent('设置已保存。'));
}

export function regenerateSecret(ctx) {
  const app = clients.byId(ctx.params.id);
  if (!app) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('应用不存在。'));
  if (ctx.body?._csrf !== CSRF(ctx)) return redirect(ctx.res, `/admin/apps/${app.client_id}?err=` + encodeURIComponent('页面已过期,请重试。'));
  if (app.token_auth === 'none') {
    return redirect(ctx.res, `/admin/apps/${app.client_id}?err=` + encodeURIComponent('公开客户端没有密钥。'));
  }
  const secret = randomToken(24);
  clients.update(app.client_id, { secretHash: hashPassword(secret) });
  sendHtml(ctx.res, 200, secretRevealPage({
    theme: ctx.theme, siteName: getRuntime().siteName, user: ctx.user,
    cur: '/admin/apps', app: clients.withUris(clients.byId(app.client_id)), secret,
    issuer: getRuntime().issuer, isNew: false,
  }));
}

export function revokeAppTokens(ctx) {
  const app = clients.byId(ctx.params.id);
  if (!app) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('应用不存在。'));
  if (ctx.body?._csrf !== CSRF(ctx)) return redirect(ctx.res, `/admin/apps/${app.client_id}?err=` + encodeURIComponent('页面已过期,请重试。'));
  tokens.revokeForClient(app.client_id);
  redirect(ctx.res, `/admin/apps/${app.client_id}?msg=` + encodeURIComponent('该应用的全部令牌已吊销。'));
}

export function deleteApp(ctx) {
  const app = clients.byId(ctx.params.id);
  if (!app) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('应用不存在。'));
  if (ctx.body?._csrf !== CSRF(ctx)) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('页面已过期,请重试。'));
  clients.remove(app.client_id);
  redirect(ctx.res, '/admin/apps?msg=' + encodeURIComponent(`应用 ${app.name} 已删除。`));
}
