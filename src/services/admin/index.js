import fs from 'node:fs';
import path from 'node:path';
import * as users from '../../models/users.js';
import * as clients from '../../models/clients.js';
import * as groups from '../../models/groups.js';
import * as sessions from '../../models/sessions.js';
import * as tokens from '../../models/tokens.js';
import * as consents from '../../models/consents.js';
import * as recovery from '../../models/recovery.js';
import { getRuntime, updateRuntime } from '../../core/runtime.js';
import * as settingsApi from '../../models/settings.js';
import { hashPassword } from '../../core/password.js';
import { randomToken } from '../../core/crypto.js';
import { splitLines, redirectUri as validUri, httpUrl, fmtTime } from '../../core/util.js';
import { SCOPES, DEFAULT_CLIENT_SCOPES } from '../../core/config.js';
import { sendHtml, sendJson, redirect } from '../../core/http.js';
import { logger } from '../../core/logger.js';
import {
  parseMultipart, sniffImageExt, ensureUploadsDir, uploadsDir,
  uploadContentType, UPLOAD_FILE_RE,
} from '../../core/upload.js';
import { dashboardPage, groupsPage, groupDetailPage, usersPage, userFormPage, appsPage, appFormPage, appDetailPage, secretRevealPage } from '../../views/admin.js';
import { errorPage } from '../../views/error.js';
import { record, csvCell } from '../audit.js';
import { isValidMsTenant } from '../auth/microsoft.js';
import * as appHealth from '../app-health.js';

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
  record(ctx, 'admin.register_toggled', next === '1' ? '开启自助注册' : '关闭自助注册');
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
  // 租户 ID 拼进 authority URL 路径:仅允许字母数字与 . _ -(含 UUID/域名形态),非法拒绝并回显
  if (!isValidMsTenant(fields.ms_tenant)) {
    return redirect(ctx.res, '/admin?err=' + encodeURIComponent('Microsoft 租户 ID 不合法,仅允许字母、数字与 . _ -(或 UUID 形态)。'));
  }
  const secret = String(b.ms_client_secret || '');
  if (secret) fields.ms_client_secret = secret; // 留空 = 保留已保存的密钥
  const authority = String(b.ms_authority || '').trim();
  if (authority) fields.ms_authority = authority.replace(/\/+$/, ''); // 默认由向导/测试直接指定,常规表单不展示
  updateRuntime(fields, settingsApi.setSetting);
  record(ctx, 'admin.ms_oauth_saved', fields.ms_enabled === '1' ? '启用 Microsoft 登录' : '停用 Microsoft 登录');
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
  // 大小写不敏感查重:'DEV' 与 'dev' 视为重名
  if (groups.nameTakenCI(name)) return back(`权限组 ${name} 已存在。`);
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

/* ---------------- 权限组详情:成员管理 + 组维度应用授权 ---------------- */

/** GET /admin/groups/:id —— 组详情:成员 + 可访问应用 + 组信息编辑 */
export function showGroupDetail(ctx) {
  const g = groups.byId(ctx.params.id);
  if (!g) return redirect(ctx.res, '/admin/groups?err=' + encodeURIComponent('权限组不存在。'));
  const members = groups.listMembers(g.id);
  const memberIds = new Set(members.map((m) => m.id));
  const candidates = users.list().filter((u) => !memberIds.has(u.id));
  const apps = clients.list().map((c) => {
    const allowed = clients.allowedGroupNames(c);
    return {
      client_id: c.client_id,
      name: c.name,
      // open = 未限制(所有用户可访问);granted/denied = 已限制且含/不含本组
      state: !allowed.length ? 'open' : allowed.includes(g.name) ? 'granted' : 'denied',
    };
  });
  sendHtml(ctx.res, 200, groupDetailPage({
    theme: ctx.theme, siteName: getRuntime().siteName, user: ctx.user,
    cur: ctx.url.pathname + ctx.url.search, group: g, members, candidates, apps, csrf: CSRF(ctx),
    msg: ctx.query.get('msg'), err: ctx.query.get('err'),
  }));
}

/** POST /admin/groups/:id/update —— 组名/描述编辑(重名校验;重命名同步应用引用与镜像文本) */
export function updateGroup(ctx) {
  const b = ctx.body || {};
  const g = groups.byId(ctx.params.id);
  if (!g) return redirect(ctx.res, '/admin/groups?err=' + encodeURIComponent('权限组不存在。'));
  const back = (e) => redirect(ctx.res, `/admin/groups/${g.id}?err=` + encodeURIComponent(e));
  if (b._csrf !== CSRF(ctx)) return back('页面已过期,请重试。');
  const name = String(b.name || '').trim();
  const description = String(b.description || '').trim();
  if (!name || name.length > 40) return back('组名必填且不超过 40 字。');
  if (/\s/.test(name)) return back('组名不能包含空白字符。');
  // 大小写不敏感查重(排除自身):'OPS' 与既有 ops 视为重名;自身改名大小写(Dev→DEV)允许
  if (groups.nameTakenCI(name, g.id)) return back(`权限组 ${name} 已存在。`);
  groups.update(g.id, { name, description });
  if (name !== g.name) {
    // 组名变更:同步引用旧组名的应用访问限制,避免授权悄悄失效
    for (const c of clients.list()) {
      const allowed = clients.allowedGroupNames(c);
      if (allowed.includes(g.name)) {
        clients.update(c.client_id, { allowedGroups: allowed.map((n) => (n === g.name ? name : n)) });
      }
    }
  }
  record(ctx, 'admin.group_updated', name);
  redirect(ctx.res, `/admin/groups/${g.id}?msg=` + encodeURIComponent('权限组信息已更新。'));
}

/** POST /admin/groups/:id/members —— 批量添加成员(users 复选框多选;幂等) */
export function addMembers(ctx) {
  const b = ctx.body || {};
  const g = groups.byId(ctx.params.id);
  if (!g) return redirect(ctx.res, '/admin/groups?err=' + encodeURIComponent('权限组不存在。'));
  const back = (e) => redirect(ctx.res, `/admin/groups/${g.id}?err=` + encodeURIComponent(e));
  if (b._csrf !== CSRF(ctx)) return back('页面已过期,请重试。');
  const raw = Array.isArray(b.users) ? b.users : b.users ? [b.users] : [];
  const added = [];
  for (const id of raw) {
    const u = users.byId(String(id));
    if (u) {
      groups.addMember(g.id, u.id);
      added.push(u.username);
    }
  }
  if (!added.length) return back('请选择要添加的用户。');
  record(ctx, 'admin.group_members_added', `${g.name} + ${added.join(',')}`);
  redirect(ctx.res, `/admin/groups/${g.id}?msg=` + encodeURIComponent(`已添加 ${added.length} 名成员。`));
}

/** POST /admin/groups/:id/members/remove —— 移除单个成员(幂等) */
export function removeMember(ctx) {
  const b = ctx.body || {};
  const g = groups.byId(ctx.params.id);
  if (!g) return redirect(ctx.res, '/admin/groups?err=' + encodeURIComponent('权限组不存在。'));
  const back = (e) => redirect(ctx.res, `/admin/groups/${g.id}?err=` + encodeURIComponent(e));
  if (b._csrf !== CSRF(ctx)) return back('页面已过期,请重试。');
  const u = users.byId(String(b.user_id || ''));
  if (!u) return back('用户不存在。');
  groups.removeMember(g.id, u.id);
  record(ctx, 'admin.group_member_removed', `${g.name} - ${u.username}`);
  redirect(ctx.res, `/admin/groups/${g.id}?msg=` + encodeURIComponent(`已移除成员 ${u.username}。`));
}

/** POST /admin/groups/:id/apps —— 组维度应用授权单端点(action = grant | revoke) */
export function grantGroupApp(ctx) {
  const b = ctx.body || {};
  const g = groups.byId(ctx.params.id);
  if (!g) return redirect(ctx.res, '/admin/groups?err=' + encodeURIComponent('权限组不存在。'));
  const back = (e) => redirect(ctx.res, `/admin/groups/${g.id}?err=` + encodeURIComponent(e));
  if (b._csrf !== CSRF(ctx)) return back('页面已过期,请重试。');
  const app = clients.byId(String(b.client_id || ''));
  if (!app) return back('应用不存在。');
  const allowed = clients.allowedGroupNames(app);
  if (b.action === 'grant') {
    // 不受限应用(空 allowed_groups = 所有用户可访问)无需也无法在此授权
    if (!allowed.length) return back('该应用未限制访问,所有用户均可访问,无需授权。');
    if (!allowed.includes(g.name)) allowed.push(g.name);
    clients.update(app.client_id, { allowedGroups: allowed });
    record(ctx, 'admin.group_app_granted', `${g.name} 授权 ${app.name}`);
    return redirect(ctx.res, `/admin/groups/${g.id}?msg=` + encodeURIComponent(`已授权组 ${g.name} 访问应用 ${app.name}。`));
  }
  if (b.action === 'revoke') {
    if (!allowed.includes(g.name)) return back('该应用尚未授权本组。');
    // 移除后列表为空则保留为空,应用回到不受限状态
    clients.update(app.client_id, { allowedGroups: allowed.filter((n) => n !== g.name) });
    record(ctx, 'admin.group_app_revoked', `${g.name} 取消授权 ${app.name}`);
    return redirect(ctx.res, `/admin/groups/${g.id}?msg=` + encodeURIComponent(`已移除组 ${g.name} 对应用 ${app.name} 的授权。`));
  }
  return back('未知的操作类型。');
}

/* ---------------- 用户管理 ---------------- */
export function listUsers(ctx) {
  const groupMap = groups.membersOfAll(); // 一次查询消除 N+1
  const list = users.list().map((u) => ({ ...u, groupNames: groupMap.get(u.id) || [], _csrf: CSRF(ctx) }));
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
    allGroups: groups.list(), csrf: CSRF(ctx),
    values: { username: '', name: '', email: '', groupSet: new Set(), is_admin: false, disabled: false },
  }));
}

export function createUser(ctx) {
  const b = ctx.body || {};
  // 与 updateUser/deleteUser 一致的会话 CSRF 校验(表单隐藏字段由 userFormPage 下发)
  if (b._csrf !== CSRF(ctx)) {
    return redirect(ctx.res, '/admin/users/new?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
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
  // RFC 5321:邮箱地址路径最长 254 字符
  const email = String(b.email || '').trim();
  if (email.length > 254) {
    return redirect(ctx.res, '/admin/users/new?err=' + encodeURIComponent('邮箱长度不能超过 254 字。'));
  }
  const groupNames = collectGroupNames(b);
  const created = users.create({
    username, passwordHash: hashPassword(b.password),
    name: String(b.name || '').trim(), email,
    userGroups: groupNames.join(' '), isAdmin: b.is_admin === '1',
  });
  if (groupNames.length) groups.setUserGroups(created.id, groupNames);
  record(ctx, 'admin.user_created', created.username);
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
  const email = String(b.email || '').trim();
  if (email.length > 254) {
    return redirect(ctx.res, `/admin/users/${target.id}?err=` + encodeURIComponent('邮箱长度不能超过 254 字。'));
  }
  const groupNames = collectGroupNames(b);
  // user_groups 文本列保留为成员关系的镜像,便于人工排查;claims/授权一律读关系表
  users.update(target.id, {
    name: String(b.name || '').trim(), email,
    userGroups: groupNames.join(' '),
    passwordHash, isAdmin: willAdmin, disabled: willDisabled,
  });
  groups.setUserGroups(target.id, groupNames);
  record(ctx, 'admin.user_updated', target.username);
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
  record(ctx, 'admin.user_deleted', target.username);
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
  const description = String(b.description || '').trim();
  if (description.length > 200) return { error: '应用描述不超过 200 字。' };
  const logoRaw = String(b.logo_url || '').trim();
  let logoUrl = '';
  if (logoRaw) {
    const canonical = httpUrl(logoRaw);
    if (!canonical || !canonical.startsWith('https://')) {
      return { error: 'Logo 图片地址不合法,需以 https:// 开头。' };
    }
    logoUrl = canonical;
  }
  const healthRaw = String(b.health_url || '').trim();
  let healthUrl = '';
  if (healthRaw) {
    const canonical = httpUrl(healthRaw);
    if (!canonical) return { error: '健康检查地址不合法,需为 http(s) 地址。' };
    healthUrl = canonical;
  }
  return { name, uris, scopes, description, logoUrl, healthUrl };
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
    cur: ctx.url.pathname, err, allGroups: groups.list(), csrf: CSRF(ctx),
    values: values || {
      name: '', client_type: 'confidential', redirect_uris: '',
      description: '', logo_url: '',
      scopeSet: new Set(DEFAULT_CLIENT_SCOPES.split(/\s+/)),
      allowedGroupSet: new Set(),
      pkce_required: true, require_consent: true,
    },
  }));
}

export function createApp(ctx) {
  const b = ctx.body || {};
  // 会话 CSRF 校验(表单隐藏字段由 appFormPage 下发),与 update/delete 等写操作保持一致
  if (b._csrf !== CSRF(ctx)) {
    return redirect(ctx.res, '/admin/apps/new?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
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
    secretHash, allowedGroups, description: v.description, logoUrl: v.logoUrl, healthUrl: v.healthUrl,
  });
  appHealth.probeSoon(app); // 填了健康检查地址则立即探测一次(fire-and-forget)
  record(ctx, 'admin.app_created', v.name);
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
  const consentedUsers = consents.listForClient(app.client_id)
    .map((row) => ({ ...row, scopeList: (row.scope || '').split(/\s+/).filter(Boolean) }));
  sendHtml(ctx.res, 200, appDetailPage({
    theme: ctx.theme, siteName: getRuntime().siteName, user: ctx.user,
    cur: ctx.url.pathname, allGroups: groups.list(),
    app: { ...clients.withUris(app), health: appHealth.get(app.client_id), _csrf: CSRF(ctx) },
    consentedUsers,
    issuer: getRuntime().issuer,
    msg: ctx.query.get('msg'), err: ctx.query.get('err'),
  }));
}

/** GET /admin/apps/:id/consents.csv —— 导出应用已授权用户 CSV
 *  UTF-8 BOM 防 Excel 乱码;csvCell 复用审计导出的转义(公式注入中和 + 引号/逗号),无授权时仅表头。 */
export function exportAppConsentsCsv(ctx) {
  const app = clients.byId(ctx.params.id);
  if (!app) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('应用不存在。'));
  const rows = consents.listForClient(app.client_id);
  const lines = ['用户名,姓名,授权范围,授权时间',
    ...rows.map((row) => [row.username, row.name, row.scope, fmtTime(row.granted_at)]
      .map(csvCell).join(','))];
  const d = new Date();
  const p2 = (n) => String(n).padStart(2, '0');
  const stamp = `${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}`
    + `-${p2(d.getHours())}${p2(d.getMinutes())}${p2(d.getSeconds())}`;
  const res = ctx.res;
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="consents-${stamp}.csv"`,
    'Cache-Control': 'no-store',
  });
  res.end('\uFEFF' + lines.join('\n') + '\n');
}

export function updateApp(ctx) {
  const b = ctx.body || {};
  const app = clients.byId(ctx.params.id);
  if (!app) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('应用不存在。'));
  if (b._csrf !== CSRF(ctx)) return redirect(ctx.res, `/admin/apps/${app.client_id}?err=` + encodeURIComponent('页面已过期,请重试。'));
  const v = validateAppInput(b);
  if (v.error) return redirect(ctx.res, `/admin/apps/${app.client_id}?err=` + encodeURIComponent(v.error));
  // Logo 字段被清空且此前用的是本站上传文件时,同步清理磁盘文件,避免孤儿文件残留
  if (!v.logoUrl && String(app.logo_url || '').startsWith('/uploads/')) removeLogoFile(app);
  clients.update(app.client_id, {
    name: v.name, redirectUris: JSON.stringify(v.uris), scopes: v.scopes.join(' '),
    pkceRequired: app.token_auth === 'none' ? true : b.pkce_required === '1',
    requireConsent: b.require_consent === '1',
    allowedGroups: collectAllowedGroups(b),
    description: v.description, logoUrl: v.logoUrl, healthUrl: v.healthUrl,
  });
  appHealth.probeSoon(clients.byId(app.client_id)); // 健康检查地址变更后立即复探
  record(ctx, 'admin.app_updated', v.name);
  redirect(ctx.res, `/admin/apps/${app.client_id}?msg=` + encodeURIComponent('设置已保存。'));
}

/** 撤销单个用户对某应用的授权:删除记住授权并吊销其在该应用下的全部令牌 */
export function revokeAppUserConsent(ctx) {
  const app = clients.byId(ctx.params.id);
  if (!app) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('应用不存在。'));
  if (ctx.body?._csrf !== CSRF(ctx)) return redirect(ctx.res, `/admin/apps/${app.client_id}?err=` + encodeURIComponent('页面已过期,请重试。'));
  const target = users.byId(String(ctx.body?.user_id || ''));
  if (!target) return redirect(ctx.res, `/admin/apps/${app.client_id}?err=` + encodeURIComponent('用户不存在。'));
  if (!consents.get(target.id, app.client_id)) {
    return redirect(ctx.res, `/admin/apps/${app.client_id}?err=` + encodeURIComponent(`用户 ${target.username} 尚未授权该应用。`));
  }
  consents.revoke(target.id, app.client_id);
  tokens.revokeForClientUser(app.client_id, target.id);
  logger.info('管理员撤销用户对应用的授权', { client: app.client_id, user: target.username });
  redirect(ctx.res, `/admin/apps/${app.client_id}?msg=` + encodeURIComponent(`已撤销用户 ${target.username} 对该应用的授权,其现有令牌已一并失效。`));
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
  record(ctx, 'admin.app_secret_rotated', app.name);
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
  record(ctx, 'admin.app_tokens_revoked', app.name);
  redirect(ctx.res, `/admin/apps/${app.client_id}?msg=` + encodeURIComponent('该应用的全部令牌已吊销。'));
}

export function deleteApp(ctx) {
  const app = clients.byId(ctx.params.id);
  if (!app) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('应用不存在。'));
  if (ctx.body?._csrf !== CSRF(ctx)) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('页面已过期,请重试。'));
  removeLogoFile(app); // 应用删除时一并清理其上传的 Logo 文件
  clients.remove(app.client_id);
  record(ctx, 'admin.app_deleted', app.name);
  redirect(ctx.res, '/admin/apps?msg=' + encodeURIComponent(`应用 ${app.name} 已删除。`));
}

/* ---------------- 应用 Logo:直接上传 / 删除 / 静态服务 ---------------- */

/** Logo 单文件大小上限:2MB */
export const MAX_LOGO_SIZE = 2 * 1024 * 1024;

/** 删除应用当前的上传 Logo 文件(仅清理本应用名下的 /uploads/ 文件;外链地址不动) */
function removeLogoFile(app) {
  const url = app?.logo_url || '';
  if (!url.startsWith('/uploads/')) return;
  const name = url.slice('/uploads/'.length);
  // 双重保险:文件名须过严格白名单且确属本应用(clientId 前缀)
  if (!UPLOAD_FILE_RE.test(name) || !name.startsWith(app.client_id + '.')) return;
  try { fs.unlinkSync(path.join(uploadsDir(), name)); } catch { /* 文件不存在视为已清理 */ }
}

/** POST /admin/apps/:id/logo —— multipart 上传应用 Logo(魔数校验,覆盖旧文件,更新 logo_url) */
export async function uploadAppLogo(ctx) {
  const app = clients.byId(ctx.params.id);
  if (!app) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('应用不存在。'));
  const back = (e) => redirect(ctx.res, `/admin/apps/${app.client_id}?err=` + encodeURIComponent(e));
  let fields, files;
  try {
    ({ fields, files } = await parseMultipart(ctx.req, { maxSize: MAX_LOGO_SIZE }));
  } catch (err) {
    if (err?.status === 413) throw err; // 管线统一渲染 413 页
    if (err?.status === 400) return back('上传报文不完整,请重新提交。');
    throw err;
  }
  // multipart 中 CSRF 位于文本字段 _csrf
  if (fields._csrf !== CSRF(ctx)) return back('页面已过期,请重试。');
  const file = files.logo;
  if (!file || !file.data?.length) return back('请选择要上传的图片文件。');
  const ext = sniffImageExt(file.data);
  if (!ext) {
    return sendHtml(ctx.res, 415, errorPage({
      theme: ctx.theme, siteName: getRuntime().siteName,
      title: '不支持的图片格式',
      message: 'Logo 仅支持 PNG / JPEG / WebP / GIF 图片(按文件内容校验),且不超过 2MB。',
    }));
  }
  ensureUploadsDir();
  const name = `${app.client_id}.${ext}`;
  // 原子化落盘:先写同盘临时文件再 rename 覆盖目标,并发读不会看到写了一半的文件
  const target = path.join(uploadsDir(), name);
  const tmp = `${target}.tmp-${randomToken(6)}`;
  try {
    await fs.promises.writeFile(tmp, file.data);
    await fs.promises.rename(tmp, target);
  } finally {
    // rename 成功后临时文件已不存在,失败时清理残渣,不留 .tmp- 文件
    await fs.promises.unlink(tmp).catch(() => {});
  }
  // rename 已原子覆盖同名旧文件;仅扩展名变化(或首次上传)时清理旧文件,避免残留
  if (app.logo_url !== `/uploads/${name}`) removeLogoFile(app);
  clients.update(app.client_id, { logoUrl: `/uploads/${name}` });
  record(ctx, 'admin.app_logo_uploaded', app.name);
  logger.info('管理员上传应用 Logo', { client: app.client_id, file: name, size: file.data.length });
  redirect(ctx.res, `/admin/apps/${app.client_id}?msg=` + encodeURIComponent('应用 Logo 已上传。'));
}

/** POST /admin/apps/:id/logo/delete —— 清理 Logo 文件并把 logo_url 置空 */
export function deleteAppLogo(ctx) {
  const app = clients.byId(ctx.params.id);
  if (!app) return redirect(ctx.res, '/admin/apps?err=' + encodeURIComponent('应用不存在。'));
  if (ctx.body?._csrf !== CSRF(ctx)) return redirect(ctx.res, `/admin/apps/${app.client_id}?err=` + encodeURIComponent('页面已过期,请重试。'));
  removeLogoFile(app);
  clients.update(app.client_id, { logoUrl: '' });
  record(ctx, 'admin.app_logo_deleted', app.name);
  redirect(ctx.res, `/admin/apps/${app.client_id}?msg=` + encodeURIComponent('应用 Logo 已删除,门户与授权页恢复首字母徽标。'));
}

/** GET /uploads/:file —— 上传文件静态服务(匿名;Logo 属公开品牌资产)。文件名严格白名单,防目录穿越 */
export async function serveUpload(ctx) {
  const name = String(ctx.params.file || '');
  const m = name.match(UPLOAD_FILE_RE);
  const notFound = () => sendJson(ctx.res, 404, { error: 'not_found' });
  if (!m) return notFound();
  let data;
  try {
    // 异步读:避免大 Logo 在高并发下阻塞事件循环
    data = await fs.promises.readFile(path.join(uploadsDir(), name));
  } catch {
    return notFound();
  }
  ctx.res.setHeader('Content-Type', uploadContentType(m[2]));
  ctx.res.setHeader('Cache-Control', 'public, max-age=604800');
  ctx.res.setHeader('X-Content-Type-Options', 'nosniff');
  ctx.res.writeHead(200, { 'Content-Length': data.length });
  ctx.res.end(data);
}
