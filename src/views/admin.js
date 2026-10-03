import { escapeHtml as esc, fmtTime } from '../core/util.js';
import { t, fmt, normalizeLang, currentLang } from '../core/i18n.js';
import { adminPage, pageTitle } from './layout.js';
import { banner, badge, hiddenInputs, kvRow, scopeList, scopeItems, statCard, SCOPE_NAMES } from './components.js';
import { SCOPES, DEFAULT_CLIENT_SCOPES } from '../core/config.js';

const scopeItemsFor = (selectedStr, checkedSet) =>
  Object.entries(SCOPES).map(([id, desc]) => ({
    id, desc, checked: checkedSet ? checkedSet.has(id) : (selectedStr || DEFAULT_CLIENT_SCOPES).split(/\s+/).includes(id),
  }));

/** 组复选框列表:用户组成员编辑与应用访问限制共用 */
const groupCheckboxList = (allGroups, checkedSet, name) => {
  if (!allGroups.length) {
    return '<p class="muted small" style="margin:var(--s1) 0">还没有权限组,可先在「权限组」页创建。</p>';
  }
  return allGroups.map((g) => `
    <label class="checkline"><input type="checkbox" name="${esc(name)}" value="${esc(g.name)}"${checkedSet && checkedSet.has(g.name) ? ' checked' : ''}>
      <span>${esc(g.name)}${g.description ? `<span class="muted">${esc(g.description)}</span>` : ''}</span></label>`).join('\n');
};

/* ---------------- 权限组管理 ---------------- */
export function groupsPage({ theme, siteName, user, cur, list, csrf, msg, err }) {
  const rows = list.map((g) => `<tr>
      <td class="wrap"><a href="/admin/groups/${esc(g.id)}"><b style="color:var(--text)">${esc(g.name)}</b></a></td>
      <td class="wrap">${esc(g.description || '-')}</td>
      <td class="muted">${g.member_count}</td>
      <td class="rowline">
        <form method="post" action="/admin/groups/${esc(g.id)}/delete" style="margin:0">
          ${hiddenInputs({ _csrf: csrf })}
          <button class="btn btn-sm btn-danger" type="submit">删除</button>
        </form>
      </td>
    </tr>`).join('\n');
  return adminPage({
    theme, siteName, user, cur, active: 'groups', title: `权限组 · ${siteName}`,
    content: `
      ${pageTitle('权限组')}
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <div class="card">
        <h3 style="margin-top:0">新建权限组</h3>
        <form method="post" action="/admin/groups/create">
          ${hiddenInputs({ _csrf: csrf })}
          <div class="grid2">
            <div><label>组名(必填且唯一,不含空格)</label>
              <input type="text" name="name" required maxlength="40" placeholder="例如:dev"></div>
            <div><label>描述(可选)</label>
              <input type="text" name="description" maxlength="120" placeholder="用途说明"></div>
          </div>
          <div class="actions"><button class="btn btn-primary" type="submit">创建组</button></div>
        </form>
      </div>
      <div class="tblwrap"><table class="tbl">
        <thead><tr><th>组名</th><th>描述</th><th>成员数</th><th>操作</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="4" class="muted">还没有权限组。</td></tr>'}</tbody>
      </table></div>
      <p class="muted small">用户的组成员关系在用户编辑页勾选维护;删除组会一并解除其成员关系,引用该组的应用访问限制需另行调整。</p>`,
  });
}

/* ---------------- 权限组详情:成员管理 + 组维度应用授权 ---------------- */
export function groupDetailPage({ theme, siteName, user, cur, group, members = [], candidates = [], apps = [], csrf, msg, err }) {
  const g = group;
  const base = `/admin/groups/${esc(g.id)}`;
  const memberRows = members.map((m) => `<tr>
      <td class="wrap"><b style="color:var(--text)">${esc(m.username)}</b> ${m.is_admin ? badge('管理员') : ''}${m.disabled ? badge('已禁用', '') : ''}</td>
      <td>${esc(m.name || '-')}</td>
      <td class="rowline">
        <form method="post" action="${base}/members/remove" style="margin:0">
          ${hiddenInputs({ _csrf: csrf, user_id: m.id })}
          <button class="btn btn-sm btn-danger" type="submit">移除</button>
        </form>
      </td>
    </tr>`).join('\n');
  const candidateItems = candidates.map((c) => `
      <label class="checkline"><input type="checkbox" name="users" value="${esc(c.id)}">
        <span>${esc(c.username)}${c.name ? `<span class="muted">${esc(c.name)}</span>` : ''}</span></label>`).join('\n');
  const appRows = apps.map((a) => {
    const stateBadge = a.state === 'open'
      ? badge('不受限(所有用户可访问)')
      : a.state === 'granted'
        ? badge('已授权')
        : '<span class="badge" style="color:var(--danger);background:color-mix(in srgb,var(--danger) 12%,transparent)">未授权</span>';
    const action = a.state === 'open' ? '<span class="muted">-</span>' : `
        <form method="post" action="${base}/apps" style="margin:0">
          ${hiddenInputs({ _csrf: csrf, client_id: a.client_id, action: a.state === 'granted' ? 'revoke' : 'grant' })}
          <button class="btn btn-sm ${a.state === 'granted' ? 'btn-danger' : 'btn-primary'}" type="submit">${a.state === 'granted' ? '移除授权' : '授权本组'}</button>
        </form>`;
    return `<tr>
      <td class="wrap"><b style="color:var(--text)">${esc(a.name)}</b><br><code>${esc(a.client_id)}</code></td>
      <td>${stateBadge}</td>
      <td class="rowline">${action}</td>
    </tr>`;
  }).join('\n');
  return adminPage({
    theme, siteName, user, cur, active: 'groups', title: `${g.name} · ${siteName}`,
    headTitle: `<h3>${esc(g.name)}</h3>
    <p class="muted small">${esc(g.description || '暂无描述')} · ${members.length} 名成员</p>`,
    actions: `<a class="btn" href="/admin/groups">返回权限组列表</a>`,
    content: `
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <div class="card">
        <h3 style="margin-top:0">成员(${members.length})</h3>
        <div class="tblwrap"><table class="tbl">
          <thead><tr><th>用户名</th><th>姓名</th><th>操作</th></tr></thead>
          <tbody>${memberRows || '<tr><td colspan="3" class="muted">该组还没有成员。</td></tr>'}</tbody>
        </table></div>
        <h3>添加成员</h3>
        ${candidates.length ? `
        <p class="muted small" style="margin:0 0 var(--s2)">勾选要加入本组的用户,可多选;已加入的用户不会重复列出。</p>
        <form method="post" action="${base}/members">
          ${hiddenInputs({ _csrf: csrf })}
          ${candidateItems}
          <div class="actions"><button class="btn btn-primary" type="submit">添加成员</button></div>
        </form>` : '<p class="muted" style="margin:var(--s2) 0 0">所有用户均已加入该组。</p>'}
      </div>
      <div class="card">
        <h3 style="margin-top:0">可访问的应用</h3>
        <div class="tblwrap"><table class="tbl">
          <thead><tr><th>应用</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>${appRows || '<tr><td colspan="3" class="muted">还没有应用,先在「应用」页创建。</td></tr>'}</tbody>
        </table></div>
        <p class="muted small">「不受限」应用对所有用户开放,需先在应用侧配置可访问的权限组后,才能在此授权;「移除授权」后若应用不再引用任何组,将回到不受限状态。</p>
      </div>
      <div class="card">
        <h3 style="margin-top:0">编辑组信息</h3>
        <form method="post" action="${base}/update">
          ${hiddenInputs({ _csrf: csrf })}
          <div class="grid2">
            <div><label>组名(必填且唯一,不含空格)</label>
              <input type="text" name="name" value="${esc(g.name)}" required maxlength="40"></div>
            <div><label>描述(可选)</label>
              <input type="text" name="description" value="${esc(g.description || '')}" maxlength="120" placeholder="用途说明"></div>
          </div>
          <div class="actions"><button class="btn btn-primary" type="submit">保存修改</button></div>
        </form>
        <p class="muted small">重命名会同步更新引用该组的应用访问限制;删除组请回到权限组列表操作。</p>
      </div>`,
  });
}

/* ---------------- 控制台首页(仅页头/统计/卡片标题/按钮接入 i18n,深度表单保持中文) ---------------- */
export function dashboardPage({ theme, siteName, user, cur, stats, issuer, allowRegister, csrf, msg, err, msOAuth = {}, lang }) {
  const L = normalizeLang(lang || currentLang());
  const ms = { enabled: false, clientId: '', clientSecret: '', tenant: 'common', redirectUri: '', ...msOAuth };
  return adminPage({
    theme, siteName, user, cur, active: 'dashboard', lang: L, title: `${t(L, 'nav.dashboard')} · ${siteName}`,
    content: `
      ${pageTitle(t(L, 'nav.dashboard'))}
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <div class="stats">
        ${statCard(stats.users, t(L, 'dash.statUsers'))}
        ${statCard(stats.clients, t(L, 'dash.statApps'))}
        ${statCard(stats.activeTokens, t(L, 'dash.statTokens'))}
        ${statCard(stats.sessions, t(L, 'dash.statSessions'))}
      </div>
      <div class="card">
        <h3 style="margin-top:0">${esc(t(L, 'dash.serviceInfo'))}</h3>
        ${kvRow('Issuer', esc(issuer))}
        ${kvRow('发现文档', `<a href="${esc(issuer + '/.well-known/openid-configuration')}">${esc(issuer + '/.well-known/openid-configuration')}</a>`)}
        ${kvRow('JWKS', `<a href="${esc(issuer + '/jwks.json')}">${esc(issuer + '/jwks.json')}</a>`)}
        ${kvRow('心跳接口', `<a href="${esc(issuer + '/api/heartbeat')}">${esc(issuer + '/api/heartbeat')}</a>`)}
        <p class="muted small">接入方只需发现文档地址即可自动完成 OIDC 配置。</p>
      </div>
      <div class="card">
        <h3 style="margin-top:0">${esc(t(L, 'dash.selfRegister'))}</h3>
        <p class="small" style="margin:var(--s2) 0">${esc(t(L, 'dash.currentStatus'))}${allowRegister ? badge(t(L, 'dash.on')) : badge(t(L, 'dash.off'), '')}</p>
        <p class="muted small">开启后,登录页会出现「注册新账号」入口,任何人都可以自助创建账号并直接登录;自助注册的账号永远不是管理员。</p>
        <form method="post" action="/admin/register-toggle">
          ${hiddenInputs({ _csrf: csrf })}
          <button class="btn ${allowRegister ? 'btn-danger' : 'btn-primary'}" type="submit">
            ${esc(t(L, allowRegister ? 'dash.disableRegister' : 'dash.enableRegister'))}
          </button>
        </form>
      </div>
      <div class="card">
        <h3 style="margin-top:0">${esc(t(L, 'dash.msLogin'))}</h3>
        <p class="small" style="margin:var(--s2) 0">${esc(t(L, 'dash.currentStatus'))}${ms.enabled ? badge(t(L, 'dash.enabled')) : badge(t(L, 'dash.disabled'), '')}</p>
        <p class="muted small">启用后,登录页出现「使用 Microsoft 账号登录」按钮;未绑定的 Microsoft 身份可在首次登录时关联已有本地账号或注册新号。</p>
        <form method="post" action="/admin/ms-oauth">
          ${hiddenInputs({ _csrf: csrf })}
          <label class="checkline"><input type="checkbox" name="ms_enabled" value="1"${ms.enabled ? ' checked' : ''}>
            <span>启用 Microsoft 账号登录<span class="muted">需先在 Microsoft Entra 管理中心注册应用,并把下方回调地址填入其「重定向 URI」</span></span></label>
          <div class="grid2">
            <div><label>Client ID</label>
              <input type="text" name="ms_client_id" value="${esc(ms.clientId)}" placeholder="Microsoft 应用的应用程序(客户端)ID"></div>
            <div><label>Tenant(common / 组织 ID / consumers)</label>
              <input type="text" name="ms_tenant" value="${esc(ms.tenant)}" placeholder="common"></div>
          </div>
          <label>Client Secret${ms.clientSecret ? '(已配置,留空保留)' : ''}</label>
          <input type="password" name="ms_client_secret" value="" autocomplete="new-password"
            placeholder="${ms.clientSecret ? '留空则保留已保存的密钥' : 'Microsoft 应用的客户端密钥'}">
          ${kvRow('回调地址', ms.redirectUri ? esc(ms.redirectUri) : '-')}
          <div class="actions"><button class="btn btn-primary" type="submit">保存 Microsoft 登录设置</button></div>
        </form>
      </div>
      <div class="card">
        <h3 style="margin-top:0">${esc(t(L, 'dash.wizard'))}</h3>
        <p class="muted small">重新运行初始化向导:会重走环境检测与站点设置(Issuer、令牌有效期、自助注册、SMTP 邮件),不会影响已有的用户与应用数据;期间全站暂时指向向导页,完成后恢复。</p>
        <form method="post" action="/admin/rerun-wizard">
          ${hiddenInputs({ _csrf: csrf })}
          <button class="btn" type="submit">${esc(t(L, 'dash.rerunWizard'))}</button>
        </form>
      </div>
      <div class="card">
        <h3 style="margin-top:0">${esc(t(L, 'dash.quickStart'))}</h3>
        <p class="small" style="margin-top:0">1. 在「应用」创建客户端,获取 client_id 与 client_secret;</p>
        <p class="small">2. 业务系统跳转到 <code>/authorize</code> 发起授权码 + PKCE 流程;</p>
        <p class="small">3. 回调换取 access_token,携带 Bearer 访问 <code>/userinfo</code>。</p>
        <div class="actions">
          <a class="btn btn-primary" href="/admin/apps/new">${esc(t(L, 'dash.newApp'))}</a>
          <a class="btn" href="/admin/users/new">${esc(t(L, 'dash.newUser'))}</a>
        </div>
      </div>`,
  });
}

/* ---------------- 用户管理 ---------------- */
export function usersPage({ theme, siteName, user, cur, list, msg, err }) {
  const rows = list.map((u) => {
    const status = u.disabled ? badge('已禁用', '') : u.is_admin ? badge('管理员') : badge('启用', '');
    const twofa = u.totp_enabled ? badge('两步验证') : '';
    return `<tr>
      <td class="wrap"><b style="color:var(--text)">${esc(u.username)}</b> ${status} ${twofa}</td>
      <td>${esc(u.name || '-')}</td>
      <td>${esc(u.email || '-')}</td>
      <td class="wrap">${esc((u.groupNames || []).join(' ') || '-')}</td>
      <td class="muted">${fmtTime(u.created_at)}</td>
      <td class="rowline">
        <a class="btn btn-sm" href="/admin/users/${u.id}">编辑</a>
        <form method="post" action="/admin/users/${u.id}/delete" style="margin:0">
          ${hiddenInputs({ _csrf: u._csrf })}
          <button class="btn btn-sm btn-danger" type="submit">删除</button>
        </form>
      </td>
    </tr>`;
  }).join('\n');
  return adminPage({
    theme, siteName, user, cur, active: 'users', title: `用户 · ${siteName}`,
    content: `
      ${pageTitle('用户')}
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <div class="spread" style="margin-bottom:var(--s4)">
        <span class="muted small">共 ${list.length} 个用户</span>
        <a class="btn btn-primary" href="/admin/users/new">新建用户</a>
      </div>
      <div class="tblwrap"><table class="tbl">
        <thead><tr><th>用户名</th><th>姓名</th><th>邮箱</th><th>用户组</th><th>创建时间</th><th>操作</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="muted">还没有用户,先创建一个。</td></tr>'}</tbody>
      </table></div>`,
  });
}

export function userFormPage({ theme, siteName, user, cur, target, values, allGroups = [], err, isNew, csrf = '' }) {
  const v = values;
  return adminPage({
    theme, siteName, user, cur, active: 'users', title: `${isNew ? '新建用户' : '编辑用户'} · ${siteName}`,
    content: `
      ${pageTitle(isNew ? '新建用户' : `编辑:${v.username}`)}
      ${banner(err ? esc(err) : '', 'err')}
      <div class="card">
        <form method="post" action="${isNew ? '/admin/users/create' : `/admin/users/${target}/update`}">
          ${hiddenInputs(isNew ? { _csrf: csrf } : { _csrf: v._csrf })}
          <div class="grid2">
            <div><label>用户名</label>
              <input type="text" name="username" value="${esc(v.username)}" ${isNew ? 'required' : 'disabled'}
                pattern="[a-zA-Z0-9_.@-]{2,64}" title="2-64 位字母数字与 _.@-"></div>
            <div><label>显示姓名</label><input type="text" name="name" value="${esc(v.name)}" maxlength="40"></div>
            <div><label>邮箱</label><input type="email" name="email" value="${esc(v.email)}"></div>
          </div>
          <label>用户组(scope=groups 时通过 claims 返回)</label>
          ${groupCheckboxList(allGroups, v.groupSet, 'groups')}
          <label>${isNew ? '初始密码(至少 8 位)' : '重置密码(留空表示不修改)'}</label>
          <input type="password" name="password" ${isNew ? 'required' : ''} minlength="8" autocomplete="new-password"
            placeholder="${isNew ? '' : '留空则保持原密码'}">
          <label class="checkline"><input type="checkbox" name="is_admin" value="1"${v.is_admin ? ' checked' : ''}>
            <span>管理员<span class="muted">可进入管理控制台并管理所有用户与应用</span></span></label>
          <label class="checkline"><input type="checkbox" name="disabled" value="1"${v.disabled ? ' checked' : ''}>
            <span>禁用账号<span class="muted">禁用后立即无法登录,已有会话一并失效</span></span></label>
          ${v.totp_enabled ? `<label class="checkline"><input type="checkbox" name="totp_reset" value="1">
            <span>重置两步验证<span class="muted">清除该用户的验证器绑定与恢复代码,用于用户丢失手机时</span></span></label>` : ''}
          <div class="actions">
            <button class="btn btn-primary" type="submit">保存</button>
            <a class="btn" href="/admin/users">返回列表</a>
          </div>
        </form>
      </div>`,
  });
}

/* ---------------- 应用(客户端)管理 ---------------- */
export function appsPage({ theme, siteName, user, cur, list, msg, err, issuer }) {
  const rows = list.map((a) => {
    const uris = JSON.parse(a.redirect_uris || '[]');
    return `<tr>
      <td class="wrap"><b style="color:var(--text)">${esc(a.name)}</b><br>
        <code>${esc(a.client_id)}</code></td>
      <td>${a.token_auth === 'none' ? badge('公开客户端') : badge('机密客户端')}</td>
      <td>${a.pkce_required ? badge('强制 PKCE') : ''}</td>
      <td class="wrap muted">${esc(uris[0] || '-')}${uris.length > 1 ? ` 等 ${uris.length} 个` : ''}</td>
      <td class="rowline">
        <a class="btn btn-sm" href="/admin/apps/${a.client_id}">详情</a>
        <form method="post" action="/admin/apps/${a.client_id}/delete" style="margin:0">
          ${hiddenInputs({ _csrf: a._csrf })}
          <button class="btn btn-sm btn-danger" type="submit">删除</button>
        </form>
      </td>
    </tr>`;
  }).join('\n');
  return adminPage({
    theme, siteName, user, cur, active: 'apps', title: `应用 · ${siteName}`,
    content: `
      ${pageTitle('应用')}
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <div class="spread" style="margin-bottom:var(--s4)">
        <span class="muted small">共 ${list.length} 个应用 · 接入发现文档:${esc(issuer + '/.well-known/openid-configuration')}</span>
        <a class="btn btn-primary" href="/admin/apps/new">新建应用</a>
      </div>
      <div class="tblwrap"><table class="tbl">
        <thead><tr><th>应用</th><th>类型</th><th>PKCE</th><th>重定向地址</th><th>操作</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5" class="muted">还没有应用。</td></tr>'}</tbody>
      </table></div>`,
  });
}

export function appFormPage({ theme, siteName, user, cur, err, values, allGroups = [], csrf = '' }) {
  const v = values;
  const urisText = Array.isArray(v.redirect_uris) ? v.redirect_uris.join('\n') : v.redirect_uris;
  return adminPage({
    theme, siteName, user, cur, active: 'apps', title: `新建应用 · ${siteName}`,
    content: `
      ${pageTitle('新建应用')}
      ${banner(err ? esc(err) : '', 'err')}
      <div class="card">
        <form method="post" action="/admin/apps/create">
          ${hiddenInputs({ _csrf: csrf })}
          <label>应用名称</label>
          <input type="text" name="name" value="${esc(v.name)}" required maxlength="40" placeholder="例如:运维门户">
          <label>客户端类型</label>
          <select name="client_type">
            <option value="confidential"${v.client_type !== 'public' ? ' selected' : ''}>机密客户端(有 client_secret,服务端应用)</option>
            <option value="public"${v.client_type === 'public' ? ' selected' : ''}>公开客户端(无密钥,SPA/移动端,必须 PKCE)</option>
          </select>
          <label>重定向地址(每行一个,必须完全匹配)</label>
          <textarea name="redirect_uris" required placeholder="https://app.example.com/callback">${esc(urisText)}</textarea>
          <label>应用描述(可选,展示在门户与授权页)</label>
          <input type="text" name="description" value="${esc(v.description || '')}" maxlength="200" placeholder="一句话介绍这个应用">
          <label>Logo 图片地址(可选,https:// 开头,留空用首字母徽标)</label>
          <input type="text" name="logo_url" value="${esc(v.logo_url || '')}" maxlength="500"
            placeholder="https://example.com/logo.png" spellcheck="false">
          <label>健康检查地址(可选,http(s)://,用于门户状态点与注册表 API)</label>
          <input type="text" name="health_url" value="${esc(v.health_url || '')}" maxlength="500"
            placeholder="https://app.example.com/healthz" spellcheck="false">
          <label>允许的 scope</label>
          ${scopeList(scopeItemsFor(null, v.scopeSet))}
          <label>可访问的权限组</label>
          <p class="muted small" style="margin:0 0 var(--s1)">不勾选 = 不限制,所有用户都可访问;勾选后仅所属组被勾选的用户能发起授权。</p>
          ${groupCheckboxList(allGroups, v.allowedGroupSet, 'allowed_groups')}
          <label class="checkline"><input type="checkbox" name="pkce_required" value="1"${v.pkce_required ? ' checked' : ''}>
            <span>强制 PKCE<span class="muted">公开客户端会自动强制</span></span></label>
          <label class="checkline"><input type="checkbox" name="require_consent" value="1"${v.require_consent ? ' checked' : ''}>
            <span>每次访问都询问用户确认<span class="muted">关闭后用户首次确认过的 scope 不再询问</span></span></label>
          <div class="actions">
            <button class="btn btn-primary" type="submit">创建应用</button>
            <a class="btn" href="/admin/apps">返回列表</a>
          </div>
        </form>
      </div>`,
  });
}

export function appDetailPage({ theme, siteName, user, cur, app, allGroups = [], consentedUsers = [], err, msg, issuer }) {
  const a = app;
  const uris = a.uriList;
  const allowed = a.allowedGroupList || [];
  // 健康探测状态:未配置地址 / 尚未探测 / 在线 / 离线
  const h = a.health;
  const healthText = !a.healthUrl
    ? '<span class="status-dot unknown"></span><span class="muted">未配置健康检查地址,不参与探测</span>'
    : !h
      ? '<span class="status-dot unknown"></span><span class="muted">尚未探测,将自动进行</span>'
      : h.status === 'up'
        ? `<span class="status-dot up"></span>在线(${esc(String(h.latencyMs))}ms)<span class="muted small">· 上次探测 ${esc(new Date(h.checkedAt).toLocaleString('zh-CN', { hour12: false }))}</span>`
        : h.status === 'down'
          ? `<span class="status-dot down"></span>离线${h.code ? `(HTTP ${esc(String(h.code))})` : '(无响应)'}<span class="muted small">· 上次探测 ${esc(new Date(h.checkedAt).toLocaleString('zh-CN', { hour12: false }))}</span>`
          : '<span class="status-dot unknown"></span><span class="muted">未知</span>';
  const consentRows = consentedUsers.map((row) => `<tr>
      <td class="wrap"><b style="color:var(--text)">${esc(row.username)}</b></td>
      <td class="wrap">${esc(row.name || '-')}</td>
      <td class="wrap">${row.scopeList.map((s) => badge(SCOPE_NAMES[s] || s)).join(' ')}</td>
      <td class="muted">${fmtTime(row.granted_at)}</td>
      <td class="rowline">
        <form method="post" action="/admin/apps/${esc(a.client_id)}/revoke-user" style="margin:0">
          ${hiddenInputs({ _csrf: a._csrf, user_id: row.user_id })}
          <button class="btn btn-sm btn-danger" type="submit">撤销授权</button>
        </form>
      </td>
    </tr>`).join('\n');
  return adminPage({
    theme, siteName, user, cur, active: 'apps', title: `${a.name} · ${siteName}`,
    content: `
      ${pageTitle(a.name, a.token_auth === 'none' ? '公开客户端' : '机密客户端')}
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <div class="card">
        <h3 style="margin-top:0">接入信息</h3>
        ${kvRow('client_id', esc(a.client_id))}
        ${a.token_auth === 'none' ? '' : kvRow('client_secret', '<span class="muted">已加密存储,仅创建/重置时展示一次</span>')}
        ${kvRow('发现文档', esc(issuer + '/.well-known/openid-configuration'))}
        ${kvRow('访问限制', allowed.length ? allowed.map(esc).join('、') : '<span class="muted">不限制(所有用户可访问)</span>')}
        ${kvRow('应用描述', a.description ? esc(a.description) : '<span class="muted">未设置</span>')}
        ${kvRow('Logo 地址', a.logoUrl ? esc(a.logoUrl) : '<span class="muted">未设置(门户与授权页用首字母徽标)</span>')}
        ${kvRow('健康检查地址', a.healthUrl ? esc(a.healthUrl) : '<span class="muted">未设置(可在下方应用设置中填写)</span>')}
        ${kvRow('健康状态', healthText)}
        <h3>端点</h3>
        ${kvRow('授权端点', esc(issuer + '/authorize'))}
        ${kvRow('令牌端点', esc(issuer + '/token'))}
        ${kvRow('用户信息', esc(issuer + '/userinfo'))}
        ${kvRow('吊销端点', esc(issuer + '/revoke'))}
      </div>
      <div class="card">
        <h3 style="margin-top:0">应用 Logo</h3>
        <div style="display:flex;align-items:center;gap:var(--s3);margin:0 0 var(--s3)">
          ${a.logoUrl
            ? `<img src="${esc(a.logoUrl)}" alt="应用 Logo 预览" style="width:48px;height:48px;object-fit:contain;border-radius:var(--radius);background:var(--surface-soft);box-shadow:inset 0 0 0 1px var(--border)">`
            : '<span class="muted">当前未设置 Logo,门户与授权页展示首字母徽标。</span>'}
          <span class="muted small" style="word-break:break-all">${a.logoUrl ? `当前:${esc(a.logoUrl)}` : '上传图片或填写外链地址均可。'}</span>
        </div>
        <form method="post" action="/admin/apps/${esc(a.client_id)}/logo" enctype="multipart/form-data">
          ${hiddenInputs({ _csrf: a._csrf })}
          <label>上传 Logo 图片</label>
          <input type="file" name="logo" accept="image/*">
          <p class="muted small" style="margin:var(--s1) 0">仅支持 PNG / JPEG / WebP / GIF,单文件不超过 2MB(按文件内容校验,与扩展名无关);上传成功后覆盖原有 Logo。</p>
          <div class="actions"><button class="btn btn-primary" type="submit">上传 Logo</button></div>
        </form>
        ${a.logoUrl ? `
        <form method="post" action="/admin/apps/${esc(a.client_id)}/logo/delete" style="margin-top:var(--s3)">
          ${hiddenInputs({ _csrf: a._csrf })}
          <button class="btn btn-danger" type="submit">删除 Logo</button>
        </form>` : ''}
        <p class="muted small" style="margin:var(--s3) 0 0">也可以在下方「应用设置」中填写 Logo 图片外链地址;外链与上传二选一,后保存者生效。</p>
      </div>
      <div class="card">
        <h3 style="margin-top:0">应用设置</h3>
        <form method="post" action="/admin/apps/${esc(a.client_id)}/update">
          ${hiddenInputs({ _csrf: a._csrf })}
          <label>应用名称</label>
          <input type="text" name="name" value="${esc(a.name)}" required maxlength="40">
          <label>重定向地址(每行一个)</label>
          <textarea name="redirect_uris" required>${esc(uris.join('\n'))}</textarea>
          <label>应用描述(可选,展示在门户与授权页)</label>
          <input type="text" name="description" value="${esc(a.description || '')}" maxlength="200" placeholder="一句话介绍这个应用">
          <label>Logo 图片地址(可选,https:// 开头,留空用首字母徽标)</label>
          <input type="text" name="logo_url" value="${esc(a.logoUrl || '')}" maxlength="500"
            placeholder="https://example.com/logo.png" spellcheck="false">
          <label>健康检查地址(可选,http(s)://,用于门户状态点与注册表 API)</label>
          <input type="text" name="health_url" value="${esc(a.healthUrl || '')}" maxlength="500"
            placeholder="https://app.example.com/healthz" spellcheck="false">
          <label>允许的 scope</label>
          ${scopeList(scopeItemsFor(null, new Set(a.scopeList)))}
          <label>可访问的权限组</label>
          <p class="muted small" style="margin:0 0 var(--s1)">不勾选 = 不限制,所有用户都可访问;勾选后仅所属组被勾选的用户能发起授权。</p>
          ${groupCheckboxList(allGroups, new Set(allowed), 'allowed_groups')}
          <label class="checkline"><input type="checkbox" name="pkce_required" value="1"${a.pkce_required ? ' checked' : ''}>
            <span>强制 PKCE</span></label>
          <label class="checkline"><input type="checkbox" name="require_consent" value="1"${a.require_consent ? ' checked' : ''}>
            <span>每次访问都询问用户确认</span></label>
          <div class="actions"><button class="btn btn-primary" type="submit">保存设置</button></div>
        </form>
      </div>
      <div class="card">
        <h3 style="margin-top:0">已授权用户</h3>
        <p class="muted small" style="margin:0 0 var(--s2)">撤销后,该用户对此应用的记住授权与现有令牌立即失效,下次访问需重新确认。</p>
        ${consentRows
          ? `<div class="spread" style="margin-bottom:var(--s3)">
              <span class="muted small">共 ${consentedUsers.length} 位用户授权</span>
              <a class="btn btn-sm" href="/admin/apps/${esc(a.client_id)}/consents.csv">导出 CSV</a>
            </div>
            <div class="tblwrap"><table class="tbl">
              <thead><tr><th>用户名</th><th>姓名</th><th>授权范围</th><th>授权时间</th><th>操作</th></tr></thead>
              <tbody>${consentRows}</tbody>
            </table></div>`
          : '<p class="muted" style="margin:var(--s1) 0 0">暂无用户授权。</p>'}
      </div>
      <div class="card">
        <h3 style="margin-top:0">模拟启动</h3>
        <p class="muted small">以所选权限组的视角发起一次统一登录,用于验证受限应用的授权链路(当前账号真实身份不变,动作会计入审计)。</p>
        <form method="get" action="/apps/launch/${esc(a.client_id)}">
          <label>模拟权限组</label>
          <select name="sim_group">
            ${allGroups.length
              ? allGroups.map((g) => `<option value="${esc(g.name)}">${esc(g.name)}${g.description ? ` — ${esc(g.description)}` : ''}</option>`).join('\n')
              : '<option value="">(暂无权限组)</option>'}
          </select>
          <div class="actions"><button class="btn btn-primary" type="submit">模拟启动</button></div>
        </form>
      </div>
      <div class="card">
        <h3 style="margin-top:0">危险操作</h3>
        <div class="actions" style="margin-top:var(--s2)">
          ${a.token_auth === 'none' ? '' : `
          <form method="post" action="/admin/apps/${a.client_id}/secret" style="margin:0">
            ${hiddenInputs({ _csrf: a._csrf })}
            <button class="btn btn-danger" type="submit">重置 client_secret</button>
          </form>`}
          <form method="post" action="/admin/apps/${a.client_id}/revoke-tokens" style="margin:0">
            ${hiddenInputs({ _csrf: a._csrf })}
            <button class="btn btn-danger" type="submit">吊销该应用全部令牌</button>
          </form>
          <form method="post" action="/admin/apps/${a.client_id}/delete" style="margin:0">
            ${hiddenInputs({ _csrf: a._csrf })}
            <button class="btn btn-danger" type="submit">删除应用</button>
          </form>
        </div>
        <p class="muted small">重置密钥后旧密钥立即失效;吊销令牌会让所有已登录该应用的会话式访问终止,用户需重新授权。</p>
      </div>`,
  });
}

/** client_secret 仅此一次展示 */
export function secretRevealPage({ theme, siteName, user, cur, app, secret, issuer, isNew }) {
  return adminPage({
    theme, siteName, user, cur, active: 'apps', title: `密钥 · ${app.name}`,
    content: `
      ${pageTitle(isNew ? '应用已创建' : 'client_secret 已重置')}
      <div class="banner warn">client_secret 只在当前页面显示这一次,请立即复制保存。之后可在应用详情中重置。</div>
      <div class="card">
        ${kvRow('应用', esc(app.name))}
        ${kvRow('client_id', esc(app.client_id))}
        ${kvRow('client_secret', `<b style="color:var(--heading)">${esc(secret)}</b>`)}
        ${kvRow('发现文档', esc(issuer + '/.well-known/openid-configuration'))}
        <div class="actions">
          <a class="btn btn-primary" href="/admin/apps/${app.client_id}">前往应用详情</a>
          <a class="btn" href="/admin/apps">返回列表</a>
        </div>
      </div>`,
  });
}

/* ---------------- 审计日志(页头/表头/筛选与按钮/分页接入 i18n) ---------------- */
export function auditPage({ theme, siteName, user, cur, list, allActions = [], filters = {}, total = 0, page = 1, pages = 1, perPage = 50, csrf, msg, err, lang }) {
  const L = normalizeLang(lang || currentLang());
  const selAction = filters.action || '';
  const q = filters.q || '';
  // 链接构造:保留当前 action/q 筛选参数,可覆盖 page(分页/导出共用)
  const buildQs = (over = {}) => {
    const usp = new URLSearchParams();
    if (selAction) usp.set('action', selAction);
    if (q) usp.set('q', q);
    if (over.page) usp.set('page', over.page);
    const qs = usp.toString();
    return qs ? `?${qs}` : '';
  };
  const pageHref = (p) => `/admin/audit${buildQs({ page: p })}`;
  const exportHref = `/admin/audit/export.csv${buildQs()}`;
  const options = allActions.map((a) =>
    `<option value="${esc(a)}"${a === selAction ? ' selected' : ''}>${esc(a)}</option>`).join('\n');
  const filterForm = `
      <form method="get" action="/admin/audit" class="rowline" style="gap:var(--s2)">
        <select name="action" style="width:auto;min-width:160px" aria-label="${esc(t(L, 'audit.filterAction'))}">
          <option value="">${esc(t(L, 'audit.allActions'))}</option>
          ${options}
        </select>
        <input type="text" name="q" value="${esc(q)}" placeholder="${esc(t(L, 'audit.searchPlaceholder'))}" style="width:200px" aria-label="${esc(t(L, 'audit.keyword'))}">
        <button class="btn" type="submit">${esc(t(L, 'audit.filter'))}</button>
        ${selAction || q ? `<a class="btn" href="/admin/audit">${esc(t(L, 'audit.reset'))}</a>` : ''}
      </form>
      <a class="btn" href="${esc(exportHref)}">${esc(t(L, 'audit.export'))}</a>`;
  const clearForm = `
      <form method="post" action="/admin/audit/clear" class="rowline" style="gap:var(--s2)">
        ${hiddenInputs({ _csrf: csrf })}
        <button class="btn btn-danger" type="submit">${esc(t(L, 'audit.clear'))}</button>
        <span class="muted small">${esc(t(L, 'audit.clearHint'))}</span>
      </form>`;
  const rows = list.map((row) => `<tr>
      <td class="muted" style="white-space:nowrap">${fmtTime(row.ts)}</td>
      <td class="wrap"><b style="color:var(--text)">${esc(row.actor)}</b></td>
      <td><span class="badge"><code>${esc(row.action)}</code></span></td>
      <td class="wrap">${esc(row.detail || '-')}</td>
      <td class="muted wrap">${esc(row.ip || '-')}</td>
    </tr>`).join('\n');
  // 分页页脚:上一页/下一页(保留筛选参数),边界用禁用样式占位
  const pagerBtn = (label, target, enabled) => (enabled
    ? `<a class="btn" href="${esc(pageHref(target))}">${esc(label)}</a>`
    : `<span class="btn" style="opacity:.45;cursor:not-allowed" aria-disabled="true">${esc(label)}</span>`);
  const pager = `
      <div class="rowline" style="gap:var(--s2);margin-top:var(--s3)">
        ${pagerBtn(t(L, 'audit.prev'), page - 1, page > 1)}
        <span class="muted small">${esc(fmt(t(L, 'audit.pageInfo'), { page, pages, total }))}</span>
        ${pagerBtn(t(L, 'audit.next'), page + 1, page < pages)}
      </div>`;
  return adminPage({
    theme, siteName, user, cur, active: 'audit', lang: L, title: `${t(L, 'nav.audit')} · ${siteName}`,
    headTitle: `<h3>${esc(t(L, 'nav.audit'))}</h3>
    <p class="muted small">${esc(fmt(t(L, 'audit.headSub'), { total, per: perPage, n: list.length }))}</p>`,
    actions: `${filterForm}${clearForm}`,
    content: `
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <div class="tblwrap"><table class="tbl">
        <thead><tr><th>${esc(t(L, 'audit.thTime'))}</th><th>${esc(t(L, 'audit.thActor'))}</th><th>${esc(t(L, 'audit.thAction'))}</th><th>${esc(t(L, 'audit.thDetail'))}</th><th>IP</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="5" class="muted">${esc(t(L, 'audit.empty'))}</td></tr>`}</tbody>
      </table></div>
      ${pager}
      <p class="muted small">审计日志滚动保留最新 5000 条,不随过期数据清理;清空后历史留痕无法找回。导出 CSV 最多包含最新 5000 条。</p>`,
  });
}
