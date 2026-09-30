import { escapeHtml as esc, fmtTime } from '../core/util.js';
import { adminPage, pageTitle } from './layout.js';
import { banner, badge, hiddenInputs, kvRow, scopeList, scopeItems, statCard } from './components.js';
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
      <td class="wrap"><b style="color:var(--text)">${esc(g.name)}</b></td>
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

/* ---------------- 控制台首页 ---------------- */
export function dashboardPage({ theme, siteName, user, cur, stats, issuer, allowRegister, csrf, msg, err }) {
  return adminPage({
    theme, siteName, user, cur, active: 'dashboard', title: `控制台 · ${siteName}`,
    content: `
      ${pageTitle('控制台')}
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <div class="stats">
        ${statCard(stats.users, '用户')}
        ${statCard(stats.clients, '应用')}
        ${statCard(stats.activeTokens, '有效访问令牌')}
        ${statCard(stats.sessions, '在线会话')}
      </div>
      <div class="card">
        <h3 style="margin-top:0">服务信息</h3>
        ${kvRow('Issuer', esc(issuer))}
        ${kvRow('发现文档', `<a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a>`)}
        ${kvRow('JWKS', `<a href="/jwks.json">/jwks.json</a>`)}
        <p class="muted small">接入方只需发现文档地址即可自动完成 OIDC 配置。</p>
      </div>
      <div class="card">
        <h3 style="margin-top:0">自助注册</h3>
        <p class="small" style="margin:var(--s2) 0">当前状态:${allowRegister ? badge('开启') : badge('关闭', '')}</p>
        <p class="muted small">开启后,登录页会出现「注册新账号」入口,任何人都可以自助创建账号并直接登录;自助注册的账号永远不是管理员。</p>
        <form method="post" action="/admin/register-toggle">
          ${hiddenInputs({ _csrf: csrf })}
          <button class="btn ${allowRegister ? 'btn-danger' : 'btn-primary'}" type="submit">
            ${allowRegister ? '关闭自助注册' : '开启自助注册'}
          </button>
        </form>
      </div>
      <div class="card">
        <h3 style="margin-top:0">快速开始</h3>
        <p class="small" style="margin-top:0">1. 在「应用」创建客户端,获取 client_id 与 client_secret;</p>
        <p class="small">2. 业务系统跳转到 <code>/authorize</code> 发起授权码 + PKCE 流程;</p>
        <p class="small">3. 回调换取 access_token,携带 Bearer 访问 <code>/userinfo</code>。</p>
        <div class="actions">
          <a class="btn btn-primary" href="/admin/apps/new">新建应用</a>
          <a class="btn" href="/admin/users/new">新建用户</a>
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

export function userFormPage({ theme, siteName, user, cur, target, values, allGroups = [], err, isNew }) {
  const v = values;
  return adminPage({
    theme, siteName, user, cur, active: 'users', title: `${isNew ? '新建用户' : '编辑用户'} · ${siteName}`,
    content: `
      ${pageTitle(isNew ? '新建用户' : `编辑:${v.username}`)}
      ${banner(err ? esc(err) : '', 'err')}
      <div class="card">
        <form method="post" action="${isNew ? '/admin/users/create' : `/admin/users/${target}/update`}">
          ${hiddenInputs(isNew ? {} : { _csrf: v._csrf })}
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

export function appFormPage({ theme, siteName, user, cur, err, values, allGroups = [] }) {
  const v = values;
  const urisText = Array.isArray(v.redirect_uris) ? v.redirect_uris.join('\n') : v.redirect_uris;
  return adminPage({
    theme, siteName, user, cur, active: 'apps', title: `新建应用 · ${siteName}`,
    content: `
      ${pageTitle('新建应用')}
      ${banner(err ? esc(err) : '', 'err')}
      <div class="card">
        <form method="post" action="/admin/apps/create">
          <label>应用名称</label>
          <input type="text" name="name" value="${esc(v.name)}" required maxlength="40" placeholder="例如:运维门户">
          <label>客户端类型</label>
          <select name="client_type">
            <option value="confidential"${v.client_type !== 'public' ? ' selected' : ''}>机密客户端(有 client_secret,服务端应用)</option>
            <option value="public"${v.client_type === 'public' ? ' selected' : ''}>公开客户端(无密钥,SPA/移动端,必须 PKCE)</option>
          </select>
          <label>重定向地址(每行一个,必须完全匹配)</label>
          <textarea name="redirect_uris" required placeholder="https://app.example.com/callback">${esc(urisText)}</textarea>
          <label>允许的 scope</label>
          ${scopeList(scopeItemsFor(null, v.scopeSet), { mode: 'checkbox' })}
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

export function appDetailPage({ theme, siteName, user, cur, app, allGroups = [], err, msg, issuer }) {
  const a = app;
  const uris = a.uriList;
  const allowed = a.allowedGroupList || [];
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
        <h3>端点</h3>
        ${kvRow('授权端点', esc(issuer + '/authorize'))}
        ${kvRow('令牌端点', esc(issuer + '/token'))}
        ${kvRow('用户信息', esc(issuer + '/userinfo'))}
        ${kvRow('吊销端点', esc(issuer + '/revoke'))}
      </div>
      <div class="card">
        <h3 style="margin-top:0">应用设置</h3>
        <form method="post" action="/admin/apps/${esc(a.client_id)}/update">
          ${hiddenInputs({ _csrf: a._csrf })}
          <label>应用名称</label>
          <input type="text" name="name" value="${esc(a.name)}" required maxlength="40">
          <label>重定向地址(每行一个)</label>
          <textarea name="redirect_uris" required>${esc(uris.join('\n'))}</textarea>
          <label>允许的 scope</label>
          ${scopeList(scopeItemsFor(null, new Set(a.scopeList)), { mode: 'checkbox' })}
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
