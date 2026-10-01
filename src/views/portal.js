import { escapeHtml as esc } from '../core/util.js';
import { adminPage } from './layout.js';
import { banner, SCOPE_NAMES } from './components.js';

const typeBadge = (app) => (app.token_auth === 'none' ? '公开客户端' : '机密客户端');

const scopeBadges = (app) =>
  `<span class="scope-badges">${app.scopeList.map((s) => `<span class="badge">${esc(SCOPE_NAMES[s] || s)}</span>`).join(' ')}</span>`;

/** 应用门户:普通用户可见的业务线(按权限组过滤),支持格子/条状两种视图;并入侧栏布局 */
export function portalPage({ theme, siteName, user, list, msg, err, csrf, cur = '/', actions = '', view = 'grid' }) {
  const initial = (name) => (String(name || '?').trim()[0] || '?').toUpperCase();

  const tiles = list.map((app) => `
    <div class="portal-tile">
      <div style="display:flex;align-items:center;gap:var(--s3)">
        <div class="app-badge">${esc(initial(app.name))}</div>
        <div style="min-width:0">
          <div class="name">${esc(app.name)}</div>
          <div class="muted small">${typeBadge(app)}</div>
        </div>
      </div>
      ${scopeBadges(app)}
      <a class="btn btn-primary" href="/apps/launch/${esc(app.client_id)}">进入应用</a>
    </div>`).join('\n');

  const rows = list.map((app) => `
    <div class="app-item">
      <div class="app-badge">${esc(initial(app.name))}</div>
      <div style="min-width:0;flex:1">
        <div class="rowline">
          <b style="color:var(--text);font-size:15px">${esc(app.name)}</b>
          <span class="badge">${typeBadge(app)}</span>
          ${scopeBadges(app)}
        </div>
        <div class="muted small" style="word-break:break-all"><code>${esc(app.client_id)}</code></div>
      </div>
      <a class="btn btn-primary btn-sm" href="/apps/launch/${esc(app.client_id)}">进入应用</a>
    </div>`).join('\n');

  const body = !list.length
    ? '<div class="card tight"><p class="muted" style="margin:0">暂无可见的应用。请联系管理员将你加入相应的权限组。</p></div>'
    : view === 'list'
      ? `<div class="card tight">${rows}</div>`
      : `<div class="portal-grid">${tiles}</div>`;

  // 顶栏:左侧标题块(标题 + 说明 + 数量),右侧视图切换与管理入口 —— 内容区直接是磁贴/列表
  const headTitle = `<h3>应用门户</h3>
    <p class="muted small">${esc(user.name || user.username)},以下是根据你的权限组可见的应用 · 共 ${list.length} 个
    <span class="muted">· 点击「进入应用」发起统一登录,受限应用仅对所属组成员开放</span></p>`;

  return adminPage({
    theme, siteName, user, active: 'portal', cur, actions, headTitle,
    title: `应用门户 · ${siteName}`,
    content: `
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      ${body}`,
  });
}
