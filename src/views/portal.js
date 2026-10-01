import { escapeHtml as esc } from '../core/util.js';
import { authPage } from './layout.js';
import { banner, SCOPE_NAMES } from './components.js';

/** 应用门户:普通用户可见的业务线磁贴(按权限组过滤) */
export function portalPage({ theme, siteName, user, list, msg, err, csrf }) {
  const tiles = list.map((app) => {
    const initial = (String(app.name || '?').trim()[0] || '?').toUpperCase();
    return `<div class="portal-tile">
      <div style="display:flex;align-items:center;gap:var(--s3)">
        <div class="app-badge">${esc(initial)}</div>
        <div style="min-width:0">
          <div class="name">${esc(app.name)}</div>
          <div class="muted small">${app.token_auth === 'none' ? '公开客户端' : '机密客户端'}</div>
        </div>
      </div>
      <div class="scope-badges">
        ${app.scopeList.map((s) => `<span class="badge">${esc(SCOPE_NAMES[s] || s)}</span>`).join(' ')}
      </div>
      <a class="btn btn-primary" href="/apps/launch/${esc(app.client_id)}">进入应用</a>
    </div>`;
  }).join('\n');
  return authPage({
    theme, siteName, wide: true, title: `应用门户 · ${siteName}`,
    content: `
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <h3 style="margin-top:0">应用门户</h3>
      <p class="muted small" style="margin-top:0">
        ${esc(user.name || user.username)},以下是根据你的权限组可见的应用。
        点击「进入应用」将使用当前账号发起统一登录;受限应用仅对所属组成员开放。
      </p>
      ${list.length
        ? `<div class="portal-grid">${tiles}</div>`
        : '<div class="card tight"><p class="muted" style="margin:0">暂无可见的应用。请联系管理员将你加入相应的权限组。</p></div>'}
      <div class="actions">
        <a class="btn" href="/account">账号设置</a>
        <a class="btn" href="/account/apps">我的授权</a>
        <a class="btn" href="/logout">退出登录</a>
      </div>`,
  });
}
