import { escapeHtml as esc } from '../core/util.js';
import { t, fmt, normalizeLang, currentLang } from '../core/i18n.js';
import { adminPage } from './layout.js';
import { banner, SCOPE_NAMES, scopeIcon } from './components.js';

const typeBadge = (app, lang) =>
  (app.token_auth === 'none' ? t(lang, 'portal.typePublic') : t(lang, 'portal.typeConfidential'));

const scopeBadges = (app, lang) =>
  `<span class="scope-badges">${app.scopeList.map((s) => `<span class="badge">${esc(t(lang, `scope.name.${s}`, SCOPE_NAMES[s] || s))}</span>`).join(' ')}</span>`;

/** 应用门户:普通用户可见的业务线(按权限组过滤),支持格子/条状两种视图;并入侧栏布局 */
export function portalPage({ theme, siteName, user, list, msg, err, csrf, cur = '/', actions = '', view = 'grid', lang }) {
  const L = normalizeLang(lang || currentLang());
  const initial = (name) => ([...String(name || '?').trim()][0] || '?').toUpperCase();
  // 健康状态点:在线=绿 / 离线=红 / 未知=灰,title 提示探测详情
  const healthDot = (app) => {
    const h = app.health;
    const status = h?.status || 'unknown';
    const cls = status === 'up' ? 'up' : status === 'down' ? 'down' : 'unknown';
    const tip = status === 'up'
      ? fmt(t(L, 'portal.healthUp'), { ms: h.latencyMs })
      : status === 'down'
        ? fmt(t(L, 'portal.healthDown'), { detail: h.code ? `(HTTP ${h.code})` : t(L, 'portal.noResponse') })
        : t(L, 'portal.healthUnknown');
    return `<span class="status-dot ${cls}" role="img" aria-label="${esc(tip)}" title="${esc(tip)}"></span>`;
  };
  // 有 Logo 用 44px 圆角图片,否则回退首字母徽标
  const appLogo = (app) => app.logoUrl
    ? `<img src="${esc(app.logoUrl)}" alt="" loading="lazy" style="width:44px;height:44px;border-radius:12px;object-fit:cover;flex:none">`
    : `<div class="app-badge">${esc(initial(app.name))}</div>`;
  const descLine = (app) => (app.description
    ? `<p class="app-description" title="${esc(app.description)}">${esc(app.description)}</p>`
    : '');

  const tiles = list.map((app) => `
    <div class="portal-tile">
      <div style="display:flex;align-items:center;gap:var(--s3)">
        ${appLogo(app)}
        <div style="min-width:0">
          <div class="name">${healthDot(app)}${esc(app.name)}</div>
          <div class="muted small">${esc(typeBadge(app, L))}</div>
        </div>
      </div>
      ${descLine(app)}
      ${scopeBadges(app, L)}
      <a class="btn btn-primary" href="/apps/launch/${esc(app.client_id)}">${esc(t(L, 'portal.enter'))}</a>
    </div>`).join('\n');

  const rows = list.map((app) => `
    <div class="app-item">
      ${appLogo(app)}
      <div style="min-width:0;flex:1">
        <div class="rowline">
          <b style="color:var(--text);font-size:15px">${esc(app.name)}</b>
          ${healthDot(app)}
          <span class="badge">${esc(typeBadge(app, L))}</span>
          ${scopeBadges(app, L)}
        </div>
        ${descLine(app)}
        <div class="muted small" style="word-break:break-all"><code>${esc(app.client_id)}</code></div>
      </div>
      <a class="btn btn-primary btn-sm" href="/apps/launch/${esc(app.client_id)}">${esc(t(L, 'portal.enter'))}</a>
    </div>`).join('\n');

  const body = !list.length
    ? `<div class="card portal-empty"><div class="app-badge" aria-hidden="true">${scopeIcon('groups')}</div>
        <h3>${esc(t(L, 'portal.emptyTitle'))}</h3><p class="muted">${esc(t(L, 'portal.empty'))}</p>
        ${user.is_admin ? `<a class="btn btn-primary" href="/admin/apps">${esc(t(L, 'portal.emptyAction'))}</a>` : `<a class="btn" href="/account">${esc(t(L, 'nav.account'))}</a>`}</div>`
    : view === 'list'
      ? `<div class="card tight">${rows}</div>`
      : `<div class="portal-grid">${tiles}</div>`;

  // 顶栏:左侧标题块(标题 + 说明 + 数量),右侧视图切换与管理入口 —— 内容区直接是磁贴/列表
  const headTitle = `<h1>${esc(t(L, 'nav.portal'))}</h1>
    <p class="muted small portal-intro">${esc(fmt(t(L, 'portal.headSub'), { name: user.name || user.username, n: list.length }))}
    <span class="portal-hint">${esc(t(L, 'portal.headHint'))}</span></p>`;

  return adminPage({
    theme, siteName, user, active: 'portal', cur, lang: L, actions, headTitle,
    title: `${t(L, 'nav.portal')} · ${siteName}`,
    content: `
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      ${body}`,
  });
}
