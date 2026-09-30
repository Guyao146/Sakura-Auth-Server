import { escapeHtml as esc } from '../core/util.js';
import { authPage } from './layout.js';
import { getRuntime } from '../core/runtime.js';

export function errorPage({ theme, title, message, siteName, extra = '' }) {
  const site = siteName || (getRuntime() ? getRuntime().siteName : '统一认证');
  return authPage({
    theme, siteName: site, title: `${title} · ${site}`,
    content: `
      <h3 style="margin-top:0">${esc(title)}</h3>
      <p class="small">${esc(message)}</p>
      ${extra}
      <div class="actions">
        <a class="btn btn-primary" href="/">返回首页</a>
        <a class="btn" href="/login">重新登录</a>
      </div>`,
  });
}
