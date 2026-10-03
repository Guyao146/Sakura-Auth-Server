import { escapeHtml as esc } from '../core/util.js';
import { t, normalizeLang, currentLang } from '../core/i18n.js';
import { authPage } from './layout.js';
import { getRuntime } from '../core/runtime.js';

export function errorPage({ theme, title, message, siteName, extra = '', lang }) {
  const L = normalizeLang(lang || currentLang());
  const site = siteName || (getRuntime() ? getRuntime().siteName : '统一认证');
  return authPage({
    theme, siteName: site, lang: L, title: `${title} · ${site}`,
    content: `
      <h3 style="margin-top:0">${esc(title)}</h3>
      <p class="small">${esc(message)}</p>
      ${extra}
      <div class="actions">
        <a class="btn btn-primary" href="/">${esc(t(L, 'err.backHome'))}</a>
        <a class="btn" href="/login">${esc(t(L, 'err.relogin'))}</a>
      </div>`,
  });
}
