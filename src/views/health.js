/** 无授权健康状态页(GET /health):品牌化、零 JS、匿名可访问。
 *  只暴露运行状态(版本/时长/数据库/Issuer/服务器时间),不含任何用户/应用等敏感计数;
 *  监控用的机器可读 JSON 由 /api/heartbeat 提供(其负责 CORS),本页 no-store 且不做 CORS。 */
import { escapeHtml as esc } from '../core/util.js';
import { getDb } from '../core/db.js';
import { getRuntime } from '../core/runtime.js';
import { config } from '../core/config.js';
import { sendHtml } from '../core/http.js';
import { t, normalizeLang, currentLang } from '../core/i18n.js';
import { langFromCookies } from './theme.js';
import { authPage } from './layout.js';
import { kvRow } from './components.js';

/** 运行时长人性化:3 天 2 小时 / 5 小时 12 分钟 / 5 分钟 / 40 秒(单位随语言) */
const fmtUptime = (sec, lang) => {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d} ${t(lang, 'health.uDay')} ${h} ${t(lang, 'health.uHour')}`;
  if (h > 0) return m > 0 ? `${h} ${t(lang, 'health.uHour')} ${m} ${t(lang, 'health.uMinute')}` : `${h} ${t(lang, 'health.uHour')}`;
  if (m > 0) return `${m} ${t(lang, 'health.uMinute')}`;
  return `${Math.max(Math.floor(sec), 0)} ${t(lang, 'health.uSecond')}`;
};

/** GET /health —— 匿名品牌化健康状态页(无需登录;未初始化时也在 setupGate 白名单内) */
export function showHealth(ctx) {
  const lang = normalizeLang(langFromCookies(ctx.cookies) || currentLang());
  let dbOk = false;
  try { getDb().prepare('SELECT 1').get(); dbOk = true; } catch { dbOk = false; }
  const rt = getRuntime();
  const html = authPage({
    theme: ctx.theme, siteName: rt.siteName, lang, title: `${t(lang, 'health.title')} · ${rt.siteName}`, footer: false,
    content: `
      <h3 style="margin-top:0">${esc(t(lang, 'health.title'))}</h3>
      <div class="rowline" style="margin:0 0 var(--s3)">
        <span class="badge" style="color:var(--ok);background:color-mix(in srgb,var(--ok) 12%,transparent);font-weight:600">${esc(t(lang, 'health.running'))}</span>
      </div>
      ${kvRow(t(lang, 'health.siteName'), esc(rt.siteName))}
      ${kvRow(t(lang, 'health.version'), esc(config.version))}
      ${kvRow(t(lang, 'health.uptime'), esc(fmtUptime(process.uptime(), lang)))}
      ${kvRow(t(lang, 'health.database'), dbOk ? `<b style="color:var(--ok)">${esc(t(lang, 'health.dbOk'))}</b>` : `<b style="color:var(--danger)">${esc(t(lang, 'health.dbBad'))}</b>`)}
      ${kvRow('Issuer', esc(rt.issuer))}
      ${kvRow(t(lang, 'health.serverTime'), esc(new Date().toLocaleString(lang === 'en' ? 'en-US' : 'zh-CN', { hour12: false })))}
      <div class="actions">
        <a class="btn" href="/.well-known/openid-configuration">${esc(t(lang, 'health.discovery'))}</a>
        <a class="btn" href="/api/heartbeat">${esc(t(lang, 'health.heartbeat'))}</a>
      </div>`,
  });
  ctx.res.setHeader('Cache-Control', 'no-store');
  sendHtml(ctx.res, 200, html);
}
