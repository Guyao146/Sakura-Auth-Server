/** 无授权健康状态页(GET /health):品牌化、零 JS、匿名可访问。
 *  只暴露运行状态(版本/时长/数据库/Issuer/服务器时间),不含任何用户/应用等敏感计数;
 *  监控用的机器可读 JSON 由 /api/heartbeat 提供(其负责 CORS),本页 no-store 且不做 CORS。 */
import { escapeHtml as esc } from '../core/util.js';
import { getDb } from '../core/db.js';
import { getRuntime } from '../core/runtime.js';
import { config } from '../core/config.js';
import { sendHtml } from '../core/http.js';
import { authPage } from './layout.js';
import { kvRow } from './components.js';

/** 运行时长人性化:3 天 2 小时 / 5 小时 12 分钟 / 5 分钟 / 40 秒 */
const fmtUptime = (sec) => {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d} 天 ${h} 小时`;
  if (h > 0) return m > 0 ? `${h} 小时 ${m} 分钟` : `${h} 小时`;
  if (m > 0) return `${m} 分钟`;
  return `${Math.max(Math.floor(sec), 0)} 秒`;
};

/** GET /health —— 匿名品牌化健康状态页(无需登录;未初始化时也在 setupGate 白名单内) */
export function showHealth(ctx) {
  let dbOk = false;
  try { getDb().prepare('SELECT 1').get(); dbOk = true; } catch { dbOk = false; }
  const rt = getRuntime();
  const html = authPage({
    theme: ctx.theme, siteName: rt.siteName, title: `服务状态 · ${rt.siteName}`, footer: false,
    content: `
      <h3 style="margin-top:0">服务状态</h3>
      <div class="rowline" style="margin:0 0 var(--s3)">
        <span class="badge" style="color:var(--ok);background:color-mix(in srgb,var(--ok) 12%,transparent);font-weight:600">服务运行中</span>
      </div>
      ${kvRow('站点名称', esc(rt.siteName))}
      ${kvRow('版本', esc(config.version))}
      ${kvRow('已运行时长', esc(fmtUptime(process.uptime())))}
      ${kvRow('数据库', dbOk ? '<b style="color:var(--ok)">连接正常</b>' : '<b style="color:var(--danger)">异常</b>')}
      ${kvRow('Issuer', esc(rt.issuer))}
      ${kvRow('服务器时间', esc(new Date().toLocaleString('zh-CN', { hour12: false })))}
      <div class="actions">
        <a class="btn" href="/.well-known/openid-configuration">发现文档</a>
        <a class="btn" href="/api/heartbeat">心跳 JSON</a>
      </div>`,
  });
  ctx.res.setHeader('Cache-Control', 'no-store');
  sendHtml(ctx.res, 200, html);
}
