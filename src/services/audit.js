/** 操作审计:各服务一行埋点 record(ctx, action, detail);并提供管理端「审计日志」页面 */
import * as audit from '../models/audit.js';
import { getRuntime } from '../core/runtime.js';
import { sendHtml, redirect } from '../core/http.js';
import { fmtTime } from '../core/util.js';
import { auditPage } from '../views/admin.js';

/** 审计页每页条数(分页与导出共用此节奏) */
const PER_PAGE = 50;

/**
 * 记录一条审计日志(actor 取当前登录用户,其次取表单提交的用户名;审计失败不阻断主流程)。
 * over.actor 可在用户对象尚未落会话时显式指定操作者(如注册/两步验证场景)。
 */
export function record(ctx, action, detail = '', over = {}) {
  try {
    audit.log({
      actor: over.actor || ctx?.user?.username || ctx?.body?.username || 'anonymous',
      action,
      detail: String(detail ?? ''),
      ip: ctx?.req?.socket?.remoteAddress || '',
    });
  } catch { /* 审计写入失败不影响业务主流程 */ }
}

/** GET /admin/audit —— 审计日志列表(筛选 + 分页,每页 50 条) */
export function showAudit(ctx, { msg, err } = {}) {
  const action = ctx.query.get('action') || '';
  const q = ctx.query.get('q') || '';
  const { rows, total, pages, page } = audit.listPaged({ page: ctx.query.get('page'), perPage: PER_PAGE, action, q });
  sendHtml(ctx.res, 200, auditPage({
    theme: ctx.theme, siteName: getRuntime().siteName, user: ctx.user,
    cur: ctx.url.pathname + ctx.url.search,
    list: rows, allActions: audit.distinctActions(),
    filters: { action, q },
    total, page, pages, perPage: PER_PAGE,
    csrf: ctx.session.csrf,
    msg, err,
  }));
}

/** POST /admin/audit/clear —— 清空审计日志(危险操作) */
export function clearAudit(ctx) {
  if (ctx.body?._csrf !== ctx.session.csrf) {
    return redirect(ctx.res, '/admin/audit?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
  audit.clear();
  redirect(ctx.res, '/admin/audit?msg=' + encodeURIComponent('审计日志已清空。'));
}

/** CSV 单元格转义:含逗号/引号/换行的字段用双引号包裹,内部引号翻倍 */
const csvCell = (v) => {
  const s = String(v ?? '');
  return /[",\r\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
};

/** GET /admin/audit/export.csv —— 导出审计日志 CSV(UTF-8 BOM 防 Excel 乱码;与页面同筛选,上限 5000 条) */
export function exportCsv(ctx) {
  const action = ctx.query.get('action') || '';
  const q = ctx.query.get('q') || '';
  const rows = audit.list({ limit: 5000, action, q });
  const lines = ['时间,操作者,动作,详情,IP',
    ...rows.map((row) => [fmtTime(row.ts), row.actor, row.action, row.detail, row.ip]
      .map(csvCell).join(','))];
  const d = new Date();
  const p2 = (n) => String(n).padStart(2, '0');
  const stamp = `${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}`
    + `-${p2(d.getHours())}${p2(d.getMinutes())}${p2(d.getSeconds())}`;
  const res = ctx.res;
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="audit-${stamp}.csv"`,
    'Cache-Control': 'no-store',
  });
  res.end('\uFEFF' + lines.join('\n') + '\n');
}
