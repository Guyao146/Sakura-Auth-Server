/** 操作审计:各服务一行埋点 record(ctx, action, detail);并提供管理端「审计日志」页面 */
import * as audit from '../models/audit.js';
import { getRuntime } from '../core/runtime.js';
import { sendHtml, redirect } from '../core/http.js';
import { auditPage } from '../views/admin.js';

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

/** GET /admin/audit —— 审计日志列表(筛选 + 最近 200 条) */
export function showAudit(ctx, { msg, err } = {}) {
  const action = ctx.query.get('action') || '';
  const q = ctx.query.get('q') || '';
  const list = audit.list({ limit: 200, action, q });
  sendHtml(ctx.res, 200, auditPage({
    theme: ctx.theme, siteName: getRuntime().siteName, user: ctx.user,
    cur: ctx.url.pathname + ctx.url.search,
    list, allActions: audit.distinctActions(),
    filters: { action, q },
    total: audit.count(),
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
