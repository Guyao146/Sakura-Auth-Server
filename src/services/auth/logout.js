import * as sessions from '../../models/sessions.js';
import { clearCookie, redirect, sendHtml } from '../../core/http.js';
import { getRuntime } from '../../core/runtime.js';
import { logoutPage } from '../../views/auth.js';
import { record } from '../audit.js';

/** GET /logout —— 确认页(避免 GET 直接销毁会话) */
export function showLogout(ctx) {
  if (!ctx.session) return redirect(ctx.res, '/');
  sendHtml(ctx.res, 200, logoutPage({
    theme: ctx.theme, siteName: ctx.runtime.siteName, csrf: ctx.session.csrf,
  }));
}

/** POST /logout */
export function handleLogout(ctx) {
  if (!ctx.session) return redirect(ctx.res, '/');
  if (ctx.body?._csrf !== ctx.session.csrf) return redirect(ctx.res, '/');
  sessions.remove(ctx.session.id_hash);
  clearCookie(ctx.res, 'sid', getRuntime().secureCookies);
  record(ctx, 'auth.logout');
  redirect(ctx.res, '/login?msg=' + encodeURIComponent('已退出登录'));
}
