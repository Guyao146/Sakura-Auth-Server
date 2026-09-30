import { parseCookies, setCookie, clearCookie, redirect } from '../core/http.js';

export const themeFromCookies = (cookies) =>
  cookies.theme === 'night' || cookies.theme === 'day' ? cookies.theme : '';

/** GET /-/theme/:mode —— day / night / auto(清除 cookie 跟随系统),回到来源页或 back 参数 */
export function setTheme(ctx) {
  const mode = ctx.params.mode;
  if (mode === 'day' || mode === 'night') {
    setCookie(ctx.res, 'theme', mode, { maxAge: 365 * 86400, httpOnly: false, secure: ctx.runtime.secureCookies });
  } else if (mode === 'auto') {
    clearCookie(ctx.res, 'theme', ctx.runtime.secureCookies);
  }
  const safeBack = (raw) => {
    if (typeof raw === 'string' && raw.startsWith('/') && !raw.startsWith('//')) return raw;
    return '/';
  };
  // 优先 back 参数,其次 referer
  const fromQuery = ctx.query.get('back');
  if (fromQuery) return redirect(ctx.res, safeBack(fromQuery));
  let back = '/';
  try {
    const ref = new URL(ctx.req.headers.referer || '');
    back = ref.pathname + ref.search;
  } catch { /* 无 referer 用首页 */ }
  redirect(ctx.res, back);
}
