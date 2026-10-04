import { setCookie, clearCookie, redirect } from '../core/http.js';

export const themeFromCookies = (cookies) =>
  cookies.theme === 'night' || cookies.theme === 'day' ? cookies.theme : '';

/** 语言来源:cookie `lang`(仅 en 显式;其余一律 zh 默认,保证既有文案零回归) */
export const langFromCookies = (cookies) => (cookies && cookies.lang === 'en' ? 'en' : 'zh');

/** 站内回跳地址白名单:仅以单个 / 开头的本站路径(back 参数优先,其次 referer) */
const safeBackPath = (raw) => {
  // 反斜杠也要拒:部分浏览器把 /\ 规范化为 //,使 /\evil.com 成为协议相对地址(开放重定向)
  if (typeof raw === 'string' && raw.startsWith('/') && !raw.startsWith('//') && !raw.includes('\\')) return raw;
  return '/';
};

const backFrom = (ctx) => {
  const fromQuery = ctx.query.get('back');
  if (fromQuery) return safeBackPath(fromQuery);
  let back = '/';
  try {
    const ref = new URL(ctx.req.headers.referer || '');
    back = ref.pathname + ref.search;
  } catch { /* 无 referer 用首页 */ }
  return back;
};

/** GET /-/theme/:mode —— day / night / auto(清除 cookie 跟随系统),回到来源页或 back 参数 */
export function setTheme(ctx) {
  const mode = ctx.params.mode;
  if (mode === 'day' || mode === 'night') {
    setCookie(ctx.res, 'theme', mode, { maxAge: 365 * 86400, httpOnly: false, secure: ctx.runtime.secureCookies });
  } else if (mode === 'auto') {
    clearCookie(ctx.res, 'theme', ctx.runtime.secureCookies);
  }
  redirect(ctx.res, backFrom(ctx));
}

/** GET /-/lang/:code —— zh / en(写 cookie + 重定向回来源页),与主题切换同模式 */
export function setLang(ctx) {
  const code = ctx.params.code;
  if (code === 'zh' || code === 'en') {
    setCookie(ctx.res, 'lang', code, { maxAge: 365 * 86400, httpOnly: false, secure: ctx.runtime.secureCookies });
  }
  redirect(ctx.res, backFrom(ctx));
}
