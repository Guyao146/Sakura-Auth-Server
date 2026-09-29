import { sendHtml } from '../core/http.js';
import { getRuntime } from '../core/runtime.js';
import { landingPage } from '../views/landing.js';

/** GET / —— 首页(服务介绍 + 接入入口) */
export function showLanding(ctx) {
  const rt = getRuntime();
  sendHtml(ctx.res, 200, landingPage({
    theme: ctx.theme, siteName: rt.siteName, issuer: rt.issuer,
    logged: !!ctx.session, msg: ctx.query.get('msg'),
  }));
}
