import { redirect } from '../core/http.js';

/** GET / —— 站点入口:未登录去登录页,已登录去应用门户 */
export function showLanding(ctx) {
  redirect(ctx.res, ctx.session ? '/apps' : '/login');
}
