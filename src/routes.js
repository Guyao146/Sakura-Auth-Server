import { createRouter } from './core/http.js';
import { sendJson } from './core/http.js';
import * as discovery from './services/oauth/discovery.js';
import * as authorize from './services/oauth/authorize.js';
import * as token from './services/oauth/token.js';
import * as userinfo from './services/oauth/userinfo.js';
import * as introspect from './services/oauth/introspect.js';
import * as login from './services/auth/login.js';
import * as register from './services/auth/register.js';
import * as logout from './services/auth/logout.js';
import * as account from './services/auth/account.js';
import * as microsoft from './services/auth/microsoft.js';
import * as reset from './services/auth/reset.js';
import * as admin from './services/admin/index.js';
import * as audit from './services/audit.js';
import * as wizard from './services/setup/wizard.js';
import * as portal from './services/portal.js';
import * as api from './services/api.js';
import * as webauthn from './services/webauthn.js';
import { showLanding } from './services/home.js';
import { setTheme } from './views/theme.js';
import { showHealth } from './views/health.js';

/** 路由表:URL → 服务函数;opts.cors 开放跨域,opts.auth 做会话/管理员校验 */
export function registerRoutes() {
  const router = createRouter();
  const r = router.add.bind(router);

  r('GET', '/healthz', (ctx) => sendJson(ctx.res, 200, { status: 'ok' }));
  // 品牌化健康状态页(匿名无需登录;no-store,不做 CORS —— 跨域 JSON 走 /api/heartbeat)
  r('GET', '/health', showHealth);
  r('GET', '/favicon.ico', (ctx) => { ctx.res.writeHead(204); ctx.res.end(); });
  r('GET', '/', showLanding);
  r('GET', '/-/theme/:mode', setTheme);

  // JSON API 套件:处理器内部自行判定登录态(未登录返回 JSON 错误,不重定向)
  r('GET', '/api/heartbeat', api.heartbeat, { cors: true });
  r('GET', '/api/session', api.session);
  r('POST', '/api/login', api.login);
  r('POST', '/api/logout', api.logout);
  r('GET', '/api/apps', api.apps);
  r('GET', '/api/sessions', api.listSessions);
  r('POST', '/api/sessions/revoke', api.revokeSession);
  r('POST', '/api/sessions/revoke-others', api.revokeOtherSessions);
  r('GET', '/api/registry', api.registry, { cors: true });

  r('GET', '/login', login.showLogin);
  r('POST', '/login', login.handleLogin);
  r('POST', '/login/2fa', login.handleTwoFa);
  r('GET', '/register', register.showRegister);
  r('POST', '/register', register.handleRegister);
  r('GET', '/logout', logout.showLogout);
  r('POST', '/logout', logout.handleLogout);
  r('GET', '/account', account.showAccount, { auth: 'user' });
  r('GET', '/apps', portal.showPortal, { auth: 'user' });
  r('GET', '/apps/launch/:clientId', portal.launch, { auth: 'user' });
  r('POST', '/account', account.handleChangePassword, { auth: 'user' });
  r('GET', '/account/apps', account.showAuthorizations, { auth: 'user' });
  r('POST', '/account/apps/revoke', account.revokeAuthorization, { auth: 'user' });
  r('GET', '/account/sessions', account.showSessions, { auth: 'user' });
  r('POST', '/account/sessions/revoke', account.revokeSession, { auth: 'user' });
  r('POST', '/account/sessions/revoke-others', account.revokeOtherSessions, { auth: 'user' });
  r('POST', '/account/2fa/start', account.startTwoFa, { auth: 'user' });
  r('POST', '/account/2fa/confirm', account.confirmTwoFa, { auth: 'user' });
  r('POST', '/account/2fa/disable', account.disableTwoFa, { auth: 'user' });

  // WebAuthn / Passkey(独立命名空间;JSON 接口按 api.js 风格由 handler 自行判定登录态,
  // 未登录 401 而非重定向,便于前端 fetch 处理;写操作要求 X-Requested-With: JSON 头)
  r('GET', '/webauthn/register/options', webauthn.registerOptions);
  r('POST', '/webauthn/register/verify', webauthn.registerVerify);
  r('GET', '/webauthn/login/options', webauthn.loginOptions);
  r('POST', '/webauthn/login/verify', webauthn.loginVerify);
  // 前端脚本资产(同源,CSP default-src 'self' 天然放行;全项目唯一页面 JS)
  r('GET', '/assets/webauthn.js', webauthn.serveJs);
  // 凭据删除:表单提交,走会话 CSRF 与登录态重定向(web 风格,区别于上面的 JSON 接口)
  r('POST', '/account/webauthn/:id/delete', webauthn.deleteCredential, { auth: 'user' });

  // 邮件找回密码(匿名;防枚举由服务层保证)
  r('GET', '/forgot-password', reset.showForgot);
  r('POST', '/forgot-password', reset.handleForgot);
  r('GET', '/reset-password', reset.showReset);
  r('POST', '/reset-password', reset.handleReset);

  // Microsoft 账号登录与绑定(发起/回调/关联匿名;解绑需登录态)
  r('GET', '/auth/microsoft', microsoft.startAuth);
  r('GET', '/auth/microsoft/callback', microsoft.callback);
  r('POST', '/auth/microsoft/link', microsoft.link);
  r('POST', '/auth/microsoft/register', microsoft.registerNew);
  r('POST', '/auth/microsoft/unbind', microsoft.unbind, { auth: 'user' });

  r('GET', '/setup', wizard.showSetup);
  r('POST', '/setup/step1', wizard.step1);
  r('POST', '/setup/step2', wizard.step2);
  r('POST', '/setup/step3', wizard.step3);
  // 管理员重新运行配置向导(重走检测与站点设置,不动用户与应用数据)
  r('POST', '/admin/rerun-wizard', wizard.rerunWizard, { auth: 'admin' });

  r('GET', '/.well-known/openid-configuration', discovery.discovery, { cors: true });
  r('GET', '/jwks.json', discovery.jwksHandler, { cors: true });
  r('GET', '/authorize', authorize.authorizeGet, { cors: true });
  r('POST', '/authorize', authorize.authorizePost, { cors: true });
  r('POST', '/token', token.tokenPost, { cors: true });
  r('GET', '/userinfo', userinfo.userinfo, { cors: true });
  r('POST', '/userinfo', userinfo.userinfo, { cors: true });
  r('POST', '/introspect', introspect.introspectPost, { cors: true });
  r('POST', '/revoke', introspect.revokePost, { cors: true });

  r('GET', '/admin', admin.showDashboard, { auth: 'admin' });
  r('POST', '/admin/register-toggle', admin.toggleRegister, { auth: 'admin' });
  r('POST', '/admin/ms-oauth', admin.saveMsOAuth, { auth: 'admin' });
  r('GET', '/admin/users', admin.listUsers, { auth: 'admin' });
  r('GET', '/admin/users/new', admin.newUserForm, { auth: 'admin' });
  r('POST', '/admin/users/create', admin.createUser, { auth: 'admin' });
  r('GET', '/admin/users/:id', admin.userDetail, { auth: 'admin' });
  r('POST', '/admin/users/:id/update', admin.updateUser, { auth: 'admin' });
  r('POST', '/admin/users/:id/delete', admin.deleteUser, { auth: 'admin' });
  r('GET', '/admin/groups', admin.listGroups, { auth: 'admin' });
  r('POST', '/admin/groups/create', admin.createGroup, { auth: 'admin' });
  r('GET', '/admin/groups/:id', admin.showGroupDetail, { auth: 'admin' });
  r('POST', '/admin/groups/:id/update', admin.updateGroup, { auth: 'admin' });
  r('POST', '/admin/groups/:id/members', admin.addMembers, { auth: 'admin' });
  r('POST', '/admin/groups/:id/members/remove', admin.removeMember, { auth: 'admin' });
  r('POST', '/admin/groups/:id/apps', admin.grantGroupApp, { auth: 'admin' });
  r('POST', '/admin/groups/:id/delete', admin.deleteGroup, { auth: 'admin' });
  r('GET', '/admin/apps', admin.listApps, { auth: 'admin' });
  r('GET', '/admin/apps/new', admin.newAppForm, { auth: 'admin' });
  r('POST', '/admin/apps/create', admin.createApp, { auth: 'admin' });
  r('GET', '/admin/apps/:id', admin.appDetail, { auth: 'admin' });
  r('POST', '/admin/apps/:id/update', admin.updateApp, { auth: 'admin' });
  r('POST', '/admin/apps/:id/logo', admin.uploadAppLogo, { auth: 'admin' });
  r('POST', '/admin/apps/:id/logo/delete', admin.deleteAppLogo, { auth: 'admin' });
  r('POST', '/admin/apps/:id/secret', admin.regenerateSecret, { auth: 'admin' });
  r('POST', '/admin/apps/:id/revoke-tokens', admin.revokeAppTokens, { auth: 'admin' });
  r('POST', '/admin/apps/:id/revoke-user', admin.revokeAppUserConsent, { auth: 'admin' });
  r('POST', '/admin/apps/:id/delete', admin.deleteApp, { auth: 'admin' });

  // 应用 Logo 静态服务(匿名可访问;文件名严格白名单防目录穿越)
  r('GET', '/uploads/:file', admin.serveUpload);

  // 审计日志:管理端查看、CSV 导出与清空(危险操作)
  r('GET', '/admin/audit', audit.showAudit, { auth: 'admin' });
  r('GET', '/admin/audit/export.csv', audit.exportCsv, { auth: 'admin' });
  r('POST', '/admin/audit/clear', audit.clearAudit, { auth: 'admin' });

  return router;
}
