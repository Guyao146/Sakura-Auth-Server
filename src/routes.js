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
import * as admin from './services/admin/index.js';
import * as wizard from './services/setup/wizard.js';
import { showLanding } from './services/home.js';
import { setTheme } from './views/theme.js';

/** 路由表:URL → 服务函数;opts.cors 开放跨域,opts.auth 做会话/管理员校验 */
export function registerRoutes() {
  const router = createRouter();
  const r = router.add.bind(router);

  r('GET', '/healthz', (ctx) => sendJson(ctx.res, 200, { status: 'ok' }));
  r('GET', '/favicon.ico', (ctx) => { ctx.res.writeHead(204); ctx.res.end(); });
  r('GET', '/', showLanding);
  r('GET', '/-/theme/:mode', setTheme);

  r('GET', '/login', login.showLogin);
  r('POST', '/login', login.handleLogin);
  r('POST', '/login/2fa', login.handleTwoFa);
  r('GET', '/register', register.showRegister);
  r('POST', '/register', register.handleRegister);
  r('GET', '/logout', logout.showLogout);
  r('POST', '/logout', logout.handleLogout);
  r('GET', '/account', account.showAccount, { auth: 'user' });
  r('POST', '/account', account.handleChangePassword, { auth: 'user' });
  r('POST', '/account/2fa/start', account.startTwoFa, { auth: 'user' });
  r('POST', '/account/2fa/confirm', account.confirmTwoFa, { auth: 'user' });
  r('POST', '/account/2fa/disable', account.disableTwoFa, { auth: 'user' });

  r('GET', '/setup', wizard.showSetup);
  r('POST', '/setup/step1', wizard.step1);
  r('POST', '/setup/step2', wizard.step2);
  r('POST', '/setup/step3', wizard.step3);

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
  r('GET', '/admin/users', admin.listUsers, { auth: 'admin' });
  r('GET', '/admin/users/new', admin.newUserForm, { auth: 'admin' });
  r('POST', '/admin/users/create', admin.createUser, { auth: 'admin' });
  r('GET', '/admin/users/:id', admin.userDetail, { auth: 'admin' });
  r('POST', '/admin/users/:id/update', admin.updateUser, { auth: 'admin' });
  r('POST', '/admin/users/:id/delete', admin.deleteUser, { auth: 'admin' });
  r('GET', '/admin/apps', admin.listApps, { auth: 'admin' });
  r('GET', '/admin/apps/new', admin.newAppForm, { auth: 'admin' });
  r('POST', '/admin/apps/create', admin.createApp, { auth: 'admin' });
  r('GET', '/admin/apps/:id', admin.appDetail, { auth: 'admin' });
  r('POST', '/admin/apps/:id/update', admin.updateApp, { auth: 'admin' });
  r('POST', '/admin/apps/:id/secret', admin.regenerateSecret, { auth: 'admin' });
  r('POST', '/admin/apps/:id/revoke-tokens', admin.revokeAppTokens, { auth: 'admin' });
  r('POST', '/admin/apps/:id/delete', admin.deleteApp, { auth: 'admin' });

  return router;
}
