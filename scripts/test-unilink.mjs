/** 两个真实 HTTP 服务的隔离联调：不访问现有数据库、密钥或生产服务。 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const uni = process.env.UNILINK_SOURCE || path.resolve(root, '../unilink/auth-server');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sakura-unilink-'));
process.env.DATA_DIR = tmp;
const children = [];
let db, count = 0, failures = 0;
async function port() {
  const s = http.createServer();
  await new Promise(resolve => s.listen(0, '127.0.0.1', resolve));
  const p = s.address().port;
  await new Promise(resolve => s.close(resolve));
  return p;
}
function launch(exe, args, cwd, env) {
  const child = spawn(exe, args, { cwd, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let errors = '';
  child.stdout.on('data', () => {});
  child.stderr.on('data', b => { errors = (errors + b).slice(-8000); });
  child.on('error', e => { errors += e.message; });
  children.push(child);
  return () => errors;
}
async function ready(url, errors) {
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(url, { signal: AbortSignal.timeout(300) })).ok) return; } catch {}
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error(`Server not ready: ${url}\n${errors()}`);
}
const req = (url, options = {}) => fetch(url, { ...options, redirect: 'manual', signal: AbortSignal.timeout(10000) });
const post = (url, data, headers = {}) => req(url, { method: 'POST', body: new URLSearchParams(data), headers });
const digest = v => crypto.createHash('sha256').update(v).digest('base64url');
async function check(name, fn) {
  try { await fn(); count++; console.log(`PASS ${name}`); }
  catch (e) { failures++; console.error(`FAIL ${name}: ${e.message}`); }
}
const cookieOf = (r, name) => r.headers.getSetCookie().find(c => c.startsWith(name + '='))?.split(';')[0];

try {
  const idpPort = await port(), qrPort = await port();
  const idp = `http://127.0.0.1:${idpPort}`, qr = `http://127.0.0.1:${qrPort}`;
  process.env.BASE_URL = idp;
  const { initDb } = await import('../src/core/db.js');
  db = initDb();
  const { initKeys } = await import('../src/core/keys.js');
  initKeys();
  const { bindSettings, updateRuntime } = await import('../src/core/runtime.js');
  const settings = await import('../src/models/settings.js');
  const users = await import('../src/models/users.js');
  const clients = await import('../src/models/clients.js');
  const sessions = await import('../src/models/sessions.js');
  const tokens = await import('../src/models/tokens.js');
  const { issueFull } = await import('../src/services/oauth/issue.js');
  bindSettings(settings.getMap);
  updateRuntime({ setup_done: '1', unilink_enabled: '1', unilink_issuer: qr,
    unilink_client_id: 'unilink-qr', unilink_client_secret: 's'.repeat(40) }, settings.setSetting);
  const user = users.create({ username: 'unilink-test', passwordHash: 'test-no-password-login' });
  const admin = users.create({ username: 'unilink-admin', passwordHash: 'x', isAdmin: true });
  const adminSid = sessions.create(admin.id, 'csrf', 3600);
  const sessionId = sessions.create(user.id, 'csrf', 3600);
  const mobile = clients.create({ name: 'Mobile', redirectUris: ['unilink://auth/callback'],
    scopes: 'openid profile email groups offline_access', isPublic: true, pkceRequired: true, requireConsent: false });
  const business = clients.create({ name: 'Business', redirectUris: ['https://business.test/cb'],
    scopes: 'openid', isPublic: true, pkceRequired: true, requireConsent: false });
  const idpErrors = launch(process.execPath, ['server.js'], root, { PORT: String(idpPort) });
  const config = { base_url: qr, authentik_url: idp, provider: 'sakura', client_id: 'unilink-qr',
    client_secret: 's'.repeat(40), app_client_id: mobile.client_id };
  const state = path.join(tmp, 'unilink'); fs.mkdirSync(state);
  fs.writeFileSync(path.join(state, 'state.json'), JSON.stringify(config));
  const py = `import config; from app import build_app; from aiohttp import web; web.run_app(build_app(config.load(), key_path=${JSON.stringify(path.join(state, 'key.pem'))}), host='127.0.0.1', port=${qrPort}, print=None)`;
  const qrErrors = launch(process.env.PYTHON || 'python', ['-c', py], uni, { UNILINK_STATE_DIR: state });
  await Promise.all([ready(idp + '/healthz', idpErrors), ready(qr + '/healthz', qrErrors)]);

  const ep = await (await req(qr + '/api/app/config')).json();
  check('Sakura endpoint configuration', () => assert.equal(ep.token_url, idp + '/token'));
  const verifier = 'v'.repeat(64);
  let r = await req(idp + '/authorize?' + new URLSearchParams({ response_type: 'code',
    client_id: mobile.client_id, redirect_uri: 'unilink://auth/callback', scope: 'openid profile email groups offline_access',
    state: 'mobile-state', code_challenge: digest(verifier), code_challenge_method: 'S256' }), { headers: { Cookie: 'sid=' + sessionId } });
  const mobileCode = new URL(r.headers.get('location')).searchParams.get('code');
  r = await post(ep.token_url, { grant_type: 'authorization_code', client_id: mobile.client_id,
    redirect_uri: 'unilink://auth/callback', code: mobileCode, code_verifier: verifier });
  let mobileToken = await r.json();
  check('mobile code + PKCE token exchange', () => assert.ok(mobileToken.refresh_token));
  r = await post(ep.token_url, { grant_type: 'refresh_token', client_id: mobile.client_id, refresh_token: mobileToken.refresh_token });
  mobileToken = await r.json();
  check('mobile refresh rotation', () => assert.ok(mobileToken.access_token));
  const info = await (await req(ep.userinfo_url, { headers: { Authorization: 'Bearer ' + mobileToken.access_token } })).json();
  check('identity uses exact local sub', () => assert.equal(info.sub, user.id));
  await check('login page shows UniLink entry', async () =>
    assert.ok((await (await req(idp + '/login')).text()).includes('/auth/unilink')));
  await check('admin settings page renders', async () =>
    assert.ok((await (await req(idp + '/admin/unilink', { headers: { Cookie: 'sid=' + adminSid } }))
      .text()).includes('auth/unilink/callback')));
  await check('admin settings save works', async () => {
    const saved = await post(idp + '/admin/unilink', { _csrf: 'csrf', enabled: '1', issuer: qr,
      // 必须保持与 UniLink 侧 state.json 里同一个密钥，否则回登时 token 交换失败
      client_id: 'unilink-qr', client_secret: 's'.repeat(40) }, { Cookie: 'sid=' + adminSid });
    assert.equal(saved.status, 302);
  });

  const next = '/authorize?' + new URLSearchParams({ response_type: 'code', client_id: business.client_id,
    redirect_uri: 'https://business.test/cb', scope: 'openid', state: 'business-state',
    code_challenge: digest(verifier), code_challenge_method: 'S256' });
  async function flow(token = mobileToken.access_token) {
    const start = await req(idp + '/auth/unilink?next=' + encodeURIComponent(next));
    const browser = cookieOf(start, 'unilink_flow');
    const authorize = new URL(start.headers.get('location'));
    const html = await (await req(authorize)).text();
    const ticket = JSON.parse(html.match(/var TK=("[^"]+")/)[1]);
    const key = JSON.parse(html.match(/KEY=("[^"]+")/)[1]);
    const approval = await req(qr + '/api/scan/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ticket, access_token: token }) });
    return { browser, authorize, approval, ticket, key };
  }
  async function callbackUrl(f) {
    const poll = await (await req(qr + '/api/session/' + f.ticket + '?k=' + f.key)).json();
    return idp + '/auth/unilink/callback?' + new URLSearchParams({ code: poll.code, state: poll.state_param });
  }
  let f = await flow();
  check('scan approval with Sakura access token', () => assert.equal(f.approval.status, 200));
  let cb = await callbackUrl(f);
  r = await req(cb);
  check('callback rejects wrong browser', () => assert.equal(r.status, 400));
  r = await req(cb, { headers: { Cookie: f.browser } });
  check('callback establishes Sakura session and restores next', () => {
    assert.equal(r.status, 302); assert.equal(r.headers.get('location'), next); assert.ok(cookieOf(r, 'sid'));
  });
  const browserSession = cookieOf(r, 'sid');
  r = await req(idp + next, { headers: { Cookie: browserSession } });
  check('downstream application receives authorization code', () => {
    const u = new URL(r.headers.get('location')); assert.equal(u.origin, 'https://business.test');
    assert.ok(u.searchParams.get('code')); assert.equal(u.searchParams.get('state'), 'business-state');
  });
  r = await req(cb, { headers: { Cookie: f.browser } });
  check('callback replay rejected', () => assert.equal(r.status, 400));
  f = await flow('invalid-test-token');
  check('invalid Sakura token rejected', () => assert.equal(f.approval.status, 401));
  const serviceToken = issueFull({ client: mobile, user: null, scope: ['openid'], withRefresh: false, withIdToken: false });
  f = await flow(serviceToken.access_token);
  check('service token cannot impersonate user', () => assert.equal(f.approval.status, 401));

  // 扫码完成后禁用用户：即使已有二维码授权也不得创建新的浏览器会话。
  f = await flow(); cb = await callbackUrl(f);
  db.prepare('UPDATE users SET disabled = 1 WHERE id = ?').run(user.id);
  r = await req(cb, { headers: { Cookie: f.browser } });
  check('disabled user cannot finish callback', () => assert.equal(r.status, 403));
  db.prepare('UPDATE users SET disabled = 0, totp_enabled = 1, totp_secret = ? WHERE id = ?')
    .run('JBSWY3DPEHPK3PXP', user.id);
  f = await flow(); cb = await callbackUrl(f);
  r = await req(cb, { headers: { Cookie: f.browser } });
  const html = await r.text();
  check('TOTP account does not bypass second factor', () => {
    assert.equal(r.status, 200); assert.equal(cookieOf(r, 'sid'), undefined); assert.ok(html.includes('/auth/unilink/2fa'));
  });
  r = await post(idp + '/auth/unilink/2fa', { _csrf: 'wrong', code: '123456' }, { Cookie: cookieOf(r, 'unilink_factor') });
  check('second factor rejects invalid CSRF', () => assert.equal(r.status, 400));
  check('tokens are actually persisted in isolated database', () =>
    assert.ok(db.prepare('SELECT COUNT(*) AS n FROM tokens').get().n > 0));
  if (failures) process.exitCode = 1;
  console.log(`UniLink integration: ${count} checks passed`);
} finally {
  await Promise.all(children.map(child => new Promise(resolve => {
    if (child.exitCode !== null) return resolve();
    child.once('exit', resolve); child.kill();
  })));
  db?.close();
  fs.rmSync(tmp, { recursive: true, force: true });
}