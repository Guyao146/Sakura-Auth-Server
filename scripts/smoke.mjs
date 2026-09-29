/**
 * 冒烟测试:在独立数据目录拉起真实服务,端到端验证
 * 配置向导 → 登录 → 授权码+PKCE → 令牌签发/刷新/内省/吊销 → 管理控制台权限。
 * 运行:npm run smoke
 */
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const PORT = Number(process.env.SMOKE_PORT || 9901); // 并发跑多份时用 SMOKE_PORT 错开
const BASE = `http://localhost:${PORT}`;
const DATA = path.join(ROOT, '.smoke-data');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b64urlSha256 = (s) => crypto.createHash('sha256').update(s).digest('base64url');

/* ---------- 简易 cookie jar + fetch 封装 ---------- */
class Jar {
  constructor() { this.map = new Map(); }
  store(res) {
    for (const c of res.headers.getSetCookie?.() || []) {
      const [kv] = c.split(';');
      const i = kv.indexOf('=');
      const name = kv.slice(0, i).trim();
      const value = kv.slice(i + 1);
      if (value === '') this.map.delete(name); else this.map.set(name, value);
    }
  }
  header() { return [...this.map].map(([k, v]) => `${k}=${v}`).join('; '); }
}

async function call(jar, pathOrUrl, { method = 'GET', form, headers = {} } = {}) {
  const res = await fetch(pathOrUrl.startsWith('http') ? pathOrUrl : BASE + pathOrUrl, {
    method, redirect: 'manual',
    headers: {
      ...(form ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
      ...(jar.header() ? { Cookie: jar.header() } : {}),
      ...headers,
    },
    body: form ? new URLSearchParams(form).toString() : undefined,
  });
  jar.store(res);
  return res;
}

const formBody = async (res) => Object.fromEntries(new URLSearchParams(await res.text()));
const location = (res) => res.headers.get('location') || '';
const extractHidden = (html) => {
  const out = {};
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) out[m[1]] = m[2];
  return out;
};
const basic = (id, secret) => 'Basic ' + Buffer.from(`${id}:${secret}`).toString('base64');

/* ---------- 断言 ---------- */
let failed = 0;
const ok = (name, cond, extra = '') => {
  if (!cond) failed++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${!cond && extra ? '  → ' + extra : ''}`);
};

async function main() {
  fs.rmSync(DATA, { recursive: true, force: true });
  process.env.DATA_DIR = DATA;

  // 先启动服务(独立进程),测试进程随后用同一数据目录造夹具
  const child = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(PORT), BASE_URL: BASE, DATA_DIR: DATA },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  child.stdout.on('data', (d) => { serverLog += d; });
  child.stderr.on('data', (d) => { serverLog += d; });

  try {
    let ready = false;
    for (let i = 0; i < 120 && !ready; i++) {
      try { ready = (await fetch(BASE + '/healthz')).ok; } catch { await sleep(150); }
    }
    ok('服务启动并响应 /healthz', ready);
    if (!ready) { console.log(serverLog.slice(-2000)); return; }

    /* ---------- 夹具:测试进程直连同一 SQLite ---------- */
    const { initDb } = await import('../src/core/db.js');
    const { initKeys } = await import('../src/core/keys.js');
    const { hashPassword } = await import('../src/core/password.js');
    const users = await import('../src/models/users.js');
    const clients = await import('../src/models/clients.js');
    initDb();
    initKeys(); // 测试进程也要载入签名密钥,便于本地验签
    const bob = users.create({ username: 'bob', passwordHash: hashPassword('BobPassw0rd!'), name: '小明', userGroups: 'dev ops' });
    const web = clients.create({
      name: 'Smoke Web', redirectUris: ['http://127.0.0.1:8080/cb'],
      scopes: 'openid profile email offline_access groups', isPublic: true, pkceRequired: true,
    });
    const svc = clients.create({
      name: 'Smoke Service', redirectUris: ['http://127.0.0.1:8080/any'],
      scopes: 'openid profile', isPublic: false, pkceRequired: false,
      secretHash: hashPassword('svc-secret-123'),
    });

    /* ---------- 配置向导(向导未完成前所有端点都会被守卫重定向) ---------- */
    const wj = new Jar();
    let r = await call(wj, '/setup');
    ok('未初始化时首页重定向到向导', (await call(new Jar(), '/')).status === 302 && r.status === 200 && (await r.text()).includes('环境检测'));
    r = await call(wj, '/setup/step1', { method: 'POST', form: {} });
    ok('向导第 1 步通过', r.status === 302 && location(r) === '/setup');
    r = await call(wj, '/setup/step2', {
      method: 'POST',
      form: { site_name: '樱落统一认证', issuer: BASE, access_ttl: '900', refresh_ttl: '2592000' },
    });
    ok('向导第 2 步站点设置', r.status === 302);
    r = await call(wj, '/setup/step3', {
      method: 'POST',
      form: { username: 'admin', name: '管理员', password: 'Wizard#12345', password2: 'Wizard#12345' },
    });
    const doneHtml = await r.text();
    ok('向导第 3 步创建管理员并完成', r.status === 200 && doneHtml.includes('配置完成'));
    ok('初始化后访问向导重定向回首页', (await call(new Jar(), '/setup')).status === 302);

    /* ---------- 发现文档与 JWKS(向导完成后才对外可用) ---------- */
    const disc = await (await fetch(BASE + '/.well-known/openid-configuration')).json();
    ok('发现文档 issuer 正确', disc.issuer === BASE, disc.issuer);
    ok('发现文档声明授权码+PKCE', disc.grant_types_supported.includes('authorization_code')
      && disc.code_challenge_methods_supported.includes('S256'));
    const jwks = await (await fetch(BASE + '/jwks.json')).json();
    ok('JWKS 暴露 RS256 公钥', jwks.keys?.[0]?.kty === 'RSA' && !!jwks.keys[0].n);

    /* ---------- 完整授权码 + PKCE(含登录、同意) ---------- */
    const verifier = crypto.randomBytes(48).toString('base64url');
    const challenge = b64urlSha256(verifier);
    const state = 'st-123', nonce = 'n-456';
    const authUrl = '/authorize?' + new URLSearchParams({
      client_id: web.client_id, redirect_uri: 'http://127.0.0.1:8080/cb',
      response_type: 'code', scope: 'openid profile offline_access groups',
      state, nonce, code_challenge: challenge, code_challenge_method: 'S256',
    }).toString();

    const uj = new Jar();
    r = await call(uj, authUrl);
    ok('未登录访问 /authorize 跳登录页', r.status === 302 && location(r).startsWith('/login?next='));

    r = await call(uj, location(r));
    const loginForm = extractHidden(await r.text());
    ok('登录页带 CSRF', !!loginForm._csrf);

    r = await call(uj, '/login', {
      method: 'POST',
      form: { username: 'bob', password: 'BobPassw0rd!', _csrf: loginForm._csrf, next: authUrl },
    });
    ok('登录成功回到 /authorize', r.status === 302 && location(r).startsWith('/authorize?'));

    r = await call(uj, location(r));
    const consentHtml = await r.text();
    const consentForm = extractHidden(consentHtml);
    ok('渲染同意授权页', consentHtml.includes('请求访问你的账号'));

    r = await call(uj, '/authorize', {
      method: 'POST',
      form: { ...consentForm, decision: 'approve', remember: 'on' },
    });
    const loc = location(r);
    const code = new URL(loc, BASE).searchParams.get('code');
    ok('同意后签发授权码并回跳', r.status === 302 && !!code && new URL(loc, BASE).searchParams.get('state') === state);

    /* ---------- 令牌端点 ---------- */
    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code, redirect_uri: 'http://127.0.0.1:8080/cb',
        client_id: web.client_id, code_verifier: verifier,
      }).toString(),
    });
    const tok = await r.json();
    ok('换取令牌成功', r.status === 200 && !!tok.access_token && !!tok.refresh_token && !!tok.id_token, JSON.stringify(tok));
    ok('scope 正确下发', (tok.scope || '').includes('openid') && (tok.scope || '').includes('offline_access'));

    const { verifyJwt } = await import('../src/core/jwt.js');
    const idPayload = verifyJwt(tok.id_token);
    ok('id_token 验签通过且带 nonce/sub', !!idPayload && idPayload.nonce === nonce && idPayload.preferred_username === 'bob');

    const ui = await fetch(BASE + '/userinfo', { headers: { Authorization: `Bearer ${tok.access_token}` } });
    const uiBody = await ui.json();
    ok('/userinfo 返回用户 claims', ui.status === 200 && uiBody.preferred_username === 'bob' && Array.isArray(uiBody.groups));

    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code, redirect_uri: 'http://127.0.0.1:8080/cb',
        client_id: web.client_id, code_verifier: verifier,
      }).toString(),
    });
    ok('授权码一次性(重放拒绝)', r.status === 400 && (await r.json()).error === 'invalid_grant');

    /* ---------- 第二轮:记忆同意 + PKCE 错误校验 ---------- */
    r = await call(uj, authUrl);
    const loc2 = location(r);
    const code2 = new URL(loc2, BASE).searchParams.get('code');
    ok('记住授权后跳过同意页', r.status === 302 && !!code2 && !loc2.includes('error'));

    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: code2, redirect_uri: 'http://127.0.0.1:8080/cb',
        client_id: web.client_id, code_verifier: 'x'.repeat(64),
      }).toString(),
    });
    ok('错误 verifier 被拒绝', r.status === 400 && (await r.json()).error === 'invalid_grant');

    r = await call(uj, authUrl);
    const code3 = new URL(location(r), BASE).searchParams.get('code');
    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: code3, redirect_uri: 'http://127.0.0.1:8080/cb',
        client_id: web.client_id, code_verifier: verifier,
      }).toString(),
    });
    const tok3 = await r.json();
    ok('正确 verifier 再次换取成功', r.status === 200 && !!tok3.access_token);

    /* ---------- 刷新令牌轮换 ---------- */
    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token', refresh_token: tok3.refresh_token, client_id: web.client_id,
      }).toString(),
    });
    const tok4 = await r.json();
    ok('刷新成功且轮换出新 refresh_token', r.status === 200 && tok4.refresh_token && tok4.refresh_token !== tok3.refresh_token);

    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tok3.refresh_token, client_id: web.client_id }).toString(),
    });
    ok('旧 refresh_token 轮换后作废', r.status === 400);

    /* ---------- 内省与吊销 ---------- */
    r = await fetch(BASE + '/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'svc-secret-123') },
      body: new URLSearchParams({ token: tok4.access_token }).toString(),
    });
    const intro = await r.json();
    ok('内省 access_token 活跃', r.status === 200 && intro.active === true && intro.username === 'bob');

    r = await fetch(BASE + '/revoke', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      // RFC 7009:令牌只能由所属客户端吊销;公开客户端以 client_id 表明身份
      body: new URLSearchParams({ token: tok4.refresh_token, client_id: web.client_id }).toString(),
    });
    ok('所属客户端吊销返回 200', r.status === 200);
    r = await fetch(BASE + '/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'svc-secret-123') },
      body: new URLSearchParams({ token: tok4.refresh_token }).toString(),
    });
    ok('吊销后内省 active=false', (await r.json()).active === false);

    /* ---------- client_credentials ---------- */
    r = await fetch(BASE + '/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'svc-secret-123') },
      body: new URLSearchParams({ grant_type: 'client_credentials' }).toString(),
    });
    const cc = await r.json();
    ok('客户端凭证模式签发成功', r.status === 200 && !!cc.access_token && !cc.refresh_token);

    const ccUi = await fetch(BASE + '/userinfo', { headers: { Authorization: `Bearer ${cc.access_token}` } });
    ok('客户端凭证令牌不能访问 /userinfo', ccUi.status === 401);

    r = await fetch(BASE + '/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'wrong-secret') },
      body: new URLSearchParams({ grant_type: 'client_credentials' }).toString(),
    });
    ok('错误密钥返回 invalid_client', r.status === 401 && (await r.json()).error === 'invalid_client');

    /* ---------- 两步验证(TOTP + 恢复代码) ---------- */
    const totp = await import('../src/core/totp.js');
    const recovery = await import('../src/models/recovery.js');
    const totpSecret = totp.generateSecret();
    users.setTotpSecret(bob.id, totpSecret);
    users.enableTotp(bob.id);
    const bobRecovery = recovery.createBatch(bob.id, 8);

    const fj = new Jar();
    r = await call(fj, '/login');
    const ffa = extractHidden(await r.text());
    r = await call(fj, '/login', { method: 'POST', form: { username: 'bob', password: 'BobPassw0rd!', _csrf: ffa._csrf } });
    const twoHtml = await r.text();
    ok('开启 2FA 后密码通过进入二步验证页', r.status === 200 && twoHtml.includes('两步验证'));
    const tf1 = extractHidden(twoHtml);
    r = await call(fj, '/login/2fa', { method: 'POST', form: { code: '000000', _csrf: tf1._csrf, pending: tf1.pending } });
    ok('错误验证码被拒', r.status === 401);
    const tf2 = extractHidden(await r.text());
    r = await call(fj, '/login/2fa', { method: 'POST', form: { code: totp.currentCode(totpSecret), _csrf: tf2._csrf, pending: tf2.pending } });
    ok('正确 TOTP 完成登录', r.status === 302 && location(r) === '/');

    // 登出后重新走一遍,验证恢复代码可以代替验证码完成登录
    r = await call(fj, '/logout');
    const lfA = extractHidden(await r.text());
    await call(fj, '/logout', { method: 'POST', form: { _csrf: lfA._csrf } });
    r = await call(fj, '/login');
    const ffa2 = extractHidden(await r.text());
    r = await call(fj, '/login', { method: 'POST', form: { username: 'bob', password: 'BobPassw0rd!', _csrf: ffa2._csrf } });
    const tf3 = extractHidden(await r.text());
    r = await call(fj, '/login/2fa', { method: 'POST', form: { code: bobRecovery[0], _csrf: tf3._csrf, pending: tf3.pending } });
    ok('恢复代码可完成登录', r.status === 302);

    // 再登出,验证已用过的恢复代码不可重用
    r = await call(fj, '/logout');
    const lf0 = extractHidden(await r.text());
    await call(fj, '/logout', { method: 'POST', form: { _csrf: lf0._csrf } });
    r = await call(fj, '/login');
    const ffa3 = extractHidden(await r.text());
    r = await call(fj, '/login', { method: 'POST', form: { username: 'bob', password: 'BobPassw0rd!', _csrf: ffa3._csrf } });
    const tf4 = extractHidden(await r.text());
    r = await call(fj, '/login/2fa', { method: 'POST', form: { code: bobRecovery[0], _csrf: tf4._csrf, pending: tf4.pending } });
    ok('恢复代码一次性(重用被拒)', r.status === 401, `status=${r.status} loc=${location(r)}`);

    /* ---------- 登录防护与管理端权限 ---------- */
    const wj2 = new Jar();
    r = await call(wj2, '/login');
    const f2 = extractHidden(await r.text());
    r = await call(wj2, '/login', { method: 'POST', form: { username: 'bob', password: 'wrong-pass', _csrf: f2._csrf } });
    ok('错误密码被拒绝', r.status === 401 && (await r.text()).includes('用户名或密码不正确'));

    r = await call(uj, '/admin');
    ok('普通用户访问控制台被拒(403)', r.status === 403);

    const aj = new Jar();
    r = await call(aj, '/login');
    const f3 = extractHidden(await r.text());
    await call(aj, '/login', { method: 'POST', form: { username: 'admin', password: 'Wizard#12345', _csrf: f3._csrf } });
    r = await call(aj, '/admin');
    ok('管理员登录后可访问控制台', r.status === 200 && (await r.text()).includes('控制台'));
    r = await call(aj, '/admin/users/create', {
      method: 'POST',
      form: { username: 'alice', password: 'Alice#12345', name: '爱丽丝', email: 'alice@example.com', user_groups: 'dev', is_admin: '' },
    });
    r = await call(aj, '/admin/users');
    ok('管理员可在控制台创建用户', r.status === 200 && (await r.text()).includes('alice'));

    r = await call(aj, '/logout');
    const f4 = extractHidden(await r.text());
    r = await call(aj, '/logout', { method: 'POST', form: { _csrf: f4._csrf } });
    r = await call(aj, '/admin');
    ok('退出后访问控制台跳回登录页', r.status === 302 && location(r).startsWith('/login'));

    /* ---------- 管理员重置用户 2FA ---------- */
    r = await call(aj, '/login');
    const f5 = extractHidden(await r.text());
    await call(aj, '/login', { method: 'POST', form: { username: 'admin', password: 'Wizard#12345', _csrf: f5._csrf } });
    r = await call(aj, `/admin/users/${bob.id}`);
    const editHtml = await r.text();
    ok('编辑页提供两步验证重置项', editHtml.includes('重置两步验证'));
    const ef = extractHidden(editHtml);
    r = await call(aj, `/admin/users/${bob.id}/update`, {
      method: 'POST',
      form: { name: '小明', email: '', user_groups: 'dev ops', is_admin: '', disabled: '', password: '', totp_reset: '1', _csrf: ef._csrf },
    });
    const bobAfter = users.byId(bob.id);
    ok('管理员重置后用户的 2FA 已清除', !bobAfter.totp_enabled && !bobAfter.totp_secret && recovery.countValid(bob.id) === 0);
    r = await call(fj, '/login');
    const f6 = extractHidden(await r.text());
    r = await call(fj, '/login', { method: 'POST', form: { username: 'bob', password: 'BobPassw0rd!', _csrf: f6._csrf } });
    ok('重置后用户可直接登录(不再要求验证码)', r.status === 302);

    /* ---------- 账号页开通/关闭 2FA 的完整流程 ---------- */
    r = await call(aj, '/account/2fa/start', { method: 'POST', form: { password: 'Wizard#12345', _csrf: ef._csrf } });
    const startHtml = await r.text();
    ok('账号页出现待确认密钥与 otpauth 地址', startHtml.includes('otpauth://totp/'));
    const secretMatch = startHtml.match(/<b>密钥<\/b><span>([A-Z2-7]+)<\/span>/);
    ok('密钥以 base32 展示', !!secretMatch);
    r = await call(aj, '/account/2fa/confirm', { method: 'POST', form: { code: totp.currentCode(secretMatch[1]), _csrf: ef._csrf } });
    const confirmHtml = await r.text();
    ok('确认后一次性展示恢复代码', confirmHtml.includes('恢复代码') && confirmHtml.includes('-'));
    r = await call(aj, '/account/2fa/disable', { method: 'POST', form: { password: 'Wizard#12345', _csrf: ef._csrf } });
    ok('验证密码后可关闭两步验证', (await r.text()).includes('两步验证已关闭'));

    /* ---------- 自助注册开关 ---------- */
    // 默认关闭:注册页与注册入口均不可用
    r = await call(new Jar(), '/register');
    ok('自助注册:默认关闭时 GET /register 重定向登录页', r.status === 302 && location(r) === '/login');
    r = await call(new Jar(), '/login');
    ok('自助注册:默认关闭时登录页不显示注册入口', r.status === 200 && !(await r.text()).includes('注册新账号'));

    // 管理员在控制台开启开关
    r = await call(aj, '/admin');
    const dashHtml = await r.text();
    ok('自助注册:控制台出现开关卡片', dashHtml.includes('自助注册') && dashHtml.includes('开启自助注册'));
    const dashForm = extractHidden(dashHtml);
    r = await call(aj, '/admin/register-toggle', { method: 'POST', form: { _csrf: dashForm._csrf } });
    ok('自助注册:管理员开启开关', r.status === 302 && location(r).startsWith('/admin?msg='));

    // 开启后:注册页可用,登录页出现注册入口
    r = await call(new Jar(), '/register');
    ok('自助注册:开启后 GET /register 返回注册页', r.status === 200 && (await r.text()).includes('确认密码'));
    r = await call(new Jar(), '/login');
    ok('自助注册:开启后登录页显示注册入口', r.status === 200 && (await r.text()).includes('注册新账号'));

    // 注册新用户:成功后直接建立会话
    const rj = new Jar();
    r = await call(rj, '/register');
    const regForm = extractHidden(await r.text());
    r = await call(rj, '/register', {
      method: 'POST',
      form: {
        username: 'carol', password: 'Carol#12345', password2: 'Carol#12345',
        name: '卡萝尔', email: 'carol@example.com', _csrf: regForm._csrf,
      },
    });
    ok('自助注册:注册成功并自动登录', r.status === 302 && location(r) === '/');
    r = await call(rj, '/account');
    ok('自助注册:新会话可访问账号页并显示新用户名', r.status === 200 && (await r.text()).includes('carol'));
    r = await call(rj, '/admin');
    ok('自助注册:注册用户不是管理员(访问控制台 403)', r.status === 403);

    // 重复用户名被拒
    const dj = new Jar();
    r = await call(dj, '/register');
    const dupForm = extractHidden(await r.text());
    r = await call(dj, '/register', {
      method: 'POST',
      form: { username: 'carol', password: 'Carol#12345', password2: 'Carol#12345', _csrf: dupForm._csrf },
    });
    ok('自助注册:重复用户名注册被拒', r.status === 400 && (await r.text()).includes('用户名已存在'));

    // 两次密码不一致被拒
    const mj = new Jar();
    r = await call(mj, '/register');
    const mmForm = extractHidden(await r.text());
    r = await call(mj, '/register', {
      method: 'POST',
      form: { username: 'dave', password: 'Dave#12345', password2: 'Dave#99999', _csrf: mmForm._csrf },
    });
    ok('自助注册:两次密码不一致被拒', r.status === 400 && (await r.text()).includes('两次输入的密码不一致'));

    // 管理员关闭开关:注册页与提交重新不可用
    r = await call(aj, '/admin');
    const dashForm2 = extractHidden(await r.text());
    r = await call(aj, '/admin/register-toggle', { method: 'POST', form: { _csrf: dashForm2._csrf } });
    ok('自助注册:管理员关闭开关', r.status === 302 && location(r).startsWith('/admin?msg='));
    r = await call(new Jar(), '/register');
    ok('自助注册:关闭后 GET /register 重新重定向登录页', r.status === 302 && location(r) === '/login');
    r = await call(new Jar(), '/register', {
      method: 'POST',
      form: { username: 'eve', password: 'Eve#12345', password2: 'Eve#12345', _csrf: 'x' },
    });
    ok('自助注册:关闭后 POST /register 不可用', r.status === 302 && location(r) === '/login');

    console.log(failed ? `\n${failed} 项失败` : '\n全部通过 ✔');
  } finally {
    child.kill();
    await sleep(800);
    // Windows 下 SQLite WAL 句柄释放稍慢,失败不掩盖真实测试结果
    try { fs.rmSync(DATA, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }); } catch {}
  }
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
