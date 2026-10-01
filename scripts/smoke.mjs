/**
 * 冒烟测试:在独立数据目录拉起真实服务,端到端验证
 * 配置向导 → 登录 → 授权码+PKCE → 令牌签发/刷新/内省/吊销 → 管理控制台权限 → 邮件找回密码。
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
    const settings = await import('../src/models/settings.js');
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
    // 模拟老库迁移:users.user_groups 自由文本 → 组与成员关系(migrate() 内自动执行,幂等)
    const { seedGroupsFromUserGroups } = await import('../src/core/db.js');
    seedGroupsFromUserGroups();

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
    ok('普通用户访问控制台被拒(403)且页面显示当前身份', r.status === 403
      && (await r.text()).includes('bob'));

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
    // crispEdges 仅二维码 SVG 携带,排除品牌图标等其它内联 SVG 的干扰
    ok('开启两步验证页内嵌 QR SVG',
      startHtml.includes('<svg') && startHtml.includes('shape-rendering="crispEdges"')
      && !!secretMatch && startHtml.includes(secretMatch[1]));
    r = await call(aj, '/account/2fa/confirm', { method: 'POST', form: { code: totp.currentCode(secretMatch[1]), _csrf: ef._csrf } });
    const confirmHtml = await r.text();
    ok('确认后一次性展示恢复代码', confirmHtml.includes('恢复代码') && confirmHtml.includes('-'));
    r = await call(aj, '/account/2fa/disable', { method: 'POST', form: { password: 'Wizard#12345', _csrf: ef._csrf } });
    ok('验证密码后可关闭两步验证', (await r.text()).includes('两步验证已关闭'));

    /* ---------- 邮件找回密码(SMTP 未配置 → 开发模式,邮件打到 serverLog) ---------- */
    const pj = new Jar();
    r = await call(pj, '/forgot-password');
    const fpf = extractHidden(await r.text());
    ok('找回密码页可访问且带 CSRF', r.status === 200 && !!fpf._csrf);

    r = await call(pj, '/forgot-password', { method: 'POST', form: { email: 'ghost@example.com', _csrf: fpf._csrf } });
    const ghostPage = await r.text();
    ok('找回密码:未知邮箱渲染通用提示', r.status === 200 && ghostPage.includes('如果该邮箱已注册'));

    r = await call(pj, '/forgot-password', { method: 'POST', form: { email: 'alice@example.com', _csrf: fpf._csrf } });
    const knownPage = await r.text();
    ok('找回密码:已知与未知邮箱响应一致(防枚举)',
      knownPage.includes('如果该邮箱已注册') && ghostPage === knownPage);

    const links = [...serverLog.matchAll(/\/reset-password\?token=([A-Za-z0-9_-]+)/g)];
    ok('找回密码:dev 模式日志输出重置链接', links.length > 0);

    const token = links[links.length - 1][1];
    r = await call(pj, `/reset-password?token=${token}`);
    const resetHtml = await r.text();
    const rpf = extractHidden(resetHtml);
    ok('找回密码:重置页渲染新密码表单',
      r.status === 200 && resetHtml.includes('设置新密码') && rpf.token === token && !!rpf._csrf);

    r = await call(pj, '/reset-password', {
      method: 'POST',
      form: { token, _csrf: rpf._csrf, password: 'NewPass#123', password2: 'NewPass#123' },
    });
    ok('找回密码:提交新密码成功', r.status === 200 && (await r.text()).includes('密码已重置'));

    const nj = new Jar();
    r = await call(nj, '/login');
    const nf = extractHidden(await r.text());
    r = await call(nj, '/login', { method: 'POST', form: { username: 'alice', password: 'NewPass#123', _csrf: nf._csrf } });
    ok('找回密码:新密码可登录', r.status === 302 && location(r) === '/');

    const oj = new Jar();
    r = await call(oj, '/login');
    const of0 = extractHidden(await r.text());
    r = await call(oj, '/login', { method: 'POST', form: { username: 'alice', password: 'Alice#12345', _csrf: of0._csrf } });
    ok('找回密码:旧密码已失效', r.status === 401);

    r = await call(new Jar(), '/reset-password?token=bogus-token-xyz');
    ok('找回密码:错误 token 渲染失败页', r.status === 400 && (await r.text()).includes('链接无效'));

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

    /* ---------- 权限组:组成员关系与应用访问控制 ---------- */
    const groupsM = await import('../src/models/groups.js');

    // 迁移播种:bob 的 'dev ops' 自由文本已变为组与成员关系
    const dev = groupsM.byName('dev'), ops = groupsM.byName('ops');
    ok('权限组:迁移播种 user_groups 生成组与成员', !!dev && !!ops
      && groupsM.membersOf(bob.id).includes('dev') && groupsM.membersOf(bob.id).includes('ops'));

    // 组管理页:新建与重名校验
    r = await call(aj, '/admin/groups');
    const gPage = await r.text();
    ok('权限组:侧栏导航与组管理页可访问', r.status === 200 && gPage.includes('权限组') && gPage.includes('新建权限组'));
    const gf = extractHidden(gPage);
    r = await call(aj, '/admin/groups/create', {
      method: 'POST', form: { name: 'contractors', description: '外部承包商', _csrf: gf._csrf },
    });
    ok('权限组:新建组成功', r.status === 302 && location(r).startsWith('/admin/groups?msg=') && !!groupsM.byName('contractors'));
    r = await call(aj, '/admin/groups/create', { method: 'POST', form: { name: 'dev', description: '', _csrf: gf._csrf } });
    ok('权限组:重名组被拒绝', r.status === 302 && location(r).includes('err=')
      && groupsM.list().filter((g) => g.name === 'dev').length === 1);

    // 用户编辑页:组复选框出现并保存到成员关系
    r = await call(aj, `/admin/users/${bob.id}`);
    const bobEditHtml = await r.text();
    ok('权限组:用户编辑页出现组复选框', bobEditHtml.includes('name="groups" value="dev" checked')
      && bobEditHtml.includes('value="ops" checked') && bobEditHtml.includes('value="contractors"'));
    const bef = extractHidden(bobEditHtml);
    r = await call(aj, `/admin/users/${bob.id}/update`, {
      method: 'POST',
      form: [
        ['name', '小明'], ['email', ''], ['is_admin', ''], ['disabled', ''], ['password', ''],
        ['_csrf', bef._csrf], ['groups', 'dev'], ['groups', 'contractors'],
      ],
    });
    ok('权限组:用户组复选框保存到成员关系', r.status === 302
      && JSON.stringify(groupsM.membersOf(bob.id)) === JSON.stringify(['contractors', 'dev']));

    // 应用表单:可访问权限组复选框与不限制说明
    r = await call(aj, '/admin/apps/new');
    const appFormHtml = await r.text();
    ok('权限组:新建应用表单出现限制组复选框', appFormHtml.includes('name="allowed_groups"') && appFormHtml.includes('不勾选'));

    // 限制组的应用:组内用户(bob ∈ dev)正常走授权码流程
    const gApp = clients.create({
      name: 'Groups Only', redirectUris: ['http://127.0.0.1:8080/gcb'],
      scopes: 'openid profile groups', isPublic: true, pkceRequired: true, allowedGroups: ['dev'],
    });
    const gVerifier = crypto.randomBytes(48).toString('base64url');
    const gAuthUrl = '/authorize?' + new URLSearchParams({
      client_id: gApp.client_id, redirect_uri: 'http://127.0.0.1:8080/gcb',
      response_type: 'code', scope: 'openid profile groups',
      state: 'g-st', code_challenge: b64urlSha256(gVerifier), code_challenge_method: 'S256',
    }).toString();

    r = await call(fj, gAuthUrl);
    const gConsentHtml = await r.text();
    ok('权限组:组内用户(∈dev)进入同意页', r.status === 200 && gConsentHtml.includes('请求访问你的账号'));
    const gForm = extractHidden(gConsentHtml);
    r = await call(fj, '/authorize', { method: 'POST', form: { ...gForm, decision: 'approve', remember: 'on' } });
    const gCode = new URL(location(r), BASE).searchParams.get('code');
    ok('权限组:组内用户授权通过并签发 code', r.status === 302 && !!gCode && !location(r).includes('error'));

    // groups claim 改由成员关系表驱动:契约组成员仍可见,已移除的 ops 不再出现
    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: gCode, redirect_uri: 'http://127.0.0.1:8080/gcb',
        client_id: gApp.client_id, code_verifier: gVerifier,
      }).toString(),
    });
    const gTok = await r.json();
    const gUi = await (await fetch(BASE + '/userinfo', { headers: { Authorization: `Bearer ${gTok.access_token}` } })).json();
    ok('权限组:groups claim/userinfo 返回关系表组名', r.status === 200 && Array.isArray(gUi.groups)
      && gUi.groups.includes('dev') && gUi.groups.includes('contractors') && !gUi.groups.includes('ops'));

    // 组外用户(无任何组):渲染 403 风格无权访问页,不重定向回 redirect_uri
    users.create({ username: 'noah', passwordHash: hashPassword('NoahPass#123'), name: '诺亚' });
    const nj2 = new Jar();
    r = await call(nj2, '/login');
    const nfa = extractHidden(await r.text());
    r = await call(nj2, '/login', {
      method: 'POST', form: { username: 'noah', password: 'NoahPass#123', _csrf: nfa._csrf, next: gAuthUrl },
    });
    r = await call(nj2, location(r));
    const deniedHtml = await r.text();
    ok('权限组:组外用户渲染无权访问页(不回跳 redirect_uri)', r.status === 403
      && deniedHtml.includes('无权访问该应用') && deniedHtml.includes('Groups Only') && deniedHtml.includes('dev')
      && location(r) === '');

    // 同一无组用户对未限制应用(allowed_groups='[]')仍可正常授权
    r = await call(nj2, authUrl);
    const nForm = extractHidden(await r.text());
    r = await call(nj2, '/authorize', { method: 'POST', form: { ...nForm, decision: 'approve', remember: 'on' } });
    ok('权限组:未限制应用对所有用户放行', r.status === 302
      && !!new URL(location(r), BASE).searchParams.get('code'));

    // client_credentials 无用户参与,不受组限制影响
    const gSvc = clients.create({
      name: 'Groups Svc', redirectUris: ['http://127.0.0.1:8080/any'],
      scopes: 'openid profile', isPublic: false, pkceRequired: false,
      secretHash: hashPassword('gsvc-secret-456'), allowedGroups: ['dev'],
    });
    r = await fetch(BASE + '/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(gSvc.client_id, 'gsvc-secret-456') },
      body: new URLSearchParams({ grant_type: 'client_credentials' }).toString(),
    });
    ok('权限组:client_credentials 不受组限制影响', r.status === 200 && !!(await r.json()).access_token);

    // 应用详情页展示当前限制组
    r = await call(aj, `/admin/apps/${gApp.client_id}`);
    const gDetail = await r.text();
    ok('权限组:应用详情展示当前限制组', gDetail.includes('可访问的权限组') && /value="dev" checked/.test(gDetail));

    // 删除组:级联解除成员关系,且不再出现在用户编辑表单
    const contractors = groupsM.byName('contractors');
    r = await call(aj, `/admin/groups/${contractors.id}/delete`, { method: 'POST', form: { _csrf: gf._csrf } });
    r = await call(aj, `/admin/users/${bob.id}`);
    const afterDeleteHtml = await r.text();
    ok('权限组:删除组后从列表与用户表单消失', r.status === 200 && !groupsM.byName('contractors')
      && !groupsM.membersOf(bob.id).includes('contractors') && !afterDeleteHtml.includes('contractors'));

    /* ---------- 我的授权:查看/撤销已记住的应用授权 ---------- */
    r = await call(fj, '/account/apps');
    const myAuthHtml = await r.text();
    ok('我的授权:列表页展示已授权的应用与范围', r.status === 200
      && myAuthHtml.includes('Smoke Web') && myAuthHtml.includes('Groups Only') && myAuthHtml.includes('基本资料'));
    r = await call(fj, '/account');
    ok('我的授权:账号页出现入口链接', (await r.text()).includes('/account/apps'));

    r = await fetch(BASE + '/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'svc-secret-123') },
      body: new URLSearchParams({ token: tok4.access_token }).toString(),
    });
    ok('我的授权:撤销前应用令牌仍活跃', (await r.json()).active === true);

    r = await call(fj, '/account/apps');
    const revokeForm = extractHidden(await r.text());
    r = await call(fj, '/account/apps/revoke', {
      method: 'POST',
      form: { client_id: web.client_id, _csrf: revokeForm._csrf },
    });
    ok('我的授权:撤销成功回到列表页', r.status === 302 && location(r).startsWith('/account/apps?msg='));

    r = await call(fj, '/account/apps');
    const afterRevoke = await r.text();
    ok('我的授权:列表中不再出现该应用', r.status === 200 && !afterRevoke.includes('Smoke Web') && afterRevoke.includes('Groups Only'));

    r = await fetch(BASE + '/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'svc-secret-123') },
      body: new URLSearchParams({ token: tok4.access_token }).toString(),
    });
    ok('我的授权:撤销后该应用现有令牌级联失效', (await r.json()).active === false);

    r = await call(fj, authUrl);
    const reConsent = await r.text();
    ok('我的授权:撤销后再次授权需重新确认', r.status === 200 && reConsent.includes('请求访问你的账号'));

    /* ---------- 应用门户:用户可见的业务线与统一登录入口 ---------- */
    r = await call(fj, '/apps');
    const portalHtml = await r.text();
    ok('门户:展示用户可访问的应用', r.status === 200 && portalHtml.includes('Smoke Web')
      && portalHtml.includes('Groups Only') && portalHtml.includes('进入应用'));

    r = await call(nj2, '/apps');
    const noahPortal = await r.text();
    ok('门户:无组用户看不到受限应用', r.status === 200 && noahPortal.includes('Smoke Web')
      && !noahPortal.includes('Groups Only'));

    r = await call(fj, `/apps/launch/${web.client_id}`);
    const launchLoc = location(r);
    ok('门户:启动跳转授权端点并代发 PKCE challenge', r.status === 302
      && launchLoc.startsWith('/authorize?') && launchLoc.includes('code_challenge=')
      && launchLoc.includes('code_challenge_method=S256'));

    r = await call(fj, launchLoc);
    const portalConsent = await r.text();
    ok('门户:启动后进入同意授权页', r.status === 200 && portalConsent.includes('请求访问你的账号'));
    const pForm = extractHidden(portalConsent);
    r = await call(fj, '/authorize', { method: 'POST', form: { ...pForm, decision: 'approve', remember: 'on' } });
    const pCallback = new URL(location(r), BASE);
    ok('门户:同意后携带 code 与 state 回跳应用回调', r.status === 302
      && !!pCallback.searchParams.get('code') && !!pCallback.searchParams.get('state'));

    // 门户代发的授权码:应用无需 code_verifier 即可换取令牌(IdP 委托闭环)
    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: pCallback.searchParams.get('code'),
        redirect_uri: 'http://127.0.0.1:8080/cb', client_id: web.client_id,
      }).toString(),
    });
    const portalTok = await r.json();
    ok('门户:PKCE 应用经门户启动后可无 verifier 换取令牌', r.status === 200 && !!portalTok.access_token,
      JSON.stringify(portalTok).slice(0, 120));

    r = await call(nj2, `/apps/launch/${gApp.client_id}`);
    const noahLaunch = await r.text();
    ok('门户:无权用户启动受限应用被拦截(403)', r.status === 403
      && noahLaunch.includes('仅对特定权限组开放') && noahLaunch.includes('Groups Only'));

    /* ---------- 配置向导增强:管理员重新运行向导(放在最后,尾部恢复 setup_done=1) ---------- */
    r = await call(aj, '/admin');
    const rerunDash = await r.text();
    const rerunForm = extractHidden(rerunDash);
    ok('向导:控制台提供重新运行向导入口', rerunDash.includes('重新运行配置向导') && !!rerunForm._csrf);
    r = await call(aj, '/admin/rerun-wizard', { method: 'POST', form: { _csrf: rerunForm._csrf } });
    ok('向导:管理员触发重跑后跳到 /setup', r.status === 302 && location(r) === '/setup');
    const gated = await call(new Jar(), '/');
    ok('向导:重跑期间普通页面重定向 /setup', gated.status === 302 && location(gated) === '/setup');
    r = await call(wj, '/setup');
    ok('向导:重跑后 /setup 显示第 1 步环境检测', r.status === 200 && (await r.text()).includes('环境检测'));

    await call(wj, '/setup/step1', { method: 'POST', form: {} });
    r = await call(wj, '/setup');
    const wz2 = await r.text();
    ok('向导:第 2 步页面含自助注册与 SMTP 主机', wz2.includes('自助注册') && wz2.includes('SMTP 主机'));
    r = await call(wj, '/setup/step2', {
      method: 'POST',
      form: {
        site_name: '樱落统一认证', issuer: BASE, access_ttl: '900', refresh_ttl: '2592000',
        allow_register: '1', smtp_host: 'smtp.example.com', smtp_port: '587', smtp_from: 'noreply@example.com',
      },
    });
    const wzSettings = settings.getMap();
    ok('向导:第 2 步提交后注册开关与 SMTP 设置生效', r.status === 302
      && wzSettings.allow_register === '1'
      && wzSettings.smtp_host === 'smtp.example.com'
      && wzSettings.smtp_from === 'noreply@example.com');

    r = await call(wj, '/setup');
    const wz3 = await r.text();
    ok('向导:已有账号时第 3 步显示跳过文案', wz3.includes('检测到已有账号'));
    r = await call(wj, '/setup/step3', { method: 'POST', form: { skip: '1' } });
    const wz4 = await r.text();
    ok('向导:跳过创建直接完成配置', r.status === 200 && wz4.includes('配置完成'));
    const homeAfter = await call(new Jar(), '/');
    const regAfter = await call(new Jar(), '/register');
    ok('向导:完成后全站恢复正常且注册开关生效', homeAfter.status === 200 && regAfter.status === 200);

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
