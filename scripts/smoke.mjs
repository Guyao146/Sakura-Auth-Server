/**
 * 冒烟测试:在独立数据目录拉起真实服务,端到端验证
 * 配置向导 → 登录 → 授权码+PKCE → 令牌签发/刷新/内省/吊销 → 管理控制台权限 → 邮件找回密码。
 * 运行:npm run smoke
 */
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
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

async function call(jar, pathOrUrl, { method = 'GET', form, json, headers = {}, raw } = {}) {
  const res = await fetch(pathOrUrl.startsWith('http') ? pathOrUrl : BASE + pathOrUrl, {
    method, redirect: 'manual',
    headers: {
      ...(form ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
      ...(json !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(jar.header() ? { Cookie: jar.header() } : {}),
      ...headers,
    },
    body: raw !== undefined ? raw
      : form ? new URLSearchParams(form).toString()
      : json !== undefined ? JSON.stringify(json) : undefined,
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

/* ---------- 模拟认证器:最小 CBOR 编码 + ES256 手造 attestation/assertion(WebAuthn 段用) ---------- */
/** 最小 CBOR 编码器:仅 map / 数组 / 字节串 / 文本串 / 正负整数(足够构造测试凭据) */
function cborEncode(value) {
  const out = [];
  const head = (mt, val) => {
    if (val < 24) out.push((mt << 5) | val);
    else if (val < 256) out.push((mt << 5) | 24, val);
    else if (val < 65536) out.push((mt << 5) | 25, val >> 8, val & 255);
    else out.push((mt << 5) | 26, (val >>> 24) & 255, (val >>> 16) & 255, (val >>> 8) & 255, val & 255);
  };
  const walk = (v) => {
    if (typeof v === 'number' && v >= 0) head(0, v);
    else if (typeof v === 'number' && v < 0) head(1, -1 - v);
    else if (Buffer.isBuffer(v)) { head(2, v.length); out.push(...v); }
    else if (typeof v === 'string') { const b = Buffer.from(v); head(3, b.length); out.push(...b); }
    else if (Array.isArray(v)) { head(4, v.length); v.forEach(walk); }
    else {
      const ks = Object.keys(v);
      head(5, ks.length);
      for (const k of ks) { walk(/^-?\d+$/.test(k) ? Number(k) : k); walk(v[k]); }
    }
  };
  walk(value);
  return Buffer.from(out);
}
// 测试用 ES256 密钥对与 COSE 公钥(EC2/P-256/ES256,与真实认证器产物同构)
const pkKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pkJwk = pkKeys.publicKey.export({ format: 'jwk' });
const pkCose = cborEncode({
  1: 2, 3: -7, [-1]: 1,
  [-2]: Buffer.from(pkJwk.x, 'base64url'),
  [-3]: Buffer.from(pkJwk.y, 'base64url'),
});
const PK_RP_ID = new URL(BASE).hostname; // 与服务端 rpId(issuer hostname)一致

/** authenticatorData:rpIdHash + flags + signCount(+ attestedCredentialData:仅注册时) */
const makeAuthData = ({ flags = 0x05, counter = 0, credId = null } = {}) => {
  const head = Buffer.alloc(37);
  crypto.createHash('sha256').update(PK_RP_ID).digest().copy(head, 0);
  head[32] = flags;
  head.writeUInt32BE(counter, 33);
  if (!credId) return head;
  const len = Buffer.alloc(2);
  len.writeUInt16BE(credId.length);
  return Buffer.concat([head, Buffer.alloc(16, 0xab), len, credId, pkCose]);
};

/** 注册 attestation(fmt 'none' 或 'packed' 自签):clientDataJSON + attestationObject */
const makeAttestation = ({ challenge, credId, origin = BASE, fmt = 'none' } = {}) => {
  const cd = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin }));
  const authData = makeAuthData({ flags: 0x45, credId });
  let attStmt = {};
  if (fmt === 'packed') {
    attStmt = { alg: -7, sig: crypto.sign('sha256', Buffer.concat([authData, crypto.createHash('sha256').update(cd).digest()]), pkKeys.privateKey) };
  }
  return {
    clientDataJSON: cd.toString('base64url'),
    attestationObject: cborEncode({ fmt, attStmt, authData }).toString('base64url'),
    transports: ['internal'],
  };
};

/** 登录 assertion:对 authData ‖ SHA256(clientDataJSON) 做 ES256 签名 */
const makeAssertion = ({ challenge, credIdB64, counter = 1, origin = BASE, userHandle = '', corrupt = false } = {}) => {
  const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }));
  const authData = makeAuthData({ flags: 0x05, counter });
  let sig = crypto.sign('sha256', Buffer.concat([authData, crypto.createHash('sha256').update(cd).digest()]), pkKeys.privateKey);
  if (corrupt) { sig = Buffer.from(sig); sig[7] ^= 0xff; }
  return {
    id: credIdB64, rawId: credIdB64, type: 'public-key',
    response: {
      clientDataJSON: cd.toString('base64url'),
      authenticatorData: authData.toString('base64url'),
      signature: sig.toString('base64url'),
      userHandle,
    },
  };
};

/* ---------- 本地 mock Microsoft(OIDC 提供方,与被测服务并行运行) ---------- */
function startMockMs({ clientId = 'smoke-ms-client', sub = 'ms-sub-123', email = 'msuser@example.com', name = 'MS 测试用户' } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { kid: 'test-kid', alg: 'RS256', use: 'sig', ...publicKey.export({ format: 'jwk' }) };
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://mock');
    const json = (status, obj) => {
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(obj));
    };
    // 发现文档:测试公钥 JWKS(kid='test-kid')
    if (req.method === 'GET' && url.pathname === '/common/discovery/v2.0/keys') {
      return json(200, { keys: [jwk] });
    }
    const m = url.pathname.match(/^\/([^/]+)\/oauth2\/v2\.0\/(authorize|token)$/);
    if (!m) { res.writeHead(404); res.end(); return; }
    const [, tenantSeg, action] = m;
    if (action === 'authorize') {
      // 原样转发 redirect_uri:由 query 构造回跳地址,携带 code 与 state
      const ru = url.searchParams.get('redirect_uri');
      if (!ru) { res.writeHead(400); res.end('missing redirect_uri'); return; }
      const sep = ru.includes('?') ? '&' : '?';
      res.writeHead(302, {
        Location: `${ru}${sep}code=TESTCODE&state=${encodeURIComponent(url.searchParams.get('state') || '')}`,
      });
      res.end();
      return;
    }
    // token:校验 form 后签发 id_token(iss 规则与 verifyIdToken 保持一致)
    let raw = '';
    for await (const ch of req) raw += ch;
    const form = new URLSearchParams(raw);
    if (form.get('grant_type') !== 'authorization_code' || form.get('client_id') !== clientId
      || !form.get('code') || !form.get('code_verifier')) {
      return json(400, { error: 'invalid_grant', error_description: 'mock: 表单校验失败' });
    }
    const authority = `http://127.0.0.1:${server.address().port}`;
    const header = b64u({ alg: 'RS256', typ: 'JWT', kid: 'test-kid' });
    const now = Math.floor(Date.now() / 1000);
    const payload = b64u({
      iss: `${authority}/${tenantSeg}/v2.0`, sub, email, preferred_username: email, name,
      aud: clientId, iat: now, exp: now + 3600,
    });
    const sig = crypto.createSign('RSA-SHA256').update(`${header}.${payload}`).sign(privateKey, 'base64url');
    return json(200, {
      access_token: 'mock-access', token_type: 'Bearer', expires_in: 3600,
      id_token: `${header}.${payload}.${sig}`,
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '0.0.0.0', () => {
      const port = server.address().port;
      resolve({
        authority: `http://127.0.0.1:${port}`,
        close: () => { server.closeAllConnections(); return new Promise((r) => server.close(r)); },
      });
    });
  });
}

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

  let msMock = null;
  try {
    let ready = false;
    for (let i = 0; i < 120 && !ready; i++) {
      try { ready = (await fetch(BASE + '/healthz')).ok; } catch { await sleep(150); }
    }
    ok('服务启动并响应 /healthz', ready);
    if (!ready) { console.log(serverLog.slice(-2000)); return; }

    // 本地 mock Microsoft(0.0.0.0 随机端口),供 MS 登录链路联调
    msMock = await startMockMs();

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
    r = await call(new Jar(), '/health');
    ok('健康:未初始化时 /health 在白名单内可直接访问', r.status === 200
      && (await r.text()).includes('服务运行中'));
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

    /* ---------- 登录流转:首页跳转约定 ---------- */
    const anonHome = await call(new Jar(), '/');
    ok('流转:未登录访问首页重定向登录页', anonHome.status === 302 && location(anonHome) === '/login');

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

    // 加固(OIDC Core §3.1.2.1):prompt=none 未登录不跳登录页,直接回跳 login_required 并透传 state
    const pnAnon = await call(new Jar(), authUrl + '&prompt=none');
    ok('加固:prompt=none 未登录回跳 login_required 并透传 state', pnAnon.status === 302
      && new URL(location(pnAnon), BASE).searchParams.get('error') === 'login_required'
      && new URL(location(pnAnon), BASE).searchParams.get('state') === state, location(pnAnon));

    r = await call(uj, location(r));
    const loginHtml = await r.text();
    const loginForm = extractHidden(loginHtml);
    ok('登录页带 CSRF', !!loginForm._csrf);
    ok('登录页含品牌面板与产品口号文案', loginHtml.includes('login-brand')
      && loginHtml.includes('管好你所有系统的登录') && loginHtml.includes('统一登录'));
    ok('登录页保留登录表单与 CSRF/next 兼容字段', loginHtml.includes('action="/login"')
      && loginHtml.includes('name="next"') && loginHtml.includes('autocomplete="current-password"'));
    ok('登录页使用分栏品牌样式与窄屏断点', loginHtml.includes('.login-split')
      && loginHtml.includes('@media(max-width:899px)'));
    ok('顶栏:登录品牌面板垂直居中且内容左对齐', /login-brand-body\{[^}]*justify-content:center/.test(loginHtml)
      && /login-brand-body\{[^}]*align-items:flex-start/.test(loginHtml)
      && /login-brand-body\{[^}]*text-align:left/.test(loginHtml)
      && /login-brand-feats li\{[^}]*align-items:flex-start/.test(loginHtml));

    r = await call(uj, '/login', {
      method: 'POST',
      form: { username: 'bob', password: 'BobPassw0rd!', _csrf: loginForm._csrf, next: authUrl },
    });
    ok('登录成功回到 /authorize', r.status === 302 && location(r).startsWith('/authorize?'));

    const loginWhileIn = await call(uj, '/login');
    ok('流转:已登录访问 /login(无 next)重定向门户', loginWhileIn.status === 302
      && location(loginWhileIn) === '/apps');

    r = await call(uj, location(r));
    const consentHtml = await r.text();
    const consentForm = extractHidden(consentHtml);
    ok('渲染同意授权页', consentHtml.includes('请求访问你的账号'));
    ok('授权页:品牌化分栏布局与品牌面板口号/特性文案(与登录页统一)', consentHtml.includes('class="login-split"')
      && consentHtml.includes('class="login-brand"')
      && consentHtml.includes('确认授权,一键进入应用')
      && consentHtml.includes('统一登录') && consentHtml.includes('权限组管控'));
    ok('授权页:首字母徽标回退、client_id 与身份胶囊展示', consentHtml.includes('class="app-badge"')
      && consentHtml.includes(web.client_id) && consentHtml.includes('的身份继续'));
    ok('授权页:记住授权勾选、拒绝/同意按钮与跳转目标提示保留', consentHtml.includes('name="remember"')
      && consentHtml.includes('value="deny"') && consentHtml.includes('value="approve"')
      && consentHtml.includes('完成登录'));

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
    // OIDC Core §3.1.3.6:at_hash = access token SHA-256 摘要左半(16 字节)的 base64url(22 字符)
    const expectAtHash = crypto.createHash('sha256').update(tok.access_token).digest().subarray(0, 16).toString('base64url');
    ok('id_token 的 at_hash 为 access token SHA-256 左半摘要', idPayload.at_hash === expectAtHash
      && idPayload.at_hash.length === 22, `got=${idPayload.at_hash} want=${expectAtHash}`);

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

    // PKCE verifier 字符集校验(RFC 7636 §4.1):plain 模式下 challenge 含 unreserved 之外的字符,
    // 换取时 verifier 必须被字符集校验拒绝
    r = await call(uj, '/authorize?' + new URLSearchParams({
      client_id: web.client_id, redirect_uri: 'http://127.0.0.1:8080/cb',
      response_type: 'code', scope: 'openid profile', state: 'pkce-cs',
      code_challenge: 'a'.repeat(42) + '+', code_challenge_method: 'plain',
    }).toString());
    const codeCs = new URL(location(r), BASE).searchParams.get('code');
    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: codeCs, redirect_uri: 'http://127.0.0.1:8080/cb',
        client_id: web.client_id, code_verifier: 'a'.repeat(42) + '+',
      }).toString(),
    });
    ok('PKCE:verifier 含 RFC 7636 之外的字符被拒绝', r.status === 400 && (await r.json()).error === 'invalid_grant');

    /* ---------- 加固:code_challenge 前置格式校验 / prompt=none / verifier 回退边界 ---------- */
    // RFC 7636 §4.1:challenge 须为 43-128 位 base64url;长度不足在 authorize 层直接 invalid_request 回跳
    r = await call(uj, '/authorize?' + new URLSearchParams({
      client_id: web.client_id, redirect_uri: 'http://127.0.0.1:8080/cb',
      response_type: 'code', scope: 'openid profile', state: 'cc-short',
      code_challenge: 'a'.repeat(42), code_challenge_method: 'S256',
    }).toString());
    ok('加固:code_challenge 长度不足 43 回跳 invalid_request 并透传 state', r.status === 302
      && new URL(location(r), BASE).searchParams.get('error') === 'invalid_request'
      && new URL(location(r), BASE).searchParams.get('state') === 'cc-short', location(r));
    // base64url 字符集之外的 challenge 同样被前置拒绝(不再发码)
    r = await call(uj, '/authorize?' + new URLSearchParams({
      client_id: web.client_id, redirect_uri: 'http://127.0.0.1:8080/cb',
      response_type: 'code', scope: 'openid profile', state: 'cc-charset',
      code_challenge: 'a'.repeat(42) + '+', code_challenge_method: 'plain',
    }).toString());
    ok('加固:code_challenge 含 base64url 之外字符回跳 invalid_request(不发码)', r.status === 302
      && new URL(location(r), BASE).searchParams.get('error') === 'invalid_request'
      && !new URL(location(r), BASE).searchParams.get('code'), location(r));

    // OIDC Core §3.1.2.1:已记住授权时 prompt=none 无需任何交互,直接发码
    r = await call(uj, authUrl + '&prompt=none');
    ok('加固:prompt=none 已记住授权正常发码(无交互)', r.status === 302
      && !!new URL(location(r), BASE).searchParams.get('code') && !location(r).includes('error'), location(r));

    // 未记住授权的新应用:prompt=none 需要同意确认 → consent_required 回跳
    const hardApp = clients.create({
      name: '加固 Consent', redirectUris: ['http://127.0.0.1:8080/hard'],
      scopes: 'openid profile', isPublic: true, pkceRequired: true,
    });
    const hardVerifier = crypto.randomBytes(48).toString('base64url');
    const hardUrl = '/authorize?' + new URLSearchParams({
      client_id: hardApp.client_id, redirect_uri: 'http://127.0.0.1:8080/hard',
      response_type: 'code', scope: 'openid profile', state: 'pn-consent',
      code_challenge: b64urlSha256(hardVerifier), code_challenge_method: 'S256',
    }).toString();
    r = await call(uj, hardUrl + '&prompt=none');
    ok('加固:prompt=none 需要同意(无记住授权)回跳 consent_required 并透传 state', r.status === 302
      && new URL(location(r), BASE).searchParams.get('error') === 'consent_required'
      && new URL(location(r), BASE).searchParams.get('state') === 'pn-consent', location(r));
    // 正常走一次同意并记住授权,prompt=none 随即可静默发码
    r = await call(uj, hardUrl);
    const hardForm = extractHidden(await r.text());
    r = await call(uj, '/authorize', { method: 'POST', form: { ...hardForm, decision: 'approve', remember: 'on' } });
    ok('加固:记住授权后 prompt=none 可静默发码', r.status === 302
      && !!new URL(location(r), BASE).searchParams.get('code') && !location(r).includes('error'), location(r));

    // 门户代发 verifier 回退仅对门户启动生效(回归):直连授权码换令牌缺 verifier 必须被拒
    r = await call(uj, authUrl);
    const noVfCode = new URL(location(r), BASE).searchParams.get('code');
    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: noVfCode, redirect_uri: 'http://127.0.0.1:8080/cb',
        client_id: web.client_id,
      }).toString(),
    });
    ok('加固:launch_verifier 回退仅限门户代发,直连授权码缺 verifier 被拒', r.status === 400
      && (await r.json()).error === 'invalid_grant');

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

    // 加固(RFC 6750 §2.3):userinfo 收紧为只认 Bearer 头,查询参数/表单主体的 access_token 一律 401
    r = await fetch(BASE + '/userinfo?access_token=' + encodeURIComponent(tok4.access_token));
    ok('加固:userinfo 查询参数 access_token 被拒(401)', r.status === 401, `status=${r.status}`);
    r = await fetch(BASE + '/userinfo', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ access_token: tok4.access_token }).toString(),
    });
    ok('加固:userinfo 表单主体 access_token 被拒(401)', r.status === 401, `status=${r.status}`);
    r = await fetch(BASE + '/userinfo', {
      method: 'POST', headers: { Authorization: `Bearer ${tok4.access_token}` },
    });
    ok('加固:userinfo Bearer 头 POST 访问不受影响(回归)', r.status === 200
      && (await r.json()).preferred_username === 'bob');

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

    /* ---------- 加固:refresh 吊销级联撤销同链令牌(RFC 7009) ---------- */
    // 造链:记住授权直接发码 → 换首对令牌(生成 chain_id)→ 刷新(沿用链)→ 吊销新 refresh → 链上旧 access 一并失效
    r = await call(uj, authUrl);
    const chainCode = new URL(location(r), BASE).searchParams.get('code');
    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: chainCode, redirect_uri: 'http://127.0.0.1:8080/cb',
        client_id: web.client_id, code_verifier: verifier,
      }).toString(),
    });
    const chainTok1 = await r.json();
    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token', refresh_token: chainTok1.refresh_token, client_id: web.client_id,
      }).toString(),
    });
    const chainTok2 = await r.json();
    ok('加固:刷新成功取得同链新令牌对', r.status === 200 && !!chainTok2.access_token && !!chainTok2.refresh_token);
    r = await fetch(BASE + '/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'svc-secret-123') },
      body: new URLSearchParams({ token: chainTok1.access_token }).toString(),
    });
    ok('加固:链上首对 access token 初始为活跃', r.status === 200 && (await r.json()).active === true);
    r = await fetch(BASE + '/revoke', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: chainTok2.refresh_token, client_id: web.client_id }).toString(),
    });
    ok('加固:所属客户端吊销刷新后的 refresh token 返回 200', r.status === 200);
    r = await fetch(BASE + '/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'svc-secret-123') },
      body: new URLSearchParams({ token: chainTok1.access_token }).toString(),
    });
    ok('加固:吊销 refresh 后链上旧 access token 内省 active=false', r.status === 200
      && (await r.json()).active === false);
    r = await fetch(BASE + '/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'svc-secret-123') },
      body: new URLSearchParams({ token: chainTok2.access_token }).toString(),
    });
    ok('加固:吊销 refresh 后链上新 access token 同样级联失效', r.status === 200
      && (await r.json()).active === false);

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
    // RFC 6749 §5.2:经 Authorization 头认证失败,401 必须携带匹配方案的 WWW-Authenticate
    ok('Basic 认证失败时 401 携带 WWW-Authenticate 挑战(RFC 6749 §5.2)',
      (r.headers.get('www-authenticate') || '').startsWith('Basic'));

    // RFC 6749 §2.3.1:Basic 的用户名/密码为 application/x-www-form-urlencoded 编码,
    // 含特殊字符的 client_secret 以编码形式提交时必须被正确解码
    const encApp = clients.create({
      name: 'Smoke Encoded', redirectUris: ['http://127.0.0.1:8080/enc'],
      scopes: 'openid', isPublic: false, pkceRequired: false,
      secretHash: hashPassword('svc%sec@123'),
    });
    r = await fetch(BASE + '/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(encApp.client_id, encodeURIComponent('svc%sec@123')) },
      body: new URLSearchParams({ grant_type: 'client_credentials' }).toString(),
    });
    ok('Basic 认证:client_secret 的表单编码(RFC 6749 §2.3.1)被正确解码', r.status === 200 && !!(await r.json()).access_token);

    // 加固(RFC 6749 §2.3.1):同一请求混用 Basic 头与表单 client_secret 属于重复认证,必须拒绝
    r = await fetch(BASE + '/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'svc-secret-123') },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_secret: 'svc-secret-123' }).toString(),
    });
    ok('加固:Basic 头与表单 client_secret 混用被拒(invalid_request)', r.status === 400
      && (await r.json()).error === 'invalid_request', `status=${r.status}`);

    /* ---------- 登录流转:无 next 登录直达门户,登出回登录页带提示 ---------- */
    const qj = new Jar();
    r = await call(qj, '/login');
    const qf = extractHidden(await r.text());
    r = await call(qj, '/login', { method: 'POST', form: { username: 'bob', password: 'BobPassw0rd!', _csrf: qf._csrf } });
    ok('流转:无 next 登录成功直达门户 /apps', r.status === 302 && location(r) === '/apps');
    r = await call(qj, '/logout');
    const qlo = extractHidden(await r.text());
    r = await call(qj, '/logout', { method: 'POST', form: { _csrf: qlo._csrf } });
    ok('流转:登出重定向登录页并携带提示参数', r.status === 302
      && location(r) === '/login?msg=' + encodeURIComponent('已退出登录'));
    r = await call(qj, location(r));
    ok('流转:登录页渲染「已退出登录」提示横幅', r.status === 200 && (await r.text()).includes('已退出登录'));

    /* ---------- 主题切换:back 参数防开放重定向 ---------- */
    r = await call(new Jar(), '/-/theme/night?back=' + encodeURIComponent('/apps'));
    ok('主题:正常 back 参数回到站内页面并写入主题 cookie', r.status === 302 && location(r) === '/apps'
      && (r.headers.getSetCookie?.() || []).some((c) => c.startsWith('theme=night')));
    // 反斜杠会被部分浏览器规范化为 /,使 /\evil.com 成为协议相对地址 → 必须落到首页
    r = await call(new Jar(), '/-/theme/day?back=' + encodeURIComponent('/\\evil.com'));
    ok('主题:反斜杠 back 参数被拒(防协议相对开放重定向)', r.status === 302 && location(r) === '/');
    r = await call(new Jar(), '/-/theme/day?back=' + encodeURIComponent('//evil.com'));
    ok('主题:协议相对 back 参数被拒', r.status === 302 && location(r) === '/');

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
    ok('正确 TOTP 完成登录', r.status === 302 && location(r) === '/apps');

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
    let adminCsrf = extractHidden(await (await call(aj, '/admin')).text())._csrf; // 管理员会话 CSRF(新建用户/应用等写表单共用;重登后需刷新)

    // 缺少会话 CSRF 的新建请求一律拒绝(与其它管理端写操作同标准)
    r = await call(aj, '/admin/users/create', { method: 'POST', form: { username: 'csrfless', password: 'Csrf#12345' } });
    ok('管理端:新建用户缺 CSRF 被拒', r.status === 302 && location(r).startsWith('/admin/users/new?err=') && !users.byUsername('csrfless'));
    r = await call(aj, '/admin/apps/create', { method: 'POST', form: { name: 'Csrfless App', redirect_uris: 'http://127.0.0.1:8080/x', scopes: 'openid' } });
    ok('管理端:新建应用缺 CSRF 被拒', r.status === 302 && location(r).startsWith('/admin/apps/new?err='));
    r = await call(aj, '/admin/users/new');
    ok('管理端:新建用户表单携带 CSRF 隐藏字段', r.status === 200 && !!extractHidden(await r.text())._csrf);

    r = await call(aj, '/admin/users/create', {
      method: 'POST',
      form: { username: 'alice', password: 'Alice#12345', name: '爱丽丝', email: 'alice@example.com', user_groups: 'dev', is_admin: '', _csrf: adminCsrf },
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
    adminCsrf = extractHidden(await (await call(aj, '/admin')).text())._csrf; // 重登产生新会话,刷新会话 CSRF
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
    ok('找回密码:新密码可登录', r.status === 302 && location(r) === '/apps');

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
    ok('自助注册:注册成功并自动登录', r.status === 302 && location(r) === '/apps');
    r = await call(rj, '/account');
    const carolAcct = await r.text();
    ok('自助注册:新会话可访问账号页并显示新用户名', r.status === 200 && carolAcct.includes('carol'));
    ok('布局:普通用户侧栏不含管理入口但含门户与授权', r.status === 200
      && !carolAcct.includes('href="/admin/users"') && !carolAcct.includes('href="/admin/groups"')
      && !carolAcct.includes('href="/admin/apps"') && !carolAcct.includes('href="/admin"')
      && carolAcct.includes('应用门户') && carolAcct.includes('我的授权'));
    ok('布局:账号页并入侧栏且保留账号信息/改密/两步验证区块', r.status === 200
      && carolAcct.includes('class="side"') && carolAcct.includes('账号信息')
      && carolAcct.includes('修改密码') && carolAcct.includes('两步验证'));
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

    // 大小写变体同样视为重复(username 列 UNIQUE COLLATE NOCASE,查重走 COLLATE NOCASE)
    r = await call(dj, '/register', {
      method: 'POST',
      form: { username: 'CAROL', password: 'Carol#12345', password2: 'Carol#12345', _csrf: dupForm._csrf },
    });
    ok('自助注册:大小写变体用户名同样被拒(COLLATE NOCASE)', r.status === 400
      && (await r.text()).includes('用户名已存在')
      && users.list().filter((u) => u.username === 'CAROL').length === 0);

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
    ok('布局:管理员侧栏含全部管理项与「我的」分组', r.status === 200
      && ['href="/admin"', 'href="/admin/users"', 'href="/admin/apps"', 'href="/admin/groups"'].every((h) => gPage.includes(h))
      && gPage.includes('账号设置') && gPage.includes('应用门户') && gPage.includes('我的授权'));
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
    // POST /authorize 直发绕过:PKCE 必选应用缺少 code_challenge 时必须拒绝(与 GET 同约束)
    r = await call(fj, '/authorize', {
      method: 'POST',
      form: {
        _csrf: gForm._csrf, response_type: 'code', client_id: web.client_id,
        redirect_uri: 'http://127.0.0.1:8080/cb', decision: 'approve', state: 'bypass-st',
      },
    });
    ok('POST /authorize:PKCE 必选应用缺少 code_challenge 被拒', r.status === 302
      && new URL(location(r), BASE).searchParams.get('error') === 'invalid_request', location(r));
    // 错误重定向(RFC 6749 §4.1.2.1):拒绝授权必须 302 回跳并携带 error=access_denied 与 state
    r = await call(fj, '/authorize', {
      method: 'POST',
      form: {
        _csrf: gForm._csrf, response_type: 'code', client_id: svc.client_id,
        redirect_uri: 'http://127.0.0.1:8080/any', decision: 'deny', state: 'deny-st',
      },
    });
    ok('POST /authorize:拒绝授权回跳 error=access_denied 并透传 state', r.status === 302
      && new URL(location(r), BASE).searchParams.get('error') === 'access_denied'
      && new URL(location(r), BASE).searchParams.get('state') === 'deny-st', location(r));
    // GET 侧错误重定向:response_type 非法时 302 携带 error 而非 500
    r = await call(fj, '/authorize?' + new URLSearchParams({
      client_id: web.client_id, redirect_uri: 'http://127.0.0.1:8080/cb',
      response_type: 'token', state: 'bad-rt',
    }).toString());
    ok('GET /authorize:非法 response_type 回跳 error=unsupported_response_type', r.status === 302
      && new URL(location(r), BASE).searchParams.get('error') === 'unsupported_response_type'
      && new URL(location(r), BASE).searchParams.get('state') === 'bad-rt', location(r));
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

    /* ---------- 组详情:管理员默认组 + 成员管理 + 组维度应用授权 ---------- */
    const { seedDefaultAdminGroup } = await import('../src/core/db.js');
    const noah = users.byUsername('noah');
    const carolUser = users.byUsername('carol');

    // 管理员默认组种子:向导创建的 admin 在种子阶段补入 admin 组(幂等)
    const seedFirst = seedDefaultAdminGroup();
    const adminUser = users.byUsername('admin');
    ok('组详情:默认组种子后 admin 组存在且管理员是成员', seedFirst === 1
      && !!groupsM.byName('admin') && groupsM.membersOf(adminUser.id).includes('admin'));
    ok('组详情:默认组种子幂等(重跑不再新增)', seedDefaultAdminGroup() === 0
      && groupsM.membersOf(adminUser.id).filter((n) => n === 'admin').length === 1);

    // 组详情页基本结构与组信息编辑
    const devGroup = groupsM.byName('dev');
    const opsGroup = groupsM.byName('ops');
    r = await call(aj, `/admin/groups/${devGroup.id}`);
    const devDetail = await r.text();
    ok('组详情:详情页可访问且含成员/应用/编辑卡片', r.status === 200 && devDetail.includes('可访问的应用')
      && devDetail.includes('添加成员') && devDetail.includes('编辑组信息') && devDetail.includes('返回权限组列表'));
    const devForm = extractHidden(devDetail);
    r = await call(aj, `/admin/groups/${devGroup.id}/update`, {
      method: 'POST', form: { name: 'dev', description: '开发组', _csrf: devForm._csrf },
    });
    ok('组详情:组信息更新成功', r.status === 302 && location(r).startsWith(`/admin/groups/${devGroup.id}?msg=`)
      && groupsM.byName('dev').description === '开发组');
    r = await call(aj, `/admin/groups/${devGroup.id}`);
    ok('组详情:页头展示组名与描述', r.status === 200 && (await r.text()).includes('开发组'));
    r = await call(aj, `/admin/groups/${devGroup.id}/update`, {
      method: 'POST', form: { name: 'ops', description: '', _csrf: devForm._csrf },
    });
    ok('组详情:组重命名重名被拒', r.status === 302 && location(r).includes('err=') && !!groupsM.byName('dev'));

    // 加固:组名大小写不敏感唯一('DEV' vs 'dev' 视为重名;重命名同理,自身大小写变更允许)
    r = await call(aj, '/admin/groups/create', { method: 'POST', form: { name: 'DEV', description: '', _csrf: gf._csrf } });
    ok('加固:新建组大小写变体重名被拒(DEV vs dev)', r.status === 302 && location(r).includes('err=')
      && groupsM.list().filter((g) => g.name.toLowerCase() === 'dev').length === 1);
    r = await call(aj, `/admin/groups/${devGroup.id}/update`, { method: 'POST', form: { name: 'OPS', description: '', _csrf: devForm._csrf } });
    ok('加固:组重命名大小写变体被拒(OPS vs ops)', r.status === 302 && location(r).includes('err=')
      && !!groupsM.byName('dev') && !groupsM.byName('OPS'));

    // 成员管理:ops 组为空组,先验证空状态,再批量添加与移除
    r = await call(aj, `/admin/groups/${opsGroup.id}`);
    const opsEmpty = await r.text();
    ok('组详情:空组显示空成员状态并列出候选用户', r.status === 200 && opsEmpty.includes('该组还没有成员')
      && opsEmpty.includes(`name="users" value="${noah.id}"`));
    const opsForm = extractHidden(opsEmpty);
    r = await call(aj, `/admin/groups/${opsGroup.id}/members`, {
      method: 'POST', form: [['users', noah.id], ['users', carolUser.id], ['_csrf', opsForm._csrf]],
    });
    ok('组详情:批量添加成员生效', r.status === 302 && location(r).startsWith(`/admin/groups/${opsGroup.id}?msg=`)
      && groupsM.membersOf(noah.id).includes('ops') && groupsM.membersOf(carolUser.id).includes('ops'));
    r = await call(aj, `/admin/groups/${opsGroup.id}/members/remove`, {
      method: 'POST', form: { user_id: noah.id, _csrf: opsForm._csrf },
    });
    ok('组详情:移除成员生效', r.status === 302 && location(r).startsWith(`/admin/groups/${opsGroup.id}?msg=`)
      && !groupsM.membersOf(noah.id).includes('ops') && groupsM.membersOf(carolUser.id).includes('ops'));

    // 组维度应用授权:dev 组视角(Groups Only 限 dev;Detail Locked 限 dev+ops;Contractor Zone 限 ops)
    const detailLocked = clients.create({
      name: 'Detail Locked', redirectUris: ['http://127.0.0.1:8080/dl'],
      scopes: 'openid profile', isPublic: true, pkceRequired: true, allowedGroups: ['dev', 'ops'],
    });
    const contractorZone = clients.create({
      name: 'Contractor Zone', redirectUris: ['http://127.0.0.1:8080/cz'],
      scopes: 'openid profile', isPublic: true, pkceRequired: true, allowedGroups: ['ops'],
    });
    r = await call(aj, `/admin/groups/${devGroup.id}`);
    const devApps = await r.text();
    const appRow = (html, from, to) => html.slice(html.indexOf(from), to ? html.indexOf(to) : undefined);
    const webRow = appRow(devApps, 'Smoke Web', 'Smoke Service');
    ok('组详情:不受限应用显示「不受限」且无操作按钮', webRow.includes('不受限(所有用户可访问)')
      && !webRow.includes('授权本组') && !webRow.includes('移除授权') && !webRow.includes('method="post"'));
    const gAppRow = appRow(devApps, 'Groups Only', 'Groups Svc');
    ok('组详情:受限且已授权应用显示「已授权」并提供移除授权', gAppRow.includes('已授权')
      && gAppRow.includes('移除授权') && gAppRow.includes('value="revoke"'));
    const czRow = appRow(devApps, 'Contractor Zone');
    ok('组详情:受限未授权应用显示「未授权」并提供授权本组', czRow.includes('未授权')
      && czRow.includes('授权本组') && czRow.includes('value="grant"'));

    // 授权本组:Contractor Zone(限 ops)加入 dev → allowed_groups 生效,bob(∈dev)可进同意页
    const devAppsForm = extractHidden(devApps);
    r = await call(aj, `/admin/groups/${devGroup.id}/apps`, {
      method: 'POST', form: { client_id: contractorZone.client_id, action: 'grant', _csrf: devAppsForm._csrf },
    });
    ok('组详情:授权本组后 allowed_groups 生效', r.status === 302 && location(r).startsWith(`/admin/groups/${devGroup.id}?msg=`)
      && clients.allowedGroupNames(clients.byId(contractorZone.client_id)).includes('dev'));
    const czVerifier = crypto.randomBytes(48).toString('base64url');
    const czAuthUrl = '/authorize?' + new URLSearchParams({
      client_id: contractorZone.client_id, redirect_uri: 'http://127.0.0.1:8080/cz',
      response_type: 'code', scope: 'openid profile', state: 'cz-st',
      code_challenge: b64urlSha256(czVerifier), code_challenge_method: 'S256',
    }).toString();
    r = await call(fj, czAuthUrl);
    ok('组详情:授权后组内用户可进入同意页', r.status === 200 && (await r.text()).includes('请求访问你的账号'));

    // 移除授权:Detail Locked(dev+ops)移除 dev → 剩 ops,bob(∉ops)被拒
    r = await call(aj, `/admin/groups/${devGroup.id}/apps`, {
      method: 'POST', form: { client_id: detailLocked.client_id, action: 'revoke', _csrf: devAppsForm._csrf },
    });
    ok('组详情:移除授权后 allowed_groups 不再含本组', r.status === 302 && location(r).startsWith(`/admin/groups/${devGroup.id}?msg=`)
      && JSON.stringify(clients.allowedGroupNames(clients.byId(detailLocked.client_id))) === JSON.stringify(['ops']));
    const dlVerifier = crypto.randomBytes(48).toString('base64url');
    const dlAuthUrl = '/authorize?' + new URLSearchParams({
      client_id: detailLocked.client_id, redirect_uri: 'http://127.0.0.1:8080/dl',
      response_type: 'code', scope: 'openid profile', state: 'dl-st',
      code_challenge: b64urlSha256(dlVerifier), code_challenge_method: 'S256',
    }).toString();
    r = await call(fj, dlAuthUrl);
    ok('组详情:移除授权后组内用户被拒(无权访问页)', r.status === 403 && (await r.text()).includes('无权访问该应用'));

    /* ---------- 我的授权:查看/撤销已记住的应用授权 ---------- */
    r = await call(fj, '/account/apps');
    const myAuthHtml = await r.text();
    ok('我的授权:列表页展示已授权的应用与范围', r.status === 200
      && myAuthHtml.includes('Smoke Web') && myAuthHtml.includes('Groups Only') && myAuthHtml.includes('基本资料'));
    r = await call(fj, '/account');
    ok('我的授权:账号页出现入口链接', (await r.text()).includes('/account/apps'));

    // 链式吊销(RFC 7009)已使 tok4 所在链的令牌全部失效;签发一对新令牌作为撤销授权的对照样本
    r = await call(fj, authUrl);
    const cnsCode = new URL(location(r), BASE).searchParams.get('code');
    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: cnsCode, redirect_uri: 'http://127.0.0.1:8080/cb',
        client_id: web.client_id, code_verifier: verifier,
      }).toString(),
    });
    const cnsTok = await r.json();

    r = await fetch(BASE + '/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'svc-secret-123') },
      body: new URLSearchParams({ token: cnsTok.access_token }).toString(),
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
      body: new URLSearchParams({ token: cnsTok.access_token }).toString(),
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
    ok('布局:门户页并入侧栏并保留磁贴网格', r.status === 200 && portalHtml.includes('portal-grid')
      && portalHtml.includes('class="side"') && portalHtml.includes('账号设置') && portalHtml.includes('我的授权'));

    r = await call(nj2, '/apps');
    const noahPortal = await r.text();
    ok('门户:无组用户看不到受限应用', r.status === 200 && noahPortal.includes('Smoke Web')
      && !noahPortal.includes('Groups Only'));

    /* ---------- 顶栏:门户右上角管理入口(仅管理员可见) ---------- */
    r = await call(aj, '/apps');
    const adminPortalHtml = await r.text();
    ok('顶栏:管理员门户右上角渲染管理后台入口', r.status === 200
      && adminPortalHtml.includes('class="main-head"')
      && adminPortalHtml.includes('<a class="btn btn-primary" href="/admin">管理后台</a>'));
    ok('顶栏:普通用户门户有视图切换但无管理后台入口', noahPortal.includes('class="side"')
      && noahPortal.includes('main-head') && noahPortal.includes('格子显示')
      && !noahPortal.includes('管理后台'));
    r = await call(aj, '/admin');
    ok('顶栏:未传 actions 的其它页面不渲染顶栏', r.status === 200 && !(await r.text()).includes('class="main-head"'));

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

    // 连续启动:先后启动两个 PKCE 应用,先启动应用的 verifier 不应被后启动的覆盖
    r = await call(fj, `/apps/launch/${web.client_id}`);
    const firstLaunch = location(r);
    r = await call(fj, `/apps/launch/${gApp.client_id}`);
    ok('门户:连续启动第二个应用进入授权流程', r.status === 302 && location(r).startsWith('/authorize?'));
    r = await call(fj, firstLaunch); // 已记住授权,直接发码
    const firstCb = new URL(location(r), BASE);
    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: firstCb.searchParams.get('code'),
        redirect_uri: 'http://127.0.0.1:8080/cb', client_id: web.client_id,
      }).toString(),
    });
    const firstTok = await r.json();
    ok('门户:连发两个应用后先启动的仍可无 verifier 换令牌(verifier 不被覆盖)',
      r.status === 200 && !!firstTok.access_token, JSON.stringify(firstTok).slice(0, 120));

    r = await call(nj2, `/apps/launch/${gApp.client_id}`);
    const noahLaunch = await r.text();
    ok('门户:无权用户启动受限应用被拦截(403)', r.status === 403
      && noahLaunch.includes('仅对特定权限组开放') && noahLaunch.includes('Groups Only'));

    /* ---------- 应用元数据(描述/Logo)与应用授权用户管理 ---------- */
    // 新建应用表单提供描述与 Logo 输入
    r = await call(aj, '/admin/apps/new');
    const metaFormHtml = await r.text();
    ok('应用信息:新建应用表单提供描述与 Logo 输入', r.status === 200
      && metaFormHtml.includes('name="description"') && metaFormHtml.includes('name="logo_url"')
      && metaFormHtml.includes('展示在门户与授权页'));

    // 通过表单创建带描述与 Logo 的应用(公开客户端),详情页回显
    r = await call(aj, '/admin/apps/create', {
      method: 'POST',
      form: [
        ['name', 'Meta Portal'], ['client_type', 'public'],
        ['redirect_uris', 'http://127.0.0.1:8080/meta'],
        ['scopes', 'openid'], ['scopes', 'profile'],
        ['description', '统一运维入口,一站聚合所有工具'],
        ['logo_url', 'https://cdn.example.com/logo.png'],
        ['require_consent', '1'],
        ['_csrf', adminCsrf],
      ],
    });
    ok('应用信息:创建带描述与 Logo 的应用成功', r.status === 302
      && location(r).startsWith('/admin/apps/') && location(r).includes('msg='));
    const metaId = new URL(location(r), BASE).pathname.split('/').pop();
    r = await call(aj, `/admin/apps/${metaId}`);
    let metaDetail = await r.text();
    ok('应用信息:详情页回显描述与 Logo', r.status === 200
      && metaDetail.includes('统一运维入口,一站聚合所有工具')
      && metaDetail.includes('https://cdn.example.com/logo.png')
      && metaDetail.includes('已授权用户'));

    // 非 https 的 Logo 地址被拒绝(http:// 不合法)
    r = await call(aj, '/admin/apps/create', {
      method: 'POST',
      form: {
        name: 'Bad Logo App', client_type: 'public',
        redirect_uris: 'http://127.0.0.1:8080/bad', scopes: 'openid',
        logo_url: 'http://cdn.example.com/x.png', _csrf: adminCsrf,
      },
    });
    ok('应用信息:非 https Logo 地址被拒绝', r.status === 200 && (await r.text()).includes('Logo 图片地址不合法'));

    // 编辑保存:更新描述与 Logo
    const metaCsrf = extractHidden(metaDetail)._csrf;
    r = await call(aj, `/admin/apps/${metaId}/update`, {
      method: 'POST',
      form: [
        ['name', 'Meta Portal'],
        ['redirect_uris', 'http://127.0.0.1:8080/meta'],
        ['scopes', 'openid'], ['scopes', 'profile'],
        ['description', '更新后的统一运维描述'],
        ['logo_url', 'https://cdn.example.com/logo2.png'],
        ['require_consent', '1'],
        ['_csrf', metaCsrf],
      ],
    });
    ok('应用信息:更新应用描述与 Logo 保存成功', r.status === 302 && location(r).includes('msg='));
    r = await call(aj, `/admin/apps/${metaId}`);
    metaDetail = await r.text();
    ok('应用信息:更新后详情回显新描述与 Logo', r.status === 200
      && metaDetail.includes('更新后的统一运维描述') && metaDetail.includes('logo2.png'));

    // 门户磁贴与条状行:Logo 图片替代首字母徽标,描述一行展示
    r = await call(fj, '/apps?view=grid');
    const metaGrid = await r.text();
    ok('应用信息:门户磁贴展示 Logo 与描述', r.status === 200
      && metaGrid.includes('<img src="https://cdn.example.com/logo2.png" alt="" loading="lazy"')
      && metaGrid.includes('更新后的统一运维描述'));
    r = await call(fj, '/apps?view=list');
    const metaList = await r.text();
    ok('应用信息:门户条状视图展示 Logo 与描述', r.status === 200
      && metaList.includes('class="app-item"')
      && metaList.includes('<img src="https://cdn.example.com/logo2.png" alt="" loading="lazy"')
      && metaList.includes('更新后的统一运维描述'));
    r = await call(fj, '/apps?view=grid'); // 恢复格子视图偏好

    // 同意授权页:Logo 与描述展示(首字母徽标逻辑保留为回退)
    const metaVerifier = crypto.randomBytes(48).toString('base64url');
    const metaAuthUrl = '/authorize?' + new URLSearchParams({
      client_id: metaId, redirect_uri: 'http://127.0.0.1:8080/meta',
      response_type: 'code', scope: 'openid profile',
      state: 'meta-st', nonce: 'meta-n',
      code_challenge: b64urlSha256(metaVerifier), code_challenge_method: 'S256',
    }).toString();
    r = await call(fj, metaAuthUrl);
    const metaConsentHtml = await r.text();
    ok('应用信息:同意授权页展示 Logo 与描述', r.status === 200
      && metaConsentHtml.includes('请求访问你的账号')
      && metaConsentHtml.includes('<img src="https://cdn.example.com/logo2.png" alt="" loading="lazy"')
      && metaConsentHtml.includes('更新后的统一运维描述'));
    ok('授权页:带 Logo 应用展示图片 Logo 与描述展示位', metaConsentHtml.includes('<img src="https://cdn.example.com/logo2.png" alt="" loading="lazy" class="consent-logo"')
      && metaConsentHtml.includes('更新后的统一运维描述')
      && metaConsentHtml.includes('class="login-form-col login-form-col-wide"'));
    const metaConsentForm = extractHidden(metaConsentHtml);
    r = await call(fj, '/authorize', { method: 'POST', form: { ...metaConsentForm, decision: 'approve', remember: 'on' } });
    const metaCode = new URL(location(r), BASE).searchParams.get('code');
    ok('应用信息:同意后签发授权码', r.status === 302 && !!metaCode && !location(r).includes('error'));
    r = await fetch(BASE + '/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: metaCode, redirect_uri: 'http://127.0.0.1:8080/meta',
        client_id: metaId, code_verifier: metaVerifier,
      }).toString(),
    });
    const metaTok = await r.json();
    ok('应用信息:授权码换取 meta 应用令牌', r.status === 200 && !!metaTok.access_token);

    // 应用详情「已授权用户」:bob 记住授权后出现,含用户名/姓名/范围徽章
    r = await call(aj, `/admin/apps/${metaId}`);
    const metaUsersHtml = await r.text();
    ok('授权用户:应用详情列出已授权用户含 bob', r.status === 200
      && metaUsersHtml.includes('已授权用户')
      && metaUsersHtml.includes('name="user_id" value="' + bob.id + '"')
      && metaUsersHtml.includes('小明') && metaUsersHtml.includes('基本资料')
      && metaUsersHtml.includes('撤销授权') && metaUsersHtml.includes('记住授权与现有令牌立即失效'));
    const metaUsersForm = extractHidden(metaUsersHtml);
    r = await call(aj, `/admin/apps/${metaId}/revoke-user`, {
      method: 'POST', form: { user_id: bob.id, _csrf: metaUsersForm._csrf },
    });
    ok('授权用户:撤销单个用户授权成功', r.status === 302
      && location(r).startsWith(`/admin/apps/${metaId}?msg=`));
    r = await call(aj, `/admin/apps/${metaId}`);
    const metaEmptyHtml = await r.text();
    ok('授权用户:撤销后已授权用户列表为空', r.status === 200
      && metaEmptyHtml.includes('暂无用户授权') && !metaEmptyHtml.includes('revoke-user'));
    r = await fetch(BASE + '/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'svc-secret-123') },
      body: new URLSearchParams({ token: metaTok.access_token }).toString(),
    });
    ok('授权用户:撤销后该用户令牌内省 active=false', r.status === 200 && (await r.json()).active === false);

    // 无任何授权的应用详情显示空状态
    r = await call(aj, `/admin/apps/${svc.client_id}`);
    ok('授权用户:无授权应用详情显示空状态', r.status === 200 && (await r.text()).includes('暂无用户授权'));

    /* ---------- 门户视图切换与页面精简 ---------- */
    r = await call(fj, '/apps');
    const gridHtml = await r.text();
    ok('门户视图:默认格子视图且提供切换入口', gridHtml.includes('portal-grid')
      && gridHtml.includes('格子显示') && gridHtml.includes('条状显示') && !gridHtml.includes('class="app-item"'));

    r = await call(fj, '/apps?view=list');
    const setCookies = r.headers.getSetCookie?.() || [];
    ok('门户视图:切到条状渲染行式列表并写入偏好 cookie', r.status === 200
      && (await r.text()).includes('class="app-item"')
      && setCookies.some((c) => c.startsWith('portal_view=list')));

    r = await call(fj, '/apps');
    ok('门户视图:无参数访问沿用记忆的条状偏好', r.status === 200 && (await r.text()).includes('class="app-item"'));

    r = await call(fj, '/apps?view=grid');
    ok('门户视图:切回格子视图', (await r.text()).includes('portal-grid'));

    r = await call(fj, '/account');
    ok('账号页:已移除应用门户入口行(侧栏已有)', !(await r.text()).includes('<b>应用门户</b>'));

    /* ---------- JSON API 套件:心跳/会话状态/登录/登出/可见应用 ---------- */
    const pkgVersion = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;

    // 心跳:匿名可访问,字段齐全,CORS 开放且 no-store
    const hbRes = await fetch(BASE + '/api/heartbeat');
    const hb = await hbRes.json();
    ok('API heartbeat 返回 200 且字段齐全', hbRes.status === 200
      && hb.ok === true && hb.status === 'alive' && hb.site_name === '樱落统一认证'
      && hb.issuer === BASE && Number.isFinite(hb.uptime_sec)
      && typeof hb.timestamp === 'string' && hb.db === 'ok', JSON.stringify(hb));
    ok('API heartbeat version 与 package.json 一致', hb.version === pkgVersion, hb.version);
    ok('API heartbeat 开放 CORS 且响应 no-store', hbRes.headers.get('access-control-allow-origin') === '*'
      && (hbRes.headers.get('cache-control') || '').includes('no-store'));

    // 会话状态:未登录
    const anonSess = await call(new Jar(), '/api/session');
    ok('API 未登录查询会话状态返回 authenticated:false', anonSess.status === 200
      && (await anonSess.json()).authenticated === false);

    // 登录:参数缺失 / 错误密码(用 noah,避免占用 bob 的限流窗口)
    const missRes = await call(new Jar(), '/api/login', { method: 'POST', json: { username: 'noah' } });
    ok('API 登录参数缺失返回 bad_request', missRes.status === 400 && (await missRes.json()).error === 'bad_request');
    const badRes = await call(new Jar(), '/api/login', {
      method: 'POST', json: { username: 'noah', password: 'wrong-pass' },
    });
    ok('API 登录错误密码返回 401 invalid_credentials', badRes.status === 401
      && (await badRes.json()).error === 'invalid_credentials');

    // 登录成功(表单编码):Set-Cookie 携带 sid
    const apiJ = new Jar();
    const formLogin = await call(apiJ, '/api/login', { method: 'POST', form: { username: 'bob', password: 'BobPassw0rd!' } });
    const formLoginBody = await formLogin.json();
    ok('API 登录成功且 Set-Cookie 有 sid', formLogin.status === 200 && formLoginBody.ok === true
      && formLoginBody.user?.username === 'bob' && !!apiJ.map.get('sid'));

    // 带 cookie 查询会话:返回用户信息(含 groups 数组)
    const sessRes = await call(apiJ, '/api/session');
    const sessBody = await sessRes.json();
    ok('API 带 cookie 查询会话返回 bob 用户信息(含 groups)', sessRes.status === 200
      && sessBody.authenticated === true && sessBody.user.username === 'bob' && sessBody.user.name === '小明'
      && Array.isArray(sessBody.user.groups) && sessBody.user.groups.includes('dev')
      && sessBody.user.is_admin === false, JSON.stringify(sessBody));

    // 可见应用:复用门户可见性过滤,未登录 401
    const appsRes = await call(apiJ, '/api/apps');
    const appsBody = await appsRes.json();
    ok('API 可见应用列表含 Smoke Web 且带 client_id', appsRes.status === 200 && Array.isArray(appsBody.apps)
      && appsBody.apps.some((a) => a.name === 'Smoke Web' && !!a.client_id
        && a.type === 'public' && a.scopes.includes('openid')), JSON.stringify(appsBody).slice(0, 120));
    const appsAnon = await call(new Jar(), '/api/apps');
    ok('API 未登录请求应用列表返回 401 unauthenticated', appsAnon.status === 401
      && (await appsAnon.json()).error === 'unauthenticated');

    // 登出:销毁会话、状态变回未登录
    const apiLoRes = await call(apiJ, '/api/logout', { method: 'POST', headers: { 'X-Requested-With': 'JSON' } });
    const apiLoBody = await apiLoRes.json();
    const afterLogout = await (await call(apiJ, '/api/session')).json();
    ok('API 登出成功且会话状态变回未登录', apiLoRes.status === 200 && apiLoBody.ok === true
      && afterLogout.authenticated === false);

    // 2FA:开启后缺 totp_code 被拒,正确验证码/恢复代码均可登录;结束清理恢复原状
    const bobApiSecret = totp.generateSecret();
    users.setTotpSecret(bob.id, bobApiSecret);
    users.enableTotp(bob.id);
    const tfApi = new Jar();
    const tfMissing = await call(tfApi, '/api/login', { method: 'POST', json: { username: 'bob', password: 'BobPassw0rd!' } });
    ok('API 2FA 用户缺 totp_code 登录返回 totp_required', tfMissing.status === 401
      && (await tfMissing.json()).error === 'totp_required');
    const tfOk = await call(tfApi, '/api/login', {
      method: 'POST',
      json: { username: 'bob', password: 'BobPassw0rd!', totp_code: totp.currentCode(bobApiSecret) },
    });
    const tfOkBody = await tfOk.json();
    ok('API 2FA 用户带正确验证码登录成功', tfOk.status === 200 && tfOkBody.ok === true
      && tfOkBody.user?.username === 'bob' && tfOkBody.user?.totp_enabled === true);
    const apiRec = recovery.createBatch(bob.id, 1)[0];
    const rcRes = await call(new Jar(), '/api/login', {
      method: 'POST',
      json: { username: 'bob', password: 'BobPassw0rd!', totp_code: apiRec },
    });
    ok('API 2FA 恢复代码可完成登录', rcRes.status === 200 && (await rcRes.json()).ok === true);
    users.clearTotp(bob.id); // 清理:恢复夹具原状,避免影响后续用例
    recovery.clearFor(bob.id);

    /* ---------- Microsoft 登录与绑定(本地 mock OIDC 提供方) ---------- */
    // 默认关闭:登录页无入口,发起被重定向回登录页
    r = await call(new Jar(), '/login');
    const msOffHtml = await r.text();
    ok('MS:默认关闭时登录页无 Microsoft 登录按钮', r.status === 200
      && !msOffHtml.includes('/auth/microsoft') && !msOffHtml.includes('使用 Microsoft 账号登录'));
    const msOff = await call(new Jar(), '/auth/microsoft');
    ok('MS:默认关闭时 /auth/microsoft 重定向登录页并带 err', msOff.status === 302
      && location(msOff).startsWith('/login?err='));

    // 管理端:控制台卡片 + 保存启用(含指向 mock 的 authority)
    r = await call(aj, '/admin');
    const msDashHtml = await r.text();
    ok('MS:控制台出现 Microsoft 登录卡片与回调地址', msDashHtml.includes('Microsoft 登录')
      && msDashHtml.includes('/admin/ms-oauth') && msDashHtml.includes('/auth/microsoft/callback'));
    const msDashForm = extractHidden(msDashHtml);
    r = await call(aj, '/admin/ms-oauth', {
      method: 'POST',
      form: {
        ms_enabled: '1', ms_client_id: 'smoke-ms-client', ms_client_secret: 'smoke-ms-secret',
        ms_tenant: 'common', ms_authority: msMock.authority, _csrf: msDashForm._csrf,
      },
    });
    ok('MS:管理端保存 Microsoft 登录配置', r.status === 302 && location(r).startsWith('/admin?msg='));
    const msSaved = settings.getMap();
    ok('MS:ms_enabled/client_id/secret/authority 写入 settings', msSaved.ms_enabled === '1'
      && msSaved.ms_client_id === 'smoke-ms-client' && msSaved.ms_client_secret === 'smoke-ms-secret'
      && msSaved.ms_authority === msMock.authority);

    // 加固:ms_tenant 格式校验(拼进 authority URL 路径,非法值保存被拒并回显)
    r = await call(aj, '/admin/ms-oauth', {
      method: 'POST',
      form: {
        ms_enabled: '1', ms_client_id: 'smoke-ms-client', ms_client_secret: 'smoke-ms-secret',
        ms_tenant: '../evil?x=1', ms_authority: msMock.authority, _csrf: msDashForm._csrf,
      },
    });
    ok('加固:ms_tenant 非法值保存被拒并回显错误', r.status === 302 && location(r).startsWith('/admin?err=')
      && settings.getMap().ms_tenant !== '../evil?x=1');
    r = await call(aj, '/admin/ms-oauth', {
      method: 'POST',
      form: {
        ms_enabled: '1', ms_client_id: 'smoke-ms-client', ms_client_secret: 'smoke-ms-secret',
        ms_tenant: 'Tenant_01.example', ms_authority: msMock.authority, _csrf: msDashForm._csrf,
      },
    });
    ok('加固:ms_tenant 合法值(含 . _ 与大小写)保存成功', r.status === 302 && location(r).startsWith('/admin?msg=')
      && settings.getMap().ms_tenant === 'Tenant_01.example');
    await call(aj, '/admin/ms-oauth', { // 还原 common,不影响后续 MS 链路用例
      method: 'POST',
      form: {
        ms_enabled: '1', ms_client_id: 'smoke-ms-client', ms_client_secret: 'smoke-ms-secret',
        ms_tenant: 'common', ms_authority: msMock.authority, _csrf: msDashForm._csrf,
      },
    });
    ok('加固:ms_tenant 还原 common 成功', settings.getMap().ms_tenant === 'common');

    r = await call(new Jar(), '/login');
    ok('MS:启用后登录页出现 Microsoft 登录按钮', r.status === 200
      && (await r.text()).includes('使用 Microsoft 账号登录'));

    // 伪造 state:回调直接 400 错误页
    r = await call(new Jar(), '/auth/microsoft/callback?code=X&state=forged-state');
    ok('MS:callback 伪造 state 返回 400 错误页', r.status === 400
      && (await r.text()).includes('Microsoft 登录失败'));

    // 完整链路:发起 → mock authorize → callback → 关联页
    const msj = new Jar();
    r = await call(msj, '/auth/microsoft');
    const msAuthLoc = location(r);
    ok('MS:/auth/microsoft 302 到 mock authorize(含 client_id 与 state)', r.status === 302
      && msAuthLoc.startsWith(`${msMock.authority}/common/oauth2/v2.0/authorize`)
      && msAuthLoc.includes('client_id=smoke-ms-client')
      && msAuthLoc.includes('code_challenge_method=S256')
      && /state=[^&]+/.test(msAuthLoc), msAuthLoc);
    r = await call(msj, msAuthLoc);
    const msCbLoc = location(r);
    ok('MS:mock authorize 302 回本站 callback 并带 code/state', r.status === 302
      && msCbLoc.startsWith(`${BASE}/auth/microsoft/callback`)
      && new URL(msCbLoc, BASE).searchParams.get('code') === 'TESTCODE'
      && !!new URL(msCbLoc, BASE).searchParams.get('state'), msCbLoc);
    r = await call(msj, msCbLoc);
    const linkHtml = await r.text();
    ok('MS:未绑定用户渲染关联本地账号页并显示 MS 邮箱', r.status === 200
      && linkHtml.includes('关联本地账号') && linkHtml.includes('msuser@example.com')
      && !linkHtml.includes('注册并绑定'), `status=${r.status}`);
    const linkForm = extractHidden(linkHtml);
    ok('MS:关联页携带 linkToken 与 CSRF', !!linkForm.state && !!linkForm._csrf);

    // 表单 A:先错密码,再正确绑定到 bob
    r = await call(msj, '/auth/microsoft/link', {
      method: 'POST',
      form: { state: linkForm.state, username: 'bob', password: 'nope-wrong', _csrf: linkForm._csrf },
    });
    ok('MS:关联本地账号密码错误被拒', r.status === 401 && (await r.text()).includes('用户名或密码不正确'));
    r = await call(msj, '/auth/microsoft/link', {
      method: 'POST',
      form: { state: linkForm.state, username: 'bob', password: 'BobPassw0rd!', _csrf: linkForm._csrf },
    });
    ok('MS:绑定 bob 成功并建立会话跳转 /apps', r.status === 302 && location(r) === '/apps', `loc=${location(r)}`);
    r = await call(msj, '/apps');
    ok('MS:Microsoft 登录后的会话可访问门户', r.status === 200);
    const boundBob = users.byMicrosoftSub('ms-sub-123');
    ok('MS:byMicrosoftSub 命中 bob', !!boundBob && boundBob.id === bob.id);

    // linkToken 一次性:重放被拒
    r = await call(new Jar(), '/auth/microsoft/link', {
      method: 'POST',
      form: { state: linkForm.state, username: 'bob', password: 'BobPassw0rd!', _csrf: 'x' },
    });
    ok('MS:linkToken 一次性(重放被拒)', r.status === 400);

    // 已绑定:再次 Microsoft 登录直达 /apps
    const msj2 = new Jar();
    r = await call(msj2, '/auth/microsoft');
    r = await call(msj2, location(r));
    r = await call(msj2, location(r));
    ok('MS:已绑定用户再次 Microsoft 登录直达 /apps', r.status === 302 && location(r) === '/apps',
      `status=${r.status} loc=${location(r)}`);

    // 账号页区块 + 解绑
    r = await call(msj, '/account');
    const msAcctHtml = await r.text();
    ok('MS:账号页出现 Microsoft 绑定区块与邮箱', msAcctHtml.includes('Microsoft 账号')
      && msAcctHtml.includes('msuser@example.com') && msAcctHtml.includes('解绑 Microsoft 账号'));
    const msAcctForm = extractHidden(msAcctHtml);
    r = await call(msj, '/auth/microsoft/unbind', { method: 'POST', form: { _csrf: msAcctForm._csrf } });
    ok('MS:解绑成功回账号页', r.status === 302 && location(r).startsWith('/account?msg='));
    ok('MS:解绑后 byMicrosoftSub 为空', !users.byMicrosoftSub('ms-sub-123'));

    // bind=1:已登录用户把 Microsoft 身份绑定到当前账号(alice)
    const aj2 = new Jar();
    r = await call(aj2, '/login');
    const a2f = extractHidden(await r.text());
    r = await call(aj2, '/login', { method: 'POST', form: { username: 'alice', password: 'NewPass#123', _csrf: a2f._csrf } });
    ok('MS:alice 本地登录成功(准备 bind=1)', r.status === 302);
    r = await call(aj2, '/auth/microsoft?bind=1');
    r = await call(aj2, location(r));
    r = await call(aj2, location(r));
    ok('MS:bind=1 回调后绑定到当前账号并回账号页', r.status === 302
      && location(r).startsWith('/account?msg=') && decodeURIComponent(location(r)).includes('已绑定'),
      `loc=${location(r)}`);
    const boundAlice = users.byMicrosoftSub('ms-sub-123');
    ok('MS:bind=1 后 byMicrosoftSub 命中 alice', !!boundAlice && boundAlice.id === users.byUsername('alice').id);

    // 已绑定账号再次发起 bind=1:拒绝静默换绑,提示先解绑(绑定仍保留)
    r = await call(aj2, '/auth/microsoft?bind=1');
    r = await call(aj2, location(r));
    r = await call(aj2, location(r));
    ok('MS:已绑定账号重复 bind=1 被拒(需先解绑,绑定不被覆盖)', r.status === 302
      && location(r).startsWith('/account?err=') && users.byMicrosoftSub('ms-sub-123')?.id === users.byUsername('alice').id);

    if (boundAlice) users.unbindMicrosoft(boundAlice.id); // 清理绑定,供后续注册链路复用同一 mock 身份

    // 表单 B:自助注册开启时注册新号并绑定
    r = await call(aj, '/admin');
    const regToggleMs = extractHidden(await r.text());
    await call(aj, '/admin/register-toggle', { method: 'POST', form: { _csrf: regToggleMs._csrf } });
    const msrj = new Jar();
    r = await call(msrj, '/auth/microsoft');
    r = await call(msrj, location(r));
    r = await call(msrj, location(r));
    const msRegHtml = await r.text();
    ok('MS:自助注册开启时关联页显示注册新账号表单', r.status === 200 && msRegHtml.includes('注册并绑定'));
    const msRegForm = extractHidden(msRegHtml);
    r = await call(msrj, '/auth/microsoft/register', {
      method: 'POST',
      form: {
        state: msRegForm.state, username: 'msreg', password: 'MsReg#12345',
        password2: 'MsReg#99999', name: '微软用户', _csrf: msRegForm._csrf,
      },
    });
    ok('MS:注册新号两次密码不一致被拒', r.status === 400 && (await r.text()).includes('两次输入的密码不一致'));
    r = await call(msrj, '/auth/microsoft/register', {
      method: 'POST',
      form: {
        state: msRegForm.state, username: 'msreg', password: 'MsReg#12345',
        password2: 'MsReg#12345', name: '微软用户', _csrf: msRegForm._csrf,
      },
    });
    ok('MS:注册新号成功并自动登录跳转 /apps', r.status === 302 && location(r) === '/apps',
      `status=${r.status} loc=${location(r)}`);
    const msRegUser = users.byUsername('msreg');
    ok('MS:注册的新用户已绑定 Microsoft 身份且非管理员', !!msRegUser
      && msRegUser.ms_sub === 'ms-sub-123' && msRegUser.email === 'msuser@example.com' && !msRegUser.is_admin);
    // 恢复自助注册开关(向导段稍后会再改写,这里保持环境一致)
    r = await call(aj, '/admin');
    const regToggleMs2 = extractHidden(await r.text());
    await call(aj, '/admin/register-toggle', { method: 'POST', form: { _csrf: regToggleMs2._csrf } });

    /* ---------- 操作审计日志(放最后段:向导重跑段之前) ---------- */
    const auditM = await import('../src/models/audit.js');

    // 管理端页面:管理员可见且含记录,普通用户 403
    r = await call(aj, '/admin/audit');
    const auditHtml = await r.text();
    ok('审计:管理员可查看审计页且含记录', r.status === 200 && auditHtml.includes('审计日志')
      && auditHtml.includes('auth.login') && auditHtml.includes('bob'));
    ok('审计:侧栏提供审计日志入口', auditHtml.includes('href="/admin/audit"') && auditHtml.includes('审计日志'));
    ok('审计:普通用户访问审计页被拒(403)', (await call(rj, '/admin/audit')).status === 403);

    // 模型层:登录成功/失败留痕
    const loginRows = auditM.list({ action: 'auth.login', limit: 500 });
    ok('审计:登录成功产生 auth.login 记录', loginRows.length > 0 && loginRows.some((row) => row.detail === 'bob'));
    ok('审计:错误密码产生 auth.login_failed 记录', auditM.list({ action: 'auth.login_failed', limit: 500 }).length > 0);

    // 撤销我的授权留痕(detail 为 client_id)
    ok('审计:撤销我的授权产生 oauth.consent_revoked', auditM.list({ action: 'oauth.consent_revoked', limit: 500 })
      .some((row) => row.detail === web.client_id));

    // 管理端经控制台新建应用留痕(actor 为管理员,detail 为应用名)
    r = await call(aj, '/admin/apps/create', {
      method: 'POST',
      // scopes 以重复键提交,服务端按数组收集(与表单复选框行为一致)
      form: [['name', '审计探针'], ['redirect_uris', 'http://127.0.0.1:8080/audit-cb'],
        ['scopes', 'openid'], ['scopes', 'profile'], ['client_type', 'public'], ['_csrf', adminCsrf]],
    });
    const appCreatedRows = auditM.list({ action: 'admin.app_created', limit: 10 });
    ok('审计:新建应用产生 admin.app_created 记录', appCreatedRows.length > 0
      && appCreatedRows[0].detail === '审计探针' && appCreatedRows[0].actor === 'admin');

    // 按 action 筛选:页面只呈现该动作的记录(MS 事件详情不得混入)
    r = await call(aj, `/admin/audit?action=${encodeURIComponent('oauth.consent_revoked')}`);
    const filteredHtml = await r.text();
    ok('审计:按 action 筛选生效', r.status === 200 && filteredHtml.includes(web.client_id)
      && !filteredHtml.includes('msuser@example.com'));
    const kwRows = auditM.list({ q: 'bob', limit: 500 });
    ok('审计:关键词过滤命中操作者或详情', kwRows.length > 0
      && kwRows.every((row) => row.actor.includes('bob') || row.detail.includes('bob')));

    // 清空(危险操作):需要 CSRF,清空后模型计数为 0 且页面显示空状态
    r = await call(aj, '/admin/audit');
    const auditClearForm = extractHidden(await r.text());
    r = await call(aj, '/admin/audit/clear', { method: 'POST', form: { _csrf: auditClearForm._csrf } });
    ok('审计:清空后列表为空', r.status === 302 && location(r).startsWith('/admin/audit') && auditM.count() === 0);
    r = await call(aj, '/admin/audit');
    ok('审计:清空后页面显示空状态', r.status === 200 && (await r.text()).includes('暂无审计记录'));

    /* ---------- 审计分页与 CSV 导出(放最后段:向导重跑段之前;测试记录本段内清理) ---------- */
    const { getDb: getAuditDb } = await import('../src/core/db.js');
    // 清空段之后审计表为空:造 60 条 pagetest 记录(每页 50 → 恰好 2 页)
    for (let i = 1; i <= 60; i++) {
      auditM.log({ actor: 'pagetester', action: 'pagetest', detail: `分页测试记录 #${i}`, ip: '127.0.0.1' });
    }

    // 第 1 页:最新 50 条,含「下一页」链接,「上一页」为禁用占位
    r = await call(aj, '/admin/audit');
    const pg1 = await r.text();
    ok('审计分页:第 1 页显示「第 1 / 2 页 · 共 60 条」且含下一页链接', r.status === 200
      && pg1.includes('第 1 / 2 页 · 共 60 条') && pg1.includes('href="/admin/audit?page=2"')
      && pg1.includes('分页测试记录 #60') && !pg1.includes('分页测试记录 #1</td>'));
    ok('审计分页:第 1 页「上一页」为禁用样式(无 page=1 链接)', !pg1.includes('href="/admin/audit?page=1"')
      && pg1.includes('aria-disabled="true"') && pg1.includes('上一页'));

    // 第 2 页:较早的 10 条,含「上一页」链接,「下一页」为禁用占位
    r = await call(aj, '/admin/audit?page=2');
    const pg2 = await r.text();
    ok('审计分页:第 2 页含上一页链接与「第 2 / 2 页」,内容与第 1 页不同', r.status === 200
      && pg2.includes('href="/admin/audit?page=1"') && pg2.includes('第 2 / 2 页 · 共 60 条')
      && pg2.includes('分页测试记录 #1</td>') && !pg2.includes('分页测试记录 #60'));
    ok('审计分页:末页「下一页」为禁用样式(无 page=3 链接)', !pg2.includes('href="/admin/audit?page=3"')
      && pg2.includes('下一页') && pg2.includes('aria-disabled="true"'));

    // 筛选 + 分页叠加:翻页/导出链接需保留 action 参数
    r = await call(aj, `/admin/audit?action=${encodeURIComponent('pagetest')}&page=2`);
    const pgF = await r.text();
    ok('审计分页:筛选与分页叠加且翻页/导出链接保留筛选参数', r.status === 200
      && pgF.includes('第 2 / 2 页 · 共 60 条')
      && pgF.includes('href="/admin/audit?action=pagetest&amp;page=1"')
      && pgF.includes('href="/admin/audit/export.csv?action=pagetest"'));
    r = await call(aj, '/admin/audit?page=999');
    ok('审计分页:页码越界自动收敛到末页', r.status === 200 && (await r.text()).includes('第 2 / 2 页 · 共 60 条'));
    r = await call(aj, '/admin/audit?page=-3');
    ok('审计分页:负数/非法页码收敛到第 1 页', r.status === 200
      && (await r.text()).includes('第 1 / 2 页 · 共 60 条'));

    // CSV 导出:造一条中文操作者 + 逗号引号明细的记录,验证转义与计数
    auditM.log({ actor: 'csv测试员', action: 'csvtest', detail: '导出,含"引号"与,逗号', ip: '10.0.0.2' });
    r = await call(aj, '/admin/audit/export.csv');
    const csvBody = await r.text();
    const csvLines = csvBody.replace(/^\uFEFF/, '').split('\n').filter((l) => l !== '');
    ok('审计导出:响应头正确(text/csv;charset=utf-8 + attachment 文件名 + no-store)', r.status === 200
      && (r.headers.get('content-type') || '') === 'text/csv; charset=utf-8'
      && /^attachment; filename="audit-\d{8}-\d{6}\.csv"$/.test(r.headers.get('content-disposition') || '')
      && (r.headers.get('cache-control') || '') === 'no-store');
    // fetch 的 text() 会按规范剥除开头 BOM,故用原始字节验证 BOM 真实存在
    const csvRaw = Buffer.from(await (await fetch(BASE + '/admin/audit/export.csv',
      { headers: { Cookie: aj.header() } })).arrayBuffer());
    ok('审计导出:BOM 开头且首行为中文表头', csvRaw[0] === 0xEF && csvRaw[1] === 0xBB && csvRaw[2] === 0xBF
      && csvRaw.slice(3).toString('utf8').split('\n')[0] === '时间,操作者,动作,详情,IP');
    ok('审计导出:数据行数等于当前记录数', csvLines.length - 1 === auditM.count()
      && auditM.count() === 61 && csvBody.includes('分页测试记录 #1,127.0.0.1'));
    ok('审计导出:含中文操作者与转义后的引号/逗号字段', csvBody.includes('csv测试员')
      && csvBody.includes('"导出,含""引号""与,逗号"'));
    ok('审计导出:时间列为本地可读格式', csvLines
      .some((l) => /^20\d{2}\/\d{1,2}\/\d{1,2} \d{2}:\d{2}:\d{2},pagetester/.test(l)));

    // 带 action 筛选导出:只含 pagetest 的 60 条,不含 csvtest
    r = await call(aj, `/admin/audit/export.csv?action=${encodeURIComponent('pagetest')}`);
    const csvFBody = await r.text();
    const csvFLines = csvFBody.replace(/^\uFEFF/, '').split('\n').filter((l) => l !== '');
    ok('审计导出:按 action 筛选导出生效', csvFLines.length === 61 && !csvFBody.includes('csv测试员')
      && csvFLines[0] === '时间,操作者,动作,详情,IP');
    ok('审计导出:普通用户访问导出被拒(403)', (await call(rj, '/admin/audit/export.csv')).status === 403);

    // 加固:CSV 公式注入中和(CWE-1236)—— = + - @ \t \r 开头的自由文本前置单引号
    const auditSvc = await import('../src/services/audit.js');
    ok('加固:csvCell 危险前缀全中和(= + - @ 制表符 回车)且普通值不受影响',
      ['=1+1', '+2', '-3', '@x', '\tT'].every((p) => auditSvc.csvCell(p) === `'${p}`)
      && auditSvc.csvCell('\rR') === '"\'\rR"'
      && auditSvc.csvCell('普通值') === '普通值');
    auditM.log({ actor: '=EvilActor', action: 'csvtest', detail: '=cmd|calc!A0', ip: '10.0.0.9' });
    auditM.log({ actor: '@spoofed', action: 'csvtest', detail: '-2+3,危险前缀', ip: '10.0.0.9' });
    r = await call(aj, '/admin/audit/export.csv');
    const csvHard = await r.text();
    ok('加固:CSV 导出 = 开头的 detail/actor 被中和(前置单引号)', csvHard.includes("'=cmd|calc!A0")
      && csvHard.includes("'=EvilActor"));
    ok('加固:CSV 导出 @/- 前缀被中和且既有引号转义不受影响', csvHard.includes("'@spoofed")
      && csvHard.includes("'-2+3,危险前缀") && csvHard.includes('"导出,含""引号""与,逗号"'));

    // 清理本段测试数据(只删 pagetest/csvtest,不影响后续用例)
    getAuditDb().prepare("DELETE FROM audit_logs WHERE action IN ('pagetest','csvtest')").run();
    ok('审计分页:测试记录清理完毕(无 pagetest/csvtest 残留)',
      auditM.list({ action: 'pagetest', limit: 10 }).length === 0
      && auditM.list({ action: 'csvtest', limit: 10 }).length === 0);

    /* ---------- 健康状态页与应用模拟权限组启动(放在向导重跑段之前) ---------- */
    // 匿名 /health:品牌化状态页,含版本/运行状态/时长/数据库/发现文档链接,无敏感计数
    r = await call(new Jar(), '/health');
    const healthHtml = await r.text();
    ok('健康:匿名访问 200 且含版本号/运行状态/站点名/数据库状态', r.status === 200
      && healthHtml.includes('服务运行中') && healthHtml.includes(pkgVersion)
      && healthHtml.includes('樱落统一认证') && healthHtml.includes('连接正常') && healthHtml.includes('已运行'));
    ok('健康:页面含发现文档与心跳 JSON 链接及 Issuer', healthHtml.includes('/.well-known/openid-configuration')
      && healthHtml.includes('/api/heartbeat') && healthHtml.includes(BASE));
    ok('健康:响应 no-store 且不开放跨域(跨域 JSON 专属 /api/heartbeat)',
      (r.headers.get('cache-control') || '').includes('no-store')
      && r.headers.get('access-control-allow-origin') === null);
    ok('健康:不含用户/应用计数等敏感信息', !healthHtml.includes('用户')
      && !healthHtml.includes('在线会话') && !healthHtml.includes('有效访问令牌')
      && !healthHtml.includes('用户数') && !healthHtml.includes('应用数'));
    r = await call(nj2, '/health');
    ok('健康:普通用户(已登录)也可访问状态页', r.status === 200 && (await r.text()).includes('服务运行中'));

    // 应用详情页:管理员可见「模拟启动」卡片与权限组下拉(Groups Only 限 dev)
    r = await call(aj, `/admin/apps/${gApp.client_id}`);
    const simDetail = await r.text();
    ok('模拟:应用详情含模拟启动卡片与权限组下拉', simDetail.includes('模拟启动')
      && simDetail.includes('以所选权限组的视角') && simDetail.includes('name="sim_group"')
      && simDetail.includes('value="dev"'));

    // 管理员携带 sim_group=dev 启动受限应用:跳过组限制,302 进入授权流程(非 403)
    r = await call(aj, `/apps/launch/${gApp.client_id}?sim_group=dev`);
    const simLoc = location(r);
    ok('模拟:管理员带 sim_group 启动受限应用进入授权流程(非 403)', r.status === 302
      && simLoc.startsWith('/authorize?') && simLoc.includes('client_id=' + gApp.client_id)
      && simLoc.includes('code_challenge='), `status=${r.status} loc=${simLoc}`);

    // 补:受限应用模拟启动走完整链路(authorize 层 sim 旁路 → 同意 → code 回调)
    r = await call(aj, simLoc);
    const gSimConsent = await r.text();
    const gSimForm = extractHidden(gSimConsent);
    ok('模拟:受限应用模拟启动进入同意页且 sim_group 随表单保留', r.status === 200
      && gSimConsent.includes('请求访问你的账号') && gSimForm.sim_group === 'dev');
    r = await call(aj, '/authorize', { method: 'POST', form: { ...gSimForm, decision: 'approve', remember: 'on' } });
    ok('模拟:受限应用模拟启动同意后签发 code(全链路)', r.status === 302
      && !!new URL(location(r), BASE).searchParams.get('code'));

    // 模拟启动的后续流程(authorize → 同意 → code 回调)完全复用现状:以未限制应用全链路验证
    r = await call(aj, `/apps/launch/${web.client_id}?sim_group=dev`);
    ok('模拟:管理员模拟启动未限制应用同样进入授权流程', r.status === 302 && location(r).startsWith('/authorize?'));
    r = await call(aj, location(r));
    const simConsentHtml = await r.text();
    ok('模拟:模拟启动后进入同意授权页(其余流程复用现状)', r.status === 200
      && simConsentHtml.includes('请求访问你的账号'));
    const simForm = extractHidden(simConsentHtml);
    r = await call(aj, '/authorize', { method: 'POST', form: { ...simForm, decision: 'approve', remember: 'on' } });
    const simCb = new URL(location(r), BASE);
    ok('模拟:同意后携带 code 与 state 回跳应用回调', r.status === 302
      && !!simCb.searchParams.get('code') && !!simCb.searchParams.get('state'));

    // 模拟启动计入审计(审计段刚清空;两次模拟启动各留痕,detail 含应用名与模拟组)
    const simRows = auditM.list({ action: 'admin.simulate_launch', limit: 10 });
    ok('模拟:产生 admin.simulate_launch 审计记录(含应用名与模拟组)', simRows.length === 2
      && simRows.every((row) => row.actor === 'admin' && row.detail.includes('dev'))
      && simRows.some((row) => row.detail.includes('Groups Only'))
      && simRows.some((row) => row.detail.includes('Smoke Web')), JSON.stringify(simRows));

    // 普通用户携带 sim_group:参数被忽略,组限制照常生效
    r = await call(nj2, `/apps/launch/${gApp.client_id}?sim_group=dev`);
    ok('模拟:普通用户带 sim_group 启动受限应用仍被拦截(403)', r.status === 403
      && (await r.text()).includes('仅对特定权限组开放'));

    // 加固:管理员直连 /authorize 携带合法 sim_group(无门户 stash)同样补审计(2 条 launch 层 → 3 条)
    r = await call(aj, '/authorize?' + new URLSearchParams({
      client_id: gApp.client_id, redirect_uri: 'http://127.0.0.1:8080/gcb',
      response_type: 'code', scope: 'openid profile groups', state: 'sim-direct',
      code_challenge: b64urlSha256(crypto.randomBytes(48).toString('base64url')),
      code_challenge_method: 'S256', sim_group: 'dev',
    }).toString());
    ok('加固:直连 /authorize 的 sim_group 旁路发码并补审计(仅一次)', r.status === 302
      && !!new URL(location(r), BASE).searchParams.get('code') && !location(r).includes('error')
      && auditM.list({ action: 'admin.simulate_launch', limit: 10 }).length === 3, location(r));

    /* ---------- 应用健康探测与注册表 API(向导重跑段之前;本地健康目标随用例启停) ---------- */
    let healthState = 200; // 探测目标的响应码,可切换 200/500
    const healthMock = http.createServer((req, res) => {
      res.writeHead(healthState, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(healthState === 200 ? 'healthy' : 'unhealthy');
    });
    await new Promise((resolve) => healthMock.listen(0, '127.0.0.1', resolve));
    const healthUrl = `http://127.0.0.1:${healthMock.address().port}/healthz`;
    try {
      const appHealth = await import('../src/services/app-health.js');

      // 服务层直探(await probeOne 保证确定性,不依赖 60s 定时器)
      const upSnap = await appHealth.probeOne({ client_id: 'direct-up', health_url: healthUrl });
      ok('健康探测:probeOne 对 2xx 目标返回 up 并记录延迟', upSnap.status === 'up'
        && Number.isFinite(upSnap.latencyMs) && !!upSnap.checkedAt, JSON.stringify(upSnap));
      // 先占一个端口再释放,得到必然拒绝连接的目标
      const deadPort = await new Promise((resolve) => {
        const s = http.createServer(() => {});
        s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
      });
      const downSnap = await appHealth.probeOne({ client_id: 'direct-down', health_url: `http://127.0.0.1:${deadPort}/x` });
      ok('健康探测:probeOne 对拒绝连接的目标返回 down', downSnap.status === 'down', JSON.stringify(downSnap));
      const unknownSnap = await appHealth.probeOne({ client_id: 'direct-none', health_url: '' });
      ok('健康探测:probeOne 对未配置健康地址返回 unknown', unknownSnap.status === 'unknown');

      // 管理端表单:健康检查地址输入与校验
      r = await call(aj, '/admin/apps/new');
      const healthFormHtml = await r.text();
      ok('健康探测:新建应用表单提供健康检查地址输入', r.status === 200
        && healthFormHtml.includes('name="health_url"') && healthFormHtml.includes('健康检查地址'));

      r = await call(aj, '/admin/apps/create', {
        method: 'POST',
        form: [['name', '健康探针'], ['client_type', 'public'],
          ['redirect_uris', 'http://127.0.0.1:8080/health-cb'],
          ['scopes', 'openid'], ['health_url', healthUrl], ['_csrf', adminCsrf]],
      });
      ok('健康探测:创建带健康检查地址的应用成功', r.status === 302 && location(r).startsWith('/admin/apps/'));
      const healthAppId = new URL(location(r), BASE).pathname.split('/').pop();
      r = await call(aj, `/admin/apps/${healthAppId}`);
      ok('健康探测:详情页回显健康检查地址', r.status === 200 && (await r.text()).includes(healthUrl));

      r = await call(aj, '/admin/apps/create', {
        method: 'POST',
        form: { name: 'Bad Health App', client_type: 'public', redirect_uris: 'http://127.0.0.1:8080/bh',
          scopes: 'openid', health_url: 'ftp://example.com/x', _csrf: adminCsrf },
      });
      ok('健康探测:非 http(s) 健康地址被拒绝', r.status === 200 && (await r.text()).includes('健康检查地址不合法'));

      // 注册表 API:client_credentials 令牌(机器身份)作为 Bearer 查询
      r = await fetch(BASE + '/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: basic(svc.client_id, 'svc-secret-123') },
        body: new URLSearchParams({ grant_type: 'client_credentials' }).toString(),
      });
      const regTok = (await r.json()).access_token;
      ok('健康探测:client_credentials 令牌签发成功', !!regTok);
      const fetchRegistry = (headers) => fetch(BASE + '/api/registry', headers ? { headers } : {});
      const findRow = (body, id) => body.apps?.find((a) => a.client_id === id);
      // 创建应用时子进程已立即探测,轮询至多 5s 等待 up 快照落定
      let reg = null;
      for (let i = 0; i < 25 && reg?.row?.status !== 'up'; i++) {
        const res = await fetchRegistry({ Authorization: `Bearer ${regTok}` });
        const body = await res.json();
        reg = { res, body, row: findRow(body, healthAppId) };
        if (reg.row?.status !== 'up') await sleep(200);
      }
      ok('健康探测:/api/registry 返回 up 且含延迟/时间/health_url', reg?.res?.status === 200
        && reg?.row?.status === 'up' && Number.isFinite(reg?.row?.latency_ms) && !!reg?.row?.checked_at
        && reg?.row?.name === '健康探针' && reg?.row?.type === 'public'
        && reg?.row?.health_url === healthUrl, JSON.stringify(reg?.row));
      ok('健康探测:/api/registry 开放 CORS 且 no-store', reg?.res?.headers?.get('access-control-allow-origin') === '*'
        && (reg?.res?.headers?.get('cache-control') || '').includes('no-store'));
      ok('健康探测:未配置健康地址的应用在注册表中为 unknown',
        reg?.body?.apps?.some((a) => a.name === 'Meta Portal' && a.status === 'unknown'));

      r = await call(aj, `/admin/apps/${healthAppId}`);
      ok('健康探测:详情页展示在线探测状态', r.status === 200 && (await r.text()).includes('在线('));

      // 未认证与普通用户会话均被拒
      const anonReg = await fetchRegistry();
      ok('健康探测:未带凭证请求注册表返回 401', anonReg.status === 401
        && (await anonReg.json()).error === 'unauthenticated');
      ok('健康探测:普通用户会话请求注册表返回 401', (await call(fj, '/api/registry')).status === 401);

      // 目标切 500:经表单保存触发立即复探 → down
      healthState = 500;
      r = await call(aj, `/admin/apps/${healthAppId}`);
      const huForm = extractHidden(await r.text());
      r = await call(aj, `/admin/apps/${healthAppId}/update`, {
        method: 'POST',
        form: [['name', '健康探针'], ['redirect_uris', 'http://127.0.0.1:8080/health-cb'],
          ['scopes', 'openid'], ['health_url', healthUrl], ['_csrf', huForm._csrf]],
      });
      ok('健康探测:更新表单保存成功(触发复探)', r.status === 302 && location(r).includes('msg='));
      let downRow = null;
      for (let i = 0; i < 25 && !downRow; i++) {
        const body = await (await fetchRegistry({ Authorization: `Bearer ${regTok}` })).json();
        const row = findRow(body, healthAppId);
        if (row?.status === 'down') downRow = row; else await sleep(200);
      }
      ok('健康探测:目标切 500 后注册表返回 down', !!downRow && downRow.status === 'down', JSON.stringify(downRow));
      r = await call(aj, `/admin/apps/${healthAppId}`);
      ok('健康探测:详情页展示离线探测状态', r.status === 200 && (await r.text()).includes('离线'));

      const adminReg = await call(aj, '/api/registry');
      ok('健康探测:管理员会话可查询注册表', adminReg.status === 200 && Array.isArray((await adminReg.json()).apps));

      // 门户状态点:磁贴与条状行均渲染,提示文案与 CSS 变体随页面下发
      r = await call(fj, '/apps?view=grid');
      const dotGrid = await r.text();
      ok('健康探测:门户磁贴含状态点与探测提示', dotGrid.includes('class="status-dot') && dotGrid.includes('健康检查:'));
      r = await call(fj, '/apps?view=list');
      const dotList = await r.text();
      ok('健康探测:门户条状行含状态点', dotList.includes('class="app-item"') && dotList.includes('class="status-dot'));
      r = await call(fj, '/apps?view=grid'); // 恢复格子视图偏好
      ok('健康探测:状态点 CSS 三种变体随页面下发', (await r.text()).includes('.status-dot.up')
        && dotGrid.includes('.status-dot.down') && dotGrid.includes('.status-dot.unknown'));
    } finally {
      healthMock.closeAllConnections?.();
      await new Promise((resolve) => healthMock.close(resolve));
    }


    /* ---------- 会话管理:用户自助查看/撤销登录设备(放在向导重跑段之前) ---------- */
    const sessionsM = await import('../src/models/sessions.js');
    const sessUser = users.create({ username: 'sessman', passwordHash: hashPassword('Sess#12345'), name: '会话管理' });
    const UA_A = 'smoke-agent-A/1.0', UA_B = 'smoke-agent-B/2.0';
    const apiLoginAs = (jar, ua) => call(jar, '/api/login', {
      method: 'POST',
      json: { username: 'sessman', password: 'Sess#12345' },
      headers: ua ? { 'User-Agent': ua } : {},
    });

    const anonSessList = await call(new Jar(), '/api/sessions');
    ok('会话:未登录请求 /api/sessions 返回 401', anonSessList.status === 401
      && (await anonSessList.json()).error === 'unauthenticated');

    // 同一用户两次 API 登录:产生两条会话(UA 各异,便于在列表中定位行)
    const sj1 = new Jar(), sj2 = new Jar();
    const sessLogin1 = await apiLoginAs(sj1, UA_A);
    const sessLogin2 = await apiLoginAs(sj2, UA_B);
    ok('会话:同一用户两次 API 登录成功', sessLogin1.status === 200 && (await sessLogin1.json()).ok === true
      && sessLogin2.status === 200 && (await sessLogin2.json()).ok === true);

    const sessList1 = await (await call(sj1, '/api/sessions')).json();
    const curRowApi = sessList1.sessions?.find((s) => s.is_current);
    ok('会话:/api/sessions 返回两条且其中一条标记当前会话', sessList1.authenticated === true
      && Array.isArray(sessList1.sessions) && sessList1.sessions.length === 2
      && sessList1.sessions.filter((s) => s.is_current).length === 1
      && curRowApi?.id_hash === sessList1.current);
    ok('会话:/api/sessions 仅返回截断 id_hash 并携带 IP/UA/时间', sessList1.sessions.every((s) => typeof s.id_hash === 'string' && s.id_hash.length === 8)
      && sessList1.sessions.some((s) => s.ua === UA_A) && sessList1.sessions.some((s) => s.ua === UA_B)
      && sessList1.sessions.every((s) => !!s.ip && s.created_at > 0 && s.expires_at > s.created_at));

    const sessDbRows = sessionsM.listForUser(sessUser.id);
    ok('会话:UA 与 IP 落库非空', sessDbRows.length === 2
      && sessDbRows.every((s) => s.ip !== '' && s.ua !== '')
      && sessDbRows.every((s) => s.ua === UA_A || s.ua === UA_B));

    // 会话列表页:两条会话都展示,当前行带「当前」徽章
    const sessPageRes = await call(sj1, '/account/sessions');
    const sessPageHtml = await sessPageRes.text();
    const pageRows = sessPageHtml.split('<tr');
    const rowA = pageRows.find((t) => t.includes(UA_A));
    const rowB = pageRows.find((t) => t.includes(UA_B));
    ok('会话:列表页展示两条会话且当前行有「当前」徽章', sessPageRes.status === 200
      && !!rowA && !!rowB && rowA !== rowB
      && rowA.includes('>当前</span>') && !rowB.includes('>当前</span>')
      && rowA.includes(curRowApi.id_hash));
    ok('会话:列表页含撤销操作、撤销其它按钮与重新登录说明', sessPageHtml.includes('重新登录')
      && sessPageHtml.includes('action="/account/sessions/revoke"')
      && sessPageHtml.includes('action="/account/sessions/revoke-others"')
      && sessPageHtml.includes('撤销其它全部会话'));

    // 撤销其它会话(当前会话保留):列表只剩一条,被撤销的 cookie 失效
    const sessOthersRes = await call(sj1, '/api/sessions/revoke-others', { method: 'POST', json: {}, headers: { 'X-Requested-With': 'JSON' } });
    const sessAfterOthers = await (await call(sj1, '/api/sessions')).json();
    ok('会话:撤销其它会话后 /api/sessions 只剩当前一条', sessOthersRes.status === 200
      && (await sessOthersRes.json()).ok === true
      && sessAfterOthers.sessions.length === 1 && sessAfterOthers.sessions[0].is_current);
    const sj2State = await (await call(sj2, '/api/session')).json();
    ok('会话:被撤销会话的 cookie 再访问 /api/session 变为未登录', sj2State.authenticated === false);

    // 撤销指定会话:用列表返回的截断 id_hash 定位
    const sj3 = new Jar();
    const sessLogin3 = await apiLoginAs(sj3, UA_B);
    ok('会话:再次 API 登录产生新会话', sessLogin3.status === 200);
    const beforeRevoke = await (await call(sj1, '/api/sessions')).json();
    const otherRow = beforeRevoke.sessions.find((s) => !s.is_current);
    const sessRevokeRes = await call(sj1, '/api/sessions/revoke', { method: 'POST', json: { id_hash: otherRow.id_hash }, headers: { 'X-Requested-With': 'JSON' } });
    const afterSessRevoke = await (await call(sj1, '/api/sessions')).json();
    ok('会话:撤销指定会话生效(截断 id_hash 定位)', sessRevokeRes.status === 200
      && (await sessRevokeRes.json()).ok === true && afterSessRevoke.sessions.length === 1);
    const sj3State = await (await call(sj3, '/api/session')).json();
    ok('会话:被撤销指定会话的 cookie 变为未登录', sj3State.authenticated === false);

    // web 表单:撤销当前会话 → 等同登出
    const curPageForm = extractHidden(await (await call(sj1, '/account/sessions')).text());
    const webRevokeRes = await call(sj1, '/account/sessions/revoke', {
      method: 'POST', form: { id_hash: curPageForm.id_hash, _csrf: curPageForm._csrf },
    });
    ok('会话:web 撤销当前会话等同登出并重定向登录页', webRevokeRes.status === 302
      && location(webRevokeRes).startsWith('/login?msg='));
    const sj1State = await (await call(sj1, '/api/session')).json();
    ok('会话:web 撤销当前会话后原 cookie 失效', sj1State.authenticated === false);

    // web 表单:撤销其它全部会话(两个浏览器会话,保留当前)
    const swj = new Jar(), swj2 = new Jar();
    let swForm = extractHidden(await (await call(swj, '/login')).text());
    await call(swj, '/login', { method: 'POST', form: { username: 'sessman', password: 'Sess#12345', _csrf: swForm._csrf } });
    swForm = extractHidden(await (await call(swj2, '/login')).text());
    await call(swj2, '/login', { method: 'POST', form: { username: 'sessman', password: 'Sess#12345', _csrf: swForm._csrf } });
    const webOthersRes = await call(swj, '/account/sessions/revoke-others', {
      method: 'POST', form: { _csrf: extractHidden(await (await call(swj, '/account/sessions')).text())._csrf },
    });
    ok('会话:web 撤销其它全部会话后回列表页带提示', webOthersRes.status === 302
      && location(webOthersRes).startsWith('/account/sessions?msg='));
    const swj2State = await (await call(swj2, '/api/session')).json();
    ok('会话:web 撤销其它会话后其它设备 cookie 失效', swj2State.authenticated === false);
    const remainRes = await call(swj, '/account/sessions');
    const remainHtml = await remainRes.text();
    ok('会话:web 撤销其它会话后列表仅剩当前会话', remainRes.status === 200
      && (remainHtml.match(/action="\/account\/sessions\/revoke"/g) || []).length === 1);

    // 越权防护:不能撤销其它用户的会话(模型层 user_id 双条件)
    const sessAdminUser = users.byUsername('admin');
    const adminHash = sessionsM.listForUser(sessAdminUser.id)[0].id_hash;
    const crossRes = await call(swj, '/account/sessions/revoke', {
      method: 'POST',
      form: { id_hash: adminHash, _csrf: extractHidden(await (await call(swj, '/account/sessions')).text())._csrf },
    });
    ok('会话:不能撤销其它用户的会话(防越权)', crossRes.status === 302
      && location(crossRes).startsWith('/account/sessions?err=')
      && sessionsM.listForUser(sessAdminUser.id).some((s) => s.id_hash === adminHash)
      && (await (await call(aj, '/api/session')).json()).authenticated === true);

    const notFoundRes = await call(swj, '/api/sessions/revoke', { method: 'POST', json: { id_hash: 'ffffffff' }, headers: { 'X-Requested-With': 'JSON' } });
    ok('会话:撤销不存在的会话返回 404', notFoundRes.status === 404);

    /* ---------- 应用 Logo 直接上传(放在向导重跑段之前) ---------- */
    const PNG_1PX = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
    const GIF_1PX = Buffer.from('R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==', 'base64');
    const uploadsDirSmoke = path.join(DATA, 'uploads');
    const listUploads = () => (fs.existsSync(uploadsDirSmoke) ? fs.readdirSync(uploadsDirSmoke).sort() : []);
    // 手拼 multipart:node 构造 boundary + 真实字节(零依赖,与浏览器表单行为一致)
    const postMultipart = async (jar, pathName, { fields = {}, file } = {}) => {
      const boundary = '----sakuralogosmoke' + crypto.randomBytes(10).toString('hex');
      const parts = [];
      for (const [k, v] of Object.entries(fields)) {
        parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`));
      }
      if (file) {
        parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${file.name}"; filename="${file.filename}"\r\nContent-Type: ${file.contentType}\r\n\r\n`));
        parts.push(file.data);
        parts.push(Buffer.from('\r\n'));
      }
      parts.push(Buffer.from(`--${boundary}--\r\n`));
      return call(jar, pathName, {
        method: 'POST',
        headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
        raw: Buffer.concat(parts),
      });
    };

    // 承载 Logo 用例的专用应用
    r = await call(aj, '/admin/apps/create', {
      method: 'POST',
      form: [['name', 'Logo 演示'], ['client_type', 'public'],
        ['redirect_uris', 'http://127.0.0.1:8080/logo-cb'], ['scopes', 'openid'], ['_csrf', adminCsrf]],
    });
    ok('Logo:创建测试应用成功', r.status === 302 && location(r).startsWith('/admin/apps/'));
    const logoAppId = new URL(location(r), BASE).pathname.split('/').pop();
    r = await call(aj, `/admin/apps/${logoAppId}`);
    const logoDetail0 = await r.text();
    const logoCsrf = extractHidden(logoDetail0)._csrf;
    ok('Logo:详情页提供上传卡片(multipart 表单/文件输入/限制说明)', r.status === 200
      && logoDetail0.includes('应用 Logo')
      && logoDetail0.includes(`action="/admin/apps/${logoAppId}/logo"`)
      && logoDetail0.includes('enctype="multipart/form-data"')
      && logoDetail0.includes('name="logo"') && logoDetail0.includes('accept="image/*"')
      && logoDetail0.includes('2MB') && logoDetail0.includes('PNG') && logoDetail0.includes('WebP'));

    // 上传 PNG:multipart 中 csrf 走 fields;302 回详情 + logo_url 更新 + 文件落盘
    r = await postMultipart(aj, `/admin/apps/${logoAppId}/logo`, {
      fields: { _csrf: logoCsrf },
      file: { name: 'logo', filename: 'logo.png', contentType: 'image/png', data: PNG_1PX },
    });
    ok('Logo:上传 PNG 成功(302 回详情页)', r.status === 302 && location(r).startsWith(`/admin/apps/${logoAppId}?msg=`),
      `status=${r.status} loc=${location(r)}`);
    const logoPngPath = path.join(uploadsDirSmoke, `${logoAppId}.png`);
    ok('Logo:上传后 logo_url 指向 /uploads 且文件字节与上传一致', clients.byId(logoAppId).logo_url === `/uploads/${logoAppId}.png`
      && fs.existsSync(logoPngPath) && Buffer.compare(fs.readFileSync(logoPngPath), PNG_1PX) === 0);
    ok('打磨:Logo 原子化上传(上传完成后 uploads 目录无 .tmp- 临时文件残留)', listUploads().length > 0
      && listUploads().every((n) => !n.includes('.tmp-')), `dir=${JSON.stringify(listUploads())}`);

    // 静态服务:匿名 200 + image/png + 字节一致 + 公开缓存 + nosniff
    r = await fetch(BASE + `/uploads/${logoAppId}.png`);
    const servedLogo = Buffer.from(await r.arrayBuffer());
    ok('Logo:GET /uploads 匿名返回 200 与 image/png 且字节一致', r.status === 200
      && r.headers.get('content-type') === 'image/png' && Buffer.compare(servedLogo, PNG_1PX) === 0,
      `status=${r.status} ct=${r.headers.get('content-type')}`);
    ok('Logo:静态服务带 public 缓存与 nosniff 头', (r.headers.get('cache-control') || '').includes('max-age=604800')
      && r.headers.get('x-content-type-options') === 'nosniff');

    // 详情页出现上传 Logo 的预览 img
    r = await call(aj, `/admin/apps/${logoAppId}`);
    const logoDetail1 = await r.text();
    ok('Logo:详情页渲染上传 Logo 预览 img', r.status === 200
      && logoDetail1.includes(`<img src="/uploads/${logoAppId}.png"`));

    // 目录穿越与白名单外文件名一律 404
    ok('Logo:目录穿越路径被拒(404)', (await fetch(BASE + '/uploads/..%2F..%2Fidp.sqlite')).status === 404);
    ok('Logo:白名单外扩展名被拒(404)', (await fetch(BASE + `/uploads/${logoAppId}.txt`)).status === 404);

    // 非图片字节(伪造 .png):415 拒绝且不留文件、logo_url 不变
    const beforeBad = listUploads();
    r = await postMultipart(aj, `/admin/apps/${logoAppId}/logo`, {
      fields: { _csrf: logoCsrf },
      file: { name: 'logo', filename: 'fake.png', contentType: 'image/png', data: Buffer.from('definitely-not-an-image-bytes-0123456789') },
    });
    ok('Logo:非图片字节被拒(415)', r.status === 415, `status=${r.status}`);
    ok('Logo:非图片拒绝后不留文件且 logo_url 不变', JSON.stringify(listUploads()) === JSON.stringify(beforeBad)
      && clients.byId(logoAppId).logo_url === `/uploads/${logoAppId}.png`);

    // 超过 2MB:413(魔数合法但体量超限)
    r = await postMultipart(aj, `/admin/apps/${logoAppId}/logo`, {
      fields: { _csrf: logoCsrf },
      file: { name: 'logo', filename: 'big.png', contentType: 'image/png', data: Buffer.concat([PNG_1PX, Buffer.alloc(2 * 1024 * 1024 + 1024, 0x61)]) },
    });
    ok('Logo:超过 2MB 上传被拒(413)', r.status === 413, `status=${r.status}`);

    // CSRF 错误被拒
    r = await postMultipart(aj, `/admin/apps/${logoAppId}/logo`, {
      fields: { _csrf: 'wrong-csrf-value' },
      file: { name: 'logo', filename: 'x.png', contentType: 'image/png', data: PNG_1PX },
    });
    ok('Logo:CSRF 错误时上传被拒', r.status === 302 && location(r).includes('err='));

    // 普通用户不可操作(路由 {auth:'admin'});未登录重定向登录页
    ok('Logo:普通用户上传被拒(403)', (await postMultipart(fj, `/admin/apps/${logoAppId}/logo`, {
      fields: { _csrf: 'x' },
      file: { name: 'logo', filename: 'x.png', contentType: 'image/png', data: PNG_1PX },
    })).status === 403);
    ok('Logo:未登录上传重定向登录页', (await postMultipart(new Jar(), `/admin/apps/${logoAppId}/logo`, {
      fields: { _csrf: 'x' },
      file: { name: 'logo', filename: 'x.png', contentType: 'image/png', data: PNG_1PX },
    })).status === 302);

    // 换格式重传 GIF:扩展名变化 → 旧 PNG 清理、logo_url 指向新文件
    r = await postMultipart(aj, `/admin/apps/${logoAppId}/logo`, {
      fields: { _csrf: logoCsrf },
      file: { name: 'logo', filename: 'logo.gif', contentType: 'image/gif', data: GIF_1PX },
    });
    ok('Logo:重传 GIF 成功且旧 PNG 文件被清理', r.status === 302
      && clients.byId(logoAppId).logo_url === `/uploads/${logoAppId}.gif`
      && !fs.existsSync(logoPngPath)
      && fs.existsSync(path.join(uploadsDirSmoke, `${logoAppId}.gif`)));
    ok('打磨:Logo 连传两种扩展后目录文件名集合精确(仅 *.gif,无旧 PNG 与 .tmp- 残留)',
      JSON.stringify(listUploads().filter((n) => n.startsWith(logoAppId + '.'))) === JSON.stringify([`${logoAppId}.gif`])
      && listUploads().every((n) => !n.includes('.tmp-')), `dir=${JSON.stringify(listUploads())}`);

    // 删除 Logo:文件删除 + logo_url 置空
    r = await call(aj, `/admin/apps/${logoAppId}/logo/delete`, { method: 'POST', form: { _csrf: logoCsrf } });
    ok('Logo:删除后 logo_url 清空且文件删除', r.status === 302 && location(r).includes('msg=')
      && clients.byId(logoAppId).logo_url === ''
      && !fs.existsSync(path.join(uploadsDirSmoke, `${logoAppId}.gif`)));

    // 外链 URL 字段仍可用(回归):与上传二选一,后保存者生效
    r = await call(aj, `/admin/apps/${logoAppId}/update`, {
      method: 'POST',
      form: [['name', 'Logo 演示'], ['redirect_uris', 'http://127.0.0.1:8080/logo-cb'],
        ['scopes', 'openid'], ['logo_url', 'https://cdn.example.com/external-logo.png'], ['_csrf', logoCsrf]],
    });
    ok('Logo:外链 URL 字段仍可用(回归)', r.status === 302 && location(r).includes('msg=')
      && clients.byId(logoAppId).logo_url === 'https://cdn.example.com/external-logo.png');

    // 审计留痕:上传 2 次 + 删除 1 次
    ok('Logo:上传与删除计入审计', auditM.list({ action: 'admin.app_logo_uploaded', limit: 100 }).length === 2
      && auditM.list({ action: 'admin.app_logo_deleted', limit: 100 }).length === 1);

    // 清空 Logo 字段(应用设置保存):此前上传的文件同步清理,不再残留孤儿文件
    r = await postMultipart(aj, `/admin/apps/${logoAppId}/logo`, {
      fields: { _csrf: logoCsrf },
      file: { name: 'logo', filename: 'logo.png', contentType: 'image/png', data: PNG_1PX },
    });
    ok('Logo:重新上传 PNG 成功(供清理用例)', r.status === 302
      && fs.existsSync(path.join(uploadsDirSmoke, `${logoAppId}.png`)));
    r = await call(aj, `/admin/apps/${logoAppId}/update`, {
      method: 'POST',
      form: [['name', 'Logo 演示'], ['redirect_uris', 'http://127.0.0.1:8080/logo-cb'],
        ['scopes', 'openid'], ['logo_url', ''], ['_csrf', logoCsrf]],
    });
    ok('Logo:清空 Logo 字段后上传文件同步清理(无孤儿文件)', r.status === 302 && location(r).includes('msg=')
      && clients.byId(logoAppId).logo_url === '' && !fs.existsSync(path.join(uploadsDirSmoke, `${logoAppId}.png`)));



    /* ---------- Passkey/WebAuthn:模拟真认证器(零依赖 CBOR + ES256 手造凭据) ---------- */
    const webauthnModel = await import('../src/models/webauthn.js');
    const pkUser = users.create({ username: 'passy', passwordHash: hashPassword('Passy#12345'), name: '帕斯基' });
    const pkHandle = Buffer.from(pkUser.id).toString('base64url');
    const pkJar = new Jar();
    const pkPreLogin = await call(pkJar, '/api/login', { method: 'POST', json: { username: 'passy', password: 'Passy#12345' } });
    ok('Passkey:前置用户经 API 登录成功', pkPreLogin.status === 200 && (await pkPreLogin.json()).ok === true);

    // JS 资产:匿名可访问且 Content-Type 正确
    r = await fetch(BASE + '/assets/webauthn.js');
    ok('Passkey:webauthn.js 资产匿名可访问且 Content-Type 正确', r.status === 200
      && /javascript/.test(r.headers.get('content-type') || '')
      && (await r.text()).includes('navigator.credentials'));

    // 登录页埋点:按钮 / 状态行 / defer 脚本引用
    r = await call(new Jar(), '/login');
    const pkLoginHtml0 = await r.text();
    ok('Passkey:登录页含按钮、状态行与脚本引用', pkLoginHtml0.includes('id="passkey-login-btn"')
      && pkLoginHtml0.includes('id="passkey-status"')
      && pkLoginHtml0.includes('<script src="/assets/webauthn.js" defer></script>'));

    // 未登录 JSON 接口 401(api.js 风格,不重定向)
    r = await call(new Jar(), '/webauthn/register/options');
    ok('Passkey:未登录请求注册参数返回 401', r.status === 401 && (await r.json()).error === 'unauthenticated');

    // 匿名登录参数:discoverable(allowCredentials 为空)
    r = await call(new Jar(), '/webauthn/login/options');
    const pkAnonOpt = await r.json();
    ok('Passkey:匿名可取登录参数且 allowCredentials 为空(discoverable)', r.status === 200
      && !!pkAnonOpt.challengeId && (pkAnonOpt.challenge || '').length >= 43
      && Array.isArray(pkAnonOpt.allowCredentials) && pkAnonOpt.allowCredentials.length === 0
      && pkAnonOpt.rpId === PK_RP_ID && pkAnonOpt.userVerification === 'preferred');

    // 注册辅助:options → 手造 attestation → verify
    const regOnce = async (jar, { name = '测试密钥', credId, challengeOverride, originOverride, noHeader = false } = {}) => {
      const optRes = await call(jar, '/webauthn/register/options', { headers: { 'X-Requested-With': 'JSON' } });
      if (optRes.status !== 200) return { status: optRes.status, body: await optRes.json() };
      const opt = (await optRes.json()).publicKey;
      const att = makeAttestation({
        challenge: challengeOverride ?? opt.challenge,
        credId,
        origin: originOverride ?? BASE,
      });
      const vRes = await call(jar, '/webauthn/register/verify', {
        method: 'POST',
        json: { name, response: att },
        headers: noHeader ? {} : { 'X-Requested-With': 'JSON' },
      });
      return { status: vRes.status, body: await vRes.json() };
    };

    // 登录辅助:options → 手造 assertion → verify(独立 jar 承接会话)
    const loginOnce = async ({ challengeOverride, originOverride, challengeIdOverride, credIdB64, counter = 1, corrupt = false, noHeader = false } = {}) => {
      const jar = new Jar();
      const oRes = await call(jar, '/webauthn/login/options');
      const o = await oRes.json();
      const assertion = makeAssertion({
        challenge: challengeOverride ?? o.challenge,
        credIdB64,
        counter,
        origin: originOverride ?? BASE,
        userHandle: pkHandle,
        corrupt,
      });
      const vRes = await call(jar, '/webauthn/login/verify', {
        method: 'POST',
        json: { challengeId: challengeIdOverride ?? o.challengeId, response: assertion },
        headers: noHeader ? {} : { 'X-Requested-With': 'JSON' },
      });
      return { jar, o, status: vRes.status, body: await vRes.json() };
    };

    // 注册(fmt=none):成功入库,计数器 0
    const credA = crypto.randomBytes(32).toString('base64url');
    let pkR = await regOnce(pkJar, { name: '主力密钥', credId: Buffer.from(credA, 'base64url') });
    ok('Passkey:注册(fmt=none)成功且返回名称', pkR.status === 200 && pkR.body.ok === true && pkR.body.name === '主力密钥');
    ok('Passkey:凭据已入库且计数器为 0', webauthnModel.countForUser(pkUser.id) === 1
      && webauthnModel.byId(credA).counter === 0 && webauthnModel.byId(credA).name === '主力密钥');

    // 重复凭据 ID
    pkR = await regOnce(pkJar, { credId: Buffer.from(credA, 'base64url') });
    ok('Passkey:重复凭据 ID 注册被拒', pkR.status === 400 && pkR.body.error === 'duplicate');

    // attestation origin / challenge 错误;缺 Ajax 头
    pkR = await regOnce(pkJar, { credId: crypto.randomBytes(32), originOverride: 'https://evil.com' });
    ok('Passkey:attestation origin 错误被拒', pkR.status === 400 && pkR.body.error === 'origin_mismatch');
    pkR = await regOnce(pkJar, { credId: crypto.randomBytes(32), challengeOverride: 'wrong-challenge' });
    ok('Passkey:attestation challenge 错误被拒', pkR.status === 400 && pkR.body.error === 'challenge_mismatch');
    r = await call(pkJar, '/webauthn/register/verify', {
      method: 'POST', json: { name: 'x', response: { clientDataJSON: 'e30', attestationObject: 'e30' } },
    });
    ok('Passkey:注册校验缺 X-Requested-With 头被拒(403)', r.status === 403);

    // packed 自证明:合法通过,签名篡改被拒
    const pkPackedReg = async (corrupt = false) => {
      const opt = (await (await call(pkJar, '/webauthn/register/options')).json()).publicKey;
      const cd = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: opt.challenge, origin: BASE }));
      const credId = crypto.randomBytes(32);
      const ad = makeAuthData({ flags: 0x45, credId });
      let sig = crypto.sign('sha256', Buffer.concat([ad, crypto.createHash('sha256').update(cd).digest()]), pkKeys.privateKey);
      if (corrupt) { sig = Buffer.from(sig); sig[9] ^= 0xff; }
      return call(pkJar, '/webauthn/register/verify', {
        method: 'POST',
        json: { name: '自签密钥', response: {
          clientDataJSON: cd.toString('base64url'),
          attestationObject: cborEncode({ fmt: 'packed', attStmt: { alg: -7, sig }, authData: ad }).toString('base64url'),
        } },
        headers: { 'X-Requested-With': 'JSON' },
      });
    };
    r = await pkPackedReg(false);
    ok('Passkey:packed 自证明 attestation 注册成功', r.status === 200 && (await r.json()).ok === true);
    r = await pkPackedReg(true);
    ok('Passkey:packed 伪造签名被拒', r.status === 400 && (await r.json()).error === 'attestation_invalid');

    // 补满 8 个上限,第 9 个被拒
    for (let i = 0; i < 6 && webauthnModel.countForUser(pkUser.id) < 8; i++) {
      pkR = await regOnce(pkJar, { name: `补充密钥 ${i + 1}`, credId: crypto.randomBytes(32) });
    }
    ok('Passkey:可注册至 8 个上限', webauthnModel.countForUser(pkUser.id) === 8);
    pkR = await regOnce(pkJar, { credId: crypto.randomBytes(32) });
    ok('Passkey:超过 8 个上限被拒', pkR.status === 400 && pkR.body.error === 'too_many');

    // 登录参数带 username:列出该用户全部凭据 ID
    r = await call(new Jar(), '/webauthn/login/options?username=passy');
    const pkWithUser = await r.json();
    ok('Passkey:登录参数带 username 时列出该用户凭据', pkWithUser.allowCredentials.length === 8
      && pkWithUser.allowCredentials.some((c) => c.id === credA));

    // assertion:未知凭据 → 404 no_credentials
    let pkL = await loginOnce({ credIdB64: crypto.randomBytes(32).toString('base64url') });
    ok('Passkey:未知凭据返回 404 no_credentials', pkL.status === 404 && pkL.body.error === 'no_credentials');

    // 缺 Ajax 头;未知 challengeId
    {
      const jar = new Jar();
      const o = await (await call(jar, '/webauthn/login/options')).json();
      r = await call(jar, '/webauthn/login/verify', {
        method: 'POST',
        json: { challengeId: o.challengeId, response: makeAssertion({ challenge: o.challenge, credIdB64: credA, counter: 1, userHandle: pkHandle }) },
      });
      ok('Passkey:登录校验缺 X-Requested-With 头被拒(403)', r.status === 403);
    }
    pkL = await loginOnce({ challengeIdOverride: 'bogus-challenge-id' });
    ok('Passkey:未知 challengeId 被拒', pkL.status === 400 && pkL.body.error === 'challenge_expired');

    // 伪造签名 / origin 错 / challenge 错
    pkL = await loginOnce({ credIdB64: credA, corrupt: true });
    ok('Passkey:assertion 伪造签名被拒(401)', pkL.status === 401 && pkL.body.error === 'invalid_credentials');
    pkL = await loginOnce({ credIdB64: credA, originOverride: 'https://evil.com' });
    ok('Passkey:assertion origin 错误被拒', pkL.status === 401 && pkL.body.error === 'invalid_credentials');
    pkL = await loginOnce({ credIdB64: credA, challengeOverride: 'wrong-challenge' });
    ok('Passkey:assertion challenge 错误被拒', pkL.status === 401 && pkL.body.error === 'invalid_credentials');

    // 正常登录(counter=1):200 + Set-Cookie sid + 会话生效 + 计数器更新
    pkL = await loginOnce({ credIdB64: credA, counter: 1 });
    ok('Passkey:正常 assertion 登录成功', pkL.status === 200 && pkL.body.ok === true && pkL.body.user?.username === 'passy');
    ok('Passkey:登录响应 Set-Cookie 携带 sid', !!pkL.jar.map.get('sid'));
    const pkSess = await (await call(pkL.jar, '/api/session')).json();
    ok('Passkey:登录后 /api/session 为 authenticated', pkSess.authenticated === true && pkSess.user.username === 'passy');
    ok('Passkey:登录后计数器更新为 1', webauthnModel.byId(credA).counter === 1);

    // 计数器回退:按克隆拒绝并记审计
    pkL = await loginOnce({ credIdB64: credA, counter: 0 });
    ok('Passkey:计数器回退按克隆拒绝(409)', pkL.status === 409 && pkL.body.error === 'credential_cloned');
    ok('Passkey:克隆嫌疑计入审计', auditM.list({ action: 'auth.passkey_clone_suspect', limit: 10 })
      .some((row) => row.detail === credA));

    // 计数器递增后可再次登录
    pkL = await loginOnce({ credIdB64: credA, counter: 2 });
    ok('Passkey:计数器递增后可再次登录', pkL.status === 200 && webauthnModel.byId(credA).counter === 2);

    // 账号设置页:管理卡片、列表项与删除按钮
    r = await call(pkJar, '/account');
    const pkAcct = await r.text();
    ok('Passkey:账号设置页渲染管理卡片与脚本引用', pkAcct.includes('id="passkey-register-btn"')
      && pkAcct.includes('id="passkey-name"') && pkAcct.includes('id="passkey-list"')
      && pkAcct.includes('<script src="/assets/webauthn.js" defer></script>'));
    const pkAcctForm = extractHidden(pkAcct);
    ok('Passkey:列表项带凭据 ID 的删除按钮', pkAcct.includes(`data-cred-id="${credA}"`)
      && pkAcct.includes(`action="/account/webauthn/${credA}/delete"`));

    // 越权:不能删除其它用户的凭据(双条件删除)
    webauthnModel.create({ id: 'bob-pk-cred', userId: bob.id, name: 'Bob 密钥', publicKey: pkCose.toString('base64url') });
    r = await call(pkJar, '/account/webauthn/bob-pk-cred/delete', { method: 'POST', form: { _csrf: pkAcctForm._csrf } });
    ok('Passkey:不能删除其它用户的凭据(防越权)', r.status === 302 && location(r).startsWith('/account?err=')
      && !!webauthnModel.byId('bob-pk-cred'));

    // 删除自己的凭据
    r = await call(pkJar, `/account/webauthn/${credA}/delete`, { method: 'POST', form: { _csrf: pkAcctForm._csrf } });
    ok('Passkey:删除凭据成功回账号页且库中消失', r.status === 302 && location(r).startsWith('/account?msg=')
      && !webauthnModel.byId(credA) && webauthnModel.countForUser(pkUser.id) === 7);

    // 删除后凭据不可再登录
    pkL = await loginOnce({ credIdB64: credA, counter: 3 });
    ok('Passkey:删除后的凭据不可登录', pkL.status === 404 && pkL.body.error === 'no_credentials');

    // 审计:注册/删除/登录留痕
    ok('Passkey:注册计入审计(account.passkey_registered)', auditM.list({ action: 'account.passkey_registered', limit: 20 }).length === 8);
    ok('Passkey:删除计入审计(account.passkey_deleted)', auditM.list({ action: 'account.passkey_deleted', limit: 10 }).length === 1);
    ok('Passkey:登录计入审计(auth.passkey_login)', auditM.list({ action: 'auth.passkey_login', limit: 10 }).length === 2);
    webauthnModel.remove('bob-pk-cred', bob.id); // 清理越权测试夹具

    /* ---------- 运维:一键备份/恢复、新设备登录提醒、授权用户 CSV 导出(放在向导重跑段之前) ---------- */
    const consentsOps = await import('../src/models/consents.js');
    const { DatabaseSync } = await import('node:sqlite');

    /* ---------- 备份与恢复(独立子进程跑脚本;restore 在临时 DATA_DIR 演练,不动 .smoke-data) ---------- */
    const backupsDir = path.join(DATA, 'backups');
    const BACKUP_DIR_RE = /^sakuraid-backup-\d{8}-\d{6}(-\d+)?$/;
    const listBackupDirs = () => (fs.existsSync(backupsDir) ? fs.readdirSync(backupsDir).filter((n) => BACKUP_DIR_RE.test(n)).sort() : []);
    const listBackupTars = () => (fs.existsSync(backupsDir) ? fs.readdirSync(backupsDir).filter((n) => /^sakuraid-backup-\d{8}-\d{6}(-\d+)?\.tar\.gz$/.test(n)).sort() : []);
    const tarAvailable = spawnSync('tar', ['--version'], { encoding: 'utf8' }).status === 0;
    const runBackup = () => spawnSync(process.execPath, ['scripts/backup.mjs'], {
      cwd: ROOT, env: { ...process.env, DATA_DIR: DATA, BACKUP_KEEP: '2' }, encoding: 'utf8',
    });
    fs.mkdirSync(path.join(DATA, 'uploads'), { recursive: true });
    fs.writeFileSync(path.join(DATA, 'uploads', 'backup-probe.txt'), 'backup-probe');

    const b1 = runBackup();
    let snapInfo = null;
    if (b1.status === 0 && listBackupDirs().length === 1) {
      const dir = path.join(backupsDir, listBackupDirs()[0]);
      if (fs.existsSync(path.join(dir, 'idp.sqlite')) && fs.existsSync(path.join(dir, 'meta.txt'))) {
        let snap = new DatabaseSync(path.join(dir, 'idp.sqlite'));
        const userCount = snap.prepare('SELECT COUNT(*) AS n FROM users').get().n;
        snap.close();
        snapInfo = { userCount, meta: fs.readFileSync(path.join(dir, 'meta.txt'), 'utf8') };
      }
    }
    ok('备份:backup 脚本退出 0 并生成备份目录(含 idp.sqlite 与 meta.txt)', b1.status === 0 && !!snapInfo,
      `status=${b1.status} out=${(b1.stderr || b1.stdout || '').slice(-200)}`);
    ok('备份:快照可被 DatabaseSync 打开查询(users>0)且 meta.txt 含版本/issuer/备份时间', !!snapInfo && snapInfo.userCount > 0
      && snapInfo.meta.includes(pkgVersion) && snapInfo.meta.includes(BASE) && snapInfo.meta.includes('备份时间'),
      `users=${snapInfo?.userCount}`);
    ok('备份:生成同名 .tar.gz(系统 tar 可用时)', !tarAvailable || listBackupTars().length === 1,
      `tars=${listBackupTars().length} tar=${tarAvailable}`);

    const b2 = runBackup();
    ok('备份:连跑两次生成两份备份', b2.status === 0 && listBackupDirs().length === 2, `dirs=${listBackupDirs().length}`);
    const firstBackup = listBackupDirs()[0];
    const b3 = runBackup();
    ok('备份:BACKUP_KEEP=2 保留规则生效(仅留最近两份,目录与 tar 均删)', b3.status === 0
      && listBackupDirs().length === 2 && !listBackupDirs().includes(firstBackup)
      && (!tarAvailable || listBackupTars().length === 2), `dirs=${listBackupDirs().length} tars=${listBackupTars().length}`);

    const restoreTarget = path.join(ROOT, '.smoke-restore-target');
    const beforeDirs = () => fs.readdirSync(ROOT).filter((n) => n.startsWith('.smoke-restore-target-before-restore-'));
    const runRestore = (...args) => spawnSync(process.execPath, ['scripts/restore.mjs', ...args], {
      cwd: ROOT, env: { ...process.env, DATA_DIR: restoreTarget }, encoding: 'utf8',
    });
    fs.rmSync(restoreTarget, { recursive: true, force: true });
    fs.mkdirSync(path.join(restoreTarget, 'uploads'), { recursive: true });
    fs.writeFileSync(path.join(restoreTarget, 'idp.sqlite'), 'not-a-real-database');
    fs.writeFileSync(path.join(restoreTarget, 'uploads', 'old-file.txt'), 'old');

    const rRefuse = runRestore(path.join(backupsDir, listBackupDirs()[0]));
    ok('备份:restore 未加 --force 时拒绝执行并提示先停止服务', rRefuse.status !== 0
      && `${rRefuse.stdout}${rRefuse.stderr}`.includes('请先停止服务再恢复')
      && fs.readFileSync(path.join(restoreTarget, 'idp.sqlite'), 'utf8') === 'not-a-real-database', `status=${rRefuse.status}`);

    const rDir = runRestore(path.join(backupsDir, listBackupDirs()[0]), '--force');
    let restoredUsers = -1;
    try {
      const rdb = new DatabaseSync(path.join(restoreTarget, 'idp.sqlite'));
      restoredUsers = rdb.prepare('SELECT COUNT(*) AS n FROM users').get().n;
      rdb.close();
    } catch { /* 恢复失败时保持 -1 */ }
    ok('备份:restore --force 对备份目录执行后 idp.sqlite 可查询(users>0)', rDir.status === 0 && restoredUsers > 0,
      `status=${rDir.status} users=${restoredUsers} ${(rDir.stderr || '').slice(-200)}`);
    ok('备份:恢复时 uploads 随备份恢复且旧数据整体改名为 data-before-restore-<ts>', rDir.status === 0
      && fs.existsSync(path.join(restoreTarget, 'uploads', 'backup-probe.txt'))
      && beforeDirs().length === 1 && fs.existsSync(path.join(ROOT, beforeDirs()[0] || '', 'idp.sqlite'))
      && fs.existsSync(path.join(ROOT, beforeDirs()[0] || '', 'uploads', 'old-file.txt')),
      `before=${beforeDirs().length}`);

    let tarRestoreOk = true, tarUsers = 0;
    if (tarAvailable) {
      fs.rmSync(restoreTarget, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
      const rTar = runRestore(path.join(backupsDir, `${listBackupDirs()[0]}.tar.gz`), '--force');
      try {
        const tdb = new DatabaseSync(path.join(restoreTarget, 'idp.sqlite'));
        tarUsers = tdb.prepare('SELECT COUNT(*) AS n FROM users').get().n;
        tdb.close();
      } catch { tarUsers = -1; }
      tarRestoreOk = rTar.status === 0 && tarUsers > 0;
    }
    ok('备份:restore 支持直接恢复 .tar.gz(解包后 idp.sqlite 可查询)', !tarAvailable || tarRestoreOk, `users=${tarUsers}`);

    // 清理恢复演练产物(临时目录 + 改名前的旧数据目录)
    fs.rmSync(restoreTarget, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
    for (const bd of beforeDirs()) fs.rmSync(path.join(ROOT, bd), { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });

    /* ---------- 新设备登录邮件提醒 ---------- */
    const countInLog = (needle) => serverLog.split(needle).length - 1;
    const ND_UA = 'smoke-new-device-agent/1.0', NOEMAIL_UA = 'smoke-noemail-agent/1.0';

    // carol 有邮箱;该 IP+UA 组合从未出现过 → 新设备提醒(未配置 SMTP,dev 模式邮件全文进 serverLog)
    const ndj = new Jar();
    r = await call(ndj, '/login', { headers: { 'User-Agent': ND_UA } });
    const ndForm = extractHidden(await r.text());
    const ndBefore = countInLog('新设备登录提醒');
    r = await call(ndj, '/login', { method: 'POST', form: { username: 'carol', password: 'Carol#12345', _csrf: ndForm._csrf }, headers: { 'User-Agent': ND_UA } });
    ok('新设备:带新 UA 登录成功', r.status === 302, `status=${r.status} loc=${location(r)}`);
    let ndSeen = 0;
    for (let i = 0; i < 40 && !ndSeen; i++) { await sleep(150); ndSeen = countInLog('新设备登录提醒') - ndBefore; }
    await sleep(300); // 邮件打日志后审计写入紧随其后,留出落库时间
    ok('新设备:dev 模式提醒邮件进入 serverLog(主题「新设备登录提醒」)', ndSeen >= 1, `mails=${ndSeen}`);
    ok('新设备:邮件正文含用户名与 IP/设备信息', serverLog.includes('用户名:carol') && serverLog.includes('IP:') && serverLog.includes(ND_UA));
    ok('新设备:审计产生 auth.new_device(detail 含 ip 与 ua)', auditM.list({ action: 'auth.new_device', limit: 100 })
      .some((row) => row.actor === 'carol' && row.detail.includes('ip=') && row.detail.includes('ua=smoke-new-device-agent/1.0')));

    // 同 IP + 同 UA 二次登录:历史会话已出现过该组合 → 不再提醒
    const ndj2 = new Jar();
    r = await call(ndj2, '/login', { headers: { 'User-Agent': ND_UA } });
    const ndForm2 = extractHidden(await r.text());
    const nd2Before = countInLog('新设备登录提醒');
    r = await call(ndj2, '/login', { method: 'POST', form: { username: 'carol', password: 'Carol#12345', _csrf: ndForm2._csrf }, headers: { 'User-Agent': ND_UA } });
    await sleep(600);
    ok('新设备:同 IP+UA 二次登录不再提醒', r.status === 302 && countInLog('新设备登录提醒') === nd2Before,
      `count=${countInLog('新设备登录提醒')} before=${nd2Before}`);

    // email 为空的用户(bob):直接跳过发送,登录不受影响
    const bej = new Jar();
    r = await call(bej, '/login', { headers: { 'User-Agent': NOEMAIL_UA } });
    const beForm = extractHidden(await r.text());
    const beBefore = countInLog('新设备登录提醒');
    r = await call(bej, '/login', { method: 'POST', form: { username: 'bob', password: 'BobPassw0rd!', _csrf: beForm._csrf }, headers: { 'User-Agent': NOEMAIL_UA } });
    await sleep(500);
    const beSess = await (await call(bej, '/api/session')).json();
    ok('新设备:email 为空用户不发送提醒且登录正常(无崩溃)', r.status === 302 && beSess.authenticated === true
      && beSess.user?.username === 'bob' && countInLog('新设备登录提醒') === beBefore,
      `mails=${countInLog('新设备登录提醒') - beBefore}`);

    /* ---------- 应用授权用户 CSV 导出 ---------- */
    const csvApp = clients.create({
      name: 'CSV 导出演示', redirectUris: ['http://127.0.0.1:8080/csv-cb'],
      scopes: 'openid profile', isPublic: true, pkceRequired: true,
    });
    consentsOps.grant(bob.id, csvApp.client_id, 'openid profile');
    r = await call(aj, `/admin/apps/${csvApp.client_id}/consents.csv`);
    ok('授权导出:响应头正确(text/csv + attachment 文件名 + no-store)', r.status === 200
      && (r.headers.get('content-type') || '') === 'text/csv; charset=utf-8'
      && /^attachment; filename="consents-\d{8}-\d{6}\.csv"$/.test(r.headers.get('content-disposition') || '')
      && (r.headers.get('cache-control') || '') === 'no-store', `status=${r.status}`);
    // fetch 的 text() 会剥除开头 BOM,用原始字节验证 BOM 真实存在
    const consCsvRaw = Buffer.from(await (await fetch(BASE + `/admin/apps/${csvApp.client_id}/consents.csv`,
      { headers: { Cookie: aj.header() } })).arrayBuffer());
    ok('授权导出:BOM 开头且首行为中文表头', consCsvRaw[0] === 0xEF && consCsvRaw[1] === 0xBB && consCsvRaw[2] === 0xBF
      && consCsvRaw.slice(3).toString('utf8').split('\n')[0] === '用户名,姓名,授权范围,授权时间');
    const consCsvBody = await (await call(aj, `/admin/apps/${csvApp.client_id}/consents.csv`)).text();
    ok('授权导出:数据行含用户名/姓名/授权范围与可读授权时间', consCsvBody.includes('bob,小明,openid profile,'), consCsvBody.slice(0, 200));

    // csvCell 转义:公式前缀中和 + 逗号/引号字段包裹(CWE-1236)
    const csvUser = users.create({ username: '+csvuser', passwordHash: hashPassword('Csv#12345'), name: '姓名,含"引号"' });
    consentsOps.grant(csvUser.id, csvApp.client_id, 'openid');
    const csvEsc = await (await call(aj, `/admin/apps/${csvApp.client_id}/consents.csv`)).text();
    ok('授权导出:csvCell 转义生效(公式前缀中和、逗号/引号字段包裹)', csvEsc.includes("'") && csvEsc.includes("'+csvuser")
      && csvEsc.includes('"姓名,含""引号"""'), csvEsc.slice(0, 300));

    consentsOps.revoke(bob.id, csvApp.client_id);
    consentsOps.revoke(csvUser.id, csvApp.client_id);
    const csvEmpty = await (await call(aj, `/admin/apps/${csvApp.client_id}/consents.csv`)).text();
    ok('授权导出:无授权时仅导出表头', csvEmpty.replace(/^\uFEFF/, '').trim() === '用户名,姓名,授权范围,授权时间');

    r = await call(aj, '/admin/apps/nonexistent-app/consents.csv');
    ok('授权导出:应用不存在重定向回应用列表', r.status === 302 && location(r).startsWith('/admin/apps?err='));
    ok('授权导出:普通用户访问被拒(403)', (await call(fj, `/admin/apps/${csvApp.client_id}/consents.csv`)).status === 403);

    // 清理导出演示夹具(应用删除级联清理授权行)
    users.remove(csvUser.id);
    clients.remove(csvApp.client_id);



    /* ---------- 界面语言切换:cookie + /-/lang/:code(默认中文零回归,显式 en 才出英文) ---------- */
    r = await call(new Jar(), '/login');
    const zhDefaultLogin = await r.text();
    ok('语言:默认(无 cookie)登录页仍为简体中文且 lang=zh-CN', r.status === 200
      && zhDefaultLogin.includes('<html lang="zh-CN"') && zhDefaultLogin.includes('欢迎回来')
      && !zhDefaultLogin.includes('Welcome back'));

    const langJ = new Jar();
    r = await call(langJ, '/-/lang/en?back=' + encodeURIComponent('/login'));
    ok('语言:GET /-/lang/en 写入 lang cookie 并回到 back 页面', r.status === 302 && location(r) === '/login'
      && (r.headers.getSetCookie?.() || []).some((c) => c.startsWith('lang=en')));
    r = await call(langJ, '/login');
    const enLogin = await r.text();
    ok('语言:英文登录页含英文口号/表单标签且 html lang=en', r.status === 200
      && enLogin.includes('<html lang="en"') && enLogin.includes('Welcome back')
      && enLogin.includes('>Username</label>') && enLogin.includes('One home for all your sign-ins.'));
    ok('语言:英文登录页不再渲染中文欢迎语与中文标签', !enLogin.includes('欢迎回来')
      && !enLogin.includes('>用户名</label>'));
    r = await call(langJ, '/login');
    ok('语言:lang cookie 持久化(再次访问 /login 仍为英文)', r.status === 200
      && (await r.text()).includes('<html lang="en"'));
    r = await call(langJ, '/-/lang/zh?back=/login');
    r = await call(langJ, '/login');
    const zhBack = await r.text();
    ok('语言:切回 zh 恢复中文文案与 lang=zh-CN', r.status === 200
      && zhBack.includes('<html lang="zh-CN"') && zhBack.includes('欢迎回来'));
    r = await call(langJ, '/-/lang/en?back=' + encodeURIComponent('//evil.com'));
    ok('语言:协议相对 back 参数被拒(与主题切换同防开放重定向)', r.status === 302 && location(r) === '/');

    // 登录态下:侧栏切换链接 + en 导航/门户按钮 + 可逆恢复(fj 为 bob 会话)
    r = await call(fj, '/account');
    const sideHtml = await r.text();
    ok('语言:侧栏底部提供语言切换链接(与主题切换并排)', sideHtml.includes('/-/lang/en?back=')
      && sideHtml.includes('>English</a>'));
    await call(fj, '/-/lang/en?back=/apps');
    r = await call(fj, '/apps');
    const enPortal = await r.text();
    ok('语言:en 下门户页导航与按钮为英文', enPortal.includes('<html lang="en"')
      && enPortal.includes('App portal') && enPortal.includes('Open app')
      && enPortal.includes('Account settings'));
    await call(fj, '/-/lang/zh?back=/apps');
    r = await call(fj, '/apps');
    ok('语言:切回 zh 后门户页恢复中文(切换可逆)', (await r.text()).includes('应用门户'));

    // 默认中文下既有同意页关键断言回归抽查(nj2=noah,未授权过 Meta Portal,require_consent=1)
    r = await call(nj2, metaAuthUrl);
    ok('语言:中文同意页「请求访问你的账号」不受切换功能影响(回归抽查)', r.status === 200
      && (await r.text()).includes('请求访问你的账号'));

    /* ---------- 配置向导增强:管理员重新运行向导(放在最后,尾部恢复 setup_done=1) ---------- */
    r = await call(aj, '/admin');
    const rerunDash = await r.text();
    const rerunForm = extractHidden(rerunDash);
    ok('向导:控制台提供重新运行向导入口', rerunDash.includes('重新运行配置向导') && !!rerunForm._csrf);
    r = await call(aj, '/admin/rerun-wizard', { method: 'POST', form: { _csrf: rerunForm._csrf } });
    ok('向导:管理员触发重跑后跳到 /setup', r.status === 302 && location(r) === '/setup');
    const gated = await call(new Jar(), '/');
    ok('向导:重跑期间普通页面重定向 /setup', gated.status === 302 && location(gated) === '/setup');
    r = await call(aj, '/setup');
    ok('向导:重跑后 /setup 显示第 1 步环境检测', r.status === 200 && (await r.text()).includes('环境检测'));

    await call(aj, '/setup/step1', { method: 'POST', form: {} });
    r = await call(aj, '/setup');
    const wz2 = await r.text();
    ok('向导:第 2 步页面含自助注册与 SMTP 主机(重跑时携带会话 CSRF)',
      wz2.includes('自助注册') && wz2.includes('SMTP 主机') && !!extractHidden(wz2)._csrf);

    // 重跑守卫:库中已有用户后,匿名请求不得在窗口期改写站点设置或抢注管理员
    r = await call(wj, '/setup/step2', {
      method: 'POST',
      form: { site_name: '匿名篡改站', issuer: BASE, access_ttl: '900', refresh_ttl: '2592000', allow_register: '1' },
    });
    ok('向导:重跑期间匿名提交第 2 步被拒且设置不被改写', r.status === 302 && location(r) === '/setup'
      && settings.getMap().site_name === '樱落统一认证');
    r = await call(wj, '/setup/step3', {
      method: 'POST',
      form: { username: 'hijacker', password: 'Hijack#12345', password2: 'Hijack#12345' },
    });
    ok('向导:重跑期间匿名创建管理员被拒', r.status === 302 && location(r) === '/setup'
      && !users.list().some((u) => u.username === 'hijacker'));

    // 管理员本人(会话 + CSRF)提交第 2 步正常生效
    r = await call(aj, '/setup/step2', {
      method: 'POST',
      form: {
        site_name: '樱落统一认证', issuer: BASE, access_ttl: '900', refresh_ttl: '2592000',
        allow_register: '1', smtp_host: 'smtp.example.com', smtp_port: '587', smtp_from: 'noreply@example.com',
        _csrf: adminCsrf,
      },
    });
    const wzSettings = settings.getMap();
    ok('向导:管理员提交第 2 步后注册开关与 SMTP 设置生效', r.status === 302
      && wzSettings.allow_register === '1'
      && wzSettings.smtp_host === 'smtp.example.com'
      && wzSettings.smtp_from === 'noreply@example.com');

    r = await call(aj, '/setup');
    const wz3 = await r.text();
    ok('向导:已有账号时第 3 步显示跳过文案', wz3.includes('检测到已有账号'));
    r = await call(aj, '/setup/step3', { method: 'POST', form: { skip: '1' } });
    const wz4 = await r.text();
    ok('向导:跳过创建直接完成配置并解除重跑守卫', r.status === 200 && wz4.includes('配置完成')
      && settings.getMap().setup_rerun === '');
    const homeAfter = await call(new Jar(), '/');
    const regAfter = await call(new Jar(), '/register');
    ok('向导:完成后首页未登录重定向登录页', homeAfter.status === 302 && location(homeAfter) === '/login');
    ok('向导:完成后注册开关生效且注册页可用', regAfter.status === 200 && (await regAfter.text()).includes('确认密码'));

    /* ---------- 加固包:redirectUri 伪协议 / email 上限 / 限流 Map 清理 / 注册 next 续流 ---------- */
    const utilM = await import('../src/core/util.js');
    ok('加固:redirectUri 拒绝 javascript:/data:/vbscript: 伪协议', utilM.redirectUri('javascript:alert(1)') === null
      && utilM.redirectUri('DATA:text/html;base64,PHNjcmlwdD4=') === null
      && utilM.redirectUri('vbscript:MsgBox(1)') === null);
    ok('加固:redirectUri 仍接受 http(s) 与自定义 app scheme', utilM.redirectUri('https://example.com/cb') === 'https://example.com/cb'
      && utilM.redirectUri('http://127.0.0.1:8080/cb') !== null
      && utilM.redirectUri('com.example.app://oauth/callback') === 'com.example.app://oauth/callback');
    r = await call(aj, '/admin/apps/create', {
      method: 'POST',
      form: { name: 'Evil Scheme App', client_type: 'public', redirect_uris: 'javascript:alert(1)',
        scopes: 'openid', _csrf: adminCsrf },
    });
    ok('加固:管理端创建应用 javascript: 回调被拒', r.status === 200 && (await r.text()).includes('重定向地址不合法'));

    r = await call(aj, '/admin/users/create', {
      method: 'POST',
      form: { username: 'longmail', password: 'Long#12345', email: 'a'.repeat(250) + '@example.com', _csrf: adminCsrf },
    });
    ok('加固:email 超过 254 字被拒', r.status === 302 && location(r).startsWith('/admin/users/new?err=')
      && !users.byUsername('longmail'));

    // 限流 Map 清理:单元级驱动惰性过期清理与硬上限(测试进程内操作模块内部 Map)
    const regSvc = await import('../src/services/auth/register.js');
    const resetSvc = await import('../src/services/auth/reset.js');
    const regRL = regSvc._rateLimitInternal, rstRL = resetSvc._rateLimitInternal;
    regRL.map.clear();
    for (let i = 0; i < 3000; i++) regRL.map.set(`reg-exp-${i}`, { count: 1, first: 0 });
    for (let i = 0; i < 3000; i++) regRL.map.set(`reg-live-${i}`, { count: 1, first: Date.now() });
    regRL.prune();
    ok('加固:注册限流 Map 惰性清理过期项', regRL.map.size === 3000 && !regRL.map.has('reg-exp-0'));
    for (let i = 0; i < 2500; i++) regRL.map.set(`reg-x-${i}`, { count: 1, first: Date.now() });
    regRL.prune();
    ok('加固:注册限流 Map 硬上限 5000(淘汰最旧)', regRL.map.size === 5000);
    regRL.map.clear();
    rstRL.map.clear();
    for (let i = 0; i < 6000; i++) rstRL.map.set(`rst-${i}`, { count: 1, first: Date.now() });
    rstRL.prune();
    ok('加固:reset 限流 Map 硬上限 5000', rstRL.map.size === 5000);
    for (let i = 0; i < 100; i++) rstRL.map.set(`rst-exp-${i}`, { count: 1, first: 0 });
    rstRL.prune();
    ok('加固:reset 限流 Map 惰性清理过期项', rstRL.map.size === 5000 && !rstRL.map.has('rst-exp-0'));
    rstRL.map.clear();

    // 注册 next 续流:授权链路未登录 → 登录页注册链接带 next → 注册页透传 → 注册成功跳回 /authorize
    const chainVerifier = b64urlSha256('chain-verifier-0123456789abcdef');
    const chainAuthUrl = '/authorize?' + new URLSearchParams({
      client_id: web.client_id, redirect_uri: 'http://127.0.0.1:8080/cb',
      response_type: 'code', scope: 'openid profile', state: 'chain-st',
      code_challenge: chainVerifier, code_challenge_method: 'S256',
    }).toString();
    r = await call(new Jar(), '/login');
    ok('加固:登录页无 next 时注册链接保持原样', (await r.text()).includes('href="/register"'));
    const chainAnon = new Jar();
    r = await call(chainAnon, chainAuthUrl);
    const chainLoginLoc = location(r);
    ok('加固:未登录授权链路 302 到登录页并带 next', r.status === 302 && chainLoginLoc.startsWith('/login?next=')
      && new URL(chainLoginLoc, BASE).searchParams.get('next') === chainAuthUrl);
    r = await call(chainAnon, chainLoginLoc);
    const chainLoginHtml = await r.text();
    ok('加固:登录页注册链接携带完整 next', chainLoginHtml.includes(`href="/register?next=${encodeURIComponent(chainAuthUrl)}"`));
    r = await call(chainAnon, `/register?next=${encodeURIComponent(chainAuthUrl)}`);
    const chainRegForm = extractHidden(await r.text());
    ok('加固:注册页隐藏字段透传完整 next', chainRegForm.next.replaceAll('&amp;', '&') === chainAuthUrl);
    r = await call(chainAnon, '/register?next=//evil.com');
    ok('加固:注册页对协议相对 next 消毒为空', extractHidden(await r.text()).next === '');
    r = await call(chainAnon, '/register', {
      method: 'POST',
      form: { username: 'chainuser', password: 'Chain#12345', password2: 'Chain#12345', _csrf: chainRegForm._csrf, next: chainAuthUrl },
    });
    ok('加固:注册成功后按 next 续流回 /authorize', r.status === 302 && location(r) === chainAuthUrl);
    r = await call(chainAnon, location(r));
    ok('加固:注册续流后直达同意授权页(链路闭环)', r.status === 200 && (await r.text()).includes('请求访问你的账号'));

    // 行为验证:注册限流生效(计数先于 CSRF 校验;同 IP 窗口内超额提交被拒)
    let sawLimit = false;
    for (let i = 0; i < 6 && !sawLimit; i++) {
      const rr = await call(new Jar(), '/register', {
        method: 'POST',
        form: { username: `rl${i}`, password: 'Rl#123456', password2: 'Rl#123456', _csrf: 'bad' },
      });
      if (rr.status === 400 && (await rr.text()).includes('注册尝试过于频繁')) sawLimit = true;
    }
    ok('加固:注册限流行为验证(同 IP 窗口内超额提交被拒)', sawLimit);

    /* ---------- 模型层补充:consents 合并语义(重复授权按并集合并) ---------- */
    const consentsM = await import('../src/models/consents.js');
    const mergeApp = clients.create({
      name: 'Merge Probe', redirectUris: ['http://127.0.0.1:8080/merge'],
      scopes: 'openid profile email', isPublic: true, pkceRequired: false,
    });
    consentsM.grant(bob.id, mergeApp.client_id, 'openid profile');
    consentsM.grant(bob.id, mergeApp.client_id, 'email');
    ok('consents:重复授权按并集合并(既有 scope 不丢失)',
      consentsM.get(bob.id, mergeApp.client_id).scope === 'openid profile email');
    consentsM.revoke(bob.id, mergeApp.client_id);
    clients.remove(mergeApp.client_id); // 清理探针应用

    /* ---------- 品牌定制:站点 Logo / 主题强调色 / 口号(管理端可视化,全站即时生效) ---------- */
    const BRAND_TAGLINE = '统一入口,尽在樱落。';

    // 红线:未配置任何品牌定制时,登录页渲染与基线一字不差(樱花标 + 默认口号,无覆盖块/无 brand-logo)
    r = await call(new Jar(), '/login');
    const brandBaseLogin = await r.text();
    ok('品牌:未配置时登录页保持默认渲染(樱花标/默认口号/无覆盖块)', r.status === 200
      && brandBaseLogin.includes('viewBox="0 0 24 24"')
      && brandBaseLogin.includes('管好你所有系统的登录')
      && (brandBaseLogin.match(/--accent:/g) || []).length === 3
      && !brandBaseLogin.includes('class="brand-logo"')
      && !brandBaseLogin.includes('color-mix(in srgb,#fff,transparent 25%)'));

    // 控制台品牌定制卡片
    r = await call(aj, '/admin');
    const brandDash0 = await r.text();
    ok('品牌:控制台提供品牌定制卡片(Logo 上传/取色器/口号)', r.status === 200
      && brandDash0.includes('品牌定制')
      && brandDash0.includes('action="/admin/branding/logo"')
      && brandDash0.includes('enctype="multipart/form-data"')
      && brandDash0.includes('name="logo"') && brandDash0.includes('accept="image/*"')
      && brandDash0.includes('name="accent"') && brandDash0.includes('type="color"')
      && brandDash0.includes('name="tagline"')
      && brandDash0.includes('当前使用默认樱花标'));

    // 保存强调色与口号
    r = await call(aj, '/admin/branding', {
      method: 'POST', form: { accent: '#123456', tagline: BRAND_TAGLINE, _csrf: adminCsrf },
    });
    ok('品牌:保存强调色与口号成功且落库', r.status === 302 && location(r).includes('/admin?msg=')
      && settings.getSetting('brand_accent') === '#123456'
      && settings.getSetting('brand_tagline') === BRAND_TAGLINE);

    // 登录页:覆盖块 + 派生色(加深 12% / 渐变混紫罗兰 / YIQ 选白字)+ 自定义口号
    r = await call(new Jar(), '/login');
    const brandLogin = await r.text();
    ok('品牌:登录页注入强调色覆盖块(派生加深/渐变/on-accent)与自定义口号', brandLogin.includes('--accent:#123456')
      && brandLogin.includes('--accent-strong:#102e4c')
      && brandLogin.includes('--on-accent:#ffffff')
      && brandLogin.includes('--login-grad-a:#123456')
      && brandLogin.includes('--login-grad-b:#42379a')
      && brandLogin.includes(BRAND_TAGLINE));

    // 全站生效:健康页与控制台
    const brandHealth = await (await fetch(BASE + '/health')).text();
    const brandDash1 = await (await call(aj, '/admin')).text();
    ok('品牌:健康页与控制台同样生效强调色覆盖', brandHealth.includes('--accent:#123456')
      && brandDash1.includes('--accent:#123456'));

    // 授权同意页:品牌口号与强调色生效(新公开应用 require_consent + PKCE,bob 已登录且未授权过)
    r = await call(aj, '/admin/apps/create', {
      method: 'POST',
      form: [['name', '品牌演示'], ['client_type', 'public'],
        ['redirect_uris', 'http://127.0.0.1:8080/brand-cb'], ['scopes', 'openid'],
        ['require_consent', '1'], ['_csrf', adminCsrf]],
    });
    const brandAppId = new URL(location(r), BASE).pathname.split('/').pop();
    ok('品牌:创建 consent 演示应用成功', r.status === 302 && location(r).startsWith('/admin/apps/') && !!brandAppId);
    r = await call(uj, '/authorize?' + new URLSearchParams({
      client_id: brandAppId, redirect_uri: 'http://127.0.0.1:8080/brand-cb',
      response_type: 'code', scope: 'openid', state: 'brand-t',
      code_challenge: b64urlSha256('brand-verifier-0123456789abcdef'), code_challenge_method: 'S256',
    }));
    const brandConsent = await r.text();
    ok('品牌:授权同意页品牌面板口号与强调色生效', r.status === 200
      && brandConsent.includes('class="login-brand"') && brandConsent.includes(BRAND_TAGLINE)
      && brandConsent.includes('--accent:#123456'));
    clients.remove(brandAppId); // 清理演示应用

    // CSS 注入防护:非法色值被拒且不落库,注入内容不出现在页面
    r = await call(aj, '/admin/branding', {
      method: 'POST', form: { accent: 'red; } body{background:url(//evil)', tagline: BRAND_TAGLINE, _csrf: adminCsrf },
    });
    ok('品牌:CSS 注入形态的色值被拒(302 err 且不落库)', r.status === 302 && location(r).includes('/admin?err=')
      && settings.getSetting('brand_accent') === '#123456');
    ok('品牌:注入内容不出现在登录页样式', !((await (await call(new Jar(), '/login')).text()).includes('body{background')));

    // 其它非法形态:无 # 前缀 / 非法字符
    r = await call(aj, '/admin/branding', { method: 'POST', form: { accent: '123456', tagline: '', _csrf: adminCsrf } });
    const brandBadNoHash = r.status === 302 && location(r).includes('/admin?err=');
    r = await call(aj, '/admin/branding', { method: 'POST', form: { accent: '#12g45z', tagline: '', _csrf: adminCsrf } });
    ok('品牌:无 # 前缀与非法字符色值均被拒', brandBadNoHash && r.status === 302 && location(r).includes('/admin?err=')
      && settings.getSetting('brand_accent') === '#123456');

    // #RGB 三位色值接受并规范化为小写六位
    r = await call(aj, '/admin/branding', { method: 'POST', form: { accent: '#AbC', tagline: '', _csrf: adminCsrf } });
    ok('品牌:#RGB 三位色值接受并规范化为小写 #RRGGBB', r.status === 302 && location(r).includes('/admin?msg=')
      && settings.getSetting('brand_accent') === '#aabbcc');

    // 浅色强调色:on-accent 依 YIQ 自动切深色文字
    r = await call(aj, '/admin/branding', { method: 'POST', form: { accent: '#ffff00', tagline: '', _csrf: adminCsrf } });
    const brandLightLogin = await (await call(new Jar(), '/login')).text();
    ok('品牌:浅色强调色自动切深色文字(YIQ 分支)', brandLightLogin.includes('--accent:#ffff00')
      && brandLightLogin.includes('--on-accent:#1f2330'));

    // 权限:普通用户 403 / 未登录重定向
    ok('品牌:普通用户保存品牌被拒(403)', (await call(fj, '/admin/branding', {
      method: 'POST', form: { accent: '#123456', _csrf: 'x' },
    })).status === 403);
    const brandAnonRes = await call(new Jar(), '/admin/branding', {
      method: 'POST', form: { accent: '#123456', _csrf: 'x' },
    });
    ok('品牌:未登录保存品牌重定向登录页', brandAnonRes.status === 302 && location(brandAnonRes).startsWith('/login'));

    // 恢复强调色与口号供 Logo 用例
    r = await call(aj, '/admin/branding', {
      method: 'POST', form: { accent: '#123456', tagline: BRAND_TAGLINE, _csrf: adminCsrf },
    });

    // 上传站点 Logo(multipart,1x1 PNG):brand_logo_url 落库
    r = await postMultipart(aj, '/admin/branding/logo', {
      fields: { _csrf: adminCsrf },
      file: { name: 'logo', filename: 'site.png', contentType: 'image/png', data: PNG_1PX },
    });
    ok('品牌:上传站点 Logo 成功且 brand_logo_url 落库', r.status === 302 && location(r).includes('/admin?msg=')
      && settings.getSetting('brand_logo_url') === '/uploads/site-logo.png');

    // 静态服务:匿名可取、字节一致
    const siteLogoRes = await fetch(BASE + '/uploads/site-logo.png');
    ok('品牌:站点 Logo 匿名可取且字节一致', siteLogoRes.status === 200
      && siteLogoRes.headers.get('content-type') === 'image/png'
      && Buffer.compare(Buffer.from(await siteLogoRes.arrayBuffer()), PNG_1PX) === 0);

    // 登录页:brand-logo img 出现,樱花标回退消失
    r = await call(new Jar(), '/login');
    const brandLogoLogin = await r.text();
    ok('品牌:登录页 brand-logo img 生效且樱花标回退消失', brandLogoLogin.includes('<img src="/uploads/site-logo.png"')
      && brandLogoLogin.includes('class="brand-logo"')
      && !brandLogoLogin.includes('viewBox="0 0 24 24"'));

    // 换格式重传(JPG 魔数):旧 PNG 清理、URL 指向新扩展
    const JPG_MAGIC = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(32, 0x11)]);
    r = await postMultipart(aj, '/admin/branding/logo', {
      fields: { _csrf: adminCsrf },
      file: { name: 'logo', filename: 'site.jpg', contentType: 'image/jpeg', data: JPG_MAGIC },
    });
    ok('品牌:重传 JPG 成功且旧 PNG 清理、URL 指向新扩展', r.status === 302
      && settings.getSetting('brand_logo_url') === '/uploads/site-logo.jpg'
      && !fs.existsSync(path.join(uploadsDirSmoke, 'site-logo.png'))
      && fs.existsSync(path.join(uploadsDirSmoke, 'site-logo.jpg')));

    // 上传后控制台出现 Logo 预览 img 与删除按钮
    r = await call(aj, '/admin');
    const brandDash2 = await r.text();
    ok('品牌:上传后控制台显示 Logo 预览与删除按钮', r.status === 200
      && brandDash2.includes('<img src="/uploads/site-logo.jpg"') && brandDash2.includes('class="brand-logo"')
      && brandDash2.includes('action="/admin/branding/logo/delete"'));

    // 删除 Logo:文件清理 + 全站恢复樱花标
    r = await call(aj, '/admin/branding/logo/delete', { method: 'POST', form: { _csrf: adminCsrf } });
    const brandAfterDelete = await (await call(new Jar(), '/login')).text();
    ok('品牌:删除 Logo 后恢复默认樱花标且文件已清理', r.status === 302 && location(r).includes('/admin?msg=')
      && (settings.getSetting('brand_logo_url') || '') === ''
      && !fs.existsSync(path.join(uploadsDirSmoke, 'site-logo.jpg'))
      && brandAfterDelete.includes('viewBox="0 0 24 24"') && !brandAfterDelete.includes('class="brand-logo"'));

    // CSRF 错误被拒(multipart 文本字段)/ 非图片字节 415
    r = await postMultipart(aj, '/admin/branding/logo', {
      fields: { _csrf: 'wrong-csrf-value' },
      file: { name: 'logo', filename: 'x.png', contentType: 'image/png', data: PNG_1PX },
    });
    ok('品牌:CSRF 错误时 Logo 上传被拒', r.status === 302 && location(r).includes('err='));
    r = await postMultipart(aj, '/admin/branding/logo', {
      fields: { _csrf: adminCsrf },
      file: { name: 'logo', filename: 'fake.png', contentType: 'image/png', data: Buffer.from('not-an-image-at-all') },
    });
    ok('品牌:非图片字节上传被拒(415)', r.status === 415);

    // 审计留痕:成功保存 4 次(注入/非法被拒不计),上传 2 次,删除 1 次
    ok('品牌:品牌保存/Logo 上传与删除计入审计',
      auditM.list({ action: 'admin.branding_saved', limit: 100 }).length >= 4
      && auditM.list({ action: 'admin.branding_logo_uploaded', limit: 100 }).length === 2
      && auditM.list({ action: 'admin.branding_logo_deleted', limit: 100 }).length === 1);

    // 重置品牌回默认(收尾恢复基线,后续段落回归默认态)
    r = await call(aj, '/admin/branding', { method: 'POST', form: { accent: '', tagline: '', _csrf: adminCsrf } });
    const brandResetLogin = await (await call(new Jar(), '/login')).text();
    ok('品牌:重置后全站恢复默认(无覆盖块/无 brand-logo)', r.status === 302 && location(r).includes('/admin?msg=')
      && (settings.getSetting('brand_accent') || '') === '' && (settings.getSetting('brand_tagline') || '') === ''
      && !brandResetLogin.includes('--accent:#123456') && !brandResetLogin.includes('class="brand-logo"'));

    /* ---------- 打磨项:LICENSE 文件 / truncateCodePoints 码点安全截断 ---------- */
    const licenseText = fs.readFileSync(path.join(ROOT, 'LICENSE'), 'utf8');
    ok('打磨:LICENSE 文件存在且为标准 MIT(含版权行)',
      licenseText.includes('MIT License') && licenseText.includes('Copyright (c) 2026 Guyao146 / Sakura-Auth-Server contributors'));

    const { truncateCodePoints } = await import('../src/core/util.js');
    const loneSurrogate = (s) => /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
    const emojiUA = '👍'.repeat(50); // 50 个码点 / 100 个 UTF-16 编码单元
    ok('打磨:truncateCodePoints 码点安全截断(emoji 代理对不被拦腰截断,默认 max=40)',
      truncateCodePoints(emojiUA) === '👍'.repeat(40) + '…'
      && [...truncateCodePoints(emojiUA)].length === 41
      && !loneSurrogate(truncateCodePoints(emojiUA))
      && truncateCodePoints('a'.repeat(50), 40) === 'a'.repeat(40) + '…'
      && truncateCodePoints('樱'.repeat(45), 40) === '樱'.repeat(40) + '…'
      && truncateCodePoints('短的') === '短的' && truncateCodePoints('') === ''
      && truncateCodePoints(null) === '');

    console.log(failed ? `\n${failed} 项失败` : '\n全部通过 ✔');
  } finally {
    child.kill();
    if (msMock) { try { await msMock.close(); } catch { /* 关闭失败不掩盖测试结果 */ } }
    await sleep(800);
    // Windows 下 SQLite WAL 句柄释放稍慢,失败不掩盖真实测试结果
    try { fs.rmSync(DATA, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }); } catch {}
  }
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
