/**
 * Microsoft 登录核心件(msal.js)联调测试:
 * 起一个本地 mock Microsoft(0.0.0.0 随机端口),自签 RS256 id_token(kid='test-kid'),
 * 用 buildAuthUrl → exchangeCode → verifyIdToken 走通 OIDC 联邦最小闭环并断言 claims;
 * 再覆盖 aud/iss/exp/签名篡改等拒绝路径。
 * 运行:node scripts/test-ms.mjs(退出码 0 = 全部通过)
 */
import crypto from 'node:crypto';
import http from 'node:http';
import { buildAuthUrl, exchangeCode, verifyIdToken } from '../src/core/msal.js';

let failed = 0;
const ok = (name, cond, extra = '') => {
  if (!cond) failed++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${!cond && extra ? '  → ' + extra : ''}`);
};

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

/* ---------- mock Microsoft:JWKS / authorize / token ---------- */
const CLIENT_ID = 'test-ms-client';
const SUB = 'ms-sub-abc123', EMAIL = 'msuser@example.com', NAME = 'MS 测试用户';
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { kid: 'test-kid', alg: 'RS256', use: 'sig', ...publicKey.export({ format: 'jwk' }) };

/** 签发 id_token;expOffset 负数模拟过期,tamper 交换载荷字节模拟签名失败 */
function makeIdToken(iss, { aud = CLIENT_ID, expOffset = 3600, tamper = false } = {}) {
  const header = b64u({ alg: 'RS256', typ: 'JWT', kid: 'test-kid' });
  const now = Math.floor(Date.now() / 1000);
  const payload = b64u({ iss, sub: SUB, email: EMAIL, preferred_username: EMAIL, name: NAME, aud, iat: now, exp: now + expOffset });
  const sig = crypto.createSign('RSA-SHA256').update(`${header}.${payload}`).sign(privateKey, 'base64url');
  const broken = tamper ? payload.slice(0, -2) + 'xx' : payload;
  return `${header}.${broken}.${sig}`;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://mock');
  const json = (status, obj) => {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(obj));
  };
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
      Location: `${ru}${sep}code=MOCKCODE&state=${encodeURIComponent(url.searchParams.get('state') || '')}`,
    });
    res.end();
    return;
  }
  // token:校验 form 后返回自签 id_token(iss 与 verifyIdToken 的规则保持一致)
  let raw = '';
  for await (const ch of req) raw += ch;
  const form = new URLSearchParams(raw);
  if (form.get('grant_type') !== 'authorization_code' || form.get('client_id') !== CLIENT_ID
    || !form.get('code') || !form.get('code_verifier') || !form.get('redirect_uri')) {
    return json(400, { error: 'invalid_grant', error_description: 'mock: 表单校验失败' });
  }
  const authority = `http://127.0.0.1:${server.address().port}`;
  return json(200, {
    access_token: 'mock-access-token', token_type: 'Bearer', expires_in: 3600,
    id_token: makeIdToken(`${authority}/${tenantSeg}/v2.0`),
  });
});

await new Promise((resolve) => server.listen(0, '0.0.0.0', resolve));
const authority = `http://127.0.0.1:${server.address().port}`;
const redirectUri = `${authority}/auth/microsoft/callback`;

try {
  /* ---------- buildAuthUrl ---------- */
  const state = 'st_abc-123';
  const verifier = 'pkce-verifier-xyz';
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const authUrl = buildAuthUrl({ tenant: 'common', clientId: CLIENT_ID, redirectUri, state, codeChallenge: challenge, authority });
  ok('MSAL:authorize URL 指向 authority/{tenant}/oauth2/v2.0/authorize', authUrl.startsWith(`${authority}/common/oauth2/v2.0/authorize?`), authUrl);
  const q = new URL(authUrl).searchParams;
  ok('MSAL:authorize 参数齐全(response_type/scope/S256/prompt)', q.get('response_type') === 'code'
    && q.get('scope') === 'openid profile email'
    && q.get('code_challenge') === challenge && q.get('code_challenge_method') === 'S256'
    && q.get('prompt') === 'select_account');
  ok('MSAL:authorize 携带 client_id/redirect_uri/state', q.get('client_id') === CLIENT_ID
    && q.get('redirect_uri') === redirectUri && q.get('state') === state);
  ok('MSAL:scope 使用 %20 编码', authUrl.includes('scope=openid%20profile%20email'), authUrl);
  ok('MSAL:缺省 authority 为 login.microsoftonline.com',
    buildAuthUrl({ tenant: 'common', clientId: 'x', redirectUri: 'https://cb', state: 's', codeChallenge: 'c' })
      .startsWith('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?'));

  /* ---------- mock authorize 302 → code ---------- */
  const azRes = await fetch(authUrl, { redirect: 'manual' });
  const azLoc = new URL(azRes.headers.get('location') || '', authority);
  ok('MSAL:mock authorize 302 回 redirect_uri 并带 code/state', azRes.status === 302
    && azLoc.searchParams.get('code') === 'MOCKCODE' && azLoc.searchParams.get('state') === state);

  /* ---------- exchangeCode → verifyIdToken ---------- */
  const tokenRes = await exchangeCode({
    tenant: 'common', clientId: CLIENT_ID, clientSecret: 'test-secret',
    redirectUri, code: 'MOCKCODE', codeVerifier: verifier, authority,
  });
  ok('MSAL:exchangeCode 返回 id_token', !!tokenRes.id_token && tokenRes.token_type === 'Bearer');

  const claims = await verifyIdToken(tokenRes.id_token, { clientId: CLIENT_ID, tenant: 'common', authority });
  ok('MSAL:verifyIdToken 验签通过并返回 sub', !!claims && claims.sub === SUB, JSON.stringify(claims));
  ok('MSAL:claims 断言 email/preferred_username/name', claims.email === EMAIL
    && claims.preferred_username === EMAIL && claims.name === NAME);

  /* ---------- 拒绝路径 ---------- */
  const throws = async (fn) => { try { await fn(); return false; } catch { return true; } };
  ok('MSAL:aud 与 client_id 不符被拒绝', await throws(() =>
    verifyIdToken(makeIdToken(`${authority}/common/v2.0`, { aud: 'other-client' }), { clientId: CLIENT_ID, tenant: 'common', authority })));
  ok('MSAL:iss(tenant)不符被拒绝', await throws(() =>
    verifyIdToken(makeIdToken(`${authority}/other-tenant/v2.0`), { clientId: CLIENT_ID, tenant: 'common', authority })));
  ok('MSAL:过期 id_token 被拒绝', await throws(() =>
    verifyIdToken(makeIdToken(`${authority}/common/v2.0`, { expOffset: -10 }), { clientId: CLIENT_ID, tenant: 'common', authority })));
  ok('MSAL:篡改载荷验签失败被拒绝', await throws(() =>
    verifyIdToken(makeIdToken(`${authority}/common/v2.0`, { tamper: true }), { clientId: CLIENT_ID, tenant: 'common', authority })));
  ok('MSAL:token 端点拒绝时 exchangeCode 抛错', await throws(() =>
    exchangeCode({ tenant: 'common', clientId: CLIENT_ID, clientSecret: 'x', redirectUri, code: '', codeVerifier: 'v', authority })));
  ok('MSAL:格式不完整的 id_token 被拒绝', await throws(() =>
    verifyIdToken('not-a-jwt', { clientId: CLIENT_ID, tenant: 'common', authority })));
} finally {
  // Windows 下 process.exit() 会在句柄关闭中途触发 libuv 断言(async.c):
  // 先显式断开 keep-alive 连接,再用退出码自然退出。
  server.closeAllConnections();
  await new Promise((r) => server.close(r));
}

console.log(failed ? `\n${failed} 项失败` : '\n全部通过 ✔');
process.exitCode = failed ? 1 : 0;
