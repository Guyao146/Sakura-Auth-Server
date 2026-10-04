/** OAuth/OIDC 回归:临时数据库 + 真实服务函数,不占用端口、不读取业务数据。 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { spawnSync } from 'node:child_process';
import { sha256hex } from '../src/core/crypto.js';

const data = fs.mkdtempSync(path.join(os.tmpdir(), 'sakura-oauth-test-'));
process.env.DATA_DIR = data;
delete process.env.SQLITE_SYNCHRONOUS;
// 模拟未包含 Microsoft 列的老库,验证先补列再建索引。
const legacy = new DatabaseSync(path.join(data, 'idp.sqlite'));
legacy.exec(`CREATE TABLE users (
  id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '',
  user_groups TEXT NOT NULL DEFAULT '', password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0, disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);`);
legacy.close();

const { initDb, getDb } = await import('../src/core/db.js');
let failed = 0, passed = 0;
async function check(name, fn) {
  try { await fn(); passed++; console.log(`PASS  ${name}`); }
  catch (e) { failed++; console.error(`FAIL  ${name}: ${e.message}`); }
}
function response() {
  return {
    statusCode: 200, headers: {}, body: '',
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    getHeader(k) { return this.headers[k.toLowerCase()]; },
    writeHead(status, headers = {}) {
      this.statusCode = status;
      for (const [k, v] of Object.entries(headers)) this.setHeader(k, v);
    },
    end(body = '') { this.body = body; },
  };
}

try {
  initDb();
  const { initKeys } = await import('../src/core/keys.js');
  const { bindSettings, getRuntime } = await import('../src/core/runtime.js');
  const settings = await import('../src/models/settings.js');
  const users = await import('../src/models/users.js');
  const clients = await import('../src/models/clients.js');
  const codes = await import('../src/models/codes.js');
  const tokens = await import('../src/models/tokens.js');
  const audit = await import('../src/models/audit.js');
  const { hashPassword, verifyPassword, verifyUserPassword, verifyPasswordSync } = await import('../src/core/password.js');
  const { handleReset } = await import('../src/services/auth/reset.js');
  const { handleChangePassword } = await import('../src/services/auth/account.js');
  const sessions = await import('../src/models/sessions.js');
  const resets = await import('../src/models/resets.js');
  const { verifyJwt, signJwt } = await import('../src/core/jwt.js');
  const { authorizeGet, authorizePost } = await import('../src/services/oauth/authorize.js');
  const { tokenPost } = await import('../src/services/oauth/token.js');
  const { issueFull } = await import('../src/services/oauth/issue.js');
  const { introspectPost } = await import('../src/services/oauth/introspect.js');
  const { registry } = await import('../src/services/api.js');
  initKeys();
  bindSettings(() => settings.getMap());
  const user = users.create({ username: 'regression', passwordHash: await hashPassword('Test-only-password!') });
  const redirectUri = 'https://client.example/callback?existing=1';
  const client = clients.create({ name: 'PKCE', redirectUris: [redirectUri],
    scopes: 'openid profile offline_access', isPublic: true, pkceRequired: true, requireConsent: false });
  const optional = clients.create({ name: 'Optional PKCE', redirectUris: [redirectUri],
    scopes: 'openid', isPublic: true, pkceRequired: false, requireConsent: false });
  const confidential = clients.create({ name: 'Resource server', redirectUris: [redirectUri],
    scopes: 'openid', isPublic: false, secretHash: await hashPassword('test-client-secret') });
  const verifier = 'a'.repeat(64);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const session = { id_hash: 'test-session', csrf: 'test-csrf', created_at: Math.floor(Date.now() / 1000) - 60 };
  const base = { client_id: client.client_id, redirect_uri: redirectUri, response_type: 'code',
    scope: 'openid profile offline_access', state: 'state & +', nonce: 'original-nonce',
    code_challenge: challenge, code_challenge_method: 'S256', _csrf: session.csrf, decision: 'approve' };
  function ctx(body = {}, headers = {}) {
    const url = new URL('https://idp.example/authorize');
    url.search = new URLSearchParams(body).toString();
    return { body, query: url.searchParams, url, res: response(), user, session,
      cookies: { csrf: session.csrf },
      theme: 'light', runtime: getRuntime(), req: { headers, socket: { remoteAddress: '127.0.0.1' } } };
  }
  function auth(method, overrides) {
    const c = ctx({ ...base, ...overrides });
    (method === 'GET' ? authorizeGet : authorizePost)(c);
    return c.res;
  }
  function redirected(res) {
    assert.equal(res.statusCode, 302);
    const url = new URL(res.getHeader('location'));
    assert.equal(url.origin, 'https://client.example');
    assert.equal(url.searchParams.get('existing'), '1');
    assert.equal(url.searchParams.get('state'), base.state);
    return url.searchParams;
  }
  async function exchange(body) {
    const c = ctx({ client_id: client.client_id, ...body });
    await tokenPost(c);
    return { status: c.res.statusCode, body: c.res.body ? JSON.parse(c.res.body) : {} };
  }
  const countCodes = () => getDb().prepare('SELECT COUNT(*) AS n FROM auth_codes').get().n;

  await check('默认使用 FULL 持久性', () => assert.equal(getDb().prepare('PRAGMA synchronous').get().synchronous, 2));
  for (const [value, expected] of [['normal', 1], ['FULL', 2], ['OFF', 'invalid']]) {
    await check(`SQLITE_SYNCHRONOUS 显式配置 ${value}`, () => {
      const moduleUrl = new URL('../src/core/db.js', import.meta.url).href;
      const script = `import assert from 'node:assert/strict';
        import { initDb } from ${JSON.stringify(moduleUrl)};
        if (${JSON.stringify(expected)} === 'invalid') {
          assert.throws(() => initDb(), /SQLITE_SYNCHRONOUS/);
        } else {
          const db = initDb();
          try { assert.equal(db.prepare('PRAGMA synchronous').get().synchronous, ${JSON.stringify(expected)}); }
          finally { db.close(); }
        }`;
      const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
        env: { ...process.env, DATA_DIR: path.join(data, value), SQLITE_SYNCHRONOUS: value },
        encoding: 'utf8', timeout: 10000,
      });
      assert.equal(result.status, 0, result.stderr || result.error?.message);
    });
  }
  await check('老库补齐 Microsoft 列后建立索引', () => {
    assert.ok(getDb().prepare('PRAGMA table_info(users)').all().some((r) => r.name === 'ms_sub'));
    assert.ok(getDb().prepare('PRAGMA index_list(users)').all().some((r) => r.name === 'idx_users_ms_sub'));
  });
  for (const method of ['GET', 'POST']) {
    await check(`${method} 不支持的 response_type 返回 OAuth 错误而非异常`, () => {
      assert.equal(redirected(auth(method, { response_type: 'token' })).get('error'), 'unsupported_response_type');
    });
    const invalid = [
      ['缺少必需 challenge', { code_challenge: '', code_challenge_method: '' }],
      ['未知 method', { code_challenge_method: 'unknown' }],
      ['S256 长度错误', { code_challenge: 'short' }],
      ['S256 非法字符', { code_challenge: '!'.repeat(43) }],
      ['可选 PKCE 仅提交 method', { client_id: optional.client_id, code_challenge: '' }],
    ];
    for (const [label, fields] of invalid) {
      await check(`${method} 拒绝 ${label} 且不发码`, () => {
        const before = countCodes();
        const q = redirected(auth(method, fields));
        assert.equal(q.get('error'), 'invalid_request');
        assert.equal(countCodes(), before);
      });
    }
    await check(`${method} 合法 S256 发码`, () => {
      const code = redirected(auth(method, {})).get('code');
      assert.ok(code);
      assert.equal(codes.byCode(code).code_challenge_method, 'S256');
    });
    await check(`${method} 省略 method 默认 plain`, () => {
      const code = redirected(auth(method, { code_challenge: verifier, code_challenge_method: '' })).get('code');
      assert.ok(code);
      assert.equal(codes.byCode(code).code_challenge_method, 'plain');
    });
    await check(`${method} 非注册回调不可重定向`, () => {
      const res = auth(method, { redirect_uri: 'https://untrusted.example/callback' });
      assert.equal(res.statusCode, 400);
      assert.equal(res.getHeader('location'), undefined);
    });
  }
  await check('POST 拒绝授权保留 state', () => {
    assert.equal(redirected(auth('POST', { decision: 'deny' })).get('error'), 'access_denied');
  });
  await check('POST 非法类型的 PKCE 参数返回 invalid_request', () => {
    assert.equal(redirected(auth('POST', { code_challenge: [challenge] })).get('error'), 'invalid_request');
  });
  await check('POST CSRF 不匹配不得发码', () => {
    const before = countCodes();
    assert.equal(auth('POST', { _csrf: 'wrong' }).statusCode, 403);
    assert.equal(countCodes(), before);
  });
  await check('PKCE verifier 包含非法字符即使哈希匹配也拒绝', async () => {
    const invalidVerifier = '!'.repeat(64);
    const q = redirected(auth('GET', {
      code_challenge: crypto.createHash('sha256').update(invalidVerifier).digest('base64url'),
    }));
    const result = await exchange({ grant_type: 'authorization_code', code: q.get('code'),
      redirect_uri: redirectUri, code_verifier: invalidVerifier });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_grant');
  });
  await check('plain 默认 method 可完成令牌交换', async () => {
    const code = redirected(auth('GET', { code_challenge: verifier, code_challenge_method: '' })).get('code');
    assert.equal((await exchange({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: verifier })).status, 200);
  });
  const code = redirected(auth('POST', {})).get('code');
  const issued = await exchange({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: verifier });
  assert.equal(issued.status, 200);
  await check('RS256 at_hash 是 SHA256 前 16 字节的 base64url', () => {
    const expected = crypto.createHash('sha256').update(issued.body.access_token).digest().subarray(0, 16).toString('base64url');
    assert.equal(verifyJwt(issued.body.id_token).at_hash, expected);
  });
  await check('首次 refresh 记录保留 auth_time 和 nonce', () => {
    const row = tokens.byId(tokens.refreshKey(issued.body.refresh_token));
    assert.equal(row.auth_time, session.created_at);
    assert.equal(row.nonce, base.nonce);
  });
  let currentRefresh = issued.body.refresh_token;
  for (let i = 0; i < 2; i++) {
    await check(`第 ${i + 1} 次刷新保留原登录信息及轮换链`, async () => {
      const previous = currentRefresh;
      const result = await exchange({ grant_type: 'refresh_token', refresh_token: previous });
      assert.equal(result.status, 200);
      currentRefresh = result.body.refresh_token;
      const row = tokens.byId(tokens.refreshKey(currentRefresh));
      assert.equal(row.auth_time, session.created_at);
      assert.equal(row.nonce, base.nonce);
      const payload = verifyJwt(result.body.id_token);
      assert.equal(payload.auth_time, session.created_at);
      assert.equal(payload.nonce, base.nonce);
      assert.equal(tokens.byId(tokens.refreshKey(previous)).replaced_by, row.id);
      // 旧令牌标记作废(此处不重放,重放检测在最后单独验证,避免整条链被牵连)
      assert.equal(tokens.byId(tokens.refreshKey(previous)).revoked, 1);
    });
  }
  await check('刷新不得把无效 scope 静默升级为原有完整权限', async () => {
    const result = await exchange({ grant_type: 'refresh_token', refresh_token: currentRefresh, scope: 'unknown-scope' });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_scope');
    assert.equal(tokens.byId(tokens.refreshKey(currentRefresh)).revoked, 0);
  });
  for (const scope of ['', 'openid unknown-scope', ['openid']]) {
    await check(`刷新拒绝非法 scope: ${JSON.stringify(scope)}`, async () => {
      const result = await exchange({ grant_type: 'refresh_token', refresh_token: currentRefresh, scope });
      assert.equal(result.status, 400);
      assert.equal(result.body.error, 'invalid_scope');
      assert.equal(tokens.byId(tokens.refreshKey(currentRefresh)).revoked, 0);
    });
  }
  await check('刷新可缩减 scope', async () => {
    const result = await exchange({ grant_type: 'refresh_token', refresh_token: currentRefresh, scope: 'openid' });
    assert.equal(result.status, 200);
    assert.equal(result.body.scope, 'openid');
    currentRefresh = result.body.refresh_token;
  });
  await check('轮换链重放检测:旧令牌再现作废整条链并审计', async () => {
    const replayResult = await exchange({ grant_type: 'refresh_token', refresh_token: issued.body.refresh_token });
    assert.equal(replayResult.status, 400);
    assert.equal(replayResult.body.error, 'invalid_grant');
    // 整条下游链(含当前有效令牌)一并作废
    assert.equal(tokens.byId(tokens.refreshKey(currentRefresh)).revoked, 1);
    const dead = await exchange({ grant_type: 'refresh_token', refresh_token: currentRefresh });
    assert.equal(dead.status, 400);
    const replayAudit = audit.list({ limit: 50, action: 'oauth.refresh_replay' });
    assert.ok(replayAudit.length >= 1, '未写入 oauth.refresh_replay 审计');
  });
  await check('JWT 必须恰好三段', () => assert.equal(verifyJwt(issued.body.access_token + '.extra'), null));
  for (const exp of [null, 'not-a-number']) {
    await check(`JWT 拒绝非法 exp (${exp}) 即使忽略过期`, () => {
      assert.equal(verifyJwt(signJwt({ sub: user.id, exp }, 60), { ignoreExp: true }), null);
    });
  }
  await check('过期 JWT 常规拒绝但允许用于吊销查找', () => {
    const expired = signJwt({ sub: user.id }, -1);
    assert.equal(verifyJwt(expired), null);
    assert.equal(verifyJwt(expired, { ignoreExp: true }).sub, user.id);
  });
  await check('JWT 拒绝缺失 exp 及未来 nbf', () => {
    assert.equal(verifyJwt(signJwt({ exp: undefined }, 60)), null);
    assert.equal(verifyJwt(signJwt({ nbf: Math.floor(Date.now() / 1000) + 300 }, 600)), null);
    assert.equal(verifyJwt(signJwt({ nbf: 'bad' }, 60)), null);
  });
  const intro = async (token) => {
    const c = ctx({ token, client_id: confidential.client_id, client_secret: 'test-client-secret' });
    await introspectPost(c);
    return c.res.body ? JSON.parse(c.res.body) : {};
  };
  await check('内省非字符串 token 返回 inactive 而非异常', async () => assert.equal((await intro({ invalid: true })).active, false));
  const registryStatus = (token) => {
    const c = ctx({}, { authorization: `Bearer ${token}` });
    c.user = null;
    registry(c);
    return c.res.statusCode;
  };
  await check('启用用户令牌内省及 registry 可用', async () => {
    assert.equal((await intro(issued.body.access_token)).active, true);
    assert.equal(registryStatus(issued.body.access_token), 200);
  });
  users.update(user.id, { disabled: true });
  await check('禁用用户令牌内省 inactive', async () => assert.equal((await intro(issued.body.access_token)).active, false));
  await check('禁用用户不得用 Bearer 访问 registry', () => assert.equal(registryStatus(issued.body.access_token), 401));
  users.remove(user.id);
  const orphan = issueFull({ client, user, scope: ['openid'], withRefresh: false, withIdToken: false });
  await check('已删除用户的残留令牌内省 inactive', async () => assert.equal((await intro(orphan.access_token)).active, false));
  await check('已删除用户的残留令牌不得访问 registry', () => assert.equal(registryStatus(orphan.access_token), 401));
  const machine = issueFull({ client: confidential, user: null, scope: [], withRefresh: false, withIdToken: false });
  await check('机器令牌不受用户检查误伤', async () => {
    assert.equal((await intro(machine.access_token)).active, true);
    assert.equal(registryStatus(machine.access_token), 200);
  });
  await check('异步密码校验:并发 24 次结果正确且混合未知用户', async () => {
    const results = await Promise.all(Array.from({ length: 24 }, (_, i) =>
      verifyUserPassword(i % 2 ? user : null, i % 2 ? 'Test-only-password!' : 'wrong')));
    assert.deepEqual(results, Array.from({ length: 24 }, (_, i) => i % 2 === 1));
    assert.equal(await verifyUserPassword(user, 'wrong'), false);
    assert.equal(await verifyUserPassword(null, 'Test-only-password!'), false);
  });
  await check('异步密码校验不阻塞事件循环(50ms 定时器按时触发)', async () => {
    const started = Date.now();
    const timer = new Promise((resolve) => setTimeout(() => resolve(Date.now() - started), 50));
    const works = Promise.all(Array.from({ length: 24 }, () => verifyUserPassword(user, 'wrong')));
    const [delay] = await Promise.all([timer, works]);
    assert.ok(delay < 1000, `50ms 定时器在 ${delay}ms 后才触发,事件循环被 scrypt 阻塞`);
  });
  await check('哈希格式兼容:异步与同步校验结果一致', async () => {
    const stored = await hashPassword('compat-check');
    assert.equal(await verifyPassword('compat-check', stored), true);
    assert.equal(verifyPasswordSync('compat-check', stored), true);
    assert.equal(await verifyPassword('nope', stored), false);
    assert.equal(verifyPasswordSync('nope', stored), false);
  });
  await check('邮件重置密码:统一失效会话、令牌与未使用授权码', async () => {
    const u2 = users.create({ username: 'reset-victim', passwordHash: await hashPassword('Old-pw-12345') });
    sessions.create(u2.id, 'csrf-u2', 3600);
    const issued2 = issueFull({ client, user: u2, scope: ['openid', 'offline_access'],
      authTime: session.created_at, nonce: 'u2', withRefresh: true, withIdToken: true });
    codes.create({ clientId: client.client_id, userId: u2.id, redirectUri, scope: 'openid', ttl: 300 });
    const token = resets.create(u2.id);
    const c = ctx({ _csrf: session.csrf, token, password: 'NewPassword#987', password2: 'NewPassword#987' });
    c.user = null; // 重置页面无登录态
    await handleReset(c);
    assert.equal(c.res.statusCode, 200);
    assert.equal(sessions.listForUser(u2.id).length, 0);
    assert.equal(tokens.byId(tokens.refreshKey(issued2.refresh_token)).revoked, 1);
    assert.equal(getDb().prepare('SELECT COUNT(*) AS n FROM auth_codes WHERE user_id = ?').get(u2.id).n, 0);
    assert.ok(audit.list({ limit: 20, action: 'auth.password_reset' }).some((r) => r.actor === 'reset-victim'));
    const freshUser = users.byUsername('reset-victim');
    assert.equal(await verifyUserPassword(freshUser, 'NewPassword#987'), true);
  });
  await check('自助改密:保留当前会话,失效令牌与其它会话', async () => {
    const u3 = users.create({ username: 'change-victim', passwordHash: await hashPassword('Old-pw-54321') });
    const sid = sessions.create(u3.id, 'csrf-u3', 3600);
    const otherSid = sessions.create(u3.id, 'csrf-u3b', 3600);
    const issued3 = issueFull({ client, user: u3, scope: ['openid', 'offline_access'],
      authTime: session.created_at, nonce: 'u3', withRefresh: true, withIdToken: true });
    codes.create({ clientId: client.client_id, userId: u3.id, redirectUri, scope: 'openid', ttl: 300 });
    const c = ctx({ _csrf: 'csrf-u3', current: 'Old-pw-54321', password: 'NewPassword#654', password2: 'NewPassword#654' });
    c.user = u3;
    c.session = { id_hash: sha256hex(sid), csrf: 'csrf-u3', created_at: Math.floor(Date.now() / 1000) - 60 };
    await handleChangePassword(c);
    assert.equal(c.res.statusCode, 200);
    const remaining = sessions.listForUser(u3.id);
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0].id_hash, sha256hex(sid));
    assert.equal(sha256hex(otherSid) === remaining[0].id_hash, false);
    assert.equal(tokens.byId(tokens.refreshKey(issued3.refresh_token)).revoked, 1);
    assert.equal(getDb().prepare('SELECT COUNT(*) AS n FROM auth_codes WHERE user_id = ?').get(u3.id).n, 0);
  });
  await check('审计每次写入后严格保留最新 5000 条', () => {
    audit.clear();
    getDb().exec('BEGIN');
    try {
      const ins = getDb().prepare('INSERT INTO audit_logs (id, ts, actor, action) VALUES (?, ?, ?, ?)');
      for (let i = 0; i < 5000; i++) ins.run(`seed-${i}`, 1, 'test', 'seed');
      audit.log({ action: 'regression' });
      assert.equal(audit.count(), 5000);
      assert.equal(audit.list({ limit: 1 })[0].action, 'regression');
    } finally { getDb().exec('ROLLBACK'); }
  });
} finally {
  getDb()?.close();
  fs.rmSync(data, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
console.log(`\nOAuth 回归: ${passed} 项通过, ${failed} 项失败`);
process.exitCode = failed ? 1 : 0;
