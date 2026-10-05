/** 安全回归:临时数据库、独立 HTTP 子进程,不接触业务数据。 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'sakura-security-'));
process.env.DATA_DIR = path.join(temp, 'data');
process.env.BASE_URL = 'http://localhost:9919';
const { initDb, transaction } = await import('../src/core/db.js');
let db = initDb();
const users = await import('../src/models/users.js');
const sessions = await import('../src/models/sessions.js');
const groups = await import('../src/models/groups.js');
const clients = await import('../src/models/clients.js');
const tokens = await import('../src/models/tokens.js');
const resets = await import('../src/models/resets.js');
const settings = await import('../src/models/settings.js');
const { bindSettings, getRuntime, updateRuntime } = await import('../src/core/runtime.js');
const pw = await import('../src/core/password.js');
const { initKeys } = await import('../src/core/keys.js');
const { sha256hex } = await import('../src/core/crypto.js');
const { parseCookies } = await import('../src/core/http.js');
const { invalidateUserCredentials } = await import('../src/services/auth/credentials.js');
const { login } = await import('../src/services/api.js');
const { handleLogin, handleTwoFa } = await import('../src/services/auth/login.js');
const { handleChangePassword, startTwoFa, disableTwoFa } = await import('../src/services/auth/account.js');
const { handleReset } = await import('../src/services/auth/reset.js');
const { tokenPost } = await import('../src/services/oauth/token.js');
const { issueFull } = await import('../src/services/oauth/issue.js');
const { verifyJwt } = await import('../src/core/jwt.js');
const { showAboutSettings, saveAbout } = await import('../src/services/about.js');
const { grantGroupApp } = await import('../src/services/admin/index.js');
const webauthn = await import('../src/services/webauthn.js');
const webcore = await import('../src/core/webauthn.js');
const credentials = await import('../src/models/webauthn.js');
initKeys(); bindSettings(settings.getMap);
let passed = 0, failed = 0, sequence = 0;
const check = async (name, fn) => {
  try { await fn(); passed++; console.log(`PASS ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}: ${e.stack}`); }
};
const response = () => ({
  headers: {}, body: '', statusCode: 200,
  setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
  getHeader(k) { return this.headers[k.toLowerCase()]; },
  writeHead(s, h = {}) { this.statusCode = s; for (const [k, v] of Object.entries(h)) this.setHeader(k, v); },
  end(b = '') { this.body = b; },
});
const context = (user = null, body = {}, url = '/') => {
  const req = { headers: { 'x-requested-with': 'JSON' }, socket: { remoteAddress: `test-${++sequence}` } };
  const res = response(); res.req = req;
  const u = new URL(url, getRuntime().issuer);
  return { user, session: null, cookies: { csrf: 'csrf' }, body, url: u, query: u.searchParams,
    runtime: getRuntime(), params: {}, theme: 'light', req, res };
};
const withSession = (user, body = {}) => {
  const c = context(user, { _csrf: 'csrf', ...body });
  const sid = sessions.create(user.id, 'csrf', 3600);
  c.session = sessions.byIdHash(sha256hex(sid));
  return c;
};
const bounded = async (p) => {
  let timer;
  try { return await Promise.race([p, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), 5000); })]); }
  finally { clearTimeout(timer); }
};
const oldHash = await pw.hashPassword('Old-password-123');
const newHash = await pw.hashPassword('New-password-456');
const newUser = () => users.create({ username: `review-${++sequence}`, passwordHash: oldHash });

try {
  await check('Cookie 畸形编码被单独忽略,正常字段保留', () => {
    const parsed = parseCookies('lang=%; sid=normal; other=%FF');
    assert.equal(parsed.lang, undefined); assert.equal(parsed.sid, 'normal');
    assert.equal(Object.getPrototypeOf(parsed), null);
  });
  await check('scrypt 同步抛错不会占住并发名额', async () => {
    const original = crypto.scrypt;
    try {
      crypto.scrypt = () => { throw new Error('injected scrypt failure'); };
      for (let i = 0; i < 12; i++) assert.equal(await pw.verifyPassword('x', oldHash), false);
    } finally { crypto.scrypt = original; }
    assert.equal(await bounded(pw.verifyPassword('Old-password-123', oldHash)), true);
  });
  await check('scrypt 队列有界,超载返回 503 且之后可恢复', async () => {
    const results = await Promise.allSettled(Array.from({ length: 80 }, () => pw.verifyPassword('Old-password-123', oldHash)));
    assert.ok(results.some((r) => r.status === 'rejected' && r.reason.status === 503));
    assert.ok(results.some((r) => r.status === 'fulfilled' && r.value));
    assert.equal(await bounded(pw.verifyPassword('Old-password-123', oldHash)), true);
    assert.equal(await pw.verifyPassword('x', 'scrypt$3$8$1$c2FsdA$YQ'), false);
  });
  for (const [name, mutate] of [
    ['改密', (u) => users.update(u.id, { passwordHash: newHash })],
    ['禁用再启用', (u) => { users.update(u.id, { disabled: true }); users.update(u.id, { disabled: false }); }],
    ['开启 MFA', (u) => { users.setTotpSecret(u.id, 'JBSWY3DPEHPK3PXP'); users.enableTotp(u.id); }],
    ['删除用户', (u) => users.remove(u.id)],
  ]) {
    await check(`API 密码校验期间${name}不得建立会话`, async () => {
      const u = newUser(), c = context(null, { username: u.username, password: 'Old-password-123' });
      const pending = login(c);
      mutate(u);
      await bounded(pending);
      assert.equal(c.res.statusCode, 401);
      assert.equal(sessions.listForUser(u.id).length, 0);
    });
  }
  await check('Web 密码校验期间改密拒绝旧密码', async () => {
    const u = newUser(), c = context(null, { username: u.username, password: 'Old-password-123', _csrf: 'csrf' });
    const pending = handleLogin(c);
    users.update(u.id, { passwordHash: newHash });
    await bounded(pending);
    assert.equal(c.res.statusCode, 401);
    assert.equal(sessions.listForUser(u.id).length, 0);
  });
  await check('MFA 中间票据绑定凭据版本与 CSRF', async () => {
    const u = newUser();
    users.setTotpSecret(u.id, 'JBSWY3DPEHPK3PXP'); users.enableTotp(u.id);
    const c = context(null, { username: u.username, password: 'Old-password-123', _csrf: 'csrf' });
    await handleLogin(c);
    const pending = c.res.body.match(/name="pending" value="([^"]+)"/)?.[1];
    assert.ok(pending);
    const wrongCsrf = context(null, { pending, _csrf: 'other-csrf', code: '000000' });
    wrongCsrf.cookies.csrf = 'other-csrf';
    handleTwoFa(wrongCsrf);
    assert.equal(wrongCsrf.res.getHeader('location'), '/login');
    users.update(u.id, { passwordHash: newHash });
    const factor = context(null, { pending, _csrf: 'csrf', code: '000000' });
    handleTwoFa(factor);
    assert.equal(factor.res.getHeader('location'), '/login');
    assert.equal(sessions.listForUser(u.id).length, 0);
  });
  for (const [name, handler, body] of [
    ['自助改密', handleChangePassword, { current: 'Old-password-123', password: 'Next-password-123', password2: 'Next-password-123' }],
    ['开启 MFA', startTwoFa, { password: 'Old-password-123' }],
    ['关闭 MFA', disableTwoFa, { password: 'Old-password-123' }],
  ]) {
    await check(`${name}计算期间会话撤销后不得写入`, async () => {
      let u = newUser();
      if (handler === disableTwoFa) {
        users.setTotpSecret(u.id, 'JBSWY3DPEHPK3PXP'); users.enableTotp(u.id); u = users.byId(u.id);
      }
      const c = withSession(u, body), pending = handler(c);
      sessions.remove(c.session.id_hash);
      await assert.rejects(bounded(pending), (e) => e.status === 401);
      const fresh = users.byId(u.id);
      assert.equal(fresh.password_hash, u.password_hash);
      assert.equal(fresh.totp_enabled, u.totp_enabled);
      assert.equal(fresh.totp_secret, u.totp_secret);
    });
  }
  await check('同一重置链接并发提交仅成功一次', async () => {
    const u = newUser(), token = resets.create(u.id);
    const body = { token, _csrf: 'csrf', password: 'Reset-password-123', password2: 'Reset-password-123' };
    const a = context(null, body), b = context(null, body);
    await Promise.all([handleReset(a), handleReset(b)]);
    assert.deepEqual([a.res.statusCode, b.res.statusCode].sort(), [200, 400]);
    assert.equal(resets.lookup(token), null);
    assert.equal(await pw.verifyPassword(body.password, users.byId(u.id).password_hash), true);
  });
  await check('重置计算期间凭据失效不覆盖较新的密码', async () => {
    const u = newUser(), token = resets.create(u.id);
    const c = context(null, { token, _csrf: 'csrf', password: 'Reset-password-123', password2: 'Reset-password-123' });
    const pending = handleReset(c);
    transaction(() => { users.update(u.id, { passwordHash: newHash }); invalidateUserCredentials(u.id); });
    await pending;
    assert.equal(c.res.statusCode, 400);
    assert.equal(users.byId(u.id).password_hash, newHash);
  });
  const makeClient = (extra = {}) => clients.create({ name: `security-${++sequence}`, redirectUris: ['http://localhost/cb'],
    scopes: 'openid offline_access', isPublic: true, ...extra });
  await check('客户端密钥校验期间轮换密钥拒绝旧请求', async () => {
    const client = makeClient({ isPublic: false, secretHash: oldHash });
    const c = context(null, { grant_type: 'client_credentials', client_id: client.client_id, client_secret: 'Old-password-123' });
    const pending = tokenPost(c);
    clients.update(client.client_id, { secretHash: newHash });
    await pending;
    assert.equal(c.res.statusCode, 401);
    assert.equal(JSON.parse(c.res.body).error, 'invalid_client');
  });
  await check('其他客户端不能利用已轮换令牌吊销受害者链', async () => {
    const u = newUser(), client = makeClient(), other = makeClient();
    const issued = issueFull({ client, user: u, scope: ['openid', 'offline_access'], withRefresh: true });
    const c = context(null, { grant_type: 'refresh_token', client_id: client.client_id, refresh_token: issued.refresh_token });
    await tokenPost(c);
    assert.equal(c.res.statusCode, 200);
    const rotated = JSON.parse(c.res.body);
    const attack = context(null, { grant_type: 'refresh_token', client_id: other.client_id, refresh_token: issued.refresh_token });
    await tokenPost(attack);
    assert.equal(attack.res.statusCode, 400);
    assert.equal(tokens.byId(tokens.refreshKey(rotated.refresh_token)).revoked, 0);
    assert.equal(tokens.byId(verifyJwt(rotated.access_token).jti).revoked, 0);
    await tokenPost(context(null, c.body));
    assert.equal(tokens.byId(tokens.refreshKey(rotated.refresh_token)).revoked, 1);
    assert.equal(tokens.byId(verifyJwt(rotated.access_token).jti).revoked, 1);
  });
  await check('无 chain_id 的旧刷新令牌重放撤销同用户同应用令牌', async () => {
    const user = newUser(), client = makeClient(), other = makeClient();
    const legacy = issueFull({ client, user, scope: ['openid'], withRefresh: true });
    const unaffected = issueFull({ client: other, user, scope: ['openid'], withRefresh: true });
    db.prepare('UPDATE tokens SET chain_id = NULL WHERE client_id = ?').run(client.client_id);
    const body = { grant_type: 'refresh_token', client_id: client.client_id, refresh_token: legacy.refresh_token };
    const c = context(null, body); await tokenPost(c);
    assert.equal(c.res.statusCode, 200);
    const rotated = JSON.parse(c.res.body);
    await tokenPost(context(null, body));
    assert.equal(tokens.byId(verifyJwt(legacy.access_token).jti).revoked, 1);
    assert.equal(tokens.byId(verifyJwt(rotated.access_token).jti).revoked, 1);
    assert.equal(tokens.byId(tokens.refreshKey(rotated.refresh_token)).revoked, 1);
    assert.equal(tokens.byId(tokens.refreshKey(unaffected.refresh_token)).revoked, 0);
  });
  await check('撤销最后一个授权组保持受限,重新授权后恢复', () => {
    const group = groups.create({ name: 'last-group' }), client = makeClient({ allowedGroups: [group.name] });
    const c = withSession(newUser(), { client_id: client.client_id, action: 'revoke' });
    c.params.id = group.id;
    grantGroupApp(c);
    assert.equal(clients.accessMode(clients.byId(client.client_id)), 'groups');
    assert.equal(clients.canAccess(clients.byId(client.client_id), [group.name]), false);
    c.body.action = 'grant'; grantGroupApp(c);
    assert.equal(clients.canAccess(clients.byId(client.client_id), [group.name]), true);
    for (const allowed_groups of ['bad-json', '{}', '[42]']) {
      assert.equal(clients.canAccess({ access_mode: 'auto', allowed_groups }, []), false);
    }
  });
  await check('启动迁移不复活已撤销成员或管理员默认组', () => {
    const u = users.create({ username: `admin-${++sequence}`, passwordHash: oldHash, isAdmin: true, userGroups: 'legacy-dev' });
    groups.removeMember(groups.byName('legacy-dev').id, u.id);
    groups.removeMember(groups.byName('admin').id, u.id);
    // 模拟旧版本遗留的镜像值,已有关系表始终是权威来源。
    db.prepare('UPDATE users SET user_groups = ? WHERE id = ?').run('legacy-dev admin', u.id);
    db.prepare("DELETE FROM settings WHERE key = 'groups_migrated_v2'").run();
    db.close(); db = initDb();
    assert.deepEqual(groups.membersOf(u.id), []);
    db.close(); db = initDb();
    assert.deepEqual(groups.membersOf(u.id), []);
  });
  await check('关于页管理表单正确显示通知且超长内容不被静默截断', () => {
    const c = withSession(newUser(), { title: 'x'.repeat(61), content: '<script>unsafe</script>' });
    updateRuntime({ about_title: 'original', about_content: 'original-content' }, settings.setSetting);
    saveAbout(c);
    assert.equal(c.res.statusCode, 200);
    assert.ok(c.res.body.includes('未保存'));
    assert.ok(c.res.body.includes('&lt;script&gt;unsafe&lt;/script&gt;'));
    assert.equal(settings.getMap().about_title, 'original');
    c.query = new URLSearchParams({ msg: '<b>saved</b>' });
    showAboutSettings(c);
    assert.ok(c.res.body.includes('&lt;b&gt;saved&lt;/b&gt;'));
  });
  await check('授权码/刷新令牌签发失败时整笔事务回滚', async () => {
    const codes = await import('../src/models/codes.js');
    const u = newUser(), client = makeClient();
    const issued = issueFull({ client, user: u, scope: ['openid'], withRefresh: true });
    const code = codes.create({ clientId: client.client_id, userId: u.id, redirectUri: 'http://localhost/cb', scope: 'openid', ttl: 300 });
    const count = db.prepare('SELECT COUNT(*) AS n FROM tokens').get().n;
    db.exec("CREATE TEMP TRIGGER fail_access BEFORE INSERT ON tokens WHEN NEW.kind = 'access' BEGIN SELECT RAISE(ABORT, 'injected'); END");
    try {
      await assert.rejects(tokenPost(context(null, { grant_type: 'authorization_code', client_id: client.client_id,
        code, redirect_uri: 'http://localhost/cb' })), /injected/);
      assert.equal(codes.byCode(code).used, 0);
      await assert.rejects(tokenPost(context(null, { grant_type: 'refresh_token', client_id: client.client_id,
        refresh_token: issued.refresh_token })), /injected/);
      assert.equal(tokens.byId(tokens.refreshKey(issued.refresh_token)).revoked, 0);
      assert.equal(db.prepare('SELECT COUNT(*) AS n FROM tokens').get().n, count);
    } finally { db.exec('DROP TRIGGER fail_access'); }
  });
  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = key.publicKey.export({ format: 'jwk' });
  const cose = Buffer.concat([Buffer.from('a5010203262001215820', 'hex'), Buffer.from(jwk.x, 'base64url'),
    Buffer.from('225820', 'hex'), Buffer.from(jwk.y, 'base64url')]);
  const assertion = (challenge, flags, counter, crossOrigin = false) => {
    const authenticatorData = Buffer.alloc(37);
    crypto.createHash('sha256').update('localhost').digest().copy(authenticatorData);
    authenticatorData[32] = flags; authenticatorData.writeUInt32BE(counter, 33);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: getRuntime().issuer, crossOrigin }));
    const signature = crypto.sign('sha256', Buffer.concat([authenticatorData,
      crypto.createHash('sha256').update(clientDataJSON).digest()]), key.privateKey);
    return { authenticatorData, clientDataJSON, signature, credentialPublicKey: cose };
  };
  await check('Passkey 必须 UP+UV 且拒绝跨域和尾随数据', () => {
    const opts = { expectedChallenge: 'test', expectedOrigin: getRuntime().issuer, rpId: 'localhost' };
    assert.equal(webcore.verifyAssertion(assertion('test', 5, 0), opts).signCount, 0);
    assert.throws(() => webcore.verifyAssertion(assertion('test', 1, 0), opts), (e) => e.code === 'user_verification_required');
    assert.throws(() => webcore.verifyAssertion(assertion('test', 5, 0, true), opts), (e) => e.code === 'origin_mismatch');
    assert.throws(() => webcore.parseAuthData(Buffer.concat([assertion('test', 5, 0).authenticatorData, Buffer.from([0])])));
  });
  await check('Passkey uint32 计数器不溢出,回退到零拒绝,双零允许', () => {
    const u = newUser(), id = crypto.randomBytes(24).toString('base64url');
    credentials.create({ id, userId: u.id, name: 'counter', publicKey: cose.toString('base64url'), counter: 0, transports: '' });
    const verify = (count) => {
      const options = context(); webauthn.loginOptions(options);
      const o = JSON.parse(options.res.body), a = assertion(o.challenge, 5, count);
      const c = context(null, { challengeId: o.challengeId, response: { id, response: {
        authenticatorData: a.authenticatorData.toString('base64url'), clientDataJSON: a.clientDataJSON.toString('base64url'),
        signature: a.signature.toString('base64url'),
      } } });
      webauthn.loginVerify(c); return c.res.statusCode;
    };
    assert.equal(verify(0), 200); assert.equal(verify(0), 200);
    assert.equal(verify(0x80000000), 200);
    assert.equal(credentials.byId(id).counter, 0x80000000);
    assert.equal(verify(0), 409);
    assert.equal(verify(0x80000001), 200);
  });
  await check('CLI 管理员重置同时撤销会话、令牌与重置链接', async () => {
    const u = users.create({ username: `cli-admin-${++sequence}`, passwordHash: oldHash, isAdmin: true });
    const sid = sessions.create(u.id, 'csrf', 3600), reset = resets.create(u.id);
    const issued = issueFull({ client: makeClient(), user: u, scope: ['openid'], withRefresh: true });
    const result = spawnSync(process.execPath, [path.join(ROOT, 'scripts/reset-admin-password.mjs'), u.username, 'CLI-new-password-123'],
      { env: process.env, encoding: 'utf8', timeout: 15000 });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(sessions.byIdHash(sha256hex(sid)), undefined);
    assert.equal(tokens.byId(tokens.refreshKey(issued.refresh_token)).revoked, 1);
    assert.equal(resets.lookup(reset), null);
    assert.equal(await pw.verifyPassword('CLI-new-password-123', users.byId(u.id).password_hash), true);
  });
  await check('备份在目标目录内也能恢复,损坏备份不会改动旧数据', () => {
    const target = path.join(temp, 'restore-target'), source = path.join(target, 'backups', 'sakuraid-backup-test');
    fs.mkdirSync(path.join(source, 'uploads'), { recursive: true });
    db.exec(`VACUUM INTO '${path.join(source, 'idp.sqlite').replaceAll("'", "''")}'`);
    fs.writeFileSync(path.join(source, 'uploads', 'sample.txt'), 'snapshot-upload');
    fs.writeFileSync(path.join(target, 'old.txt'), 'preserve-me');
    const runRestore = (backup, force = true) => spawnSync(process.execPath,
      [path.join(ROOT, 'scripts/restore.mjs'), backup, ...(force ? ['--force'] : [])],
      { env: { ...process.env, DATA_DIR: target }, encoding: 'utf8', timeout: 15000 });
    assert.equal(runRestore(source, false).status, 1);
    assert.equal(fs.readFileSync(path.join(target, 'old.txt'), 'utf8'), 'preserve-me');
    const result = runRestore(source);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(fs.readFileSync(path.join(target, 'uploads', 'sample.txt'), 'utf8'), 'snapshot-upload');
    const old = fs.readdirSync(temp).find((n) => n.startsWith('restore-target-before-restore-'));
    assert.ok(old);
    assert.equal(fs.readFileSync(path.join(temp, old, 'old.txt'), 'utf8'), 'preserve-me');
    const restored = new DatabaseSync(path.join(target, 'idp.sqlite'), { readOnly: true });
    try { assert.equal(restored.prepare('SELECT COUNT(*) AS n FROM users').get().n, users.count()); }
    finally { restored.close(); }
    const bad = path.join(temp, 'bad-backup'); fs.mkdirSync(bad);
    fs.writeFileSync(path.join(bad, 'idp.sqlite'), 'not a database');
    const before = fs.readFileSync(path.join(target, 'idp.sqlite'));
    assert.equal(runRestore(bad).status, 1);
    assert.deepEqual(fs.readFileSync(path.join(target, 'idp.sqlite')), before);
    assert.equal(fs.readdirSync(temp).some((n) => n.startsWith('restore-target-restore-stage-')), false);
  });
  await check('健康探测最多四路并发并取消无须读取的响应体', async () => {
    const health = await import('../src/services/app-health.js');
    const apps = Array.from({ length: 7 }, () => makeClient({ healthUrl: 'http://localhost/health' }));
    const original = globalThis.fetch;
    let active = 0, peak = 0, cancelled = 0;
    try {
      globalThis.fetch = async () => {
        active++; peak = Math.max(peak, active);
        await new Promise((resolve) => setTimeout(resolve, 15));
        active--;
        return { ok: true, status: 200, body: { async cancel() { cancelled++; } } };
      };
      await health.probeAll();
      assert.equal(peak, 4);
      assert.equal(cancelled, apps.length);
      for (const app of apps) assert.equal(health.get(app.client_id).status, 'up');
    } finally {
      globalThis.fetch = original;
      for (const app of apps) clients.remove(app.client_id);
    }
  });
  await check('HTTP 畸形 Cookie 不崩溃,读请求体期间撤销会话后拒绝管理写入', async () => {
    updateRuntime({ setup_done: '1' }, settings.setSetting);
    const admin = users.create({ username: `http-admin-${++sequence}`, passwordHash: oldHash, isAdmin: true });
    const sid = sessions.create(admin.id, 'csrf', 3600);
    const probe = net.createServer();
    await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const port = probe.address().port;
    await new Promise((resolve) => probe.close(resolve));
    const base = `http://127.0.0.1:${port}`;
    const child = spawn(process.execPath, [path.join(ROOT, 'server.js')], { cwd: ROOT,
      env: { ...process.env, PORT: String(port), BASE_URL: base, TLS_CERT: '', TLS_KEY: '', TLS_REDIRECT_PORT: '' },
      stdio: ['ignore', 'pipe', 'pipe'] });
    let log = ''; child.stdout.on('data', (b) => { log += b; }); child.stderr.on('data', (b) => { log += b; });
    const closed = new Promise((resolve) => child.once('close', resolve));
    let socket;
    try {
      let ready = false;
      for (let i = 0; i < 100; i++) {
        try {
          const r = await fetch(base + '/api/heartbeat', { signal: AbortSignal.timeout(500) });
          ready = r.ok; await r.text();
          if (ready) break;
        } catch { /* 等待服务启动 */ }
        if (child.exitCode !== null) throw new Error(log);
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      assert.ok(ready, log);
      for (const cookie of ['lang=%', 'sid=%FF', 'lang=zh; csrf=%E0%A4%A']) {
        const r = await fetch(base + '/api/heartbeat', { headers: { cookie } });
        assert.equal(r.status, 200); await r.text();
      }
      const originalTitle = settings.getMap().about_title;
      const body = new URLSearchParams({ _csrf: 'csrf', title: 'stale-write', content: 'stale' }).toString();
      socket = net.connect(port, '127.0.0.1');
      const received = new Promise((resolve, reject) => {
        let text = ''; socket.on('data', (b) => { text += b; });
        socket.on('end', () => resolve(text)); socket.on('error', reject);
      });
      await new Promise((resolve) => socket.once('connect', resolve));
      socket.write(`POST /admin/about HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nCookie: sid=${sid}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body.slice(0, -1)}`);
      await new Promise((resolve) => setTimeout(resolve, 150));
      sessions.remove(sha256hex(sid));
      socket.write(body.slice(-1));
      const raw = await bounded(received);
      assert.match(raw, /^HTTP\/1\.1 401 /);
      assert.equal(settings.getMap().about_title, originalTitle);
      const alive = await fetch(base + '/api/heartbeat');
      assert.equal(alive.status, 200); await alive.text();
    } finally {
      socket?.destroy(); child.kill(); await bounded(closed);
    }
  });
} finally {
  db.close();
  fs.rmSync(temp, { recursive: true, force: true });
}
console.log(`Security regression: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
