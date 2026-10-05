/** 视图回归:默认零依赖 SSR 检查;--browser 用 BROWSER_PATH 指定本机 Chromium,检查真实布局。
 *  浏览器使用临时用户目录和只读演示页面,不会接触实际数据库或个人浏览器配置。
 *  UI_SCREENSHOT_DIR 可选,指定截图保存目录。 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { bindSettings } from '../src/core/runtime.js';
import { runWithLang } from '../src/core/i18n.js';
import { adminPage, SAKURA_CSS } from '../src/views/layout.js';
import { loginPage, registerPage, consentPage } from '../src/views/auth.js';
import { dashboardPage, usersPage } from '../src/views/admin.js';
import { portalPage } from '../src/views/portal.js';
import { setupStep2, setupStep3 } from '../src/views/setup.js';
import { banner } from '../src/views/components.js';
import { WEBAUTHN_JS } from '../src/services/webauthn-js.js';

bindSettings(() => ({ ms_enabled: '1', unilink_enabled: '1' }));
const user = { id: 'demo', username: 'sakura', name: '小樱 & Sakura', is_admin: 1 };
const apps = ['工作台', '🌸 团队知识库', '项目协作', '统一运维平台', '文件中心', '设计资源'].map((name, i) => ({
  client_id: `app-demo-${i}`, name, token_auth: i % 2 ? 'none' : 'client_secret_basic',
  description: '安全连接你的工作与协作空间,使用统一账号即可访问。', scopeList: ['openid', 'profile', 'groups'],
  health: { status: i === 2 ? 'down' : 'up', latencyMs: 26, code: i === 2 ? 503 : 200 },
}));
const common = { siteName: '樱落统一认证', user, csrf: 'view-test-csrf' };
const actions = '<div class="seg-group"><a class="seg active" href="/portal">格子显示</a><a class="seg" href="/list">条状显示</a></div>';
const fixtures = {
  login: (opts) => loginPage({ ...opts, allowRegister: true, next: '/authorize?client_id=demo&scope=openid' }),
  register: (opts) => registerPage(opts),
  portal: (opts) => portalPage({ ...opts, cur: '/apps', list: apps, actions }),
  list: (opts) => portalPage({ ...opts, cur: '/apps', list: apps, actions, view: 'list' }),
  empty: (opts) => portalPage({ ...opts, cur: '/apps', list: [], actions }),
  long: (opts) => portalPage({ ...opts, siteName: 'LongBrand'.repeat(8), cur: '/apps', list: [
    { ...apps[0], name: 'LongApplicationName'.repeat(12), description: 'LongDescription'.repeat(40) },
  ], actions }),
  dashboard: (opts) => dashboardPage({ ...opts, cur: '/admin', issuer: 'https://sso.example.com',
    stats: { users: 128, clients: 6, activeTokens: 256, sessions: 42 }, allowRegister: false }),
  users: (opts) => usersPage({ ...opts, cur: '/admin/users', list: [
    { ...user, email: 'sakura@example.com', groupNames: ['admin', 'design'], created_at: 1700000000, _csrf: opts.csrf },
  ] }),
  consent: (opts) => consentPage({ ...opts, client: { ...apps[0], redirect_uris: '["https://app.example.com/cb"]' },
    scopeList: ['openid', 'profile', 'groups'], replay: { client_id: 'demo', redirect_uri: 'https://app.example.com/cb' }, remember: true }),
  setup: (opts) => setupStep2({ ...opts, values: { site_name: opts.siteName, issuer: 'https://sso.example.com', access_ttl: 900, refresh_ttl: 2592000 } }),
};
const render = (name, theme = 'day', lang = 'zh') => runWithLang(lang, () => fixtures[name]({ ...common, theme, lang }));
let passed = 0;
const check = async (name, fn) => { await fn(); passed++; console.log(`PASS ${name}`); };

await check('手机菜单使用原生 details,与桌面共享导航及当前页标记', () => {
  const html = render('portal');
  assert.match(html, /<details class="mobile-menu">/);
  assert.equal((html.match(/href="\/apps" class="active" aria-current="page"/g) || []).length, 2);
  assert.match(html, /href="#main-content"/);
  assert.match(html, /<main class="main" id="main-content" tabindex="-1">/);
});
await check('普通用户的手机及桌面菜单均不显示管理入口', () => {
  const html = adminPage({ ...common, user: { ...user, is_admin: 0 }, cur: '/account/sessions', active: 'account', title: 'Devices', content: '' });
  assert.doesNotMatch(html, /href="\/admin/);
  assert.equal((html.match(/href="\/account\/sessions" class="active" aria-current="page"/g) || []).length, 2);
});
await check('登录方式只分隔一次,保留 CSRF/next/密码自动填充和 Passkey ID', () => {
  const html = render('login');
  assert.equal((html.match(/class="login-divider"/g) || []).length, 1);
  for (const value of ['name="_csrf"', 'name="next"', 'autocomplete="current-password"', 'id="passkey-login-btn"', 'id="passkey-status"', 'href="/auth/microsoft"', 'href="/auth/unilink?next=']) assert.ok(html.includes(value), value);
  assert.match(html, /name="next" value="\/authorize\?client_id=demo&amp;scope=openid"/);
});
await check('登录方式开关组合不出现空分隔区或残留脚本', () => {
  try {
    for (const showPasskey of [false, true]) for (const msEnabled of [false, true]) for (const unilink of [false, true]) {
      bindSettings(() => ({ unilink_enabled: unilink ? '1' : '0' }));
      const html = loginPage({ ...common, showPasskey, msEnabled });
      assert.equal(html.includes('class="login-divider"'), showPasskey || msEnabled || unilink);
      assert.equal(html.includes('id="passkey-login-btn"'), showPasskey);
      assert.equal(html.includes('src="/assets/webauthn.js"'), showPasskey);
      assert.equal(html.includes('href="/auth/microsoft"'), msEnabled);
      assert.equal(html.includes('href="/auth/unilink?next='), unilink);
    }
  } finally { bindSettings(() => ({ ms_enabled: '1', unilink_enabled: '1' })); }
});
await check('门户空状态按身份提供入口,不输出未转义的应用文案', () => {
  const html = portalPage({ ...common, user: { ...user, is_admin: 0 }, list: [] });
  assert.ok(html.includes('class="card portal-empty"'));
  assert.ok(html.includes('href="/account"')); assert.doesNotMatch(html, /href="\/admin/);
  const hostile = portalPage({ ...common, list: [{ ...apps[0], name: '<script>alert(1)</script>', description: '" onmouseover="alert(1)' }] });
  assert.ok(hostile.includes('&lt;script&gt;')); assert.ok(!hostile.includes('<script>alert(1)'));
  assert.ok(!hostile.includes(' onmouseover="alert(1)'));
});
await check('门户姓名只转义一次,emoji 首字完整,状态有可访问名称', () => {
  const html = render('portal');
  assert.ok(html.includes('小樱 &amp; Sakura')); assert.ok(!html.includes('&amp;amp;'));
  assert.ok(html.includes('>🌸</div>')); assert.match(html, /role="img" aria-label=/);
});
await check('英语菜单和登录方式有对应翻译', () => {
  assert.ok(render('portal', 'day', 'en').includes('Signed-in devices'));
  assert.ok(render('login', 'day', 'en').includes('Other ways to sign in'));
});
await check('错误提示有 alert 语义,支持减少动画和明暗原生控件', () => {
  assert.match(banner('error', 'err'), /role="alert"/);
  assert.ok(SAKURA_CSS.includes('prefers-reduced-motion:reduce'));
  assert.ok(SAKURA_CSS.includes('color-scheme:dark'));
});
await check('重跑向导跳过表单包含 CSRF', () => {
  const html = setupStep3({ ...common, hasUsers: true, values: {} });
  const form = html.match(/<form[^>]+action="\/setup\/step3"[^>]*>([\s\S]*?)<\/form>/)?.[1];
  assert.ok(form.includes('name="skip"')); assert.ok(form.includes('name="_csrf"'));
});
if (process.argv.includes('--browser')) {
  const executable = process.env.BROWSER_PATH;
  assert.ok(executable && fs.existsSync(executable), 'Set BROWSER_PATH to a Chromium executable');
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'sakura-ui-'));
  const screenshots = process.env.UI_SCREENSHOT_DIR;
  if (screenshots) fs.mkdirSync(screenshots, { recursive: true });
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/assets/webauthn.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript' }); return res.end(WEBAUTHN_JS);
    }
    if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
    const name = url.pathname.slice(1);
    if (!Object.hasOwn(fixtures, name)) { res.writeHead(404); return res.end(); }
    try {
      const html = render(name, url.searchParams.get('theme') ?? 'day', url.searchParams.get('lang') || 'zh');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch (err) { res.writeHead(500); res.end(String(err.stack)); }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = spawn(executable, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--remote-debugging-port=0', `--user-data-dir=${temp}`, 'about:blank'],
  { stdio: ['ignore', 'ignore', 'pipe'] });
  let browserLog = '', launchError;
  browser.stderr.on('data', (b) => { browserLog += b; });
  browser.once('error', (err) => { launchError = err; });
  const exited = new Promise((resolve) => browser.once('close', resolve));
  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  let ws;
  try {
    const portFile = path.join(temp, 'DevToolsActivePort');
    for (let i = 0; i < 200 && !fs.existsSync(portFile); i++) {
      if (launchError) throw launchError;
      if (browser.exitCode !== null) throw new Error(browserLog);
      await delay(50);
    }
    assert.ok(fs.existsSync(portFile), browserLog);
    const port = fs.readFileSync(portFile, 'utf8').split('\n')[0];
    const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json();
    ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => { ws.addEventListener('open', resolve, { once: true }); ws.addEventListener('error', reject, { once: true }); });
    let seq = 0;
    const waiting = new Map();
    ws.addEventListener('message', ({ data }) => {
      const msg = JSON.parse(data), pending = waiting.get(msg.id);
      if (!pending) return;
      waiting.delete(msg.id); clearTimeout(pending.timer);
      if (msg.error) pending.reject(new Error(JSON.stringify(msg.error))); else pending.resolve(msg.result);
    });
    const command = (method, params = {}) => new Promise((resolve, reject) => {
      const id = ++seq;
      const timer = setTimeout(() => { waiting.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 15000);
      waiting.set(id, { resolve, reject, timer }); ws.send(JSON.stringify({ id, method, params }));
    });
    const evaluate = async (expression) => {
      const r = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
      return r.result.value;
    };
    const navigate = async (name, width, theme = 'day', lang = 'zh') => {
      await command('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
      const url = `${origin}/${name}?theme=${theme}&lang=${lang}`;
      await command('Page.navigate', { url });
      let ready = false;
      for (let i = 0; i < 100; i++) {
        if (await evaluate(`location.href === ${JSON.stringify(url)} && document.readyState === 'complete'`)) { ready = true; break; }
        await delay(30);
      }
      assert.ok(ready, `Page did not load: ${url}`);
      await delay(60);
    };
    await command('Page.enable');
    for (const width of [320, 390, 768, 1024, 1440]) {
      for (const name of Object.keys(fixtures)) {
        await check(`浏览器 ${name} ${width}px 无页面横向溢出`, async () => {
          await navigate(name, width, width === 390 ? 'night' : 'day', width === 768 ? 'en' : 'zh');
          const layout = await evaluate(`({ width: innerWidth, scroll: document.documentElement.scrollWidth,
            main: !!document.querySelector('main'), overflow: [...document.querySelectorAll('body *')].filter(el => {
              const r = el.getBoundingClientRect(); return r.width && (r.right > innerWidth + 1 || r.left < -1);
            }).slice(0, 8).map(el => el.tagName + '.' + el.className) })`);
          assert.ok(layout.main, `${name}: missing main`);
          assert.ok(layout.scroll <= layout.width + 1, JSON.stringify(layout));
          if (screenshots && ['login', 'portal', 'dashboard'].includes(name) && [390, 1440].includes(width)) {
            const shot = await command('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
            fs.writeFileSync(path.join(screenshots, `${name}-${width}.png`), Buffer.from(shot.data, 'base64'));
          }
        });
      }
    }
    await check('浏览器跳转正文链接可见且能转移键盘焦点', async () => {
      await navigate('portal', 390);
      await evaluate(`document.querySelector('.skip-link').focus()`);
      assert.equal(await evaluate(`document.querySelector('.skip-link').getBoundingClientRect().top >= 0`), true);
      await command('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' });
      await command('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
      assert.equal(await evaluate(`document.activeElement.id`), 'main-content');
    });
    await check('浏览器窄屏表格可独立滚动,操作列保持单元格布局', async () => {
      await navigate('users', 320);
      assert.equal(await evaluate(`getComputedStyle(document.querySelector('td.rowline')).display`), 'table-cell');
      assert.equal(await evaluate(`(() => { const el = document.querySelector('.tblwrap'); el.scrollLeft = el.scrollWidth;
        return el.scrollWidth > el.clientWidth && el.scrollLeft > 0 && document.documentElement.scrollWidth <= innerWidth + 1; })()`), true);
      await evaluate(`document.querySelector('td.rowline button').focus()`);
      assert.equal(await evaluate(`(() => { const r = document.activeElement.getBoundingClientRect();
        return r.left >= 0 && r.right <= innerWidth && r.height >= 44; })()`), true);
    });
    await check('浏览器手机菜单支持 Enter 打开并可键盘到达导航(禁用页面脚本)', async () => {
      await command('Emulation.setScriptExecutionDisabled', { value: true });
      await navigate('portal', 390);
      assert.equal(await evaluate(`getComputedStyle(document.querySelector('.side')).display`), 'none');
      await evaluate(`document.querySelector('summary').focus()`);
      await command('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r', unmodifiedText: '\r' });
      await command('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
      assert.equal(await evaluate(`document.querySelector('.mobile-menu').open`), true);
      await command('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
      await command('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
      assert.equal(await evaluate(`document.activeElement.closest('.mobile-menu') !== null && document.activeElement.tagName === 'A'`), true);
      assert.equal(await evaluate(`document.documentElement.scrollWidth <= innerWidth + 1`), true);
      if (screenshots) {
        const shot = await command('Page.captureScreenshot', { format: 'png' });
        fs.writeFileSync(path.join(screenshots, 'mobile-menu.png'), Buffer.from(shot.data, 'base64'));
      }
    });
    await check('浏览器系统夜间/显式日间及减少动画偏好生效', async () => {
      await command('Emulation.setScriptExecutionDisabled', { value: false });
      await command('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'dark' }, { name: 'prefers-reduced-motion', value: 'reduce' }] });
      await navigate('login', 390, '');
      assert.equal(await evaluate(`getComputedStyle(document.documentElement).colorScheme`), 'dark');
      assert.equal(await evaluate(`getComputedStyle(document.querySelector('.btn')).transitionDuration`), '0s');
      await navigate('login', 390, 'day');
      assert.equal(await evaluate(`getComputedStyle(document.documentElement).colorScheme`), 'light');
      assert.equal(await evaluate(`document.querySelectorAll('.login-divider').length`), 1);
      assert.equal(await evaluate(`document.querySelector('#password').getBoundingClientRect().height >= 44`), true);
      await command('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });
      await navigate('login', 1440, '');
      assert.equal(await evaluate(`getComputedStyle(document.documentElement).colorScheme`), 'light');
      await navigate('login', 1440, 'night');
      assert.equal(await evaluate(`getComputedStyle(document.documentElement).colorScheme`), 'dark');
    });
  } finally {
    ws?.close(); browser.kill(); await exited;
    server.closeAllConnections(); await new Promise((resolve) => server.close(resolve));
    fs.rmSync(temp, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}
console.log(`View regression: ${passed} passed`);
