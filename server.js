/**
 * SakuraID —— 类 authentik 的轻量 OAuth2 / OpenID Connect 认证服务。
 * 入口:初始化(数据库 → 签名密钥 → 运行时配置)→ 组装请求管线 → 监听。
 */
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import { config } from './src/core/config.js';
import { logger } from './src/core/logger.js';
import { initDb, purgeExpired } from './src/core/db.js';
import { initKeys } from './src/core/keys.js';
import { bindSettings, getRuntime } from './src/core/runtime.js';
import * as settings from './src/models/settings.js';
import * as sessions from './src/models/sessions.js';
import * as users from './src/models/users.js';
import { matchRoute, parseCookies, readBody, parseBody, sendHtml, sendJson, redirect } from './src/core/http.js';
import { sha256hex, nowSec } from './src/core/crypto.js';
import { registerRoutes } from './src/routes.js';
import { setupGate } from './src/services/setup/wizard.js';
import { forbidden } from './src/services/auth/login.js';
import { themeFromCookies, langFromCookies } from './src/views/theme.js';
import { errorPage } from './src/views/error.js';
import { runWithLang, t } from './src/core/i18n.js';
import { ensureUploadsDir } from './src/core/upload.js';

initDb();
initKeys();
bindSettings(() => settings.getMap());
ensureUploadsDir(); // 应用 Logo 等上传文件目录({DATA_DIR}/uploads)

const router = registerRoutes();

const CORS_PATHS = new Set(['/token', '/introspect', '/revoke', '/userinfo', '/jwks.json',
  '/authorize', '/.well-known/openid-configuration', '/api/heartbeat', '/api/registry']);

const applyCors = (res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Max-Age', '600');
};

const wantsJson = (url) => CORS_PATHS.has(url.pathname) && url.pathname !== '/authorize';

function resolveSession(cookies) {
  const sid = cookies.sid;
  if (!sid) return { session: null, user: null };
  const row = sessions.byIdHash(sha256hex(sid));
  if (!row) return { session: null, user: null };
  if (row.expires_at <= nowSec()) {
    sessions.remove(row.id_hash);
    return { session: null, user: null };
  }
  const u = users.byId(row.user_id);
  if (!u || u.disabled) {
    sessions.remove(row.id_hash);
    return { session: null, user: null };
  }
  return { session: row, user: u };
}

// 传输加密:TLS_CERT/TLS_KEY 同时提供时走 HTTPS(并全局附加 HSTS),否则 HTTP
const useTls = !!(config.tls.cert && config.tls.key);
const serverOptions = useTls
  ? { cert: fs.readFileSync(config.tls.cert), key: fs.readFileSync(config.tls.key) }
  : {};
const handleRequest = async (req, res) => {
  const started = Date.now();
  if (useTls) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  let method = req.method.toUpperCase();
  let url;
  try {
    url = new URL(req.url, 'http://internal');
    const cookies = parseCookies(req.headers.cookie);
    const theme = themeFromCookies(cookies);
    const rt = getRuntime();

    if (method === 'OPTIONS') {
      if (CORS_PATHS.has(url.pathname)) {
        applyCors(res);
        res.writeHead(204);
        res.end();
      } else {
        sendJson(res, 404, { error: 'not_found' });
      }
      return;
    }

    const gate = setupGate(url.pathname);
    if (gate) return redirect(res, gate);

    const { session, user } = resolveSession(cookies);

    const m = matchRoute(router, method, url.pathname);
    if (!m) {
      if (wantsJson(url)) return sendJson(res, 404, { error: 'not_found' });
      const lang = langFromCookies(cookies);
      return sendHtml(res, 404, errorPage({
        theme, siteName: rt.siteName, lang,
        title: t(lang, 'err.notFoundTitle'), message: t(lang, 'err.notFoundMsg'),
      }));
    }

    if (m.route.opts.cors) applyCors(res);

    if (m.route.opts.auth) {
      if (!session) {
        return redirect(res, '/login?next=' + encodeURIComponent(url.pathname + url.search));
      }
      if (m.route.opts.auth === 'admin' && !user.is_admin) {
        return forbidden({ res, theme, runtime: rt, session, user });
      }
    }

    const ctx = {
      req, res, url, method, params: m.params, query: url.searchParams,
      cookies, theme, session, user, runtime: rt, body: null,
    };
    if (method === 'POST') {
      const contentType = String(req.headers['content-type'] || '');
      if (contentType.toLowerCase().includes('multipart/form-data')) {
        // multipart 含二进制文件,文本 readBody 会破坏内容:跳过读取并保留 req 可读流,
        // 由上传 handler 内部用 parseMultipart 自行按字节读取
        ctx.body = null;
      } else {
        const raw = await readBody(req, config.bodyLimit);
        ctx.body = parseBody(raw, contentType);
      }
    }
    await m.route.handler(ctx);
  } catch (err) {
    logger.error('请求处理异常', { path: url ? url.pathname : req.url, err: err.stack || String(err) });
    if (!res.headersSent) {
      const status = err.status || 500;
      const theme = themeFromCookies(parseCookies(req.headers.cookie));
      const lang = langFromCookies(parseCookies(req.headers.cookie));
      if (wantsJson(url || new URL(req.url, 'http://internal'))) {
        sendJson(res, status, { error: 'server_error' });
      } else {
        sendHtml(res, status, errorPage({
          theme, siteName: getRuntime().siteName, lang,
          title: t(lang, status === 413 ? 'err.tooLargeTitle' : 'err.serverTitle'),
          message: t(lang, status === 413 ? 'err.tooLargeMsg' : 'err.serverMsg'),
        }));
      }
    } else {
      res.end();
    }
  } finally {
    logger.request(method, url ? url.pathname : req.url, res.statusCode, Date.now() - started);
  }
};

// 语言上下文:请求入口按 lang cookie 固定到整个请求生命周期(AsyncLocalStorage,zh 默认),
// 视图函数经 currentLang() 读取,服务层无需逐层透传;保证默认语言下既有文案零回归。
const server = (useTls ? https : http).createServer(serverOptions, (req, res) =>
  runWithLang(langFromCookies(parseCookies(req.headers.cookie)), () => handleRequest(req, res)));

setInterval(() => {
  try { purgeExpired(); } catch (e) { logger.error('过期数据清理失败', { err: String(e) }); }
}, 10 * 60 * 1000).unref();

// 可选:TLS_REDIRECT_PORT 指定时,另起一个 HTTP 端口把全部请求 301 到 HTTPS
if (useTls && config.tls.redirectPort) {
  const proto = config.tls.redirectPort === 443 ? 'https' : `https:${config.port}`;
  http.createServer((req, res) => {
    const host = (req.headers.host || '').split(':')[0];
    res.writeHead(301, { Location: `${proto}://${host}${req.url}` });
    res.end();
  }).listen(config.tls.redirectPort, () => {
    logger.info(`HTTP 跳转端口已启动:${config.tls.redirectPort} → HTTPS ${config.port}`);
  });
}

server.listen(config.port, () => {
  const rt = getRuntime();
  const line = '='.repeat(56);
  const scheme = useTls ? 'https' : 'http';
  console.log(`\n${line}\n  ${rt.siteName} 已启动\n`);
  console.log(`  本机访问   ${scheme}://localhost:${config.port}`);
  console.log(`  Issuer     ${rt.issuer}`);
  console.log(`  传输加密   ${useTls ? 'HTTPS(TLS 直连 + HSTS)' : 'HTTP(反代终止 TLS 时请配置 BASE_URL 为 https)'}`);
  console.log(`  数据目录   ${config.dataDir}`);
  if (!rt.setupDone) {
    console.log(`\n  首次部署:请打开配置向导完成初始化`);
    console.log(`  ${rt.issuer}/setup`);
  }
  console.log(`\n${line}\n`);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    logger.info('收到退出信号,正在关闭');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  });
}
