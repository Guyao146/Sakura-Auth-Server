import crypto from 'node:crypto';

/** 极简路由器:精确段 + :param 段匹配 */

export function createRouter() {
  const routes = [];
  return {
    routes,
    add(method, pattern, handler, opts = {}) {
      routes.push({
        method: method.toUpperCase(),
        parts: pattern.split('/').filter(Boolean),
        handler,
        opts,
      });
    },
  };
}

export function matchRoute(router, method, pathname) {
  const segs = pathname.split('/').filter(Boolean);
  for (const r of router.routes) {
    if (r.method !== method) continue;
    if (r.parts.length !== segs.length) continue;
    const params = {};
    let ok = true;
    for (let i = 0; i < r.parts.length; i++) {
      const p = r.parts[i];
      if (p.startsWith(':')) params[p.slice(1)] = decodeURIComponent(segs[i]);
      else if (p !== segs[i]) { ok = false; break; }
    }
    if (ok) return { route: r, params };
  }
  return null;
}

/* ---------- 请求/响应原语 ---------- */

export function parseCookies(header) {
  const out = Object.create(null);
  if (typeof header !== 'string') return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    const name = part.slice(0, i).trim();
    try { out[name] = decodeURIComponent(part.slice(i + 1).trim()); }
    catch { /* 非法百分号/UTF-8 cookie 单独丢弃,不得使整个服务退出 */ }
  }
  return out;
}

export function setCookie(res, name, value, { maxAge, httpOnly = true, path = '/', sameSite = 'Lax', secure = false } = {}) {
  let c = `${name}=${encodeURIComponent(value)}; Path=${path}; SameSite=${sameSite}`;
  if (maxAge !== undefined) c += `; Max-Age=${maxAge}`;
  if (httpOnly) c += '; HttpOnly';
  if (secure) c += '; Secure';
  const prev = res.getHeader('Set-Cookie');
  const list = prev ? (Array.isArray(prev) ? prev : [prev]) : [];
  list.push(c);
  res.setHeader('Set-Cookie', list);
}

export function clearCookie(res, name, secure = false) {
  setCookie(res, name, '', { maxAge: 0, secure });
}

export function readBody(req, limit = 100 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (ch) => {
      size += ch.length;
      if (size > limit) {
        reject(Object.assign(new Error('请求体过大'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(ch);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/** 解析表单(application/x-www-form-urlencoded)或 JSON 请求体为普通对象;重复键合并为数组 */
export function parseBody(raw, contentType = '') {
  if (!raw) return {};
  if (contentType.includes('application/json')) {
    try { return JSON.parse(raw); } catch { return {}; }
  }
  const params = new URLSearchParams(raw);
  const out = {};
  for (const key of new Set(params.keys())) {
    const vals = params.getAll(key);
    out[key] = vals.length > 1 ? vals : vals[0];
  }
  return out;
}

const baseHeaders = (res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; " +
    "form-action 'self'; frame-ancestors 'none'; base-uri 'self'");
};

export function sendHtml(res, status, html) {
  baseHeaders(res);
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

export function sendJson(res, status, obj, headers = {}) {
  baseHeaders(res);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(obj));
}

export function redirect(res, location) {
  baseHeaders(res);
  res.writeHead(302, { Location: location });
  res.end();
}
