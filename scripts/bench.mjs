/** 临时性能基准:对运行中的实例做延迟与并发压测(用完即删) */
import { performance } from 'node:perf_hooks';

const BASE = process.env.BENCH_BASE || 'http://localhost:9000';
const CONC = Number(process.env.BENCH_CONC || 20);
const DURATION_MS = Number(process.env.BENCH_MS || 4000);

const stats = (arr) => {
  const a = [...arr].sort((x, y) => x - y);
  return {
    n: a.length,
    avg: Math.round(a.reduce((s, x) => s + x, 0) / a.length),
    p50: Math.round(a[Math.floor(a.length * 0.5)]),
    p95: Math.round(a[Math.floor(a.length * 0.95)]),
    max: Math.round(a[a.length - 1]),
  };
};

async function bench(name, path, { method = 'GET', headers = {}, body } = {}) {
  const lat = [];
  const t0 = performance.now();
  let done = 0;
  const worker = async () => {
    while (performance.now() - t0 < DURATION_MS) {
      const s = performance.now();
      try {
        await fetch(BASE + path, { method, headers, body, redirect: 'manual' });
      } catch { /* 忽略连接错误,记为高延迟 */ }
      lat.push(performance.now() - s);
      done++;
    }
  };
  await Promise.all(Array.from({ length: CONC }, worker));
  const wall = performance.now() - t0;
  const st = stats(lat);
  console.log(
    `${name.padEnd(28)} ${String(st.n).padStart(6)} req  avg ${String(st.avg).padStart(5)}ms  p50 ${String(st.p50).padStart(5)}ms  p95 ${String(st.p95).padStart(5)}ms  max ${String(st.max).padStart(6)}ms  ≈${Math.round((st.n / wall) * 1000)} rps`
  );
  return st;
}

// 登录(含 scrypt)单次与失败路径延迟
class Jar {
  map = new Map();
  store(res) { for (const c of res.headers.getSetCookie?.() || []) { const [kv] = c.split(';'); const i = kv.indexOf('='); const v = kv.slice(i + 1); if (v === '') this.map.delete(kv.slice(0, i).trim()); else this.map.set(kv.slice(0, i).trim(), v); } }
  header() { return [...this.map].map(([k, v]) => `${k}=${v}`).join('; '); }
}
const j = new Jar();
let r = await fetch(BASE + '/login', { redirect: 'manual' });
j.store(r);
const html = await r.text();
const csrf = html.match(/name="_csrf" value="([^"]*)"/)[1];
const loginOnce = async (user, pass) => {
  const t = performance.now();
  await fetch(BASE + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: j.header() },
    body: new URLSearchParams({ _csrf: csrf, username: user, password: pass }).toString(),
  });
  return Math.round(performance.now() - t);
};
console.log(`登录成功(含 scrypt)      单次  ${await loginOnce('demo', 'Demo#12345')}ms`);
console.log(`登录失败(未知用户)      单次  ${await loginOnce('ghost-' + Date.now(), 'x'.repeat(60))}ms`);

console.log('\n--- 并发压测(并发 ' + CONC + ',持续 ' + DURATION_MS + 'ms,连接复用由 fetch 自管)---');
await bench('GET /health(匿名状态页)', '/health');
await bench('GET /api/heartbeat(匿名 JSON)', '/api/heartbeat');
await bench('GET /login(匿名页面)', '/login');
await bench('GET /.well-known/…(发现文档)', '/.well-known/openid-configuration');
await bench('GET /jwks.json', '/jwks.json');

process.exit(0);
