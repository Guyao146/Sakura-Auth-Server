/** 通用小工具:HTML 转义、时间格式化、校验 */

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const escapeHtml = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ESC[c]);

export const fmtTime = (sec) => (sec ? new Date(sec * 1000).toLocaleString('zh-CN', { hour12: false }) : '-');

/** 校验 http(s) 绝对 URL,返回规范值或 null */
export function httpUrl(s) {
  try {
    const u = new URL(String(s));
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.toString();
  } catch {
    return null;
  }
}

/** 可执行伪协议黑名单:此类地址在浏览器中会以脚本/文档形式执行,绝不允许作为重定向目标 */
const DANGEROUS_SCHEMES = new Set(['javascript', 'data', 'vbscript']);

/** 校验重定向地址:允许 http(s) 与自定义 scheme(如移动端 app 回调 com.example.app://cb),
 *  拒绝 javascript:/data:/vbscript: 等可执行伪协议与无 scheme 的相对路径 */
export function redirectUri(s) {
  const v = String(s || '').trim();
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:[^\s]+$/.test(v)) return null;
  const scheme = v.slice(0, v.indexOf(':')).toLowerCase();
  if (DANGEROUS_SCHEMES.has(scheme)) return null;
  return v;
}

/** 多行文本 → 去空去重的数组(重定向 URI 列表用) */
export const splitLines = (text) =>
  String(text || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);

/** 相对路径跳转校验,防开放重定向 */
export function safeNext(n, fallback = '/') {
  if (typeof n === 'string' && n.startsWith('/') && !n.startsWith('//') && !n.includes('\\')) return n;
  return fallback;
}

export const USERNAME_RE = /^[a-zA-Z0-9_.@-]{2,64}$/;

/** 码点安全截断:按 Unicode 码点(而非 UTF-16 编码单元)计数与截取,
 *  emoji 等代理对字符不会被拦腰截成非法半截;超长时以「…」结尾 */
export function truncateCodePoints(str, max = 40) {
  const s = String(str ?? '');
  const cps = Array.from(s);
  if (cps.length <= max) return s;
  return cps.slice(0, max).join('') + '…';
}
