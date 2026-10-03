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

/** 品牌强调色:仅接受 #RGB / #RRGGBB(不区分大小写),规范化为小写 #rrggbb;
 *  其余一律返回 null —— 非法值永不落库、永不进入样式,天然杜绝 CSS 注入。 */
export function normalizeHexColor(s) {
  const v = String(s ?? '').trim().toLowerCase();
  const m = v.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/);
  if (!m) return null;
  const h = m[1];
  return h.length === 3 ? '#' + [...h].map((c) => c + c).join('') : `#${h}`;
}

/** 由品牌强调色在视图层派生品牌覆盖 CSS 块(具体色值先算好再输出;非法输入返回 '' = 不覆盖):
 *  accent = 用户色;accent-strong = 同色加深 12%(RGB × 0.88);on-accent 按 YIQ 亮度选深/浅文字色;
 *  登录渐变 b 色 = 用户色 55% 混原紫罗兰 #7c3aed 45%(保持原渐变混色风格);on 系列为白色透明度分层。
 *  选择器覆盖 :root(默认亮色)、html[data-theme="night"](夜间)与 prefers-color-scheme 暗色分支,
 *  且置于全站样式之后 —— 两套主题的强调色/登录渐变统一被品牌色覆盖。 */
export function brandAccentCss(accent) {
  const c = normalizeHexColor(accent);
  if (!c) return '';
  const rgb = [1, 3, 5].map((i) => parseInt(c.slice(i, i + 2), 16));
  const yiq = (rgb[0] * 299 + rgb[1] * 587 + rgb[2] * 114) / 1000;
  const hex = (n) => Math.round(Math.min(255, Math.max(0, n))).toString(16).padStart(2, '0');
  const darken = (n) => hex(n * 0.88);
  const mixViolet = (n, v) => hex(n * 0.55 + v * 0.45);
  const strong = `#${darken(rgb[0])}${darken(rgb[1])}${darken(rgb[2])}`;
  const gradB = `#${mixViolet(rgb[0], 0x7c)}${mixViolet(rgb[1], 0x3a)}${mixViolet(rgb[2], 0xed)}`;
  const onAccent = yiq >= 128 ? '#1f2330' : '#ffffff';
  return 'html,:root,html[data-theme="night"],html:not([data-theme="day"]){'
    + `--accent:${c};--accent-strong:${strong};--on-accent:${onAccent};`
    + `--login-grad-a:${c};--login-grad-b:${gradB};--login-on:#ffffff;`
    + '--login-on-soft:color-mix(in srgb,#fff,transparent 25%);'
    + '--login-on-faint:color-mix(in srgb,#fff,transparent 55%);'
    + '--login-chip:color-mix(in srgb,#fff,transparent 80%)}';
}

/** 码点安全截断:按 Unicode 码点(而非 UTF-16 编码单元)计数与截取,
 *  emoji 等代理对字符不会被拦腰截成非法半截;超长时以「…」结尾 */
export function truncateCodePoints(str, max = 40) {
  const s = String(str ?? '');
  const cps = Array.from(s);
  if (cps.length <= max) return s;
  return cps.slice(0, max).join('') + '…';
}
