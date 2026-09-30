import { escapeHtml as esc } from '../core/util.js';

/**
 * 页面骨架 + 樱落设计语言(参照 mcylyr 设计规范):
 * 明暗双 token / 去边框靠明度差 / 轻投影 / 4px 间距网格 / 150–200ms 过渡 / 零 JS。
 */

export const SAKURA_CSS = `
:root{
  --page:#ffffff;--surface:#f7f7f8;--surface-soft:#f0f0f2;
  --text:#23232a;--text-soft:#3f3f49;--muted:#6f6f7b;--heading:#17171d;
  --accent:#b84d66;--accent-strong:#9c3549;--on-accent:#ffffff;
  --ok:#1a7f4b;--warn:#9a6700;--danger:#c93c37;
  --border:#dedee3;--code-bg:#f4f4f6;--code-text:#292934;
  --shadow-sm:0 1px 2px rgba(30,30,45,.06);--shadow-md:0 4px 14px rgba(30,30,45,.10);
  --radius:8px;
  --s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:24px;--s6:32px;--s7:48px;--s8:64px;
}
html[data-theme="night"]{
  --page:#1b1b1f;--surface:#171719;--surface-soft:#202024;
  --text:#f1f1f3;--text-soft:#c7c7ce;--muted:#92929d;--heading:#ffffff;
  --accent:#ef9aab;--accent-strong:#f6b3c0;--on-accent:#2a1218;
  --ok:#4cae7f;--warn:#d4a72c;--danger:#f07f7a;
  --border:#303036;--code-bg:#141416;--code-text:#e6e6eb;
  --shadow-sm:0 1px 2px rgba(0,0,0,.20);--shadow-md:0 4px 14px rgba(0,0,0,.32);
}
@media (prefers-color-scheme: dark){
  html:not([data-theme="day"]){
    --page:#1b1b1f;--surface:#171719;--surface-soft:#202024;
    --text:#f1f1f3;--text-soft:#c7c7ce;--muted:#92929d;--heading:#ffffff;
    --accent:#ef9aab;--accent-strong:#f6b3c0;--on-accent:#2a1218;
    --ok:#4cae7f;--warn:#d4a72c;--danger:#f07f7a;
    --border:#303036;--code-bg:#141416;--code-text:#e6e6eb;
    --shadow-sm:0 1px 2px rgba(0,0,0,.20);--shadow-md:0 4px 14px rgba(0,0,0,.32);
  }
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--page);color:var(--text-soft);
  font-family:"PingFang SC","Microsoft YaHei",system-ui,sans-serif;font-size:16px;line-height:1.7;
  transition:background .2s ease,color .2s ease}
h1,h2,h3{color:var(--heading);line-height:1.35}
h1{font-size:2.25rem;font-weight:700;margin:0 0 18px}
h2{font-size:1.55rem;font-weight:650;margin:var(--s6) 0 var(--s4);padding-bottom:.65rem;border-bottom:1px solid var(--border)}
h3{font-size:1.22rem;font-weight:625;margin:var(--s5) 0 var(--s3)}
h1:first-child,h2:first-child{margin-top:0}
p{margin:var(--s4) 0}
a{color:var(--accent);text-decoration:underline;text-decoration-color:transparent;text-underline-offset:3px;transition:color .18s ease}
a:hover{color:var(--accent-strong);text-decoration-color:currentColor}
code{font-family:ui-monospace,Consolas,monospace;border:0;border-radius:5px;padding:.12em .38em;color:var(--code-text);background:var(--surface-soft);font-size:.9em}
.muted{color:var(--muted);font-size:14px}
.small{font-size:14px}
hr{border:0;border-top:1px solid var(--border);margin:var(--s5) 0}
/* 卡片:面代替框 */
.card{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow-sm);padding:var(--s5);margin:0 0 var(--s5)}
.card.tight{padding:var(--s4)}
/* 表格 */
.tblwrap{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow-sm);overflow-x:auto;margin-bottom:var(--s5)}
table.tbl{width:100%;border-collapse:collapse;font-size:14px;line-height:1.5}
.tbl th{text-align:left;color:var(--muted);font-weight:600;font-size:13px;background:var(--surface-soft);padding:10px 14px;white-space:nowrap}
.tbl td{padding:10px 14px;border-top:1px solid var(--border);vertical-align:middle}
.tbl td.wrap{word-break:break-all}
/* 按钮:150–200ms 过渡 + hover 上抬 */
.btn{display:inline-flex;align-items:center;gap:var(--s2);padding:var(--s2) var(--s4);border:0;border-radius:var(--radius);
  background:var(--surface-soft);color:var(--text);font:inherit;font-size:14px;font-weight:600;cursor:pointer;
  text-decoration:none;transition:all .18s ease}
.btn:hover{transform:translateY(-1px);box-shadow:var(--shadow-md);text-decoration:none}
.btn:active{transform:translateY(0);box-shadow:var(--shadow-sm)}
.btn-primary{background:var(--accent);color:var(--on-accent)}
.btn-primary:hover{background:var(--accent-strong)}
.btn-danger{color:var(--danger);background:transparent;box-shadow:inset 0 0 0 1px var(--border)}
.btn-danger:hover{background:color-mix(in srgb,var(--danger) 10%,transparent);box-shadow:inset 0 0 0 1px var(--border)}
.btn-sm{padding:var(--s1) var(--s3);font-size:13px}
/* 表单 */
label{display:block;font-size:13px;font-weight:600;color:var(--text-soft);margin:var(--s3) 0 var(--s1)}
input[type=text],input[type=password],input[type=email],input[type=number],input[type=url],select,textarea{
  width:100%;padding:var(--s2) var(--s3);border:1px solid var(--border);border-radius:var(--radius);
  background:var(--surface-soft);color:var(--text);font:inherit;transition:border-color .18s ease,box-shadow .18s ease}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);
  box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 25%,transparent)}
input::placeholder,textarea::placeholder{color:var(--muted)}
textarea{min-height:84px;resize:vertical;font-family:ui-monospace,Consolas,monospace;font-size:13px}
.checkline{display:flex;gap:var(--s2);align-items:flex-start;margin:var(--s2) 0;font-size:14px}
.checkline input{width:auto;margin-top:5px;accent-color:var(--accent)}
.checkline .muted{display:block;font-size:13px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 var(--s4)}
@media(max-width:720px){.grid2{grid-template-columns:1fr}}
/* 提示条:blockquote 式左侧强调线 */
.banner{padding:.65rem 1rem;border-left:3px solid var(--accent);border-radius:0 var(--radius) var(--radius) 0;
  background:color-mix(in srgb,var(--surface-soft) 55%,transparent);color:var(--text-soft);margin:0 0 var(--s4);font-size:14px}
.banner.err{border-left-color:var(--danger)}
.banner.ok{border-left-color:var(--ok)}
.banner.warn{border-left-color:var(--warn)}
/* 徽章 / 键值 */
.badge{display:inline-block;padding:1px 10px;border-radius:99px;background:var(--surface-soft);color:var(--muted);font-size:12px;line-height:1.7}
.kv{display:flex;gap:var(--s2);align-items:baseline;background:var(--surface-soft);border-radius:var(--radius);
  padding:var(--s2) var(--s3);font-family:ui-monospace,Consolas,monospace;font-size:13px;word-break:break-all;margin:var(--s2) 0}
.kv b{color:var(--muted);font-weight:600;flex:none}
pre.block{background:var(--code-bg);color:var(--code-text);border-radius:var(--radius);box-shadow:var(--shadow-sm);
  padding:var(--s4);font-family:ui-monospace,Consolas,monospace;font-size:13px;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:var(--s3) 0}
/* 统计卡 */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:var(--s4);margin-bottom:var(--s5)}
.stat{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow-sm);padding:var(--s4) var(--s5)}
.stat b{display:block;color:var(--heading);font-size:2rem;font-weight:700;line-height:1.2}
.stat span{color:var(--muted);font-size:13px}
/* 侧栏:玻璃化,当前项 2px 指示条 */
.side{position:fixed;top:0;left:0;bottom:0;width:264px;display:flex;flex-direction:column;
  background:color-mix(in srgb,var(--surface) 88%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);overflow-y:auto}
.side-brand{display:flex;align-items:center;gap:var(--s3);padding:var(--s5) var(--s5) var(--s4)}
.side-brand svg{color:var(--accent);flex:none}
.side-brand b{color:var(--heading);font-size:16px;line-height:1.3}
.side nav{flex:1;padding:0 var(--s5) var(--s5)}
.side nav .sep{margin:var(--s5) 0 var(--s2);color:var(--muted);font-size:12px;font-weight:600;letter-spacing:.05em}
.side nav a{display:block;position:relative;color:var(--muted);font-size:14px;text-decoration:none;padding:var(--s1) 0 var(--s1) 10px;margin:3px 0;transition:color .15s ease}
.side nav a:hover{color:var(--accent-strong);text-decoration:none}
.side nav a.active{color:var(--accent-strong);font-weight:600}
.side nav a.active::before{content:"";position:absolute;left:-10px;top:50%;transform:translateY(-50%);width:2px;height:18px;border-radius:2px;background:var(--accent)}
.side-foot{padding:var(--s4) var(--s5);border-top:1px solid var(--border);font-size:13px;color:var(--muted)}
.side-foot .row{display:flex;justify-content:space-between;align-items:center;gap:var(--s2)}
.main{margin-left:264px;padding:var(--s7) var(--s6) 100px;max-width:1160px}
@media(max-width:900px){.side{display:none}.main{margin-left:0;padding:var(--s5) var(--s4) 64px}}
.topbar{display:none}
@media(max-width:900px){.topbar{display:flex;align-items:center;gap:var(--s2);padding:var(--s4);color:var(--heading);font-weight:700}.topbar svg{color:var(--accent)}}
/* 居中认证布局 */
.auth-wrap{min-height:100vh;display:grid;place-items:center;padding:var(--s6) var(--s4)}
.auth-col{width:100%;max-width:460px}
.auth-col-wide{max-width:560px}
.auth-card{background:var(--surface);border-radius:12px;box-shadow:var(--shadow-sm);padding:var(--s6)}
.auth-brand{display:flex;align-items:center;gap:var(--s3);margin-bottom:var(--s5)}
.auth-brand svg{color:var(--accent)}
.auth-brand h1{font-size:20px;font-weight:700;margin:0;line-height:1.3}
.auth-brand .muted{font-size:13px}
.auth-foot{text-align:center;color:var(--muted);font-size:12px;margin-top:var(--s4)}
/* 授权同意页 */
.app-row{display:flex;align-items:center;gap:var(--s3);margin-bottom:var(--s5)}
.app-badge{width:52px;height:52px;border-radius:14px;background:color-mix(in srgb,var(--accent) 12%,transparent);color:var(--accent);display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;flex:none}
.identity{display:flex;align-items:center;gap:var(--s2);background:var(--surface-soft);border-radius:99px;padding:4px 14px 4px 4px;font-size:14px;margin:0 0 var(--s4);width:fit-content;max-width:100%}
.identity .avatar{width:28px;height:28px;border-radius:99px;background:var(--accent);color:var(--on-accent);display:inline-flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex:none}
.scope-item{display:flex;gap:var(--s3);align-items:flex-start;padding:var(--s3) 0;border-bottom:1px solid var(--border)}
.scope-item:last-child{border-bottom:0}
.scope-item .scope-ico{width:34px;height:34px;border-radius:10px;background:var(--surface-soft);color:var(--accent);display:inline-flex;align-items:center;justify-content:center;flex:none}
.scope-item b{display:block;color:var(--text);font-size:14px;font-weight:600;line-height:1.4}
.scope-item .desc{display:block;font-size:13px;color:var(--muted)}
.consent-actions{display:flex;gap:var(--s3);margin-top:var(--s4)}
.consent-actions .btn{flex:1;justify-content:center;padding:var(--s3) var(--s4);font-size:15px}
/* 向导步骤 */
.steps{display:flex;gap:var(--s2);margin-bottom:var(--s5)}
.step{flex:1;text-align:center;font-size:12px;color:var(--muted);padding-top:10px;position:relative}
.step::before{content:"";position:absolute;top:0;left:0;right:0;height:4px;border-radius:4px;background:var(--surface-soft)}
.step.on{color:var(--accent-strong);font-weight:600}
.step.on::before{background:var(--accent)}
.step.done::before{background:color-mix(in srgb,var(--accent) 45%,var(--surface-soft))}
/* 检查项(向导第一步) */
.chk{display:flex;gap:var(--s3);padding:var(--s2) 0;font-size:14px;align-items:baseline}
.chk .s{flex:none;font-weight:700}
.chk .s.ok{color:var(--ok)}.chk .s.bad{color:var(--danger)}
.actions{display:flex;gap:var(--s3);margin-top:var(--s5);flex-wrap:wrap}
.rowline{display:flex;gap:var(--s3);align-items:center;flex-wrap:wrap}
.spread{display:flex;justify-content:space-between;align-items:center;gap:var(--s3);flex-wrap:wrap}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
`;

const THEME_HINT = '切换主题';

/** 樱落品牌标:五瓣花(纯内联 SVG,零外部资源) */
export function mark(size = 26) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
<g><circle cx="12" cy="6.5" r="4.1"/><circle cx="6.77" cy="10.3" r="4.1"/><circle cx="8.77" cy="16.45" r="4.1"/><circle cx="15.23" cy="16.45" r="4.1"/><circle cx="17.23" cy="10.3" r="4.1"/><circle cx="12" cy="11.8" r="2.1" style="fill:var(--page)"/></g></svg>`;
}

const themeToggle = (theme, cur) => {
  const next = theme === 'night' ? 'day' : 'night';
  const label = theme === 'night' ? '日间' : '夜间';
  return `<a href="/-/theme/${next}?back=${encodeURIComponent(cur || '/')}" title="${THEME_HINT}">${label}主题</a>`;
};

function head(theme, title) {
  return `<!doctype html>
<html lang="zh-CN"${theme ? ` data-theme="${theme}"` : ''}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${esc(title)}</title>
<style>${SAKURA_CSS}</style>
</head>`;
}

/** 认证类页面骨架(登录 / 同意 / 向导):居中卡片;wide 供授权页等需要更宽的场景 */
export function authPage({ theme, siteName, title, content, footer = true, wide = false }) {
  return `${head(theme, title)}
<body>
<div class="auth-wrap"><div class="auth-col${wide ? ' auth-col-wide' : ''}">
  <div class="auth-card">
    <div class="auth-brand">${mark(30)}<div><h1>${esc(siteName)}</h1><div class="muted">统一身份认证服务</div></div></div>
    ${content}
  </div>
  ${footer ? '<p class="auth-foot">SakuraID · 由樱落生态设计语言驱动</p>' : ''}
</div></div>
</body></html>`;
}

/** 控制台骨架:左侧玻璃侧栏 + 内容区 */
export function adminPage({ theme, siteName, user, active = '', title, content, cur = '/' }) {
  const items = [
    ['', '控制台', 'dashboard'],
    ['users', '用户', 'users'],
    ['groups', '权限组', 'groups'],
    ['apps', '应用', 'apps'],
  ];
  const link = (href, label, key) =>
    `<a href="${href}"${key === active ? ' class="active"' : ''}>${label}</a>`;
  return `${head(theme, title)}
<body>
<div class="topbar">${mark(22)} ${esc(siteName)}</div>
<aside class="side">
  <div class="side-brand">${mark(26)}<b>${esc(siteName)}<br><span class="muted small">管理控制台</span></b></div>
  <nav>
    ${link('/admin', '控制台', 'dashboard')}
    ${link('/admin/users', '用户', 'users')}
    ${link('/admin/groups', '权限组', 'groups')}
    ${link('/admin/apps', '应用', 'apps')}
    <div class="sep">账号</div>
    ${link('/account', '账号设置', 'account')}
    <a href="/logout">退出登录</a>
  </nav>
  <div class="side-foot">
    <div class="row"><span>${esc(user.username)}${user.is_admin ? ' · 管理员' : ''}</span><span>${themeToggle(theme, cur)}</span></div>
  </div>
</aside>
<main class="main">
${content}
</main>
</body></html>`;
}

/** 页头标题块 */
export const pageTitle = (t, sub = '') =>
  `<h1>${esc(t)}${sub ? `<span class="muted" style="font-weight:400;font-size:15px;margin-left:12px">${esc(sub)}</span>` : ''}</h1>`;
