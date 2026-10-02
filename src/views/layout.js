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
  /* 品牌分栏登录页:樱色→紫罗兰渐变面板(全页唯一重强调色块) */
  --login-grad-a:#b84d66;--login-grad-b:#7c3aed;
  --login-on:#ffffff;--login-on-soft:rgba(255,255,255,.82);--login-on-faint:rgba(255,255,255,.62);
  --login-chip:rgba(255,255,255,.16);
}
html[data-theme="night"]{
  --page:#1b1b1f;--surface:#171719;--surface-soft:#202024;
  --text:#f1f1f3;--text-soft:#c7c7ce;--muted:#92929d;--heading:#ffffff;
  --accent:#ef9aab;--accent-strong:#f6b3c0;--on-accent:#2a1218;
  --ok:#4cae7f;--warn:#d4a72c;--danger:#f07f7a;
  --border:#303036;--code-bg:#141416;--code-text:#e6e6eb;
  --shadow-sm:0 1px 2px rgba(0,0,0,.20);--shadow-md:0 4px 14px rgba(0,0,0,.32);
  --login-grad-a:#8f3a50;--login-grad-b:#5326b8;
  --login-on:#ffffff;--login-on-soft:rgba(255,255,255,.80);--login-on-faint:rgba(255,255,255,.60);
  --login-chip:rgba(255,255,255,.14);
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
.btn-ghost{background:transparent;color:var(--text);box-shadow:inset 0 0 0 1px var(--border)}
.btn-ghost:hover{background:var(--surface-soft);box-shadow:inset 0 0 0 1px var(--border)}
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
.side{position:fixed;top:0;left:0;bottom:0;width:304px;display:flex;flex-direction:column;
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
/* 侧栏加宽(304px),内容列恢复靠左排布 */
.main{margin-left:304px;padding:var(--s7) var(--s6) 100px;max-width:1500px}
@media(max-width:900px){.side{display:none}.main{margin-left:0;padding:var(--s5) var(--s4) 64px}}
.topbar{display:none}
@media(max-width:900px){.topbar{display:flex;align-items:center;gap:var(--s2);padding:var(--s4);color:var(--heading);font-weight:700}.topbar svg{color:var(--accent)}}
/* 内容顶栏:左侧页级标题块,右侧页级控件/actions */
.main-head{display:flex;justify-content:space-between;align-items:flex-end;gap:var(--s3);margin-bottom:var(--s5);flex-wrap:wrap}
.main-head-title h3{margin:0}
.main-head-title p{margin:2px 0 0}
.main-head .rowline{padding-bottom:2px}
/* 视图切换分段控件 */
.seg-group{display:inline-flex;background:var(--surface-soft);border-radius:10px;padding:3px;gap:2px}
.seg{display:inline-flex;align-items:center;padding:4px 12px;border-radius:8px;color:var(--muted);font-size:13px;font-weight:600;text-decoration:none;transition:all .18s ease}
.seg:hover{color:var(--text);text-decoration:none}
.seg.active{background:var(--surface);color:var(--text);box-shadow:var(--shadow-sm)}
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
/* 品牌化分栏登录(登录页专用):桌面 ≥900px 左品牌渐变面板 + 右表单,窄屏仅表单 */
.login-split{min-height:100vh;display:grid;grid-template-columns:minmax(440px,46%) 1fr;background:var(--page)}
.login-brand{position:relative;overflow:hidden;display:flex;flex-direction:column;justify-content:space-between;gap:var(--s7);
  padding:var(--s8) var(--s7) var(--s6);color:var(--login-on);background:linear-gradient(150deg,var(--login-grad-a),var(--login-grad-b))}
.login-brand-deco{position:absolute;right:-72px;bottom:-72px;opacity:.12;pointer-events:none}
.login-brand-body{position:relative;flex:1;display:flex;flex-direction:column;justify-content:center;align-items:center;
  text-align:center;padding-left:var(--s6);padding-right:var(--s6)}
.login-brand-mark{display:inline-flex;align-items:center;justify-content:center;width:72px;height:72px;border-radius:20px;background:var(--login-chip)}
.login-brand-name{color:var(--login-on);font-size:2.1rem;font-weight:700;margin:var(--s5) 0 0}
.login-brand-slogan{margin:var(--s2) 0 0;font-size:17px;color:var(--login-on-soft)}
.login-brand-feats{list-style:none;margin:var(--s6) 0 0;padding:0;display:flex;flex-direction:column;gap:var(--s4);align-items:center}
.login-brand-feats li{display:flex;align-items:center;gap:var(--s3)}
.login-brand-feats .feat-ico{width:34px;height:34px;border-radius:10px;background:var(--login-chip);color:var(--login-on);display:inline-flex;align-items:center;justify-content:center;flex:none}
.login-brand-feats b{display:block;color:var(--login-on);font-size:14px;font-weight:600;line-height:1.5}
.login-brand-feats small{display:block;color:var(--login-on-soft);font-size:13px;line-height:1.55}
.login-brand-foot{position:relative;margin:0;font-size:12px;color:var(--login-on-faint)}
/* 品牌标中心镂空落在渐变面板上时透出渐变,而非页面底色 */
.login-brand svg circle[style]{fill:transparent !important}
.login-form{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:var(--s7) var(--s5)}
.login-form-col{width:100%;max-width:400px}
.login-form-col-wide{max-width:480px}
.login-form-brand{display:none;align-items:center;gap:var(--s2);color:var(--accent);margin-bottom:var(--s5)}
.login-form-brand b{color:var(--heading);font-size:17px;line-height:1.3}
.login-form-title{margin:0;padding-bottom:0;border-bottom:0;font-size:1.45rem}
.login-form-sub{margin:0 0 var(--s5)}
.login-form .actions .btn-primary{flex:1;justify-content:center;padding:var(--s3) var(--s4);font-size:15px}
.login-form-foot{margin:var(--s5) 0 0;text-align:center;font-size:12px;color:var(--muted)}
@media(max-width:899px){
  .login-split{grid-template-columns:1fr}
  .login-brand{display:none}
  .login-form{min-height:100vh;padding:var(--s6) var(--s4)}
  .login-form-brand{display:flex}
}
/* 授权同意页(品牌化分栏,与登录页同骨架) */
.app-row{display:flex;align-items:center;gap:var(--s3);margin-bottom:var(--s5)}
.app-badge{width:52px;height:52px;border-radius:14px;background:color-mix(in srgb,var(--accent) 12%,transparent);color:var(--accent);display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;flex:none}
.consent-logo{width:52px;height:52px;border-radius:14px;object-fit:cover;flex:none}
.identity{display:flex;align-items:center;gap:var(--s2);background:var(--surface-soft);border-radius:99px;padding:4px 14px 4px 4px;font-size:14px;margin:0 0 var(--s4);width:fit-content;max-width:100%}
.identity .avatar{width:28px;height:28px;border-radius:99px;background:var(--accent);color:var(--on-accent);display:inline-flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex:none}
.scope-item{display:flex;gap:var(--s3);align-items:flex-start;padding:var(--s3) 0;border-bottom:1px solid var(--border)}
.scope-item:last-child{border-bottom:0}
.scope-item .scope-ico{width:34px;height:34px;border-radius:10px;background:var(--surface-soft);color:var(--accent);display:inline-flex;align-items:center;justify-content:center;flex:none}
.scope-item b{display:block;color:var(--text);font-size:14px;font-weight:600;line-height:1.4}
.scope-item .desc{display:block;font-size:13px;color:var(--muted)}
.consent-actions{display:flex;gap:var(--s3);margin-top:var(--s4)}
.consent-actions .btn{flex:1;justify-content:center;padding:var(--s3) var(--s4);font-size:15px}
.app-item{display:flex;gap:var(--s3);align-items:center;padding:var(--s3) 0;border-bottom:1px solid var(--border)}
.app-item:last-child{border-bottom:0}
.app-item .app-badge{width:44px;height:44px;font-size:18px;border-radius:12px}
/* 应用门户 */
.portal-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:var(--s4);margin-bottom:var(--s5)}
.portal-tile{background:var(--surface);border-radius:12px;box-shadow:var(--shadow-sm);padding:var(--s5);display:flex;flex-direction:column;gap:var(--s3);transition:transform .18s ease,box-shadow .18s ease}
.portal-tile:hover{transform:translateY(-1px);box-shadow:var(--shadow-md)}
.portal-tile .name{color:var(--heading);font-weight:650;font-size:15px;line-height:1.35}
.portal-tile .scope-badges{display:flex;flex-wrap:wrap;gap:var(--s1) var(--s2)}
.portal-tile .btn{justify-content:center;margin-top:auto}
/* 应用健康状态点(up=在线/down=离线/unknown=未知) */
.status-dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--muted);flex:none;vertical-align:middle}
.status-dot.up{background:var(--ok)}
.status-dot.down{background:var(--danger)}
.status-dot.unknown{background:var(--muted)}
.portal-tile .name .status-dot{margin-right:7px}
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

/**
 * 品牌化分栏骨架(登录页 / 同意授权页):左侧樱色渐变品牌面板(全页唯一重强调色块),
 * 右侧表单面板;窄屏(≤899px)单栏仅表单,改由表单面板内的紧凑品牌行承接识别。
 * wide=true 时右栏加宽(同意页的徽标行 / 权限清单需要更多横向空间),登录页不受影响。
 */
export function brandPage({
  theme, siteName, title, tagline = '', features = [], content, footer = true, cur = '/login', wide = false,
}) {
  const feats = features.map((f) => `
      <li><span class="feat-ico">${f.icon}</span><span><b>${esc(f.title)}</b><small>${esc(f.desc)}</small></span></li>`).join('\n');
  return `${head(theme, title)}
<body>
<div class="login-split">
  <aside class="login-brand">
    <div class="login-brand-deco" aria-hidden="true">${mark(220)}</div>
    <div class="login-brand-body">
      <div class="login-brand-mark">${mark(40)}</div>
      <h1 class="login-brand-name">${esc(siteName)}</h1>
      ${tagline ? `<p class="login-brand-slogan">${esc(tagline)}</p>` : ''}
      ${features.length ? `<ul class="login-brand-feats">${feats}
      </ul>` : ''}
    </div>
    <p class="login-brand-foot">由樱落生态设计语言驱动</p>
  </aside>
  <main class="login-form"><div class="login-form-col${wide ? ' login-form-col-wide' : ''}">
    <div class="login-form-brand">${mark(24)}<b>${esc(siteName)}</b></div>
    ${content}
    ${footer ? `<p class="login-form-foot">SakuraID · ${themeToggle(theme, cur)}</p>` : ''}
  </div></main>
</div>
</body></html>`;
}

/** 控制台骨架:左侧玻璃侧栏 + 内容区;导航按身份渲染 —— 管理员含管理项,普通用户仅「我的」分组 */
export function adminPage({ theme, siteName, user, active = '', title, content, cur = '/', actions = '', headTitle = '' }) {
  const link = (href, label, key) =>
    `<a href="${href}"${key === active ? ' class="active"' : ''}>${label}</a>`;
  const adminNav = user.is_admin
    ? `${link('/admin', '控制台', 'dashboard')}
    ${link('/admin/users', '用户', 'users')}
    ${link('/admin/apps', '应用', 'apps')}
    ${link('/admin/groups', '权限组', 'groups')}
    ${link('/admin/audit', '审计日志', 'audit')}
    `
    : '';
  return `${head(theme, title)}
<body>
<div class="topbar">${mark(22)} ${esc(siteName)}</div>
<aside class="side">
  <div class="side-brand">${mark(26)}<b>${esc(siteName)}<br><span class="muted small">${user.is_admin ? '管理控制台' : '个人中心'}</span></b></div>
  <nav>
    ${adminNav}<div class="sep">我的</div>
    ${link('/apps', '应用门户', 'portal')}
    ${link('/account/apps', '我的授权', 'authz')}
    ${link('/account', '账号设置', 'account')}
    <a href="/logout">退出登录</a>
  </nav>
  <div class="side-foot">
    <div class="row"><span>${esc(user.username)}${user.is_admin ? ' · 管理员' : ''}</span><span>${themeToggle(theme, cur)}</span></div>
  </div>
</aside>
<main class="main">
${actions || headTitle ? `<div class="main-head">
  ${headTitle ? `<div class="main-head-title">${headTitle}</div>` : ''}
  ${actions ? `<div class="rowline">${actions}</div>` : ''}
</div>` : ''}
${content}
</main>
</body></html>`;
}

/** 页头标题块 */
export const pageTitle = (t, sub = '') =>
  `<h1>${esc(t)}${sub ? `<span class="muted" style="font-weight:400;font-size:15px;margin-left:12px">${esc(sub)}</span>` : ''}</h1>`;
