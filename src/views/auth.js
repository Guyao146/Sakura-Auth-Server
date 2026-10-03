import { escapeHtml as esc, fmtTime } from '../core/util.js';
import { authPage, adminPage, brandPage } from './layout.js';
import { banner, badge, hiddenInputs, kvRow, scopeItems, scopeIcon, SCOPE_NAMES } from './components.js';
import { getRuntime } from '../core/runtime.js';

/* 登录页品牌面板的特性条目:线性小图标随 currentColor,零外部资源 */
const featIcon = (paths) =>
  `<svg viewBox="0 0 16 16" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
const LOGIN_FEATURES = [
  {
    icon: featIcon('<path d="M6.6 2.6h5.2c.7 0 1.2.5 1.2 1.2v8.4c0 .7-.5 1.2-1.2 1.2H6.6"/><path d="M2 8h7.2M6.8 5.6 9.2 8l-2.4 2.4"/>'),
    title: '统一登录', desc: '一套账号通行所有接入的业务系统',
  },
  {
    icon: featIcon('<path d="M8 1.9 13.3 3.7v3.5c0 3.3-2.2 5.8-5.3 6.9-3.1-1.1-5.3-3.6-5.3-6.9V3.7z"/><path d="M5.8 7.9l1.6 1.6 2.9-3.1"/>'),
    title: '两步验证', desc: '验证器动态码为密码再加一道锁',
  },
  {
    icon: featIcon('<circle cx="5.6" cy="5.8" r="2.4"/><circle cx="11.3" cy="6.5" r="1.9"/><path d="M2.2 13.4c.5-2.4 2.3-3.6 4.4-3.6M9.3 13.4c.3-1.8 1.7-2.8 3.3-2.8"/>'),
    title: '权限组管控', desc: '按权限组精细分配应用访问范围',
  },
];

/** 微软四色方块标(16px,品牌固定色) */
const MS_LOGO = `<svg width="16" height="16" viewBox="0 0 23 23" aria-hidden="true" style="flex:none"><rect width="11" height="11" fill="#f25022"/><rect x="12" width="11" height="11" fill="#7fba00"/><rect y="12" width="11" height="11" fill="#00a4ef"/><rect x="12" y="12" width="11" height="11" fill="#ffb900"/></svg>`;

/** 登录页(品牌化分栏:左侧品牌渐变面板 + 右侧登录表单;窄屏仅表单)。
 *  msEnabled 缺省时回退读运行时配置(启用后表单下方出现 Microsoft 登录入口)。 */
export function loginPage({ theme, siteName, csrf, next, err, username = '', allowRegister = false, msg = '', msEnabled }) {
  const rt = getRuntime();
  const showMs = msEnabled !== undefined ? !!msEnabled : !!(rt && rt.msOAuth && rt.msOAuth.enabled);
  return brandPage({
    theme, siteName, title: `登录 · ${siteName}`,
    tagline: '这一站,管好你所有系统的登录。',
    features: LOGIN_FEATURES,
    content: `
      ${banner(err ? esc(err) : '', 'err')}
      ${banner(msg ? esc(msg) : '', 'ok')}
      <h2 class="login-form-title">欢迎回来</h2>
      <p class="login-form-sub muted small">登录 ${esc(siteName)} 账号,继续访问你的应用。</p>
      <form method="post" action="/login">
        ${hiddenInputs({ _csrf: csrf, next: next || '' })}
        <label for="username">用户名</label>
        <input type="text" id="username" name="username" value="${esc(username)}" required autofocus autocomplete="username">
        <label for="password">密码</label>
        <input type="password" id="password" name="password" required autocomplete="current-password">
        <div class="actions">
          <button class="btn btn-primary" type="submit">登 录</button>
        </div>
      </form>
      ${showMs ? `
      <div style="display:flex;align-items:center;gap:var(--s3);margin:var(--s4) 0 0">
        <span style="flex:1;border-top:1px solid var(--border)"></span>
        <span class="muted small">或</span>
        <span style="flex:1;border-top:1px solid var(--border)"></span>
      </div>
      <div class="actions" style="margin-top:var(--s3)">
        <a class="btn" href="/auth/microsoft" style="flex:1;justify-content:center;padding:var(--s3) var(--s4);font-size:15px">${MS_LOGO}使用 Microsoft 账号登录</a>
      </div>` : ''}
      <p class="muted small" style="margin:var(--s3) 0 0"><a href="/forgot-password">忘记密码?</a></p>
      ${allowRegister ? `<p class="muted small" style="text-align:center;margin:var(--s4) 0 0">还没有账号?<a href="/register${next ? `?next=${encodeURIComponent(next)}` : ''}">注册新账号</a></p>` : ''}`,
  });
}

/** 注册页(自助注册开启时可用);next 为续流目标(如 /authorize 授权链路),经隐藏字段回传 */
export function registerPage({ theme, siteName, csrf, err, values = {}, next = '' }) {
  const v = values;
  return authPage({
    theme, siteName, title: `注册新账号 · ${siteName}`,
    content: `
      ${banner(err ? esc(err) : '', 'err')}
      <form method="post" action="/register">
        ${hiddenInputs({ _csrf: csrf, next: next || '' })}
        <label for="username">用户名</label>
        <input type="text" id="username" name="username" value="${esc(v.username || '')}" required autofocus
          autocomplete="username" pattern="[a-zA-Z0-9_.@-]{2,64}" title="2-64 位字母数字与 _.@-">
        <label for="password">密码(至少 8 位)</label>
        <input type="password" id="password" name="password" required minlength="8" autocomplete="new-password">
        <label for="password2">确认密码</label>
        <input type="password" id="password2" name="password2" required minlength="8" autocomplete="new-password">
        <label for="name">显示姓名(可选)</label>
        <input type="text" id="name" name="name" value="${esc(v.name || '')}" maxlength="40" autocomplete="name">
        <label for="email">邮箱(可选)</label>
        <input type="email" id="email" name="email" value="${esc(v.email || '')}" autocomplete="email">
        <div class="actions">
          <button class="btn btn-primary" type="submit">注 册</button>
          <a class="btn" href="/login">返回登录</a>
        </div>
      </form>`,
  });
}

/** 二步验证页(第二因子) */
export function twofaPage({ theme, siteName, csrf, pending, next, username, err }) {  return authPage({
    theme, siteName, title: `两步验证 · ${siteName}`,
    content: `
      ${banner(err ? esc(err) : '', 'err')}
      <h3 style="margin-top:0">两步验证</h3>
      <p class="muted small">账号 <b style="color:var(--text)">${esc(username)}</b> 已开启两步验证。请输入验证器 App 中的 6 位验证码;没有 App 时可填写恢复代码。</p>
      <form method="post" action="/login/2fa">
        ${hiddenInputs({ _csrf: csrf, pending, next: next || '' })}
        <label for="code">验证码 / 恢复代码</label>
        <input type="text" id="code" name="code" required autofocus autocomplete="one-time-code"
          placeholder="123456 或 abcd-1234" inputmode="numeric">
        <div class="actions">
          <button class="btn btn-primary" type="submit">验 证</button>
          <a class="btn" href="/login">返回重新登录</a>
        </div>
      </form>`,
  });
}

/** 找回密码页(输入邮箱;无论邮箱是否存在,提交后的提示都一致,防枚举) */
export function forgotPasswordPage({ theme, siteName, csrf, err, msg, email = '' }) {
  return authPage({
    theme, siteName, title: `找回密码 · ${siteName}`,
    content: `
      ${banner(err ? esc(err) : '', 'err')}
      ${banner(msg ? esc(msg) : '', 'ok')}
      <h3 style="margin-top:0">找回密码</h3>
      <p class="muted small">输入账号绑定的邮箱地址,我们会发送一封包含重置链接的邮件,链接 30 分钟内有效。</p>
      <form method="post" action="/forgot-password">
        ${hiddenInputs({ _csrf: csrf })}
        <label for="email">邮箱地址</label>
        <input type="email" id="email" name="email" value="${esc(email)}" required autofocus autocomplete="email" placeholder="you@example.com">
        <div class="actions">
          <button class="btn btn-primary" type="submit">发送重置邮件</button>
          <a class="btn" href="/login">返回登录</a>
        </div>
      </form>`,
  });
}

/** 设置新密码页(GET /reset-password?token=...,token 走 hidden 回传) */
export function resetPasswordPage({ theme, siteName, csrf, token, err }) {
  return authPage({
    theme, siteName, title: `设置新密码 · ${siteName}`,
    content: `
      ${banner(err ? esc(err) : '', 'err')}
      <h3 style="margin-top:0">设置新密码</h3>
      <p class="muted small">请设置至少 8 位的新密码。重置成功后,该账号所有已登录的会话都会被退出。</p>
      <form method="post" action="/reset-password">
        ${hiddenInputs({ _csrf: csrf, token })}
        <label for="password">新密码(至少 8 位)</label>
        <input type="password" id="password" name="password" required minlength="8" autofocus autocomplete="new-password">
        <label for="password2">确认新密码</label>
        <input type="password" id="password2" name="password2" required minlength="8" autocomplete="new-password">
        <div class="actions">
          <button class="btn btn-primary" type="submit">重置密码</button>
        </div>
      </form>`,
  });
}

/** 密码重置成功页(提示用新密码重新登录) */
export function resetDonePage({ theme, siteName }) {
  return authPage({
    theme, siteName, title: `密码已重置 · ${siteName}`, footer: false,
    content: `
      <h3 style="margin-top:0">密码已重置</h3>
      <p class="small">你的密码已更新,所有已登录的会话均已退出。请使用新密码重新登录。</p>
      <div class="actions"><a class="btn btn-primary" href="/login">前往登录</a></div>`,
  });
}

/** 同意授权页(品牌化分栏,与登录页同一骨架):应用徽标 + 身份标识 + 图标化权限清单 + 跳转目标提示 */
export function consentPage({ theme, siteName, user, client, scopeList: scopes, csrf, replay, remember }) {
  const items = scopeItems(scopes);
  let target = String(replay.redirect_uri || '');
  try { target = new URL(replay.redirect_uri).host || target; } catch { /* 自定义 scheme 原样展示 */ }
  const appInitial = (String(client.name || '?').trim()[0] || '?').toUpperCase();
  const userInitial = (String(user.name || user.username).trim()[0] || '?').toUpperCase();
  const appLogo = client.logoUrl
    ? `<img src="${esc(client.logoUrl)}" alt="" loading="lazy" class="consent-logo">`
    : `<div class="app-badge">${esc(appInitial)}</div>`;
  // 主题切换后回到同一授权页:由 replay 还原 /authorize 查询串(空值剔除,防止缺参报错)
  const backParams = new URLSearchParams();
  for (const [k, v] of Object.entries(replay)) if (v) backParams.set(k, String(v));
  const back = '/authorize' + (backParams.toString() ? `?${backParams}` : '');
  return brandPage({
    theme, siteName, title: `授权 · ${siteName}`,
    tagline: '确认授权,一键进入应用。',
    features: LOGIN_FEATURES,
    wide: true, cur: back,
    content: `
      <div class="app-row">
        ${appLogo}
        <div style="min-width:0">
          <div style="font-size:17px;font-weight:650;color:var(--heading);line-height:1.3">${esc(client.name)}</div>
          ${client.description ? `<div class="muted small" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(client.description)}</div>` : ''}
          <div class="muted small" style="word-break:break-all">${esc(client.client_id)}</div>
        </div>
      </div>
      <h2 class="login-form-title">请求访问你的账号</h2>
      <p class="login-form-sub muted small" style="margin-bottom:var(--s4)">验证你的身份后,${esc(siteName)} 才会向应用披露下面所请求的信息。</p>
      <div class="identity">
        <span class="avatar">${esc(userInitial)}</span>
        <span>以 <b style="color:var(--text)">${esc(user.name || user.username)}</b>(<span>${esc(user.username)}</span>)的身份继续</span>
      </div>
      <div class="card tight" style="margin-bottom:var(--s4)">
        ${items.map((it) => `<div class="scope-item">
          <span class="scope-ico">${scopeIcon(it.id)}</span>
          <span style="min-width:0"><b>${esc(SCOPE_NAMES[it.id] || it.id)}</b><span class="desc">${esc(it.desc)}</span></span>
        </div>`).join('\n')}
      </div>
      <form method="post" action="/authorize">
        ${hiddenInputs({ ...replay, _csrf: csrf, decision: 'approve' })}
        ${remember ? `<label class="checkline"><input type="checkbox" name="remember" value="on" checked><span>记住此应用的授权,下次不再询问<span class="muted">可在管理员撤销后重新确认</span></span></label>` : ''}
        <p class="muted small" style="margin:var(--s2) 0 0">同意后将跳转至 <code>${esc(target)}</code> 完成登录;拒绝则不产生任何授权。</p>
        <div class="consent-actions">
          <button class="btn btn-ghost" type="submit" name="decision" value="deny">拒 绝</button>
          <button class="btn btn-primary" type="submit" name="decision" value="approve">同意并继续</button>
        </div>
      </form>`,
  });
}

/** 无权访问该应用(403 风格:应用按权限组限制访问,用户不在所需组内) */
export function accessDeniedPage({ theme, siteName, clientName, requiredGroups = [] }) {
  return authPage({
    theme, siteName, title: `无权访问 · ${siteName}`, footer: false,
    content: `
      <h3 style="margin-top:0">无权访问该应用</h3>
      <p class="small">应用 <b style="color:var(--text)">${esc(clientName)}</b> 仅对特定权限组的成员开放,你的账号不在所需组内。</p>
      <div class="card tight">
        ${kvRow('应用', esc(clientName))}
        ${kvRow('所需权限组', requiredGroups.map(esc).join('、') || '-')}
      </div>
      <p class="muted small">如需访问,请联系管理员将你加入相应权限组。</p>
      <div class="actions"><a class="btn btn-primary" href="/">返回首页</a></div>`,
  });
}

/** 退出确认页(GET /logout) */
export function logoutPage({ theme, siteName, csrf }) {
  return authPage({
    theme, siteName, title: `退出登录 · ${siteName}`, footer: false,
    content: `
      <h3 style="margin-top:0">确认退出登录?</h3>
      <p class="muted small">退出后,需要重新输入用户名和密码才能再次登录。</p>
      <form method="post" action="/logout">
        ${hiddenInputs({ _csrf: csrf })}
        <div class="actions">
          <button class="btn btn-primary" type="submit">确认退出</button>
          <a class="btn" href="/">取消</a>
        </div>
      </form>`,
  });
}

/**
 * Microsoft 关联本地账号页:MS 身份验证成功但未绑定任何本站账号。
 * 表单 A:已有账号绑定(用户名/密码);表单 B(自助注册开启时):注册新号并绑定。
 * 两个表单都携带一次性 linkToken(隐藏字段 state)与 cookie 双提交 CSRF。
 */
export function msLinkPage({ theme, siteName, csrf, linkToken, msEmail, allowRegister = false, err, values = {} }) {
  const v = values;
  return authPage({
    theme, siteName, title: `关联本地账号 · ${siteName}`,
    content: `
      ${banner(err ? esc(err) : '', 'err')}
      <h3 style="margin-top:0">关联本地账号</h3>
      <p class="muted small">Microsoft 身份验证成功:<b style="color:var(--text)">${esc(msEmail || '未知账号')}</b>。这个 Microsoft 账号还没有绑定本站账号,请选择一种方式继续。</p>
      <form method="post" action="/auth/microsoft/link">
        ${hiddenInputs({ state: linkToken, _csrf: csrf })}
        <label>已有账号:用户名</label>
        <input type="text" name="username" value="${esc(v.username || '')}" required autofocus autocomplete="username">
        <label>密码</label>
        <input type="password" name="password" required autocomplete="current-password">
        <div class="actions"><button class="btn btn-primary" type="submit">绑定并登录</button></div>
      </form>
      ${allowRegister ? `
      <hr>
      <h3>注册新账号</h3>
      <p class="muted small">还没有本站账号?直接用当前 Microsoft 身份注册一个并自动绑定。</p>
      <form method="post" action="/auth/microsoft/register">
        ${hiddenInputs({ state: linkToken, _csrf: csrf })}
        <label>用户名</label>
        <input type="text" name="username" value="${esc(v.username || '')}" required autocomplete="username"
          pattern="[a-zA-Z0-9_.@-]{2,64}" title="2-64 位字母数字与 _.@-">
        <label>密码(至少 8 位)</label>
        <input type="password" name="password" required minlength="8" autocomplete="new-password">
        <label>确认密码</label>
        <input type="password" name="password2" required minlength="8" autocomplete="new-password">
        <label>显示姓名(可选)</label>
        <input type="text" name="name" value="${esc(v.name || '')}" maxlength="40" autocomplete="name">
        <div class="actions"><button class="btn btn-primary" type="submit">注册并绑定</button></div>
      </form>` : ''}`,
  });
}

/**
 * 账号设置页(密码 + 两步验证管理),并入控制台侧栏布局。
 * twoFa: { enabled, pendingSecret, otpauth, secret, recoveryCodes }
 */
export function accountPage({ theme, siteName, user, csrf, msg, err, twoFa, cur = '/' }) {
  let twofaBlock;
  if (twoFa.recoveryCodes) {
    twofaBlock = `
      <h3>两步验证已开启</h3>
      <div class="banner warn">请立即保存恢复代码,每个只能使用一次,且不会再显示:</div>
      <pre class="block">${twoFa.recoveryCodes.join('\n')}</pre>
      <form method="post" action="/account/2fa/disable">
        ${hiddenInputs({ _csrf: csrf })}
        <label>关闭两步验证(需输入当前密码)</label>
        <input type="password" name="password" required autocomplete="current-password">
        <div class="actions"><button class="btn btn-danger" type="submit">关闭两步验证</button></div>
      </form>`;
  } else if (twoFa.enabled) {
    twofaBlock = `
      <h3>两步验证</h3>
      <p class="small">${banner('两步验证已开启。登录时需要输入验证器 App 的 6 位验证码。', 'ok')}</p>
      <p class="muted small">剩余可用恢复代码:${twoFa.recoveryLeft} 枚。</p>
      <form method="post" action="/account/2fa/disable">
        ${hiddenInputs({ _csrf: csrf })}
        <label>关闭两步验证(需输入当前密码)</label>
        <input type="password" name="password" required autocomplete="current-password">
        <div class="actions"><button class="btn btn-danger" type="submit">关闭两步验证</button></div>
      </form>`;
  } else if (twoFa.pendingSecret) {
    const scanStep = twoFa.qr
      ? `<p class="small" style="margin-bottom:var(--s2)">1. 用验证器 App(Google Authenticator、1Password 等)扫描下方二维码:</p>
      <div style="margin:0 0 var(--s3)">${twoFa.qr}</div>
      <p class="small" style="margin-bottom:var(--s1)">2. 无法扫码时手动添加以下密钥:</p>`
      : `<p class="small" style="margin-bottom:var(--s1)">1. 在验证器 App(Google Authenticator、1Password 等)中手动添加以下密钥:</p>`;
    twofaBlock = `
      <h3>开启两步验证</h3>
      ${scanStep}
      <div class="kv"><b>密钥</b><span>${esc(twoFa.pendingSecret)}</span></div>
      <p class="muted small" style="word-break:break-all">${twoFa.qr ? 3 : 2}. 或复制此地址到 App: <code>${esc(twoFa.otpauth)}</code></p>
      <form method="post" action="/account/2fa/confirm">
        ${hiddenInputs({ _csrf: csrf })}
        <label>输入 App 显示的 6 位验证码完成开启</label>
        <input type="text" name="code" required inputmode="numeric" autocomplete="one-time-code" placeholder="123456">
        <div class="actions">
          <button class="btn btn-primary" type="submit">确认开启</button>
        </div>
      </form>`;
  } else {
    twofaBlock = `
      <h3>两步验证</h3>
      <p class="muted small">开启后,登录除了密码还需验证器 App 的动态码,可大幅降低密码泄露的影响。</p>
      <form method="post" action="/account/2fa/start">
        ${hiddenInputs({ _csrf: csrf })}
        <label>输入当前密码开始设置</label>
        <input type="password" name="password" required autocomplete="current-password">
        <div class="actions"><button class="btn btn-primary" type="submit">开始设置两步验证</button></div>
      </form>`;
  }
  // Microsoft 账号绑定区块:绑定状态直接读 users 行的 ms_sub / ms_email 列
  const msBound = !!user.ms_sub;
  const msBlock = `
    <hr>
    <h3>Microsoft 账号</h3>
    ${msBound
      ? `<div class="kv"><b>绑定邮箱</b><span>${esc(user.ms_email || '-')}</span></div>
      <form method="post" action="/auth/microsoft/unbind">
        ${hiddenInputs({ _csrf: csrf })}
        <p class="muted small">解绑后将无法继续使用该 Microsoft 账号登录本站。</p>
        <div class="actions"><button class="btn btn-danger" type="submit">解绑 Microsoft 账号</button></div>
      </form>`
      : `<p class="muted small">绑定后,可以使用 Microsoft 账号一键登录,无需再输入本站密码。</p>
      <div class="actions"><a class="btn" href="/auth/microsoft?bind=1">绑定 Microsoft 账号</a></div>`}`;
  return adminPage({
    theme, siteName, user, active: 'account', cur,
    title: `账号设置 · ${siteName}`,
    content: `
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <h3 style="margin-top:0">账号信息</h3>
      <div class="kv"><b>用户名</b><span>${esc(user.username)}</span></div>
      <div class="kv"><b>姓名</b><span>${esc(user.name || '-')}</span></div>
      <div class="kv"><b>邮箱</b><span>${esc(user.email || '-')}</span></div>
      <div class="kv"><b>我的授权</b><span><a href="/account/apps">查看与管理已授权的应用 →</a></span></div>
      <div class="kv"><b>登录会话</b><span><a href="/account/sessions">查看与管理已登录的设备 →</a></span></div>
      <h3>修改密码</h3>
      <form method="post" action="/account">
        ${hiddenInputs({ _csrf: csrf })}
        <label>当前密码</label>
        <input type="password" name="current" required autocomplete="current-password">
        <label>新密码(至少 8 位)</label>
        <input type="password" name="password" required minlength="8" autocomplete="new-password">
        <label>确认新密码</label>
        <input type="password" name="password2" required minlength="8" autocomplete="new-password">
        <div class="actions"><button class="btn btn-primary" type="submit">保存修改</button></div>
      </form>
      <hr>
      ${twofaBlock}
      ${msBlock}`,
  });
}

/** 开启 2FA 后的恢复代码展示页(独立一次) */
export function recoveryCodesPage({ theme, siteName, user, codes }) {
  return authPage({
    theme, siteName, title: `恢复代码 · ${siteName}`, footer: false,
    content: `
      <h3 style="margin-top:0">两步验证已开启</h3>
      <div class="banner warn">恢复代码在无法使用验证器 App 时替代验证码登录,每个只能用一次。请立即保存,关闭本页后不再显示。</div>
      <pre class="block">${codes.join('\n')}</pre>
      <div class="actions"><a class="btn btn-primary" href="/account">返回账号设置</a></div>`,
  });
}

/** 我的授权页:查看/撤销已记住的应用授权(并入控制台侧栏布局) */
export function authorizationsPage({ theme, siteName, user, csrf, list, msg, err, cur = '/' }) {
  const fmt = (sec) => new Date(sec * 1000).toLocaleString('zh-CN', { hour12: false });
  const rows = list.map((row) => {
    const initial = (String(row.name || '?').trim()[0] || '?').toUpperCase();
    return `<div class="app-item">
      <div class="app-badge">${esc(initial)}</div>
      <div style="min-width:0;flex:1">
        <div style="display:flex;gap:var(--s2);align-items:center;flex-wrap:wrap">
          <b style="color:var(--text);font-size:15px">${esc(row.name)}</b>
          ${row.scopeItems.map((s) => `<span class="badge">${esc(SCOPE_NAMES[s.id] || s.id)}</span>`).join(' ')}
        </div>
        <div class="muted small" style="word-break:break-all"><code>${esc(row.client_id)}</code> · 授权于 ${fmt(row.granted_at)}</div>
      </div>
      <form method="post" action="/account/apps/revoke" style="margin:0">
        ${hiddenInputs({ _csrf: csrf, client_id: row.client_id })}
        <button class="btn btn-danger btn-sm" type="submit">撤销授权</button>
      </form>
    </div>`;
  }).join('\n');
  return adminPage({
    theme, siteName, user, active: 'authz', cur,
    title: `我的授权 · ${siteName}`,
    content: `
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <h3 style="margin-top:0">我的授权</h3>
      <p class="muted small" style="margin-top:0">这里列出你确认过「记住授权」的应用。撤销后,该应用的记住授权立即删除,其现有访问令牌一并失效;下次访问时需要重新确认。</p>
      ${list.length
        ? `<div class="card tight">${rows}</div>`
        : '<div class="card tight"><p class="muted" style="margin:0">还没有授权过任何应用。登录业务系统并同意授权后,会出现在这里。</p></div>'}`,
  });
}

/** 登录会话页:查看/撤销已登录设备(并入控制台侧栏布局,挂在账号设置入口下)。
 *  list 会话行含 is_current 标记;UA 超 40 字截断,完整值放 title 悬停可见。 */
export function sessionsPage({ theme, siteName, user, csrf, list, msg, err, cur = '/' }) {
  const clip = (s) => {
    const v = String(s || '');
    return v.length > 40 ? `${v.slice(0, 40)}…` : v;
  };
  const rows = list.map((row) => `<tr>
      <td class="wrap"><code>${esc(row.id_hash.slice(0, 8))}</code>${row.is_current ? ` ${badge('当前')}` : ''}</td>
      <td>${fmtTime(row.created_at)}</td>
      <td>${fmtTime(row.expires_at)}</td>
      <td class="wrap">${esc(row.ip || '-')}</td>
      <td class="wrap"${row.user_agent ? ` title="${esc(row.user_agent)}"` : ''}>${esc(clip(row.user_agent) || '-')}</td>
      <td><form method="post" action="/account/sessions/revoke" style="margin:0">
        ${hiddenInputs({ _csrf: csrf, id_hash: row.id_hash })}
        <button class="btn btn-danger btn-sm" type="submit">撤销</button>
      </form></td>
    </tr>`).join('\n');
  return adminPage({
    theme, siteName, user, active: 'account', cur,
    title: `登录会话 · ${siteName}`,
    content: `
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <h3 style="margin-top:0">登录会话</h3>
      <p class="muted small" style="margin-top:0">这里列出你当前所有已登录的设备。撤销后,对应设备下次访问需要重新登录;带「当前」徽章的是你正在使用的这个会话,撤销它等同于退出登录。</p>
      <div class="tblwrap"><table class="tbl">
        <thead><tr><th>会话</th><th>创建时间</th><th>过期时间</th><th>IP</th><th>User-Agent</th><th>操作</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
      <form method="post" action="/account/sessions/revoke-others">
        ${hiddenInputs({ _csrf: csrf })}
        <div class="actions"><button class="btn btn-danger" type="submit">撤销其它全部会话</button></div>
      </form>`,
  });
}
