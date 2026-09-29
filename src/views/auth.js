import { escapeHtml as esc } from '../core/util.js';
import { authPage } from './layout.js';
import { banner, hiddenInputs, scopeList, scopeItems } from './components.js';

/** 登录页 */
export function loginPage({ theme, siteName, csrf, next, err, username = '', allowRegister = false }) {
  return authPage({
    theme, siteName, title: `登录 · ${siteName}`,
    content: `
      ${banner(err ? esc(err) : '', 'err')}
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
      <p class="muted small" style="margin:var(--s3) 0 0"><a href="/forgot-password">忘记密码?</a></p>
      ${allowRegister ? `<p class="muted small" style="text-align:center;margin:var(--s4) 0 0">还没有账号?<a href="/register">注册新账号</a></p>` : ''}`,
  });
}

/** 注册页(自助注册开启时可用) */
export function registerPage({ theme, siteName, csrf, err, values = {} }) {
  const v = values;
  return authPage({
    theme, siteName, title: `注册新账号 · ${siteName}`,
    content: `
      ${banner(err ? esc(err) : '', 'err')}
      <form method="post" action="/register">
        ${hiddenInputs({ _csrf: csrf })}
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

/** 同意授权页 */
export function consentPage({ theme, siteName, user, client, scopeList: scopes, csrf, replay, remember }) {
  const items = scopeItems(scopes);
  return authPage({
    theme, siteName, title: `授权 · ${siteName}`,
    content: `
      <h3 style="margin-top:0;margin-bottom:4px">${esc(client.name)} 请求访问你的账号</h3>
      <p class="muted">以 <b style="color:var(--text)">${esc(user.username)}</b> 的身份登录该应用</p>
      <div class="card tight">
        ${scopeList(items)}
      </div>
      <form method="post" action="/authorize">
        ${hiddenInputs({ ...replay, _csrf: csrf, decision: 'approve' })}
        ${remember ? `<label class="checkline"><input type="checkbox" name="remember" value="on" checked><span>记住此应用的授权,下次不再询问<span class="muted">可在管理员撤销后重新确认</span></span></label>` : ''}
        <div class="actions">
          <button class="btn btn-primary" type="submit" name="decision" value="approve">同 意</button>
          <button class="btn btn-danger" type="submit" name="decision" value="deny">拒 绝</button>
        </div>
      </form>`,
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
 * 账号设置页(密码 + 两步验证管理)。
 * twoFa: { enabled, pendingSecret, otpauth, secret, recoveryCodes }
 */
export function accountPage({ theme, siteName, user, csrf, msg, err, twoFa }) {
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
  return authPage({
    theme, siteName, title: `账号设置 · ${siteName}`,
    content: `
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <h3 style="margin-top:0">账号信息</h3>
      <div class="kv"><b>用户名</b><span>${esc(user.username)}</span></div>
      <div class="kv"><b>姓名</b><span>${esc(user.name || '-')}</span></div>
      <div class="kv"><b>邮箱</b><span>${esc(user.email || '-')}</span></div>
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
      ${twofaBlock}`,
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
