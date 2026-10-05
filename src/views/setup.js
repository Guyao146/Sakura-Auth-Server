import { escapeHtml as esc } from '../core/util.js';
import { authPage } from './layout.js';
import { banner, hiddenInputs, stepIndicator } from './components.js';

/** 重跑向导时表单需携带会话 CSRF(首次部署无会话则不下发) */
const csrfField = (csrf) => (csrf ? hiddenInputs({ _csrf: csrf }) : '');

/** 向导外框 */
function shell({ theme, siteName, step, title, content, err, msg }) {
  return authPage({
    theme, siteName, title: `配置向导 · ${siteName}`,
    content: `
      ${stepIndicator(step)}
      ${banner(msg ? esc(msg) : '', 'ok')}
      ${banner(err ? esc(err) : '', 'err')}
      <h3 style="margin-top:0">${esc(title)}</h3>
      ${content}`,
  });
}

/** 第 1 步:环境检测(结果由服务层传入) */
export function setupStep1({ theme, siteName, checks, err }) {
  const rows = checks.map((c) =>
    `<div class="chk"><span class="s ${c.ok ? 'ok' : 'bad'}">${c.ok ? '✓' : '✗'}</span><span>${esc(c.label)}</span></div>`
  ).join('\n');
  const allOk = checks.every((c) => c.ok);
  return shell({
    theme, siteName, step: 1, title: '环境检测',
    err,
    content: `
      <div class="card tight">${rows}</div>
      <form method="post" action="/setup/step1">
        <div class="actions">
          <button class="btn btn-primary" type="submit" ${allOk ? '' : 'disabled'}>下一步:站点设置</button>
          <button class="btn" type="submit" name="rerun" value="1">重新检测</button>
        </div>
      </form>`,
  });
}

/** 第 2 步:站点设置(含自助注册开关与 SMTP 邮件服务) */
export function setupStep2({ theme, siteName, values, err, csrf = '' }) {
  const v = values;
  return shell({
    theme, siteName, step: 2, title: '站点设置', err,
    content: `
      <form method="post" action="/setup/step2">
        ${csrfField(csrf)}
        <label for="site_name">站点名称</label>
        <input type="text" id="site_name" name="site_name" value="${esc(v.site_name)}" required maxlength="40">
        <label for="issuer">对外地址(Issuer)</label>
        <input type="url" id="issuer" name="issuer" value="${esc(v.issuer)}" required
          placeholder="https://sso.example.com">
        <p class="muted small">签发的 token 与 OIDC 发现文档都以该地址为准。走宝塔/Nginx 反代时填对外 https 域名;本机体验可保持默认。</p>
        <h3>令牌有效期(秒)</h3>
        <div class="grid2">
          <div><label for="access_ttl">Access Token</label><input type="number" id="access_ttl" name="access_ttl" value="${esc(v.access_ttl)}" min="60" max="86400"></div>
          <div><label for="refresh_ttl">Refresh Token</label><input type="number" id="refresh_ttl" name="refresh_ttl" value="${esc(v.refresh_ttl)}" min="3600" max="31536000"></div>
        </div>
        <label class="checkline"><input type="checkbox" name="allow_register" value="1"${v.allow_register ? ' checked' : ''}>
          <span>开启自助注册<span class="muted">登录页出现「注册新账号」入口,任何人可自行创建账号;之后也可在管理控制台随时开关</span></span></label>
        <h3>邮件服务(SMTP)</h3>
        <p class="muted small">用于发送找回密码邮件。全部可选:留空即开发模式,邮件内容只输出到日志而不真正发信;若已设置 SMTP_* 环境变量,则以环境变量优先。</p>
        <div class="grid2">
          <div><label for="smtp_host">SMTP 主机</label><input type="text" id="smtp_host" name="smtp_host" value="${esc(v.smtp_host)}" placeholder="如 smtp.example.com"></div>
          <div><label for="smtp_port">端口</label><input type="number" id="smtp_port" name="smtp_port" value="${esc(v.smtp_port)}" min="1" max="65535" placeholder="587"></div>
        </div>
        <div class="grid2">
          <div><label for="smtp_user">用户名</label><input type="text" id="smtp_user" name="smtp_user" value="${esc(v.smtp_user)}" autocomplete="off"></div>
          <div><label for="smtp_pass">密码</label><input type="password" id="smtp_pass" name="smtp_pass" autocomplete="new-password" placeholder="留空保持已保存的密码"></div>
        </div>
        <label for="smtp_from">发件人地址</label>
        <input type="text" id="smtp_from" name="smtp_from" value="${esc(v.smtp_from)}" placeholder="noreply@example.com">
        <div class="actions">
          <button class="btn btn-primary" type="submit">下一步:管理员账号</button>
        </div>
      </form>`,
  });
}

/** 第 3 步:创建管理员(已有账号时提供跳过入口) */
export function setupStep3({ theme, siteName, values, err, hasUsers, csrf = '' }) {
  const v = values;
  return shell({
    theme, siteName, step: 3, title: '管理员账号', err,
    msg: hasUsers ? '检测到已有账号,无需新建管理员,可直接完成配置。' : '',
    content: `
      ${hasUsers ? `
      <form method="post" action="/setup/step3">
        <input type="hidden" name="skip" value="1">
        ${csrfField(csrf)}
        <div class="actions" style="margin-top:0">
          <button class="btn btn-primary" type="submit">跳过创建,直接完成配置</button>
        </div>
      </form>
      <h3>或新建一个管理员账号</h3>` : ''}
      <p class="muted small">该账号将拥有管理控制台的全部权限,请妥善保管密码。</p>
      <form method="post" action="/setup/step3">
        ${csrfField(csrf)}
        <label for="username">管理员用户名</label>
        <input type="text" id="username" name="username" value="${esc(v.username)}" required autofocus
          pattern="[a-zA-Z0-9_.@-]{2,64}" title="2-64 位字母数字与 _.@-">
        <label for="name">显示姓名(可选)</label>
        <input type="text" id="name" name="name" value="${esc(v.name)}" maxlength="40">
        <div class="grid2">
          <div><label for="password">密码(至少 8 位)</label><input type="password" id="password" name="password" required minlength="8" autocomplete="new-password"></div>
          <div><label for="password2">确认密码</label><input type="password" id="password2" name="password2" required minlength="8" autocomplete="new-password"></div>
        </div>
        <div class="actions">
          <button class="btn btn-primary" type="submit">完成配置</button>
        </div>
      </form>`,
  });
}

/** 第 4 步:完成(adminUsername 为空表示跳过创建、沿用已有账号) */
export function setupStep4({ theme, siteName, issuer, adminUsername }) {
  return shell({
    theme, siteName, step: 4, title: '配置完成',
    content: `
      <p>站点已就绪。以下信息将用于所有签发的令牌:</p>
      <div class="kv"><b>Issuer</b><span>${esc(issuer)}</span></div>
      <div class="kv"><b>管理员</b><span>${esc(adminUsername || '已有账号(未新建)')}</span></div>
      <div class="kv"><b>发现文档</b><span>${esc(issuer + '/.well-known/openid-configuration')}</span></div>
      <div class="actions">
        <a class="btn btn-primary" href="/admin">进入管理控制台</a>
        <a class="btn" href="/">查看首页</a>
      </div>
      <p class="muted small">下一步建议:在「应用」中创建你的第一个 OAuth2 客户端,拿到的 client_id / client_secret 配置到业务系统。</p>`,
  });
}
