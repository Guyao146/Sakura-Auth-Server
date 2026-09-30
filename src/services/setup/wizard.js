import fs from 'node:fs';
import * as users from '../../models/users.js';
import * as settingsApi from '../../models/settings.js';
import { getDb } from '../../core/db.js';
import { config } from '../../core/config.js';
import { getRuntime, updateRuntime } from '../../core/runtime.js';
import { getSigningKey } from '../../core/keys.js';
import { hashPassword } from '../../core/password.js';
import { sendHtml, redirect } from '../../core/http.js';
import { httpUrl, USERNAME_RE } from '../../core/util.js';
import { logger } from '../../core/logger.js';
import { setupStep1, setupStep2, setupStep3, setupStep4 } from '../../views/setup.js';

const MAJOR = Number(process.versions.node.split('.')[0]);

function runChecks() {
  let dirOk = false;
  try { fs.accessSync(config.dataDir, fs.constants.W_OK); dirOk = true; } catch { dirOk = false; }
  return [
    { label: `Node.js 版本 ≥ 22.5(当前 ${process.versions.node})`, ok: MAJOR >= 22 && Number(process.versions.node.split('.')[1] + '.' + process.versions.node.split('.')[2]) >= 5 || MAJOR > 22 },
    { label: `数据目录可写:${config.dataDir}`, ok: dirOk },
    { label: 'SQLite 数据库连接正常', ok: !!getDb() },
    { label: 'RSA-2048 令牌签名密钥已生成', ok: !!getSigningKey() },
  ];
}

const isSetupPath = (p) => p === '/setup' || p.startsWith('/setup/');

/** 部署守卫:未完成向导时,除向导与健康检查外全部重定向 */
export function setupGate(pathname) {
  const rt = getRuntime();
  if (!rt.setupDone && !isSetupPath(pathname) && pathname !== '/healthz' && !pathname.startsWith('/-/theme/')) {
    return '/setup';
  }
  if (rt.setupDone && isSetupPath(pathname)) return '/';
  return null;
}

/** GET /setup —— 按进度渲染当前步骤 */
export function showSetup(ctx, { err, values } = {}) {
  const rt = getRuntime();
  if (rt.setupDone) return redirect(ctx.res, '/');
  const step = rt.setupStep;
  if (step <= 1) {
    sendHtml(ctx.res, 200, setupStep1({ theme: ctx.theme, siteName: rt.siteName, checks: runChecks(), err }));
  } else if (step === 2) {
    const smtp = rt.smtp || {};
    sendHtml(ctx.res, 200, setupStep2({
      theme: ctx.theme, siteName: rt.siteName, err,
      values: {
        site_name: values?.site_name ?? rt.siteName,
        issuer: values?.issuer ?? rt.issuer,
        access_ttl: values?.access_ttl ?? rt.accessTokenTtl,
        refresh_ttl: values?.refresh_ttl ?? rt.refreshTokenTtl,
        allow_register: values?.allow_register ?? (rt.allowRegister ? '1' : ''),
        smtp_host: values?.smtp_host ?? (smtp.host || ''),
        smtp_port: values?.smtp_port ?? (smtp.port || '587'),
        smtp_user: values?.smtp_user ?? (smtp.user || ''),
        smtp_from: values?.smtp_from ?? (smtp.from || ''),
      },
    }));
  } else {
    sendHtml(ctx.res, 200, setupStep3({
      theme: ctx.theme, siteName: rt.siteName, err,
      hasUsers: users.count() > 0,
      values: { username: values?.username ?? '', name: values?.name ?? '' },
    }));
  }
}

/** POST /setup/step1 —— 检测通过进入第二步 */
export function step1(ctx) {
  if (getRuntime().setupDone) return redirect(ctx.res, '/');
  if (!ctx.body?.rerun && runChecks().every((c) => c.ok)) {
    updateRuntime({ setup_step: 2 }, settingsApi.setSetting);
  }
  redirect(ctx.res, '/setup');
}

/** POST /setup/step2 —— 站点设置(含自助注册开关与 SMTP 邮件服务) */
export function step2(ctx) {
  const b = ctx.body || {};
  const issuer = httpUrl(b.issuer || '');
  const accessTtl = Number(b.access_ttl), refreshTtl = Number(b.refresh_ttl);
  const smtpHost = String(b.smtp_host || '').trim();
  const smtpPortRaw = String(b.smtp_port ?? '').trim();
  const smtpFrom = String(b.smtp_from || '').trim();
  // 出错回显时显式归一化 checkbox,未勾选(缺省)不得回填为已勾选
  const values = () => ({ ...b, allow_register: b.allow_register === '1' ? '1' : '' });
  if (!String(b.site_name || '').trim()) return showSetup(ctx, { err: '站点名称不能为空。', values: values() });
  if (!issuer) return showSetup(ctx, { err: 'Issuer 必须是合法的 http(s) 地址。', values: values() });
  if (!(accessTtl >= 60 && accessTtl <= 86400) || !(refreshTtl >= 3600 && refreshTtl <= 31536000)) {
    return showSetup(ctx, { err: '令牌有效期超出允许范围。', values: values() });
  }
  if (smtpPortRaw && (!/^\d{1,5}$/.test(smtpPortRaw) || Number(smtpPortRaw) < 1 || Number(smtpPortRaw) > 65535)) {
    return showSetup(ctx, { err: 'SMTP 端口需为 1-65535 的数字。', values: values() });
  }
  if (smtpFrom && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(smtpFrom)) {
    return showSetup(ctx, { err: '发件人地址格式不正确。', values: values() });
  }
  // SMTP 全部留空 = 开发模式;填了主机才保存,密码留空保持已保存值(回显也不回传密码)
  const smtpFields = smtpHost
    ? {
        smtp_host: smtpHost,
        smtp_port: smtpPortRaw || '587',
        smtp_user: String(b.smtp_user || '').trim(),
        smtp_pass: typeof b.smtp_pass === 'string' && b.smtp_pass ? b.smtp_pass : (settingsApi.getSetting('smtp_pass') || ''),
        smtp_from: smtpFrom,
      }
    : { smtp_host: '', smtp_port: '', smtp_user: '', smtp_pass: '', smtp_from: '' };
  updateRuntime({
    site_name: String(b.site_name).trim(), issuer,
    access_ttl: accessTtl, refresh_ttl: refreshTtl,
    allow_register: b.allow_register === '1' ? '1' : '0',
    ...smtpFields,
    setup_step: 3,
  }, settingsApi.setSetting);
  logger.info('向导:站点设置完成', {
    issuer,
    allow_register: b.allow_register === '1',
    smtp_mode: smtpHost ? 'smtp' : 'dev',
  });
  redirect(ctx.res, '/setup');
}

/** POST /setup/step3 —— 创建管理员并完成安装(库中已有账号时可跳过创建) */
export function step3(ctx) {
  const b = ctx.body || {};
  if (String(b.skip || '') === '1' && users.count() > 0) {
    updateRuntime({ setup_done: 1 }, settingsApi.setSetting);
    logger.info('向导:检测到已有账号,跳过创建直接完成');
    const rt = getRuntime();
    return sendHtml(ctx.res, 200, setupStep4({
      theme: ctx.theme, siteName: rt.siteName, issuer: rt.issuer, adminUsername: null,
    }));
  }
  const username = String(b.username || '').trim();
  const values = { username, name: String(b.name || '') };
  if (!USERNAME_RE.test(username)) return showSetup(ctx, { err: '用户名需为 2-64 位字母数字与 _.@-。', values });
  if (typeof b.password !== 'string' || b.password.length < 8) return showSetup(ctx, { err: '管理员密码至少 8 位。', values });
  if (b.password !== b.password2) return showSetup(ctx, { err: '两次输入的密码不一致。', values });
  if (users.byUsername(username)) return showSetup(ctx, { err: '该用户名已存在。', values });

  users.create({ username, passwordHash: hashPassword(b.password), name: values.name, isAdmin: true });
  updateRuntime({ setup_done: 1 }, settingsApi.setSetting);
  logger.info('向导:初始化完成,管理员已创建', { username });
  const rt = getRuntime();
  sendHtml(ctx.res, 200, setupStep4({ theme: ctx.theme, siteName: rt.siteName, issuer: rt.issuer, adminUsername: username }));
}

/** POST /admin/rerun-wizard —— 管理员重新运行配置向导:重走检测与站点设置,不影响用户与应用数据 */
export function rerunWizard(ctx) {
  if (ctx.body?._csrf !== ctx.session?.csrf) {
    return redirect(ctx.res, '/admin?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
  updateRuntime({ setup_step: 1, setup_done: 0 }, settingsApi.setSetting);
  logger.info('向导:管理员触发重新运行配置向导');
  redirect(ctx.res, '/setup');
}
