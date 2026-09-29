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
    sendHtml(ctx.res, 200, setupStep2({
      theme: ctx.theme, siteName: rt.siteName, err,
      values: {
        site_name: values?.site_name ?? rt.siteName,
        issuer: values?.issuer ?? rt.issuer,
        access_ttl: values?.access_ttl ?? rt.accessTokenTtl,
        refresh_ttl: values?.refresh_ttl ?? rt.refreshTokenTtl,
      },
    }));
  } else {
    sendHtml(ctx.res, 200, setupStep3({
      theme: ctx.theme, siteName: rt.siteName, err,
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

/** POST /setup/step2 —— 站点设置 */
export function step2(ctx) {
  const b = ctx.body || {};
  const issuer = httpUrl(b.issuer || '');
  const accessTtl = Number(b.access_ttl), refreshTtl = Number(b.refresh_ttl);
  if (!String(b.site_name || '').trim()) return showSetup(ctx, { err: '站点名称不能为空。', values: b });
  if (!issuer) return showSetup(ctx, { err: 'Issuer 必须是合法的 http(s) 地址。', values: b });
  if (!(accessTtl >= 60 && accessTtl <= 86400) || !(refreshTtl >= 3600 && refreshTtl <= 31536000)) {
    return showSetup(ctx, { err: '令牌有效期超出允许范围。', values: b });
  }
  updateRuntime({
    site_name: String(b.site_name).trim(), issuer,
    access_ttl: accessTtl, refresh_ttl: refreshTtl, setup_step: 3,
  }, settingsApi.setSetting);
  logger.info('向导:站点设置完成', { issuer });
  redirect(ctx.res, '/setup');
}

/** POST /setup/step3 —— 创建管理员并完成安装 */
export function step3(ctx) {
  const b = ctx.body || {};
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
