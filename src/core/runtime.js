import { config } from './config.js';

/**
 * 运行时配置:env 默认值 ← settings 表(配置向导/管理端写入)。
 * 进程内缓存,updateRuntime() 写库后刷新缓存。
 */
const KEYS = [
  'site_name', 'issuer', 'access_ttl', 'refresh_ttl', 'session_ttl', 'allow_register',
  'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'smtp_from',
];

let rt = null;
let settingsGetter = null;

/** SMTP 配置合并:settings 表(向导写入)打底,显式设置的 SMTP_* 环境变量优先覆盖
 *  (与 issuer 的 env 优先策略一致)。host 为空 = 开发模式,邮件内容只打日志。 */
function mergeSmtp(s) {
  const e = config.smtpEnv || {};
  return {
    host: e.host ?? (s.smtp_host || ''),
    port: Number(e.port ?? (s.smtp_port || 587)) || 587,
    user: e.user ?? (s.smtp_user || ''),
    pass: e.pass ?? (s.smtp_pass || ''),
    from: e.from ?? (s.smtp_from || ''),
  };
}

export function bindSettings(getter) {
  settingsGetter = getter;
  reloadRuntime();
}

export function reloadRuntime() {
  const s = settingsGetter ? settingsGetter() : {};
  const issuer = config.envBaseUrl || s.issuer || `http://localhost:${config.port}`;
  rt = {
    siteName: s.site_name || '樱落统一认证',
    issuer,
    secureCookies: issuer.startsWith('https'),
    accessTokenTtl: Number(s.access_ttl) || config.accessTokenTtl,
    refreshTokenTtl: Number(s.refresh_ttl) || config.refreshTokenTtl,
    sessionTtl: Number(s.session_ttl) || config.sessionTtl,
    authCodeTtl: config.authCodeTtl,
    setupStep: Number(s.setup_step || 1),
    setupDone: String(s.setup_done || '') === '1',
    allowRegister: String(s.allow_register || '') === '1',
    smtp: mergeSmtp(s),
  };
  return rt;
}

export const getRuntime = () => rt;

/** SMTP 配置合并结果(settings 打底,env 覆盖);运行时未初始化时仅环境变量生效 */
export const getSmtpConfig = () => (rt ? rt.smtp : mergeSmtp({}));

/** 部分更新运行时配置(写 settings 表);fields 用 settings 表键名 */
export function updateRuntime(fields, setSetting) {
  for (const [k, v] of Object.entries(fields)) {
    if (KEYS.includes(k) || k === 'setup_step' || k === 'setup_done') setSetting(k, String(v));
  }
  reloadRuntime();
  return rt;
}
