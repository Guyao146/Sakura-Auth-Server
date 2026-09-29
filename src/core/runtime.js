import { config } from './config.js';

/**
 * 运行时配置:env 默认值 ← settings 表(配置向导/管理端写入)。
 * 进程内缓存,updateRuntime() 写库后刷新缓存。
 */
const KEYS = ['site_name', 'issuer', 'access_ttl', 'refresh_ttl', 'session_ttl', 'allow_register'];

let rt = null;
let settingsGetter = null;

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
  };
  return rt;
}

export const getRuntime = () => rt;

/** 部分更新运行时配置(写 settings 表);fields 用 settings 表键名 */
export function updateRuntime(fields, setSetting) {
  for (const [k, v] of Object.entries(fields)) {
    if (KEYS.includes(k) || k === 'setup_step' || k === 'setup_done') setSetting(k, String(v));
  }
  reloadRuntime();
  return rt;
}
