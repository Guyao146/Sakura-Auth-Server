import { config } from './config.js';

/**
 * 运行时配置:env 默认值 ← settings 表(配置向导/管理端写入)。
 * 进程内缓存,updateRuntime() 写库后刷新缓存。
 */
const KEYS = [
  'site_name', 'issuer', 'access_ttl', 'refresh_ttl', 'session_ttl', 'allow_register',
  'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'smtp_from',
  'ms_enabled', 'ms_client_id', 'ms_client_secret', 'ms_tenant', 'ms_authority',
  'unilink_enabled', 'unilink_issuer', 'unilink_client_id', 'unilink_client_secret',
  'about_title', 'about_content',
  'brand_logo_url', 'brand_accent', 'brand_tagline',
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
  // issuer 去尾部斜杠:避免 /auth/microsoft/callback 等拼接地址出现双斜杠,
  // 也保证 iss / 发现文档地址全站一致(旧值含尾斜杠的库会被这里统一纠正)
  const issuer = (config.envBaseUrl || s.issuer || `http://localhost:${config.port}`).replace(/\/+$/, '');
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
    // 品牌定制(空串 = 使用内置默认):logo 为 /uploads/site-logo.<ext>,accent 为规范化 #rrggbb
    brandLogoUrl: s.brand_logo_url || '',
    brandAccent: s.brand_accent || '',
    brandTagline: s.brand_tagline || '',
    smtp: mergeSmtp(s),
    // 「关于我们」公开页(/about):管理端填写,空内容时不显示页脚入口
    about: {
      title: s.about_title || '关于我们',
      content: s.about_content || '',
    },
    unilink: {
      enabled: s.unilink_enabled === '1',
      issuer: (s.unilink_issuer || '').replace(/\/+$/, ''),
      clientId: s.unilink_client_id || 'unilink-qr',
      clientSecret: s.unilink_client_secret || '',
      redirectUri: `${issuer}/auth/unilink/callback`,
    },
    // Microsoft 账号登录(联邦 OIDC):redirectUri 恒为 {issuer}/auth/microsoft/callback,不落库
    msOAuth: {
      enabled: String(s.ms_enabled || '') === '1',
      clientId: s.ms_client_id || '',
      clientSecret: s.ms_client_secret || '',
      tenant: s.ms_tenant || 'common',
      authority: (s.ms_authority || 'https://login.microsoftonline.com').replace(/\/+$/, ''),
      redirectUri: `${issuer}/auth/microsoft/callback`,
    },
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
