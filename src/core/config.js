import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '..', '..');
const port = Number(process.env.PORT || 9000);

/** 环境变量默认配置。站点相关项(siteName/issuer/TTL)会被配置向导写入的
 *  settings 表覆盖,见 core/runtime.js;env 优先级高于向导值,便于容器化时锁定。 */
export const config = {
  port,
  envBaseUrl: (process.env.BASE_URL || '').replace(/\/+$/, ''),
  dataDir: process.env.DATA_DIR || path.join(projectRoot, 'data'),
  get dbFile() {
    return path.join(this.dataDir, 'idp.sqlite');
  },
  accessTokenTtl: Number(process.env.ACCESS_TOKEN_TTL || 900),          // 15 分钟
  refreshTokenTtl: Number(process.env.REFRESH_TOKEN_TTL || 30 * 86400), // 30 天
  sessionTtl: Number(process.env.SESSION_TTL || 14 * 86400),            // 14 天
  authCodeTtl: 300,                                                     // 授权码 5 分钟
  bodyLimit: 100 * 1024,
  // SMTP 邮件配置(找回密码用)。未配置 SMTP_HOST 时为开发模式:
  // 不真正发信,邮件完整内容(含重置链接)打到日志。
  smtpHost: process.env.SMTP_HOST || '',
  smtpPort: Number(process.env.SMTP_PORT || 587),
  smtpUser: process.env.SMTP_USER || '',
  smtpPass: process.env.SMTP_PASS || '',
  smtpFrom: process.env.SMTP_FROM || '',
};

/** 内置 scope 及其中文描述(向导/管理端/同意页共用) */
export const SCOPES = {
  openid: '使用 OpenID Connect 登录(获取用户唯一标识)',
  profile: '读取你的基本资料(用户名、姓名)',
  email: '读取你的邮箱地址',
  groups: '读取你所属的用户组',
  offline_access: '在你离线时保持访问(获取刷新令牌)',
};

export const DEFAULT_CLIENT_SCOPES = Object.keys(SCOPES).join(' ');
