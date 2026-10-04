/** 用户凭据变更/账号禁用后的统一失效:清会话(可保留当前)、吊销令牌、删除未使用授权码。
 *  keepSession 传当前会话 id_hash 时保留它(自助改密:本人继续在线);找回密码与禁用一律全清。 */
import * as sessions from '../../models/sessions.js';
import * as tokens from '../../models/tokens.js';
import * as codes from '../../models/codes.js';

export function invalidateUserCredentials(userId, { keepSession = null } = {}) {
  if (keepSession) sessions.removeAllOther(userId, keepSession);
  else sessions.removeByUser(userId);
  tokens.revokeForUser(userId);
  codes.removeForUser(userId);
}
