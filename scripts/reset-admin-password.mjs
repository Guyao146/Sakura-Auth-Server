/** 重置管理员/用户密码(直接操作数据库,不需要登录)。
 *  用法:node scripts/reset-admin-password.mjs [用户名] [新密码]
 *  不给新密码时自动生成并打印。仅允许重置管理员账号。 */
import { initDb, transaction } from '../src/core/db.js';
import { invalidateUserCredentials } from '../src/services/auth/credentials.js';
import { users } from '../src/models/index.js';
import { hashPassword } from '../src/core/password.js';
import { randomToken } from '../src/core/crypto.js';

const [username = 'admin', explicitPassword] = process.argv.slice(2);

initDb();
const user = users.byUsername(username);
if (!user) {
  console.error(`用户 ${username} 不存在。`);
  process.exit(1);
}
if (!user.is_admin) {
  console.error(`${username} 不是管理员;为安全起见,此脚本只重置管理员密码。`);
  process.exit(1);
}
const password = explicitPassword && explicitPassword.length >= 8
  ? explicitPassword
  : randomToken(9);
if (explicitPassword && explicitPassword.length < 8) {
  console.error('密码至少 8 位。');
  process.exit(1);
}
const passwordHash = await hashPassword(password);
transaction(() => {
  users.update(user.id, { passwordHash });
  invalidateUserCredentials(user.id);
});
console.log(`已重置 ${username} 的密码:${password}`);
console.log('请立即登录并妥善保存。');
