/** 灌入演示数据:演示用户 + 一个 PKCE 公开客户端。幂等,已存在则跳过。
 *  用法:npm run seed-demo */
import { initDb } from '../src/core/db.js';
import { users, clients } from '../src/models/index.js';
import { hashPassword } from '../src/core/password.js';
import { DEFAULT_CLIENT_SCOPES } from '../src/core/config.js';

initDb();

if (!users.byUsername('demo')) {
  users.create({
    username: 'demo',
    passwordHash: hashPassword('Demo#12345'),
    name: '演示用户',
    email: 'demo@example.com',
    userGroups: 'demo',
  });
  console.log('已创建用户 demo(密码 Demo#12345)');
} else {
  console.log('用户 demo 已存在,跳过');
}

const hasDemoApp = clients.list().some((c) => c.name === 'Demo PKCE App');
if (!hasDemoApp) {
  const app = clients.create({
    name: 'Demo PKCE App',
    redirectUris: ['http://localhost:8080/callback'],
    scopes: DEFAULT_CLIENT_SCOPES,
    isPublic: true,
    pkceRequired: true,
    requireConsent: true,
  });
  console.log(`已创建公开客户端 Demo PKCE App:client_id=${app.client_id}(公开客户端无密钥,强制 PKCE)`);
} else {
  console.log('客户端 Demo PKCE App 已存在,跳过');
}
