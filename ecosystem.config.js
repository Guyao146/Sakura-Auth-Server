/** PM2 配置:宝塔「Node 项目」或手动 pm2 start ecosystem.config.js */
module.exports = {
  apps: [
    {
      // 进程名统一为 sakura-auth-server;从 1.6.1 升级时先执行 pm2 delete sakura-idp
      name: 'sakura-auth-server',
      script: 'server.js',
      cwd: __dirname,
      instances: 1,          // SQLite 单写者,保持单实例
      autorestart: true,
      max_memory_restart: '300M',
      env: {
        PORT: 9000,
        // 对外地址,反代后必填,例如:
        // BASE_URL: 'https://sso.example.com',
      },
    },
  ],
};
