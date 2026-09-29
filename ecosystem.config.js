/** PM2 配置:宝塔「Node 项目」或手动 pm2 start ecosystem.config.js */
module.exports = {
  apps: [
    {
      name: 'sakura-idp',
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
