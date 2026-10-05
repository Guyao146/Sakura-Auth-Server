# 宝塔面板部署(Ubuntu)

> 适用版本:`v1.6.1` · Sakura-Auth-Server

为兼容既有部署,本文保留 `/www/sakura-idp` 路径和 `sakura-idp` PM2 进程名。

宝塔部署分四步:装 Node → 起服务 → 建站反代 → 跑配置向导。全程不需要编译依赖,项目零 npm 包。

## 第 1 步:准备 Node.js ≥ 22.5

宝塔面板 →「软件商店」→ 安装「Node.js 版本管理器」,选择 v22 或 v24 的最新版。

```bash
node -v
```

看到 `v22.x` 或更高即成功(`node:sqlite` 内置模块要求 ≥ 22.5)。

## 第 2 步:上传代码并启动

把整个 `Sakura-Auth-Server` 目录上传到服务器,例如 `/www/sakura-idp`。

```bash
cd /www/sakura-idp
node server.js
```

这条命令以前台方式启动服务。看到「已启动」与配置向导地址即成功;按 Ctrl+C 停止,改用下面的常驻方式。

宝塔 →「软件商店」→ 安装「PM2 管理器」,然后:

```bash
cd /www/sakura-idp
pm2 start ecosystem.config.js
pm2 save
```

`ecosystem.config.js` 已带好单实例与内存阈值配置;如需对外域名,先在其中补一行 `BASE_URL: 'https://sso.example.com'` 再启动。

## 第 3 步:建站并反向代理

宝塔 →「网站」→「添加站点」:域名填 `sso.example.com`,PHP 版本选「纯静态」。然后进入该站点 →「反向代理」→ 添加:

| 配置项 | 值 |
| --- | --- |
| 目标 URL | `http://127.0.0.1:9000` |
| 发送域名 | `$host` |

若使用自定义 Nginx 配置,等价写法:

```nginx
location / {
    proxy_pass http://127.0.0.1:9000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Real-IP $remote_addr;
}
```

保存后用「SSL」页签签发 Let's Encrypt 证书并开启强制 HTTPS。

## 可选:TLS 直连(不经宝塔反代)

不使用宝塔反向代理时,也可以让服务自身直接对外 HTTPS:设置环境变量 `TLS_CERT`(证书)与 `TLS_KEY`(私钥)后服务以 HTTPS 启动并自动附加 HSTS,`TLS_REDIRECT_PORT` 可另起一个 HTTP 端口把全部请求 301 到 HTTPS。PM2 方式在 `ecosystem.config.js` 的 `env` 里加这三项后重启即可。证书放置、端口映射与完整示例见 [Docker 部署的「TLS 直连」](docker.md#tls-直连不用反向代理),变量含义两种部署方式一致。

## 第 4 步:配置向导

浏览器打开 `https://sso.example.com`,会自动跳到四步配置向导:环境检测 → 站点设置(站点名称、Issuer 填 `https://sso.example.com`)→ 创建管理员 → 完成。

> [!WARNING]
> 初始化完成后,管理员仍可从控制台重新运行配置向导。忘记密码时可在服务器源码目录运行 `npm run reset-admin -- <管理员用户名>`(使用实例的 `DATA_DIR`),会重置密码并撤销该用户旧凭据;不要为此删除数据库。

## 防火墙

公网只需放行 80/443。服务默认没有限制为仅监听 `127.0.0.1`,应通过防火墙限制 9000 端口只接受本机或可信反代访问,不要直接暴露公网。

## 日常运维

```bash
pm2 logs sakura-idp     # 看日志
pm2 restart sakura-idp  # 重启
```

数据全部在 `/www/sakura-idp/data`(SQLite + 签名密钥),定期备份该目录即可。

> 文档基于对应项目源码整理。实现变更后,以项目仓库、版本文件和 CHANGELOG 为最终依据。
