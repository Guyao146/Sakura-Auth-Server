# Docker 部署

> Wiki 文档版本:`v1.0.0` · 更新日期:`2026-09-29`(SakuraID 独立版本)

Docker 是推荐的部署方式:数据卷挂载后,升级只需换镜像。

## 快速开始

```bash
docker compose up -d --build
```

这条命令构建镜像并启动服务。看到 `http://<服务器IP>:9000/setup` 可访问即成功。

1. 修改 `docker-compose.yml` 里的 `BASE_URL` 为你的对外地址(域名或 `https://...`);
2. 启动后打开 `http://服务器IP:9000/setup` 完成配置向导;
3. 数据(SQLite + 签名密钥)全部落在 `./data`,备份该目录即可。

> [!WARNING]
> `data/` 目录包含 RSA 签名私钥与全部用户数据,丢失后所有已签发令牌立即失效,请纳入备份。

## 常用命令

| 命令 | 用途 |
| --- | --- |
| `docker compose up -d --build` | 构建并启动 |
| `docker compose logs -f` | 跟踪日志 |
| `docker compose restart` | 重启 |
| `docker compose down` | 停止(保留 data) |

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `BASE_URL` | `http://localhost:9000` | 对外地址,同时是 OIDC issuer;反代/域名部署必填 |
| `PORT` | `9000` | 容器内监听端口 |
| `ACCESS_TOKEN_TTL` | `900` | access token 有效期(秒) |
| `REFRESH_TOKEN_TTL` | `2592000` | refresh token 有效期(秒) |
| `SESSION_TTL` | `1209600` | 登录会话有效期(秒) |

## 反向代理要点

用 Nginx/Caddy 反代时,把 `BASE_URL` 设为对外 https 地址即可,服务自身只出 HTTP。WebSocket 不涉及,普通 `proxy_pass` 即可;请转发 `Host` 与 `X-Forwarded-Proto` 头。

> 文档基于对应项目源码整理。实现变更后,以项目仓库、版本文件和 CHANGELOG 为最终依据。
