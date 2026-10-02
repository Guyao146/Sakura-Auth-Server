# Docker 部署(Docker Compose)

> Wiki 文档版本:`v1.1.0` · 更新日期:`2026-10-01`(SakuraID 独立版本)

两条路径:优先**拉取官方镜像**(不依赖源码,升级只换镜像),拉不到镜像时用**本地构建**兜底。

## 路径 A:拉取镜像部署(推荐)

先准备环境变量文件。

```bash
cp .env.example .env
```

编辑 `.env`,至少把 `BASE_URL` 改为你的对外地址;然后拉取镜像并启动。

```bash
docker compose pull && docker compose up -d
```

看到 `docker compose ps` 中状态为 `Up … (healthy)` 即成功。

| 项 | 说明 |
| --- | --- |
| 官方镜像 | `ghcr.io/sakura-eco/sakuraid:latest` |
| 自托管 registry / 锁定版本 | `.env` 里设 `SAKURAID_IMAGE=registry.example.com/sakuraid:v0.8.0` |
| 拉取策略 | `pull_policy: missing`:本地已有该标签就不再拉取;要每次检查远端改为 `always` |

## 路径 B:本地构建(兜底)

在 `docker-compose.yml` 里注释掉 `image:` 一行、取消 `build:` 两行注释,然后构建并启动。

```bash
docker compose up -d --build
```

看到构建完成后容器 `Up … (healthy)` 即成功;此后升级 = 更新源码 + 重跑该命令。

## 配置向导

1. 修改 `.env` 里的 `BASE_URL` 为你的对外地址(域名或 `https://...`);
2. 启动后打开 `http://服务器IP:9000/setup` 完成配置向导;
3. 数据(SQLite + 签名密钥)全部落在 `./data`,备份该目录即可。

> [!WARNING]
> `data/` 目录包含 RSA 签名私钥与全部用户数据,丢失后所有已签发令牌立即失效,请纳入备份。

## 常用命令

| 命令 | 用途 |
| --- | --- |
| `docker compose pull && docker compose up -d` | 拉取部署的升级 |
| `docker compose up -d --build` | 本地构建并启动 |
| `docker compose logs -f` | 跟踪日志 |
| `docker compose down` | 停止(保留 data) |

## TLS 直连(不用反向代理)

服务内置 TLS:`TLS_CERT` / `TLS_KEY` 同时设置后,容器内直接以 HTTPS 对外并自动附加 HSTS;`TLS_REDIRECT_PORT` 可另起一个 HTTP 端口,把全部请求 301 到 HTTPS。

1. 证书(fullchain.pem + privkey.pem)放到 `./data/tls/`,随数据卷挂进容器;
2. `.env` 里启用:

```bash
TLS_CERT=/data/tls/fullchain.pem
TLS_KEY=/data/tls/privkey.pem
TLS_REDIRECT_PORT=80
```

3. `docker-compose.yml` 的端口改为映射 443 与 80:

```yaml
ports:
  - "443:9000"
  - "80:80"
```

执行 `docker compose up -d` 后,`https://你的域名` 可访问、`http://` 自动 301 即成功。注意容器内服务仍监听 9000(TLS 只换协议不换端口),`BASE_URL` 保持 `https://` 开头。

## 反向代理要点

用 Nginx/Caddy 反代时,把 `BASE_URL` 设为对外 https 地址即可,服务自身只出 HTTP。不涉及 WebSocket,普通 `proxy_pass` 即可;请转发 `Host` 与 `X-Forwarded-Proto` 头。

## 探活与监控

| 端点 | 用途 |
| --- | --- |
| `/healthz` | 轻量 JSON(`{"status":"ok"}`),容器 HEALTHCHECK 用它 |
| `/health` | 无需登录的状态页,适合负载均衡健康检查 / 浏览器快速查看 |
| `/api/heartbeat` | JSON 心跳(版本 / uptime / DB 探测),适合外部拨测 |

容器自带 HEALTHCHECK(每 30 秒请求一次 `/healthz`),`docker compose ps` 出现 `(healthy)` 即正常。

## 升级与备份

拉取部署的升级(数据在 `./data` 卷,不受影响):

```bash
docker compose pull && docker compose up -d
```

看到容器以新镜像重建并回到 `(healthy)` 即成功;本地构建部署则改用 `git pull && docker compose up -d --build`。备份只需打包数据目录:

```bash
tar czf sakuraid-data-$(date +%F).tgz data/
```

看到压缩包里含 `idp.sqlite` 与密钥文件即完整。若容器日志报 `/data` 无写入权限,说明宿主机目录属主不对,执行 `chown -R 1000:1000 ./data`(容器内 node 用户 uid 1000)后 `docker compose restart`;也可改用命名卷 `sakuraid-data:/data` 规避属主问题。

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `BASE_URL` | `http://localhost:9000` | 对外地址,同时是 OIDC issuer;反代/域名部署必填 |
| `PORT` | `9000` | 容器内监听端口(`.env` 里的 `PORT` 是宿主机映射端口) |
| `TLS_CERT` / `TLS_KEY` | 未设置 | 同时设置后容器内 HTTPS 直连,配合 `TLS_REDIRECT_PORT` 做 80 跳转 |
| `ACCESS_TOKEN_TTL` | `900` | access token 有效期(秒),覆盖向导值 |
| `REFRESH_TOKEN_TTL` | `2592000` | refresh token 有效期(秒) |
| `SESSION_TTL` | `1209600` | 登录会话有效期(秒) |

完整清单与中文注释见项目根目录 `.env.example`。

> 文档基于对应项目源码整理。实现变更后,以项目仓库、版本文件和 CHANGELOG 为最终依据。
