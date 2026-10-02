# Node 部署(systemd,Ubuntu 22.04)

> Wiki 文档版本:`v1.0.0` · 更新日期:`2026-10-01`(SakuraID 独立版本)

不用 Docker 时,用 systemd 托管 Node 进程:开机自启、崩溃自动拉起、日志进 journald。项目零 npm 依赖,全程无需 `npm install`。

## 第 1 步:安装 Node.js 24

添加 NodeSource 官方源并安装(项目要求 Node ≥ 22.5,内置 `node:sqlite`)。

```bash
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash - \
  && sudo apt-get install -y nodejs
```

确认版本。

```bash
node -v
```

看到 `v24.x` 即成功。

## 第 2 步:目录布局与专用账号

| 路径 | 用途 |
| --- | --- |
| `/opt/sakuraid` | 程序代码(`server.js` + `src/` + `package.json`) |
| `/var/lib/sakuraid` | 数据(SQLite + 签名密钥,`DATA_DIR` 指向这里) |

创建不可登录的系统账号,上传代码并初始化目录:

```bash
sudo useradd -r -s /usr/sbin/nologin sakuraid
sudo mkdir -p /opt/sakuraid /var/lib/sakuraid
sudo tar xzf oauth2-idp.tar.gz -C /opt/sakuraid     # 或 git clone / scp 上传整个项目
sudo chown -R sakuraid:sakuraid /opt/sakuraid /var/lib/sakuraid
```

看到两个目录属主都是 `sakuraid` 即成功。

## 第 3 步:systemd 单元

新建 `/etc/systemd/system/sakuraid.service`(通过域名访问时把 `BASE_URL` 换成你的 https 地址;TLS 直连见下一节):

```ini
[Unit]
Description=SakuraID OAuth2/OIDC 认证服务
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sakuraid
Group=sakuraid
WorkingDirectory=/opt/sakuraid
ExecStart=/usr/bin/node server.js
Environment=NODE_ENV=production
Environment=PORT=9000
Environment=BASE_URL=https://sso.example.com
Environment=DATA_DIR=/var/lib/sakuraid
# TLS 直连时取消注释(证书路径须对 sakuraid 用户可读):
# Environment=TLS_CERT=/etc/sakuraid/tls/fullchain.pem
# Environment=TLS_KEY=/etc/sakuraid/tls/privkey.pem
# Environment=TLS_REDIRECT_PORT=80
Restart=always
RestartSec=3

# 基础加固:文件系统只读 + 仅数据目录可写
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/sakuraid

[Install]
WantedBy=multi-user.target
```

启用开机自启并立即启动。

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sakuraid
```

确认状态。

```bash
systemctl status sakuraid
```

看到 `active (running)` 即成功;浏览器打开 `http://服务器IP:9000/setup` 完成四步配置向导。

## 第 4 步:TLS 直连(可选,不用反代)

与 Docker 部署是同一套变量:`TLS_CERT` / `TLS_KEY` 同时设置后服务以 HTTPS 直连(自动附加 HSTS),`TLS_REDIRECT_PORT` 另起一个 HTTP 端口做 301 跳转。证书放置、443/80 端口与注意事项见 [Docker 部署的「TLS 直连」](docker.md#tls-直连不用反向代理);systemd 下只需把证书路径写进上面单元文件的 `Environment=` 行,然后 `sudo systemctl restart sakuraid`,日志出现「HTTPS(TLS 直连 + HSTS)」即成功。

## 日常运维

| 命令 | 用途 |
| --- | --- |
| `journalctl -u sakuraid -f` | 跟踪日志 |
| `sudo systemctl restart sakuraid` | 重启 |
| `systemctl status sakuraid` | 看运行状态 |

探活:`/healthz` 轻量 JSON、`/health` 无需登录的状态页、`/api/heartbeat` 心跳(版本 / uptime / DB 探测),用法见 [Docker 部署的「探活与监控」](docker.md#探活与监控)。

## 升级步骤

覆盖代码并重启(数据在 `/var/lib/sakuraid`,不受影响)。

```bash
sudo tar xzf oauth2-idp-new.tar.gz -C /opt/sakuraid
sudo systemctl restart sakuraid
```

看到 `systemctl status sakuraid` 回到 `active (running)` 且 `journalctl -u sakuraid` 无报错即成功。备份只需打包数据目录:

```bash
sudo tar czf sakuraid-data-$(date +%F).tgz -C /var/lib sakuraid
```

> [!WARNING]
> `/var/lib/sakuraid` 包含 RSA 签名私钥与全部用户数据,丢失后所有已签发令牌立即失效,请纳入备份。

## 防火墙

| 场景 | 放行 |
| --- | --- |
| 反代(Nginx/Caddy/宝塔) | 只放行 80/443,9000 仅监听本机 |
| TLS 直连 | 放行 443 与(启用跳转时)80 |
| 自定义端口 | 放行 `PORT` 对应端口 |

放行标准 Web 端口。

```bash
sudo ufw allow 80,443/tcp
```

看到 `Rule added` 即成功。

> 文档基于对应项目源码整理。实现变更后,以项目仓库、版本文件和 CHANGELOG 为最终依据。
