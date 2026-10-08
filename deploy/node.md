# Node 部署(systemd,Ubuntu 22.04)

> 适用版本:`v1.6.2` · Sakura-Auth-Server · 推荐 Node.js 24

部署标识(系统账号、服务名、路径)与项目名称一致,均为 `sakura-auth-server`:`/opt/sakura-auth-server` 放代码,`/var/lib/sakura-auth-server` 放数据,systemd 服务名 `sakura-auth-server`。从 1.6.1 及更早版本升级时见文末「从旧版命名迁移」。

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
| `/opt/sakura-auth-server` | 程序代码(`server.js` + `src/` + `package.json`) |
| `/var/lib/sakura-auth-server` | 数据(SQLite + 签名密钥,`DATA_DIR` 指向这里) |

创建不可登录的系统账号,上传代码并初始化目录:

```bash
sudo useradd -r -s /usr/sbin/nologin sakura-auth-server
sudo mkdir -p /opt/sakura-auth-server /var/lib/sakura-auth-server
sudo tar xzf Sakura-Auth-Server.tar.gz -C /opt/sakura-auth-server # 使用内容位于归档根目录的源码包,或上传整个项目
sudo chown -R sakura-auth-server:sakura-auth-server /opt/sakura-auth-server /var/lib/sakura-auth-server
```

看到两个目录属主都是 `sakura-auth-server` 即成功。

## 第 3 步:systemd 单元

新建 `/etc/systemd/system/sakura-auth-server.service`(通过域名访问时把 `BASE_URL` 换成你的 https 地址;TLS 直连见下一节):

```ini
[Unit]
Description=Sakura-Auth-Server OAuth2/OIDC 认证服务
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sakura-auth-server
Group=sakura-auth-server
WorkingDirectory=/opt/sakura-auth-server
ExecStart=/usr/bin/node server.js
Environment=NODE_ENV=production
Environment=PORT=9000
Environment=BASE_URL=https://sso.example.com
Environment=DATA_DIR=/var/lib/sakura-auth-server
# TLS 直连时取消注释(证书路径须对 sakura-auth-server 用户可读):
# Environment=TLS_CERT=/etc/sakura-auth-server/tls/fullchain.pem
# Environment=TLS_KEY=/etc/sakura-auth-server/tls/privkey.pem
# Environment=TLS_REDIRECT_PORT=80
Restart=always
RestartSec=3

# 基础加固:文件系统只读 + 仅数据目录可写
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/sakura-auth-server

[Install]
WantedBy=multi-user.target
```

启用开机自启并立即启动。

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sakura-auth-server
```

确认状态。

```bash
systemctl status sakura-auth-server
```

看到 `active (running)` 即成功;浏览器打开 `http://服务器IP:9000/setup` 完成四步配置向导。

## 第 4 步:TLS 直连(可选,不用反代)

与 Docker 部署是同一套变量:`TLS_CERT` / `TLS_KEY` 同时设置后服务以 HTTPS 直连(自动附加 HSTS),`TLS_REDIRECT_PORT` 另起一个 HTTP 端口做 301 跳转。证书放置、443/80 端口与注意事项见 [Docker 部署的「TLS 直连」](docker.md#tls-直连不用反向代理);systemd 下只需把证书路径写进上面单元文件的 `Environment=` 行,然后 `sudo systemctl restart sakura-auth-server`,日志出现「HTTPS(TLS 直连 + HSTS)」即成功。

## 日常运维

| 命令 | 用途 |
| --- | --- |
| `journalctl -u sakura-auth-server -f` | 跟踪日志 |
| `sudo systemctl restart sakura-auth-server` | 重启 |
| `systemctl status sakura-auth-server` | 看运行状态 |

探活:`/healthz` 轻量 JSON、`/health` 无需登录的状态页、`/api/heartbeat` 心跳(版本 / uptime / DB 探测),用法见 [Docker 部署的「探活与监控」](docker.md#探活与监控)。

## 升级步骤

升级前先备份数据与部署配置。以下示例保留现有 `/opt/sakura-auth-server` 和 `/var/lib/sakura-auth-server`,源码包需将程序文件放在归档根目录:

```bash
sudo systemctl stop sakura-auth-server && \
  sudo tar czf "sakura-auth-server-data-$(date +%Y%m%d-%H%M%S).tgz" -C /var/lib sakura-auth-server && \
  sudo tar xzf Sakura-Auth-Server-new.tar.gz -C /opt/sakura-auth-server && \
  sudo chown -R sakura-auth-server:sakura-auth-server /opt/sakura-auth-server && \
  sudo systemctl start sakura-auth-server
```

任一步失败都会停止后续操作;检查错误,必要时恢复备份和旧代码,确认无误后再启动服务。不要直接复制运行中的 SQLite 主文件;备份时也要保管好 systemd 单元、环境配置及外部证书。

升级后检查 `systemctl status sakura-auth-server` 是否为 `active (running)`,通过 `journalctl -u sakura-auth-server` 检查错误,并用 `/api/heartbeat` 核对版本。回滚须先确认旧程序能读取当前数据库;不兼容时需停服恢复升级前数据,并评估丢失新数据及回退凭据撤销状态的风险。

> [!WARNING]
> `/var/lib/sakura-auth-server` 包含 RSA 签名私钥与全部用户数据,丢失后所有已签发令牌立即失效,请纳入备份。

## 从旧版命名迁移(1.6.1 及更早)

1.6.2 起部署标识统一为 `sakura-auth-server`。既有部署可按需迁移(数据内容不变,仅改名;不迁移也能继续运行,但建议统一以免混淆):

```bash
sudo systemctl stop sakuraid
sudo systemctl disable sakuraid
sudo mv /opt/sakuraid /opt/sakura-auth-server
sudo mv /var/lib/sakuraid /var/lib/sakura-auth-server
sudo mv /etc/systemd/system/sakuraid.service /etc/systemd/system/sakura-auth-server.service
sudo sed -i 's/sakuraid/sakura-auth-server/g' /etc/systemd/system/sakura-auth-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now sakura-auth-server
```

继续沿用旧的 `sakuraid` 系统账号也没问题;想统一账号名时新建账号并移交目录属主:

```bash
sudo useradd -r -s /usr/sbin/nologin sakura-auth-server
sudo chown -R sakura-auth-server:sakura-auth-server /opt/sakura-auth-server /var/lib/sakura-auth-server
```

迁移后检查 `systemctl status sakura-auth-server` 与 `/api/heartbeat`。历史备份目录 `sakuraid-backup-*` 仍可被恢复脚本识别,无需改名。

## 防火墙

| 场景 | 放行 |
| --- | --- |
| 反代(Nginx/Caddy/宝塔) | 只放行 80/443,用防火墙限制 9000,仅允许本机或可信反代访问 |
| TLS 直连 | 放行 443 与(启用跳转时)80 |
| 自定义端口 | 放行 `PORT` 对应端口 |

放行标准 Web 端口。

```bash
sudo ufw allow 80,443/tcp
```

看到 `Rule added` 即成功。

> 文档基于对应项目源码整理。实现变更后,以项目仓库、版本文件和 CHANGELOG 为最终依据。
