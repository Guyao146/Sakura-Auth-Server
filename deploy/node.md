# Node 部署(systemd,Ubuntu 22.04)

> 适用版本:`v1.6.1` · Sakura-Auth-Server · 推荐 Node.js 24

为兼容既有部署,本文保留 `sakuraid` 系统账号、服务名及路径;它们是部署标识,不是项目名称。

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
sudo tar xzf Sakura-Auth-Server.tar.gz -C /opt/sakuraid # 使用内容位于归档根目录的源码包,或上传整个项目
sudo chown -R sakuraid:sakuraid /opt/sakuraid /var/lib/sakuraid
```

看到两个目录属主都是 `sakuraid` 即成功。

## 第 3 步:systemd 单元

新建 `/etc/systemd/system/sakuraid.service`(通过域名访问时把 `BASE_URL` 换成你的 https 地址;TLS 直连见下一节):

```ini
[Unit]
Description=Sakura-Auth-Server OAuth2/OIDC 认证服务
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

升级前先备份数据与部署配置。以下示例保留现有 `/opt/sakuraid` 和 `/var/lib/sakuraid`,源码包需将程序文件放在归档根目录:

```bash
sudo systemctl stop sakuraid && \
  sudo tar czf "sakuraid-data-$(date +%Y%m%d-%H%M%S).tgz" -C /var/lib sakuraid && \
  sudo tar xzf Sakura-Auth-Server-new.tar.gz -C /opt/sakuraid && \
  sudo chown -R sakuraid:sakuraid /opt/sakuraid && \
  sudo systemctl start sakuraid
```

任一步失败都会停止后续操作;检查错误,必要时恢复备份和旧代码,确认无误后再启动服务。不要直接复制运行中的 SQLite 主文件;备份时也要保管好 systemd 单元、环境配置及外部证书。

升级后检查 `systemctl status sakuraid` 是否为 `active (running)`,通过 `journalctl -u sakuraid` 检查错误,并用 `/api/heartbeat` 核对版本。回滚须先确认旧程序能读取当前数据库;不兼容时需停服恢复升级前数据,并评估丢失新数据及回退凭据撤销状态的风险。

> [!WARNING]
> `/var/lib/sakuraid` 包含 RSA 签名私钥与全部用户数据,丢失后所有已签发令牌立即失效,请纳入备份。

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
