# Sakura-Auth-Server —— 类 authentik 的轻量 OAuth2 / OIDC 认证后台

> 版本:`v1.6.2` · 零 npm 依赖 · Node.js ≥ 22.5(推荐 24 LTS) · SQLite 存储

[CI 状态](https://github.com/Guyao146/Sakura-Auth-Server/actions/workflows/ci.yml) · [GHCR 镜像](https://github.com/Guyao146/Sakura-Auth-Server/pkgs/container/sakura-auth-server) · [更新记录与升级注意事项](CHANGELOG.md)

Sakura-Auth-Server 是一个自托管的统一身份认证服务(IdP):业务系统统一跳转到这里登录,通过 OAuth 2.0 / OpenID Connect 拿回令牌访问各自的接口。定位对标 authentik 的核心子集——不过超大而全,只把「发令牌」这一件事做对。

## 快速开始

```bash
node server.js
```

这条命令启动服务(默认 `http://localhost:9000`)。看到配置向导地址即成功。

1. 打开 `http://localhost:9000/setup` 完成四步配置向导(环境检测 → 站点设置 → 管理员 → 完成);
2. 控制台「应用」里新建一个客户端,拿到 `client_id` / `client_secret`;
3. 业务系统对接发现文档 `/.well-known/openid-configuration` 即可。

零 npm 依赖,无需 `npm install`;Windows / Linux / macOS 均可直接运行。

## 部署

命名说明:自 `v1.6.2` 起,部署标识统一为 **Sakura-Auth-Server** —— Compose 服务与容器名、systemd 账号/服务/路径、宝塔目录与 PM2 进程名均为 `sakura-auth-server`,镜像变量为 `SAKURA_AUTH_SERVER_IMAGE`,备份前缀为 `sakura-auth-server-backup-*`。从 1.6.1 升级时:`.env` 里的 `SAKURAID_IMAGE` 需改名为 `SAKURA_AUTH_SERVER_IMAGE`(旧容器 `sakura-idp` 先 `docker compose down` 移除,迁移步骤见 [Docker 部署](deploy/docker.md)、[Node 部署](deploy/node.md)、[宝塔部署](deploy/baotao.md));历史备份目录 `sakuraid-backup-*` 恢复脚本仍兼容,无需改名。实例的站点名称由配置向导或管理端定制,不受更名影响。

支持 [Docker Compose](deploy/docker.md)、[Node + systemd](deploy/node.md) 和 [宝塔 PM2](deploy/baotao.md)。容器镜像基于 Node 24 Alpine,以非 root 的 `node` 用户(uid 1000)运行;当前 GHCR 构建平台为 **`linux/amd64`**,尚未提供 ARM64 镜像。

### GHCR 镜像

| 标签 | 用途 |
| --- | --- |
| `ghcr.io/guyao146/sakura-auth-server:1.6.2` | 本次正式版本,推荐部署时显式锁定 |
| `ghcr.io/guyao146/sakura-auth-server:latest` | 滚动标签,随 `main` 或正式版本流水线更新 |
| `ghcr.io/guyao146/sakura-auth-server:sha-<提交短哈希>` | 按源码提交追溯构建 |

Git 标签使用 `v1.6.2`,镜像版本标签为 **`1.6.2`(不带 `v`)**。需要不可变引用时,使用镜像发布后的 `@sha256:...` 摘要。

```bash
docker pull ghcr.io/guyao146/sakura-auth-server:1.6.2
```

在源码目录复制配置样例(已有 `.env` 时不要覆盖):

```bash
cp .env.example .env
```

编辑 `.env`,将 `BASE_URL` 换成实际对外地址,并指定版本:

```dotenv
BASE_URL=https://sso.example.com
SAKURA_AUTH_SERVER_IMAGE=ghcr.io/guyao146/sakura-auth-server:1.6.2
```

首次本机试用可设 `BASE_URL=http://localhost:9000`;公网部署应使用 HTTPS 和正确的域名。然后启动:

```bash
docker compose pull
docker compose up -d
docker compose ps
```

浏览器访问对外地址的 `/setup` 完成初始化。`/healthz` 用于容器存活检查,`/api/heartbeat` 可核对运行版本。Compose 将宿主机 `data/` 挂载到 `/data`;若遇到写权限问题,按 [Docker 部署说明](deploy/docker.md)设置目录属主或改用命名卷。

### 升级、备份与回滚

1. 升级前备份数据和部署配置。Docker 部署应先停服再复制完整数据目录,详见 [升级与备份](deploy/docker.md#升级与备份);不要直接复制运行中的 SQLite 主文件。
2. 修改 `.env` 的 `SAKURA_AUTH_SERVER_IMAGE`,再执行 `docker compose pull && docker compose up -d`。
3. 检查 `docker compose ps`、`/healthz` 和 `/api/heartbeat`。默认 `pull_policy: missing` 不会主动更新本地已有的 `latest`,因此升级时需要显式 `pull`。
4. 回滚前先确认数据库兼容性;若新版本做过不兼容迁移,需停服并恢复升级前备份,不能只换旧镜像。恢复会丢失备份后的数据,也可能回退密码和凭据撤销状态。

以下 npm 运维脚本在**源码目录**运行,要求可用的 Node.js 和正确的 `DATA_DIR`;当前精简运行时镜像不包含 `scripts/`,不能直接在容器内执行这些 npm 脚本。环境变量完整清单见 [.env.example](.env.example)。

数据备份:`npm run backup` —— 一键备份到 `data/backups/sakura-auth-server-backup-<时间戳>/`(idp.sqlite 用 VACUUM INTO 产生一致性快照 + uploads/ 整目录 + meta.txt,可选打包 .tar.gz),默认保留最近 14 份(`BACKUP_KEEP` 环境变量可调);可在服务运行中执行。

数据恢复:`npm run restore -- <备份目录或 .tar.gz> --force` —— 恢复前请先停止服务;不加 `--force` 不替换数据。脚本先复制到同文件系统的暂存目录并检查 SQLite 完整性,再将现有 data 目录改名为 `data-before-restore-<时间戳>/` 后切换;切换失败会尝试复位旧目录。支持恢复位于当前数据目录内的备份。仅恢复可信备份,旧数据及历史备份保留在改名后的目录中。

## 当前状态

| 项 | 状态 |
| --- | --- |
| 运行要求 | Node.js ≥ 22.5(使用内置 `node:sqlite`) |
| 依赖 | 零 npm 依赖 |
| 存储 | SQLite(WAL,单文件,位于 `data/`) |
| 令牌签名 | RS256(RSA-2048,密钥自动生成并落库)+ JWKS |
| 部署 | Docker Compose(拉取镜像或本地构建)/ Node + systemd / 宝塔 PM2,见 `deploy/` |
| 许可证 | Sakura-License-1.2(源码可用,限制商用,非 OSI 批准的开源许可证) |

## 功能概览

| 领域 | 能力 |
| --- | --- |
| OAuth2 | 授权码 + PKCE(S256/plain)、refresh_token 轮换、client_credentials |
| OIDC | 发现文档、JWKS、id_token(nonce/at_hash/auth_time)、/userinfo |
| 运维端点 | RFC 7662 内省、RFC 7009 吊销 |
| 控制台 | 用户管理(禁用/重置密码/用户组)、应用管理(机密/公开客户端、密钥重置、令牌吊销) |
| 两步验证 | 账号页自助开启 TOTP(RFC 6238,兼容 Google Authenticator 等)、服务端渲染扫码二维码、8 枚一次性恢复代码、登录第二因子、管理员可重置 |
| 应用门户 | 普通用户的业务线入口页:按权限组过滤可见应用,一键发起统一登录(IdP 代发 PKCE,授权码可直接换取令牌) |
| 权限组 | 组管理与成员关系(迁移时自动从旧用户字段播种);应用(业务线)可限制「可访问的权限组」,组外用户在授权阶段被拦截;groups claim 由成员关系驱动 |
| 我的授权 | 用户侧「我的授权」页:查看已记住授权的应用/范围/时间,一键撤销并级联吊销其现有令牌,下次访问重新确认 |
| 账号自助 | 找回密码(零依赖 SMTP 客户端,支持 STARTTLS;SMTP 可在向导/环境变量配置,未配置时走开发模式把邮件打到日志)、管理员可控的自助注册开关 |
| 会话安全 | 用户自助「登录会话」页:查看全部登录设备(IP/UA/时间),撤销单个或其它全部会话;/api/sessions 同能力 |
| 审计 | 登录/2FA/授权同意与撤销/注册/管理操作全量留痕(滚动保留 5000 条),管理端「审计日志」页可按动作/关键词筛选、清空 |
| 应用元数据 | 应用描述与 Logo(https)字段,门户磁贴/条状/同意页展示;应用详情「已授权用户」列表,可单独撤销某用户的授权与令牌 |
| 品牌定制 | 管理端可视化配置:站点 Logo(上传/删除)、主题强调色(全站变量覆盖,防 CSS 注入)、品牌口号,保存即全站生效 |
| 界面语言 | 简体中文 / English 切换(cookie + /-/lang/:code),登录/授权/门户/账号/控制台导航等高流量页面覆盖,缺词回退中文 |
| Passkey | WebAuthn/Passkey 无密码登录:账号页注册凭据(上限 8 个),要求 PIN/生物识别等用户验证(UV);检查非零 counter 的递增并支持双零计数器;零依赖 CBOR/ES256 实现 |
| 联邦登录 | Microsoft 账号 OIDC 登录与绑定;UniLink 扫码登录,保留原授权目标并对已开启 TOTP 的账号继续执行第二因子验证 |
| 流转 | 未登录访问首页跳登录页、登录后直达应用门户、已登录访问登录页跳门户 |
| JSON API | /api/heartbeat 心跳(含版本/uptime/DB 探测)、/api/session 登录状态、/api/login 登录(支持 2FA)、/api/logout、/api/apps 可见应用、/api/sessions 会话列表与撤销、/api/registry 应用状态(令牌认证)。会话型写操作需带 `X-Requested-With: JSON` 头(防跨站纵深防御) |
| 安全 | scrypt 口令哈希(异步并发限流)、CSRF 双提交、登录限流、授权码/刷新令牌哈希落库、授权码一次性、刷新令牌轮换与重放检测(全链作废)、改密/重置/禁用后统一凭据失效、防用户枚举(含登录耗时一致) |
| 界面 | 配置向导、明暗双主题(跟随系统 + 手动切换)、樱落生态设计语言;无脚本手机菜单、键盘焦点与跳转正文、减少动画偏好、响应式登录及应用门户 |

## 架构

```text
┌─────────────────────────── server.js(入口/请求管线) ───────────────────────────┐
│  安全头 → setup 守卫 → 会话解析 → 路由匹配 → CORS → 鉴权 → 请求体 → 服务函数      │
└──────────────┬─────────────────────────┬──────────────────────┬────────────────┘
               ▼                         ▼                      ▼
      src/services/oauth          src/services/auth       src/services/admin
   authorize/token/userinfo     login/logout/account    用户与应用管理
   introspect/discovery              src/services/setup
                                    配置向导(四步)
               ▼                         ▼                      ▼
      src/models(数据访问层)    ──▶  src/core(db/keys/jwt/password/http/config)
               ▼
      data/idp.sqlite(用户/应用/会话/授权码/令牌/同意/设置)
```

视图层在 `src/views`,使用服务端 HTML 渲染,按樱落生态设计语言实现明暗主题、轻投影和响应式布局,不依赖前端框架或外部字体。基础表单和手机菜单无需 JavaScript;Passkey、取色等增强交互使用项目内置脚本,并非所有页面都零脚本。

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PORT` | `9000` | 监听端口 |
| `BASE_URL` | `http://localhost:PORT` | 对外地址 = OIDC issuer;反代/域名部署必填 |
| `DATA_DIR` | `./data` | SQLite 与密钥所在目录(容器内为 `/data`) |
| `SQLITE_SYNCHRONOUS` | `FULL` | 仅支持 FULL/NORMAL;NORMAL 减少写入同步开销,但断电/系统崩溃可能丢失已提交事务,认证数据建议保持 FULL |
| `ACCESS_TOKEN_TTL` | `900` | access token 有效期(秒) |
| `REFRESH_TOKEN_TTL` | `2592000` | refresh token 有效期(秒) |
| `SESSION_TTL` | `1209600` | 登录会话有效期(秒) |
| `SMTP_HOST` 等 | 未配置 | `SMTP_PORT`/`SMTP_USER`/`SMTP_PASS`/`SMTP_FROM`;配置后启用真实发信,未配置时邮件打到日志 |

向导里设置的同名项保存在 settings 表;`BASE_URL` 等环境变量优先级更高,便于容器化锁定。

## 端到端示例(授权码 + PKCE)

以下示例使用已配置的 **PKCE 公开客户端**。在 Linux/macOS shell 或 Windows Git Bash 中执行,替换 `app-xxx`、回调地址及 `<CODE>` / `<ACCESS_TOKEN>`;机密客户端还需按其认证方式提供客户端凭据。

```bash
# 1. 使用项目已要求的 Node.js 生成 PKCE 和随机 state
VERIFIER=$(node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))")
CHALLENGE=$(node -e "console.log(require('node:crypto').createHash('sha256').update(process.argv[1]).digest('base64url'))" "$VERIFIER")
STATE=$(node -e "console.log(require('node:crypto').randomBytes(24).toString('base64url'))")

# 2. 将输出的地址复制到浏览器(redirect_uri 必须与注册值一致)
printf '%s\n' "http://localhost:9000/authorize?client_id=app-xxx&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcb&response_type=code&scope=openid%20profile&state=$STATE&code_challenge=$CHALLENGE&code_challenge_method=S256"

# 3. 登录同意后先校验回调 state 与 $STATE 一致,再用 code 换令牌
curl -sS http://localhost:9000/token \
  --data-urlencode 'grant_type=authorization_code' --data-urlencode 'code=<CODE>' \
  --data-urlencode 'redirect_uri=http://localhost:8080/cb' \
  --data-urlencode 'client_id=app-xxx' --data-urlencode "code_verifier=$VERIFIER"

# 4. 携带 Bearer 访问用户信息
curl -sS http://localhost:9000/userinfo -H 'Authorization: Bearer <ACCESS_TOKEN>'
```

## 测试与验证

建议使用与 CI 相同的 Node.js 24,无需 `npm install`。

| 命令 | 覆盖范围 | 默认 CI |
| --- | --- | --- |
| `npm run smoke` | 487 项端到端断言:向导、认证、授权、管理、Passkey、品牌及备份恢复等 | 是 |
| `npm run test:oauth` | 56 项 OAuth/OIDC、PKCE、刷新轮换、JWT 边界和旧库迁移检查 | 是 |
| `npm run test:security` | 27 项认证竞态、凭据失效、权限组、Passkey 及运维安全回归 | 是 |
| `npm run test:views` | 10 项 SSR 项目署名、导航、权限入口、表单、多语言和可访问性标记检查 | 是 |
| `node scripts/test-qr.mjs` | QR 编码器,46 项 | 是 |
| `node scripts/test-smtp.mjs` | SMTP 对话,9 项 | 是 |
| `node scripts/test-ms.mjs` | Microsoft OIDC 本地模拟联邦,15 项 | 是 |
| `npm run test:views -- --browser` | 共 64 项:SSR + Chromium 布局、主题及键盘检查 | 否,需本机浏览器 |
| `node scripts/test-unilink.mjs` | 两个真实 HTTP 服务的隔离扫码联调 | 否,需 UniLink 源码及其 Python 依赖 |

协议、安全和冒烟测试使用临时数据库,不读取生产数据。并行运行多份冒烟测试时,通过 `SMOKE_PORT` 错开端口。UniLink 联调通过 `UNILINK_SOURCE` 指定其 `auth-server` 绝对目录,通过 `PYTHON` 指定已安装该服务依赖的 Python 可执行文件。

### 可选浏览器检查

通过 `BROWSER_PATH` 指定本机 Edge/Chrome(Chromium)可执行文件的绝对路径。Windows PowerShell 示例:

```powershell
$env:BROWSER_PATH = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$env:UI_SCREENSHOT_DIR = Join-Path $env:TEMP 'sakura-ui-preview'
npm.cmd run test:views -- --browser
```

测试启动只监听本机随机端口的演示页面服务和临时浏览器配置,检查 320/390/768/1024/1440px 布局、明暗/自动主题、禁用页面脚本后的手机菜单、跳转正文和表格滚动。浏览器配置会清理,可选的 `UI_SCREENSHOT_DIR` 截图目录会保留;不使用实际数据库或个人浏览器配置。这些检查不等同于真机、跨浏览器或完整读屏器可访问性审计。

## 发布流程

推送 `main` 或 `v*` 标签会触发 [GitHub Actions](https://github.com/Guyao146/Sakura-Auth-Server/actions/workflows/ci.yml):先运行默认回归,通过后构建并发布到 `ghcr.io/guyao146/sakura-auth-server`。拉取请求只执行测试,不发布镜像。

发布前同步更新 `package.json`、README、CHANGELOG 和部署示例中的版本;使用新的附注 Git 标签,不要移动已发布标签。发布后应检查 Actions 结果、GHCR 镜像版本/提交标签及实际运行的 `/api/heartbeat`。当前仅构建 `linux/amd64`,本机没有 Docker 时可由该流水线完成镜像打包。

## 安全与运维说明

安全行为说明:撤销应用最后一个授权组后保持受限,不会自动向所有用户开放;Passkey 注册和登录要求认证器完成用户验证(PIN/生物识别等),仅支持用户在场、不支持 UV 的旧认证器将不能继续使用无密码登录。

运维脚本:`npm run reset-admin -- <用户名> [新密码]`(直接重置管理员密码,并使该用户的会话、令牌、授权码和密码重置链接失效);`npm run seed-demo`(灌入演示用户与一个 PKCE 公开客户端)。首次部署自动进入配置向导(环境检测 → 站点/注册/SMTP → 管理员 → 完成);已初始化的实例可在控制台「配置向导」卡片重新运行,不影响已有用户与应用数据。

## 与生态其他项目的关系

界面遵循樱落生态 Wiki 的设计规范(`wiki.mcylyr.cn` 设计指南);作为樱落生态的基础设施,可为生态内各系统提供统一登录。站点名称可在向导中自定义。

## 许可证

本项目采用 **Sakura-License-1.2**(许可文本标识 `Sakura-License-1.2`,正式固定版本,发布于 2026-10-04),正文见仓库根目录 [LICENSE](LICENSE) 与樱落生态 Wiki:<https://wiki.mcylyr.cn/#/../licenses/Sakura-License-1.2>。它是**源码可用(source-available)许可证,限制特定商业利用,不是 OSI 批准的开源许可证**:商用(有偿提供受覆盖作品或其托管、部署、定制、维护、支持等服务)须在开展前取得许可人的明确书面授权;申请、自动回复、沉默或未答复均不构成授权。

按许可证第 1 条第 2 款记录采用声明:

| 项 | 内容 |
| --- | --- |
| 项目名称 | Sakura-Auth-Server(npm 标识:`sakura-auth-server`) |
| 项目仓库 | `https://github.com/Guyao146/Sakura-Auth-Server` |
| 上游来源 | `https://github.com/sakura-eco/oauth2-idp` |
| 许可人 | 樱落生态(具体许可主体应由有权许可人填写确认) |
| 适用文件 | 本仓库全部源码、文档与素材,即 `src/`、`server.js`、`scripts/`、`deploy/`、`README.md`、`LICENSE` 及 Dockerfile 等 |
| 排除项 | 依赖与第三方内容保持其原始许可(本项目零 npm 依赖;Node.js 与 `node:sqlite` 属运行时,随其自身许可) |
| 许可版本 | `Sakura-License-1.2` |
| 首次适用 | 自采用声明随附上述版本的提交起 |

> 版本说明:本仓库早期曾采用审阅稿 `Sakura-License-1.2-draft`;正式版条文与审阅稿修订 3 逐字一致,仅标题、文本标识、前言与第 15 条的状态表述不同。此次切换为正式固定版本,不改变此前已授予的权利。

以 Docker 镜像、二进制或网络服务形式再分发或对外提供时,请同时阅读 LICENSE 中关于署名(第 5 条)、对应源码同步公开(第 6 条)与同许可共享(第 7 条)的义务。本节仅为导览,权利义务以许可证正文为准;许可证文本可逐字复制用于采用、合规说明或法律讨论。

## 安全边界(已知未实现)

- 未内置 SAML、LDAP 或 authentik 的通用 flows/表达式策略;已实现的 Microsoft 与 UniLink 联邦入口见上文。找回密码依赖 SMTP 发信,未配置 SMTP 时邮件打到日志(开发模式);
- SQLite 单写者,服务按单实例运行(PM2 配置已锁定);大规模并发建议评估外部数据库方案;
- 反代部署时务必设置 `BASE_URL` 为 https 地址,会话 Cookie 会自动附加 `Secure`。

> 文档基于对应项目源码整理。实现变更后,以项目仓库、版本文件和 CHANGELOG 为最终依据。

License: [Sakura-License-1.2](./LICENSE)
