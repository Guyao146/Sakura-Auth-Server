# SakuraID —— 类 authentik 的轻量 OAuth2 / OIDC 认证后台

> 版本:`v0.7.0` · 零 npm 依赖 · Node.js ≥ 22.5 · SQLite 存储

SakuraID 是一个自托管的统一身份认证服务(IdP):业务系统统一跳转到这里登录,通过 OAuth 2.0 / OpenID Connect 拿回令牌访问各自的接口。定位对标 authentik 的核心子集——不过超大而全,只把「发令牌」这一件事做对。

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

两种官方部署方式:

1. **Docker Compose(推荐)**:拉取官方镜像或本地构建,数据落在 `./data` 卷,升级只换镜像 —— 见 `deploy/docker.md`;
2. **Node + systemd**:Ubuntu 上以 systemd 托管 Node 进程,开机自启、崩溃拉起 —— 见 `deploy/node.md`。

宝塔面板(PM2)部署见 `deploy/baotao.md`;环境变量完整清单见 `.env.example`。

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
| 联邦登录 | Microsoft 账号 OIDC 登录与绑定:登录页一键登录、账号设置绑定/解绑、未绑定可关联本地账号或注册新号;管理端配置(client_id/secret/tenant) |
| 流转 | 未登录访问首页跳登录页、登录后直达应用门户、已登录访问登录页跳门户 |
| JSON API | /api/heartbeat 心跳(含版本/uptime/DB 探测)、/api/session 登录状态、/api/login 登录(支持 2FA)、/api/logout、/api/apps 可见应用、/api/sessions 会话列表与撤销、/api/registry 应用状态(令牌认证)。会话型写操作需带 `X-Requested-With: JSON` 头(防跨站纵深防御) |
| 安全 | scrypt 口令哈希(异步并发限流)、CSRF 双提交、登录限流、授权码/刷新令牌哈希落库、授权码一次性、刷新令牌轮换与重放检测(全链作废)、改密/重置/禁用后统一凭据失效、防用户枚举(含登录耗时一致) |
| 界面 | 配置向导、明暗双主题(跟随系统 + 手动切换)、樱落生态设计语言 |

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
      src/models(7 张表的 CRUD)  ──▶  src/core(db/keys/jwt/password/http/config)
               ▼
      data/idp.sqlite(用户/应用/会话/授权码/令牌/同意/设置)
```

视图层在 `src/views`,按樱落生态设计语言实现(明暗双 token、去边框靠明度差、轻投影、150–200ms 过渡),零 JavaScript、零外部字体。

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

```bash
# 1. 生成 PKCE(Windows 用 Git Bash;Linux/macOS 相同)
VERIFIER=$(head -c 48 /dev/urandom | base64url | tr -d '=')
CHALLENGE=$(printf %s "$VERIFIER" | openssl sha256 -binary | base64 | tr '/+' '_-' | tr -d '=')

# 2. 浏览器打开授权端点(替换 client_id 与已注册的 redirect_uri)
open "http://localhost:9000/authorize?client_id=app-xxx&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcb&response_type=code&scope=openid%20profile&state=xyz&code_challenge=$CHALLENGE&code_challenge_method=S256"

# 3. 登录并同意后,用回调里的 code 换令牌
curl -s http://localhost:9000/token -d grant_type=authorization_code -d code=<CODE> \
  -d redirect_uri=http://localhost:8080/cb -d client_id=app-xxx -d code_verifier=$VERIFIER

# 4. 携带 Bearer 访问用户信息
curl -s http://localhost:9000/userinfo -H "Authorization: Bearer <ACCESS_TOKEN>"
```

测试工具链:`npm run smoke` 会自动拉起独立实例,端到端验证向导、登录、两步验证(TOTP/恢复代码/管理员重置)、找回密码、自助注册、权限组与应用访问控制、授权码 + PKCE、刷新轮换、内省/吊销、client_credentials 与控制台权限、我的授权管理、应用门户、JSON API 套件、Microsoft 账号登录绑定、审计日志、应用元数据、注册表 API、会话管理、Logo 上传、审计导出与双部署方式(312 项断言);另有 `node scripts/test-qr.mjs`(QR 编码器 46 项)与 `node scripts/test-smtp.mjs`(SMTP 对话 9 项)两个单元测试。

独立协议回归:`npm run test:oauth` 使用系统临时目录,验证 GET/POST PKCE 校验、授权错误回跳、OIDC at_hash、刷新元数据与 scope、JWT 边界、禁用用户令牌检查、审计上限和旧库迁移。CI 同时运行该回归与冒烟测试。冒烟测试也使用独立临时目录;并行执行时仍需用 `SMOKE_PORT` 错开端口。

运维脚本:`npm run reset-admin -- <用户名> [新密码]`(直接重置管理员密码,用于忘记密码);`npm run seed-demo`(灌入演示用户与一个 PKCE 公开客户端)。首次部署自动进入配置向导(环境检测 → 站点/注册/SMTP → 管理员 → 完成);已初始化的实例可在控制台「配置向导」卡片重新运行,不影响已有用户与应用数据。

## 与生态其他项目的关系

界面遵循樱落生态 Wiki 的设计规范(`wiki.mcylyr.cn` 设计指南);作为樱落生态的基础设施,可为生态内各系统提供统一登录。站点名称可在向导中自定义。

## 许可证

本项目采用 **Sakura-License-1.2**(许可文本标识 `Sakura-License-1.2`,正式固定版本,发布于 2026-10-04),正文见仓库根目录 [LICENSE](LICENSE) 与樱落生态 Wiki:<https://wiki.mcylyr.cn/#/../licenses/Sakura-License-1.2>。它是**源码可用(source-available)许可证,限制特定商业利用,不是 OSI 批准的开源许可证**:商用(有偿提供受覆盖作品或其托管、部署、定制、维护、支持等服务)须在开展前取得许可人的明确书面授权;申请、自动回复、沉默或未答复均不构成授权。

按许可证第 1 条第 2 款记录采用声明:

| 项 | 内容 |
| --- | --- |
| 项目名称 | SakuraID(`oauth2-idp`) |
| 原始仓库 | `https://github.com/sakura-eco/oauth2-idp` |
| 许可人 | 樱落生态(具体许可主体应由有权许可人填写确认) |
| 适用文件 | 本仓库全部源码、文档与素材,即 `src/`、`server.js`、`scripts/`、`deploy/`、`README.md`、`LICENSE` 及 Dockerfile 等 |
| 排除项 | 依赖与第三方内容保持其原始许可(本项目零 npm 依赖;Node.js 与 `node:sqlite` 属运行时,随其自身许可) |
| 许可版本 | `Sakura-License-1.2` |
| 首次适用 | 自采用声明随附上述版本的提交起 |

> 版本说明:本仓库早期曾采用审阅稿 `Sakura-License-1.2-draft`;正式版条文与审阅稿修订 3 逐字一致,仅标题、文本标识、前言与第 15 条的状态表述不同。此次切换为正式固定版本,不改变此前已授予的权利。

以 Docker 镜像、二进制或网络服务形式再分发或对外提供时,请同时阅读 LICENSE 中关于署名(第 5 条)、对应源码同步公开(第 6 条)与同许可共享(第 7 条)的义务。本节仅为导览,权利义务以许可证正文为准;许可证文本可逐字复制用于采用、合规说明或法律讨论。

## 安全边界(已知未实现)

- 未内置 SAML、LDAP、社交登录等 authentik 高级流程(flows/表达式策略);找回密码依赖 SMTP 发信,未配置 SMTP 时邮件打到日志(开发模式);
- SQLite 单写者,服务按单实例运行(PM2 配置已锁定);大规模并发建议评估外部数据库方案;
- 反代部署时务必设置 `BASE_URL` 为 https 地址,会话 Cookie 会自动附加 `Secure`。

> 文档基于对应项目源码整理。实现变更后,以项目仓库、版本文件和 CHANGELOG 为最终依据。
