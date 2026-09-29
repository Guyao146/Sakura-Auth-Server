# SakuraID —— 类 authentik 的轻量 OAuth2 / OIDC 认证后台

> 版本:`v0.2.0` · 零 npm 依赖 · Node.js ≥ 22.5 · SQLite 存储

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

## 当前状态

| 项 | 状态 |
| --- | --- |
| 运行要求 | Node.js ≥ 22.5(使用内置 `node:sqlite`) |
| 依赖 | 零 npm 依赖 |
| 存储 | SQLite(WAL,单文件,位于 `data/`) |
| 令牌签名 | RS256(RSA-2048,密钥自动生成并落库)+ JWKS |
| 部署 | Docker / docker-compose / PM2(宝塔),见 `deploy/` |

## 功能概览

| 领域 | 能力 |
| --- | --- |
| OAuth2 | 授权码 + PKCE(S256/plain)、refresh_token 轮换、client_credentials |
| OIDC | 发现文档、JWKS、id_token(nonce/at_hash/auth_time)、/userinfo |
| 运维端点 | RFC 7662 内省、RFC 7009 吊销 |
| 控制台 | 用户管理(禁用/重置密码/用户组)、应用管理(机密/公开客户端、密钥重置、令牌吊销) |
| 两步验证 | 账号页自助开启 TOTP(RFC 6238,兼容 Google Authenticator 等)、8 枚一次性恢复代码、登录第二因子、管理员可重置 |
| 安全 | scrypt 口令哈希、CSRF 双提交、登录限流、授权码/刷新令牌哈希落库、授权码一次性 |
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
| `ACCESS_TOKEN_TTL` | `900` | access token 有效期(秒) |
| `REFRESH_TOKEN_TTL` | `2592000` | refresh token 有效期(秒) |
| `SESSION_TTL` | `1209600` | 登录会话有效期(秒) |

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

测试工具链:`npm run smoke` 会自动拉起独立实例,端到端验证向导、登录、两步验证(TOTP/恢复代码/管理员重置)、授权码 + PKCE、刷新轮换、内省/吊销、client_credentials 与控制台权限(47 项断言)。

运维脚本:`npm run reset-admin -- <用户名> [新密码]`(直接重置管理员密码,用于忘记密码);`npm run seed-demo`(灌入演示用户与一个 PKCE 公开客户端)。

## 与生态其他项目的关系

界面遵循樱落生态 Wiki 的设计规范(`wiki.mcylyr.cn` 设计指南);作为樱落生态的基础设施,可为生态内各系统提供统一登录。站点名称可在向导中自定义。

## 安全边界(已知未实现)

- 未内置 SAML、LDAP、社交登录与邮件找回密码等 authentik 高级流程(flows/表达式策略);密码重置由管理员在控制台完成或用 `npm run reset-admin`;
- SQLite 单写者,服务按单实例运行(PM2 配置已锁定);大规模并发建议评估外部数据库方案;
- 反代部署时务必设置 `BASE_URL` 为 https 地址,会话 Cookie 会自动附加 `Secure`。

> 文档基于对应项目源码整理。实现变更后,以项目仓库、版本文件和 CHANGELOG 为最终依据。
