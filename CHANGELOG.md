# 更新记录

## 1.7.0

### Google 账号联邦登录与登录页 One-Tap 气泡

- 新增 Google 账号(OAuth2 / OIDC)登录与绑定,与 Microsoft 联邦同构:登录页 One-Tap 风格气泡卡片(纯服务端渲染、零 JS、暗色模式双保险)、账号设置页绑定/解绑区块、未绑定身份回落到「关联本地账号 / 注册新号」二选一页;`?bind=1` 可由已登录用户主动绑定,重复绑定显式拒绝(必须先解绑,防止静默覆盖)。
- 联邦客户端为自研零依赖实现(`src/core/google-oidc.js`):授权码 + PKCE(S256)换取令牌、id_token 的 RS256 JWKS 验签(缓存 1 小时)与 aud/exp/iss 校验;`email_verified !== false` 时才采信邮箱 claim。
- 数据库:`users` 表新增 `google_sub` / `google_email` 列(幂等迁移)与 `idx_users_google_sub` 索引,`credential_version` 触发器覆盖 google_sub 变更,实现与密码/2FA 一致的统一凭据失效语义。
- 管理控制台新增 Google 登录配置卡(`POST /admin/google-oauth`):client_id / client_secret(留空保留旧值)、authority / 令牌端点 / JWKS 地址可覆盖(默认为 Google 官方端点,自托管或联调可改);端点必须是 http(s) 形态,非法值保存被拒并回显,避免 SSRF 与重定向滥用。
- 回调地址恒为 `{issuer}/auth/google/callback`,不落库、不合并上游 id_token 的任何 claim;state 与 linkToken 内存暂存(500 上限、10 分钟 TTL),关联令牌一次性。
- 测试:`scripts/test-google.mjs`(15 项核心件:授权 URL、换令牌、JWKS 验签、aud/iss/exp/签名/邮箱验证拒绝路径)、冒烟测试新增 30 项 Google 端到端断言、视图回归新增气泡与账号区块检查;CI 加入 test-google。

## 1.6.3

### 启动诊断

- 数据库打开失败(`unable to open database file`,SQLITE errcode 14)时,报错改为包含 `进程uid/ gid`、目录是否存在/可写/权限位与具体修复命令(Docker 绑定挂载属主不是容器内 `node` 用户 uid 1000 时最常见),避免误以为业务故障。
- 冒烟测试在 Linux 下覆盖「只读数据目录 → 明确报错」路径。

## 1.6.2

### 部署标识统一为 Sakura-Auth-Server

- Docker Compose 服务名与容器名改为 `sakura-auth-server`,镜像变量改名为 `SAKURA_AUTH_SERVER_IMAGE`;`.env` 中的旧变量 `SAKURAID_IMAGE` 需相应改名,未设置时默认 `ghcr.io/guyao146/sakura-auth-server:latest`。
- systemd 账号、服务名与路径改为 `sakura-auth-server`(`/opt/sakura-auth-server`、`/var/lib/sakura-auth-server`);宝塔部署目录与 PM2 进程名改为 `/www/sakura-auth-server`、`sakura-auth-server`;三篇部署文档均附旧命名迁移步骤。
- 备份目录前缀改为 `sakura-auth-server-backup-*`,备份与恢复脚本同时识别历史 `sakuraid-backup-*`;恢复脚本用法、临时目录与文档中的打包示例文件名一并更名。
- GHCR 镜像地址不变(`ghcr.io/guyao146/sakura-auth-server`),镜像标题与许可证标签与 1.6.1 一致。
- 本次不更改认证、授权逻辑或数据库结构。

## 1.6.1

### 文档、项目名称与镜像发布

- 统一项目文档、页面署名、备份说明和镜像标题为 Sakura-Auth-Server,npm 标识改为小写 sakura-auth-server;保留部署配置名、服务名、数据路径、旧备份前缀及上游归属。
- 增加项目署名回归,确认中英文页面均使用正确名称且不覆盖自定义站点名。

- README 补充 GHCR 镜像地址、版本标签规则、Compose 部署、升级、备份与回滚说明。
- 整理默认 CI、可选浏览器及 UniLink 联调命令,澄清服务端渲染和本地增强脚本的边界。
- 更新环境变量样例和 Docker 部署文档中的镜像引用,明确当前发布平台为 linux/amd64。
- 修正文档中 PKCE 命令的跨平台依赖和参数引用,使用随机 state;备份示例生成的压缩包加入 Git / Docker 忽略规则。
- 显式设置 GHCR 镜像的项目名称、描述及 Sakura-License-1.2 许可证标签,避免被自动元数据覆盖为 NOASSERTION;本地构建的来源标签指向本仓库。
- 本次不更改认证、授权逻辑或数据库结构,保留 1.6.0 的界面与安全改进。

## 1.6.0

### 界面与可访问性

- 统一桌面与移动导航,按身份过滤管理入口,增加登录设备入口和当前页标记。
- 手机菜单使用原生 details,无需 JavaScript;补充跳转正文、键盘焦点及减少动画支持。
- 优化登录、注册、授权确认及应用门户在窄屏下的布局,合并其他登录方式分隔区。
- 修复门户姓名重复转义、emoji 首字和长文本显示;补充健康状态可访问名称及身份相关空状态。
- 增加零依赖 SSR 页面回归和可选 Chromium 布局、主题及键盘操作检查。

### 认证与运维安全

- 异步认证和写请求重新验证账号状态及会话,防止改密、禁用、MFA 或权限变化期间的竞态。
- 收紧密码计算队列和输入校验,修复畸形 Cookie 处理。
- 刷新令牌重放撤销同一授权链,令牌签发和凭据失效采用事务保护。
- 修复权限组迁移与旧字段同步;移除应用最后一个授权组后保持受限,不会自动向所有用户开放。
- Passkey 要求用户验证(UV),修复 origin 与计数器处理,支持计数器恒为零的认证器。
- 重跑配置向导的跳过表单补充 CSRF;CLI 改密统一撤销既有凭据。
- 恢复备份时先暂存并验证数据库,再切换数据目录;支持备份位于当前数据目录内。
- 安全和页面回归纳入 CI,保留 OAuth、冒烟及现有单元测试。
- 停止跟踪历史调试数据库,排除 Docker 构建上下文中的调试数据、工作树副本、环境配置和密钥。

### 升级注意事项

- 升级前备份数据目录,SQLite 仍按单实例运行。
- 仅支持用户在场(UP)、不支持用户验证(UV)的旧认证器不能再用于 Passkey 登录。
- 需要重新开放应用时应由管理员明确修改访问限制,删除最后一个权限组不再隐式开放。
- 浏览器回归不是完整的真机、跨浏览器或读屏器可访问性审计。
