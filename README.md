# cloud-r2pan 架构说明

一个 iOS 26 液态玻璃风格的网盘分享系统，基于 **Cloudflare Workers + R2 + D1** 构建。支持文件上传、分享链接（有效期 / 次数 / 访问密码）、流量限额、单 IP 限流与自动封禁、下载日志、登录审计、2FA 两步验证、Turnstile 人机验证，以及中英双语。

---

## 技术选型

| 层 | 技术 | 理由 |
|---|---|---|
| 计算 | **Cloudflare Workers** | 边缘计算，毫秒级冷启动，自带全球 CDN，零服务器运维 |
| 对象存储 | **Cloudflare R2** | 与 Worker 同生态，API 兼容 S3，无出站流量费 |
| 数据库 | **Cloudflare D1** | Serverless SQLite，支持 SQL 原子更新（用于下载计数扣减），自带索引优化 |
| 前端 | **原生 HTML + CSS + JavaScript** | 单文件无构建，`fetch` + `FormData` + 动态模板，零运行时开销 |
| 加密 | **Web Crypto API** | Worker 运行时原生支持（SHA-256、HMAC-SHA256、AES-GCM、HKDF），无第三方依赖 |
| 人机验证 | **Cloudflare Turnstile** | 与 Workers 同生态，零配置，前端 widget + 后端 siteverify 双重校验 |
| 2FA | **TOTP (RFC 6238)** | Google Authenticator 标准，Worker 原生 `crypto.subtle` 实现 HMAC-SHA1 |

---

## 目录结构

```
.
├── src/                        # Worker 源码（TypeScript）
│   ├── index.ts               # 入口 & 路由分发
│   ├── admin.ts               # 管理后台全部 REST API
│   ├── public.ts              # 公开分享页、下载、密码校验、Turnstile
│   ├── pages.ts               # HTML 页面 & 错误页渲染
│   ├── db.ts                  # D1 建表 + 幂等迁移
│   ├── settings.ts            # 站点配置读写 + 流量统计
│   ├── auth.ts                # Session 签发校验、IP 识别、登录限流
│   ├── crypto.ts              # 密码哈希、HMAC、AES-GCM、TOTP、恢复码
│   ├── ua.ts                  # User-Agent → 浏览器 / 系统
│   └── i18n.ts                # Accept-Language + 时区 → 中文 / 英文
├── public/                     # 前端页面（被 Worker 以静态资源形式内嵌）
│   ├── admin.html             # 管理后台 SPA（登录 + 六个 Tab）
│   └── share.html             # 分享页（下载 + 密码 + Turnstile）
└── package.json
```

**零运行时依赖**：除了 `typescript`、`wrangler`、`@cloudflare/workers-types` 三个开发依赖，生产代码不引入任何 npm 包。全部使用 Worker 原生 API。

---

## 路由架构

所有请求先进入 `index.ts` 做一次路由分发，路由规则简单清晰：

```
GET  /admin                → 管理后台 HTML
ANY  /api/admin/*          → admin.ts 统一处理（鉴权后分发到各子接口）
GET  /s/:token             → 分享页 HTML
GET  /s/:token/info        → 分享元信息 JSON（文件大小、状态、Turnstile 状态）
POST /s/:token/verify      → 密码校验 + Turnstile 校验 → 颁发下载令牌
GET  /s/:token/download    → 下载主流程（封禁 → 密码 → Turnstile → R2 Range）
其他                        → 404
```

管理后台 API 内部再按路径分发到十几个子接口（登录、文件增删、分享增删查改、封禁、日志、2FA、Turnstile、设置）。

---

## 数据库 Schema（D1）

共 **7 张表**，首次请求时由 `ensureSchema` 自动创建，旧库有幂等 `ALTER TABLE` 迁移：

| 表 | 主键 | 核心字段 | 用途 |
|---|---|---|---|
| `files` | `id` | `key`, `name`, `size`, `mime` | R2 对象的元数据索引 |
| `shares` | `id` | `file_id`, `expires_at`, `max_downloads`, `download_count`, `revoked`, `password_hash`, `password_cipher` | 分享链接。`password_cipher` 存可逆加密后的密码明文（AES-GCM），用于管理员事后查看 |
| `download_logs` | `id` | `share_id`, `file_id`, `ip`, `browser`, `os`, `country`, `bytes`, `created_at` | 每次下载一行，用于"单 IP 重复下载检测"和流量统计 |
| `login_logs` | `id` | `action`, `ip`, `browser`, `os`, `country`, `result`, `reason`, `created_at` | 管理员登录审计（成功 / 失败 / 限流 / 登出 / 恢复码） |
| `turnstile_visits` | `(ip, day)` | `count` | 每 IP 每天访问次数，复合主键按天自动归零，超过阈值触发 Turnstile |
| `banned_ips` | `ip` | `reason`, `banned_at`, `expires_at` | 自动封禁 + 到期自动解封 |
| `settings` | `key` | `value` | 全站 KV 配置（流量限额、Turnstile、2FA 等） |
| `traffic_stats` | `day` | `bytes`, `downloads` | 每日流量/下载汇总 |

**关键索引**：`idx_shares_file`、`idx_logs_share_ip`、`idx_logs_created`、`idx_login_logs_ip`、`idx_turnstile_day` —— 支撑高频查询在 D1 毫秒级响应。

---

## 安全实现亮点

### 管理登录（Session Cookie + 可选 2FA）

```
POST /api/admin/login { key }
  ├─ 密码错误 → 写 login_logs → 401
  ├─ 限流（同 IP 10 次 / 分钟）→ 写 login_logs → 429
  ├─ 密码正确 + 2FA 未开 → 签发 cookie → 200
  └─ 密码正确 + 2FA 已开
      ├─ 无 code → 返回 { need_2fa: true }
      └─ 带 code
          ├─ TOTP 6 位码 ✓ → 签发 cookie → 200
          └─ TOTP ✗ → 尝试恢复码：
              ├─ Cloudflare Secret totp_recovery → 通过（不消耗）→ 重置 2FA → 200
              └─ D1 存储的恢复码列表（SHA-256 hash）→ 通过（消耗一个）→ 重置 2FA → 200
```

- **Session**：`cd_admin` cookie，`HttpOnly + SameSite=Strict`，签名用 HMAC-SHA256
- **TOTP**：Worker 原生 `crypto.subtle` 实现 HMAC-SHA1（±90 秒窗口，共 3 个时间步）
- **恢复码**：两种来源——Cloudflare Secret（万能恢复，不消耗）和 D1 存储的 8 个消耗型码（只存 hash）
- **2FA 关闭时需二次输入 admin key**，防止被一键关掉

### 分享密码（双重存储）

- `password_hash`：加盐 SHA-256，只用于**验证**（不可逆）
- `password_cipher`：AES-GCM + HKDF 从 admin 密钥派生密钥，用于**事后查看**
- 分享列表 API 返回 `password_plain`（解密后的明文），前端提供 👁 显示/隐藏 + 📋 一键复制

### 下载授权（HMAC 令牌）

没有密码的分享直接 R2 流式输出；有密码的分享在 `POST /verify` 后颁发一个 `t=expiry.HMAC(admin, "token:expiry")` 的短时令牌（24h），下载时校验签名和过期时间。令牌本身不带密码，防重放能力通过签名 + 过期双重保障。

### Turnstile 人机验证（规则化触发）

- **4 种触发模式**：`off` / `on_share`（打开分享页时）/ `on_download`（点下载时）/ `both`（双重保险）
- **阈值规则**：每 IP 每天访问分享页超过 N 次后开始弹，默认 5 次，`turnstile_visits` 复合主键 `(ip, day)` 天然按天归零
- **双重校验**：前端 widget 渲染 + 后端 `siteverify` API 校验 token，缺其一直接 403
- **凭证三层兜底**：`turnstile_secret`（Cloudflare Secret，必须）→ `turnstile_sitekey`（Cloudflare Secret，可选）→ `sitekey_override`（D1 settings 里填）

### 下载流程（层层拦截）

```
handleDownload 执行顺序：
  1. banned_ips 表检查 → 过期自动解封
  2. 分享有效性 → 状态机（revoked / expired / maxed）
  3. 原子扣减 download_count（SQL UPDATE ... WHERE download_count < max_downloads）
  4. 密码校验（需要 HMAC 令牌）
  5. Turnstile 校验（on_download / both 模式）
  6. 流量限额（达上限暂停全部下载）
  7. 单 IP 重复下载检查 + 自动封禁
  8. R2 流式读取（支持 Range 断点续传）
  9. waitUntil 异步：写 download_logs + addTraffic
```

第 3 步是防并发超卖的关键：原实现用旧值拦截后才 +1，并发 20 个请求全过。修复后用 SQL 条件原子完成——`UPDATE ... WHERE download_count < max`，`changes=0` 即达上限。

---

## 前端架构

两个 HTML 页面，各自内嵌完整的 JavaScript SPA，零构建、零框架依赖：

### admin.html（管理后台）

单文件 2000+ 行，iOS 26 液态玻璃设计（毛玻璃 + 渐变球形背景 + 上升动画）。六个 Tab：

| Tab | 功能 |
|---|---|
| 概览 | 流量图表（每日 / 每周）、下载 / 分享 / 文件计数、最近活动 |
| 文件 | 上传（FormData 直传 Worker → R2）、删除（级联删 shares） |
| 分享 | 列表（文件大小、有效期、密码明文显示、下载状态徽章）、创建、撤销 |
| 日志 | 下载记录（IP / 浏览器 / OS / 国家 / 流量）、分页、搜索 |
| 封禁 | 封禁列表 + 解封 |
| 安全 | 登录审计日志（成功 / 失败 / 登出 / 2FA）、24h 失败告警、分页搜索 |
| 设置 | 站点标题、流量限额、单 IP 限流、2FA 开关、Turnstile 模式 / 阈值 / SiteKey |

### share.html（公开分享页）

访客看到的下载页。逻辑分支：

- 链接已撤销 / 过期 / 下载满 → 错误页
- 有密码 → 密码输入框 + 提交后颁发下载令牌
- Turnstile on_share 模式 + 超过阈值 → 页面加载即渲染 widget
- Turnstile on_download 模式 → 点下载按钮时才渲染 widget
- Turnstile both 模式 → 分享页弹一次 + verify 阶段再校验一次

底部有 GitHub Octocat 悬浮按钮（跳转到 `Admin666pro/cloud-oauth2`），iOS safe-area 适配。

---

## 流量统计

三个来源互相配合：

- **实时扣减**：每次下载后 `ctx.waitUntil(addTraffic(bytes))` 更新 `settings.traffic_used_bytes`（原子 + 月度重置）
- **每日汇总**：`traffic_stats(day)` 表记录每天的 `bytes` 和 `downloads`，概览页图表用
- **下载日志**：`download_logs` 保留完整明细，用于 IP 重复下载检测

月度自动重置逻辑：读 settings 时发现当前月份 ≠ 存储的 `trafficMonth`，立即重置 `trafficUsedBytes = 0` 并更新月份。

---

## 关键设计决策总结

| 决策 | 理由 |
|---|---|
| **原生 HTML + JS，不用 React/Vue** | Worker 对包大小敏感，SPA 纯 HTML 模板 + fetch 就能搞定，省了构建链路和运行时开销 |
| **Worker Secret 存一切敏感值** | `admin` / `turnstile_secret` / `turnstile_sitekey` / `totp_recovery` 都走 Secret，D1 只存可公开的配置和加密后的派生数据 |
| **密码双重存储（hash + cipher）** | hash 用于验证，cipher（AES-GCM）用于管理员事后查看。换 admin secret 后 cipher 会失效，但 hash 仍可验证 |
| **Session Cookie 而不是 JWT** | Worker 冷启动时间对加密无关，Cookie + SameSite 更适合浏览器场景 |
| **D1 复合主键做计数器** | `turnstile_visits(ip, day)` 天然按天归零，不需要定时任务清理旧数据 |
| **并发安全用 SQL 原子 UPDATE** | Worker 无锁，靠 SQL `WHERE download_count < max` 拦截超卖 |
| **waitUntil 异步写日志** | 下载主流程不等待日志写完就返回响应，降低下载首字节延迟 |
