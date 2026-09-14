# 完整部署指南

本项目有 **两种部署模式**，根据你的存储需求选择：

> 📌 **重要提示（必读）**
>
> 本项目的「资源绑定」（D1、R2、Analytics Engine）和「密钥/Secret」（admin 密码、Turnstile 密钥等）
> 都存储在 **Cloudflare 侧**，不属于代码仓库。因此：
>
> - **首次部署**：需要手动创建资源 + 配置 Secret（下面的准备工作和第五节）
> - **后续更新代码**：只需要跑 `npm run deploy`，已有的资源绑定和 Secret **会自动续上，不会丢失，也不需要重新配置**
> - 不要把 Secret 的明文值写到 `wrangler.jsonc` 或任何代码文件里

| 模式 | 存储后端 | 适用场景 | 费用 |
|---|---|---|---|
| **Cloudflare 全家桶** | R2（Worker binding 零配置） | 不想维护外部服务，Cloudflare 内部生态 | R2 免费 10GB + 零出口费 |
| **混合部署** | 任意 S3 兼容存储 | 想用 AWS S3 / Backblaze B2 / MinIO / 阿里云 OSS / 腾讯云 COS | 外部存储自费，Worker 免费 |

两种模式都可选绑定 **Workers Analytics Engine** 来启用「全球分布」Tab 的精确经纬度数据。

---

## 一、准备工作

### 1.1 安装 Wrangler CLI

```bash
# 全局安装（推荐）
npm install -g wrangler

# 或用 npx 临时执行
npx wrangler --version
```

### 1.2 登录 Cloudflare

```bash
npx wrangler login
```

浏览器弹出 Cloudflare 授权页面，确认后控制台会显示你的 Account ID（后面绑定资源要用）。

### 1.3 安装项目依赖

```bash
cd cloud-r2pan
npm install
```

---

## 二、基础资源创建（所有模式都需要）

### 2.1 创建 D1 数据库

```bash
npx wrangler d1 create cloud-r2pan
```

输出会包含 `database_id`（UUID 格式），**复制它**，后面要填进 `wrangler.jsonc`。

或者用控制台：**Cloudflare Dashboard → D1 → Create database → cloud-r2pan**

### 2.2（可选）创建 R2 Bucket

```bash
npx wrangler r2 bucket create cloud-r2pan
```

> 💡 如果打算用 **S3 兼容存储**（第 3 节），这步可以跳过。

### 2.3 创建 Worker

```bash
npx wrangler deploy
```

首次部署会因为没有绑定资源而 500 报错，**正常的**——接下来的绑定步骤会让它跑起来。

---

## 三、存储后端选择

### 方案 A：Cloudflare R2（推荐，零配置）

`wrangler.jsonc` 默认就是 R2 模式：

```jsonc
"r2_buckets": [
  { "binding": "r2", "bucket_name": "cloud-r2pan" }
]
```

**优点**：Worker 和 R2 同属 Cloudflare，访问零延迟、零出口费、D1/R2 在 Worker 里直接用 binding 调用。

### 方案 B：S3 兼容存储

如果你的数据已经存在 AWS S3 / Backblaze B2 / MinIO 里，或者想省掉 Cloudflare R2 的存储费用，可以切换到 S3 模式。

#### 3.1 在 `wrangler.jsonc` 中关闭 R2 binding（可选）

如果你只使用 S3，可以注释掉 `r2_buckets` 块来节省 Cloudflare 侧的检查开销。但保留它也没问题——代码会自动根据管理后台设置选择后端。

#### 3.2 在管理后台配置 S3 连接

部署后登录 `/admin` → **设置** → 找到「存储后端」区块：

| 字段 | 示例 | 说明 |
|---|---|---|
| **存储后端** | `s3` | 切换到 S3 模式 |
| **Endpoint** | `https://s3.amazonaws.com` | 你的 S3 服务地址 |
| **Region** | `us-east-1` | 存储所在区域 |
| **Bucket** | `my-files` | 存储桶名称 |
| **Access Key ID** | `AKIAIOSFODNN7EXAMPLE` | 访问密钥 ID（明文存） |
| **Secret Access Key** | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | 访问密钥（用 admin AES-GCM 加密存） |
| **Addressing Style** | `path` 或 `virtual` | Bucket 在 URL 中的位置。大多数用 `path`，AWS S3 两者都支持 |

#### 3.3 测试连通性

填完 S3 配置后，点**测试连接**按钮。Worker 会往指定 bucket 写一个临时文件、读回验证、再删除：

```
POST /api/admin/storage/test
body: { provider: "s3", endpoint, region, bucket, access_key_id, secret_key, addressing_style }
```

成功返回 `{ ok: true, head_ok: true, head_size: 36 }` 表示连通。失败会返回 `s3_test_failed` 和原始错误信息。

#### 3.4 常见 S3 服务配置参考

| 服务商 | Endpoint | Region 示例 | Addressing Style | 备注 |
|---|---|---|---|---|
| **AWS S3** | `https://s3.amazonaws.com` 或 `https://s3.{region}.amazonaws.com` | `us-east-1` | `path` 或 `virtual` | 费用：$0.023/GB 存储 + $0.09/GB 出口费 |
| **Backblaze B2** | `https://s3.us-west-002.backblazeb2.com` | `us-west-002` / `us-east-005` / `eu-central-003` | `path` | 费用最低：$0.006/GB 存储 + $0.01/GB 出口费 |
| **Cloudflare R2** | `https://{account-id}.r2.cloudflarestorage.com` | `auto` | `path` | 出口费 = $0（推荐） |
| **阿里云 OSS** | `https://oss-cn-hangzhou.aliyuncs.com` | `cn-hangzhou` / `cn-shanghai` / `cn-beijing` | `virtual` | 国内访问快 |
| **腾讯云 COS** | `https://cos.ap-guangzhou.myqcloud.com` | `ap-guangzhou` / `ap-shanghai` | `virtual` | 国内访问快 |
| **七牛云 Kodo** | `https://s3-cn.qiniu.com` | `cn-z0` / `cn-z1` / `cn-na0` | `virtual` | 性价比高 |
| **MinIO（自建）** | `http://your-minio-server:9000` | `us-east-1`（任意） | `path` | 内网部署，注意 Worker 跨域 |
| **DigitalOcean Spaces** | `https://nyc3.digitaloceanspaces.com` | `nyc3` / `sfo3` / `fra1` | `path` | 带 CDN 加速 |
| **Wasabi** | `https://s3.us-west-1.wasabisys.com` | `us-west-1` | `path` | 无免费 tier 但非常便宜 |

> ⚠️ **跨网段访问注意**：Cloudflare Workers 是公网出口，访问内网 MinIO 等需要通过 Cloudflare Tunnel。

#### 3.5 AWS Signature V4 实现说明

项目内置了完整的 AWS Signature V4 签名（见 `src/storage.ts`），零 npm 依赖。签名覆盖以下操作：
- `PutObject` — 上传文件
- `GetObject` — 下载文件（支持 Range 断点续传）
- `DeleteObject` — 删除文件
- `HeadObject` — 获取元数据

---

## 四、Workers Analytics Engine（全球分布分析）

### 4.1 启用 Analytics Engine

`wrangler.jsonc` 里默认已配置：

```jsonc
"analytics_engine_datasets": [
  { "binding": "analytics", "dataset": "r2pan_downloads" }
]
```

**首次部署**时 Cloudflare 会自动创建 `r2pan_downloads` 数据集（在 **Dashboard → Workers → Analytics Engine** 可以看到）。

### 4.2 数据写入方式

每次下载完成后，Worker 会自动写入一条数据点：

```typescript
env.analytics.writeDataPoint({
  blobs: [
    country,          // 国家代码 US/CN/JP...
    file_name,        // 文件名
    browser,          // 浏览器
    os,               // 操作系统
    share_id,         // share token
    activation_code,  // 激活码（或 "none"）
    latitude,         // CF-IPLatitude 头提供
    longitude,        // CF-IPLongitude 头提供
    storage_provider, // r2 或 s3
  ],
  doubles: [bytes, 1],  // 字节数 + 下载计数（恒为 1）
  indexes: [share_id],
});
```

> 💡 写入是 **fire-and-forget** 的，不会阻塞下载响应。Worker isolation 重启也不影响已有数据。

### 4.3 SQL API 查询（可选）

如果你想做更复杂的分析，可以用 Cloudflare Analytics Engine SQL API：

```bash
# 设置 Cloudflare API Token（需要 Analytics Engine:Read 权限）
export CF_API_TOKEN="your-api-token"
export CF_ACCOUNT_ID="your-account-id"

# 查询过去 7 天各国家下载分布
curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/analytics_engine/sql" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT blob1 AS country, COUNT(*) AS downloads, SUM(double1) AS bytes FROM r2pan_downloads WHERE timestamp > NOW() - INTERVAL '\''7'\'' DAY GROUP BY country ORDER BY downloads DESC"}'
```

### 4.4 未绑定 Analytics Engine 时

全球分布 Tab 会自动降级使用 D1 的 `download_logs` 表，功能基本相同（国家统计、下载量、流量、独立 IP），只是没有精确经纬度数据。

### 4.5 关于腾讯云 Analytics Engine

如果你指的是腾讯云的数据分析产品，本项目暂未直接集成。建议使用 Cloudflare Workers Analytics Engine 搭配 CF Worker，因为：
1. 同属 Cloudflare 生态，API 原生集成
2. 零额外付费额度
3. 数据写入不影响 Worker 性能

如果一定要用腾讯云 Analytics Engine，可以通过 Worker 的 `fetch()` 调用其 SDK API 作为 subrequest 上报数据。

---

## 五、设置 Secret

```bash
npx wrangler secret put admin
# 输入你的管理密钥

npx wrangler secret put totp_recovery    # 可选：2FA 万能恢复码
npx wrangler secret put turnstile_secret # 可选：Turnstile 人机验证
npx wrangler secret put turnstile_sitekey # 可选
```

### 完整 Secret 列表

| 名称 | 必填 | 用途 |
|---|---|---|
| `admin` | ✅ | 管理后台密码 + AES-GCM 加密密钥 |
| `totp_recovery` | ❌ | 2FA 万能恢复码（Cloudflare Secret 优先于 D1 恢复码） |
| `turnstile_sitekey` | ❌ | Turnstile 前端 SiteKey |
| `turnstile_secret` | ❌ | Turnstile 后端 Secret |

> 💡 S3 的 Access Key 和 Secret Key **不走 Cloudflare Secret**，存在 D1 `settings` 表里，Secret Access Key 用 `admin` 密钥 AES-GCM 加密。这样避免了在 Cloudflare 控制台管理多套 Secret。

> ✅ **这一节只需要做一次**。Cloudflare Secrets 存储在 Cloudflare 服务器上，不属于代码仓库。
> 以后更新代码跑 `npm run deploy` 时，已有的 Secret **完全不会被影响，自动续上，不会丢失**。
> 要修改密码也不需要重新部署——直接在 Cloudflare 后台改 Secret 即可，Worker 下次请求就会读到新值。

---

## 六、正式部署

```bash
npm run deploy
```

首次部署完成后，**首次访问时自动建表**（不需要手动 SQL 迁移）：
- 8 张 D1 表（files, shares, download_logs, login_logs, turnstile_visits, banned_ips, settings, traffic_stats）
- OAuth2 相关 2 张表（oauth_states, oauth_providers）
- 激活码 2 张表（activation_plans, activation_codes）
- Analytics Engine dataset（首次写入时创建）

### 切换 S3 存储的完整流程

1. 先用默认 R2 模式部署一次（让 D1 自动建表）
2. 登录 `/admin`
3. 点「文件」Tab → **上传测试文件**（走 R2，验证 Worker 正常）
4. 点「设置」Tab → 找到「存储后端」区块
5. 选择 **s3**，填写 S3 endpoint / region / bucket / AK / SK
6. 点 **保存** → 点 **测试连接**（如果用刚填的配置就用 settings 里已存的值）
7. 成功后，**下次上传的文件会写入 S3，下载也从 S3 读**
8. 已存在 R2 里的文件仍从 R2 读取（如果 R2 binding 还在）。如果完全移除 R2 binding，旧文件的 key 还在 D1 里，但 R2 中已无对象 → 下载会报 404。可以用 cleanup API 清理孤儿记录。

### 迁移 R2 数据到 S3

项目当前不提供一键迁移脚本（R2 有 S3 兼容 API 但 R2 Worker binding 无法直接 S3 客户端访问）。建议用：

1. **rclone**：`rclone copy cloudflare-r2:bucket/path s3-alias:bucket/path`
2. **awscli**：`aws s3 cp --recursive s3://r2-bucket/files/ s3://new-s3-bucket/files/`（需要配置 R2 为 S3 endpoint）
3. **Cloudflare R2 一键迁移**：Dashboard → R2 → Migration Tool → 选择目标 S3 存储桶

迁移完成后在 Worker 设置里切换 storage_provider 即可。

---

## 七、管理后台功能总览

### 各 Tab 功能

| Tab | 说明 |
|---|---|
| **概览** | 流量环形图 + 14 天下载趋势 + 最近下载 |
| **文件** | 上传 / 删除 / 查看下载量。存储后端切换后自动写入 S3 |
| **分享** | 创建带有效期 / 次数 / 密码的分享链接，市场页开关 |
| **记录** | 下载日志分页 + 搜索 + 清理 |
| **封禁** | 手动封禁 / 解封 IP |
| **🌍 全球分布** | **本次新增** — ECharts 世界地图 + 国家下载排行 Top 20 |
| **激活码** | 批量生成带独立额度的激活码 |
| **安全** | 登录审计日志 + 2FA 管理 |
| **设置** | Site Title / 流量限额 / 单 IP 限流 / Turnstile / OAuth2 / **存储后端** |

### 存储后端相关 API

| API | 方法 | 说明 |
|---|---|---|
| `/api/admin/storage/test` | POST | 测试 S3 连通性（write→read→delete 往返） |
| `/api/admin/settings` | PUT | 更新 `storage_provider`、`s3_*` 系列字段 |
| `/api/admin/files/upload` | POST | 上传（自动路由到当前选择的存储后端） |
| `/api/admin/files/:id` | DELETE | 删除（D1 记录 + 存储对象级联删除） |
| `/api/admin/shares/cleanup` | POST | 清理失效分享 + 孤儿存储对象 |

### 全球分布相关 API

| API | 方法 | 说明 |
|---|---|---|
| `/api/admin/global/stats?since_days=N` | GET | 按国家聚合下载量、字节数、独立 IP 数 |

### Analytics Engine SQL 查询参考

```sql
-- 过去 24h 下载最多的文件
SELECT blob2 AS file_name, COUNT(*) AS downloads, SUM(double1) AS bytes
FROM r2pan_downloads
WHERE timestamp > NOW() - INTERVAL '24' HOUR
GROUP BY blob2
ORDER BY downloads DESC
LIMIT 20;

-- 按存储后端统计（切换到 S3 后用来验证）
SELECT blob9 AS backend, COUNT(*) AS downloads
FROM r2pan_downloads
WHERE timestamp > NOW() - INTERVAL '7' DAY
GROUP BY blob9;

-- 精确经纬度散点（CF-IPLatitude/Longitude 头提供）
SELECT blob7 AS lat, blob8 AS lng, blob1 AS country, COUNT(*) AS downloads
FROM r2pan_downloads
WHERE timestamp > NOW() - INTERVAL '1' DAY
  AND blob7 != '' AND blob8 != ''
GROUP BY blob7, blob8, blob1;
```

---

## 八、本地开发

```bash
echo 'admin=本地测试密码' > .dev.vars
npm run dev
```

- `wrangler dev` 会自动创建本地 D1 和 R2 模拟实例
- 本地默认使用 R2 模式（miniflare 模拟）
- 要测试 S3：在 `.dev.vars` 里加 `CF_ACCOUNT_ID=xxx`、`S3_ACCESS_KEY_ID=xxx`、`S3_SECRET_ACCESS_KEY=xxx`，然后在管理后台切到 S3 模式

---

## 九、排查指南

| 现象 | 可能原因 | 解决方案 |
|---|---|---|
| 上传报 500 "Storage write failed" | S3 endpoint/region/bucket 配置错误；或网络不通 | 管理后台 → 设置 → 测试连接 |
| 下载报 404 文件不存在 | 存储里没这个对象（迁移遗漏或被清理） | 用 `/api/admin/shares/cleanup` 清理孤儿 |
| 下载报 502 "Storage Error" | S3 临时不可达 / 网络抖动 | 等待或切换回 R2 |
| 全球分布 Tab 空数据 | Analytics Engine 还没写入 | 部署后多下载几次，数据写入有延迟（分钟级） |
| Analytics Engine SQL 查不到数据 | dataset 名字拼错；或 `analytics_engine_datasets` 没配 | 检查 `wrangler.jsonc`，首次部署后自动创建 |
| S3 测试连接超时 | Worker 无法访问 S3 endpoint | 用 Workers VPC Tunnel 或确认 endpoint 是公网可达的 |
| R2 binding 报错 `r2 is not defined` | 注释掉了 `r2_buckets` 但 settings 里还是 `storage_provider=r2` | 要么恢复 R2 binding，要么切到 S3 模式 |

---

## 十、费用说明

| 组件 | 费用 | 免费额度 |
|---|---|---|
| **Workers** | $5/百万次请求 | 100,000 次/天 |
| **R2 Bucket** | $0.015/GB 存储 + $0 出口 | 10GB 存储 + 1M Class A ops + 10M Class B ops / 月 |
| **D1** | 随 Workers 包含 | 50MB 免费存储空间 |
| **Analytics Engine** | 包含在 Workers 套餐 | 1 亿数据点 / 月 |
| **Turnstile** | 免费 | 无限 |
| **外部 S3** | 取决于服务商 | — |

**费用最低组合**：Worker（免费额度内）+ R2（10GB 免费）+ Analytics Engine（1亿点免费），完全可以跑一个小型分享站 **零费用**。

---

## 十一、项目结构总览（修改后）

```
cloud-r2pan/
├── src/
│   ├── index.ts           # 入口 + 路由分发
│   ├── admin.ts           # 管理后台 REST API（含存储测试 + 全球分布统计）
│   ├── public.ts          # 公开下载流程（含 Analytics Engine 写入）
│   ├── storage.ts         # ⭐ 新增 — StorageProvider 抽象 + R2/S3 双后端
│   ├── settings.ts        # Settings 读写（新增 s3_* 字段）
│   ├── db.ts              # D1 Schema + 迁移
│   ├── crypto.ts          # AES-GCM / SHA256 / HMAC-SHA256 / TOTP
│   ├── auth.ts            # Session + IP 限流
│   ├── pages.ts           # HTML 渲染（CSP 已放行 CDN）
│   ├── oauth_handlers.ts  # OAuth2 HTTP 层
│   ├── oauth.ts           # OAuth2 协议实现
│   ├── codes.ts           # 激活码
│   ├── types.ts           # Env + 所有 D1 表类型
│   ├── ua.ts              # User-Agent 解析
│   └── i18n.ts            # 中英双语
├── public/
│   ├── admin.html         # 管理后台（⭐ 新增全球分布 Tab）
│   ├── share.html         # 分享页
│   └── market.html        # 下载市场页
├── wrangler.jsonc         # Worker 配置（⭐ 新增 Analytics Engine 绑定）
└── DEPLOY-S3.md           # ⭐ 本部署文档
```
