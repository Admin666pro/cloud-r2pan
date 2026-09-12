# 部署指南

cloud-r2pan 是一个 Cloudflare Workers 网盘分享系统，使用 TypeScript + 原生 HTML/JS 零构建架构，R2 存储文件，D1 存储元数据。

---

## 一、环境要求

| 项目 | 要求 |
|---|---|
| 运行平台 | Cloudflare Workers（免费额度够用） |
| 开发机 Node.js | ≥ 18，推荐 20 或 22 |
| 项目依赖 | 仅 3 个 devDependency：`wrangler`、`@cloudflare/workers-types`、`typescript`；**生产零运行时依赖** |
| 单文件上传上限 | 100 MB（Worker 请求体限制） |

---

## 二、前置准备（一次性）

### 2.1 安装依赖

```bash
git clone <你的仓库地址>
cd cloud-r2pan
npm install
```

### 2.2 登录 Cloudflare

```bash
npx wrangler login
```

浏览器会弹出授权页面，确认后 `wrangler` 本地保存令牌。

### 2.3 创建 R2 存储桶

```bash
npx wrangler r2 bucket create cloud-r2pan
```

### 2.4 创建 D1 数据库

```bash
npx wrangler d1 create cloud-r2pan
```

输出里会有一行 `database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`，**记下来**，下一步绑定时需要。

### 2.5 创建 Worker

```bash
npx wrangler init cloud-r2pan
```

或直接跳到第 3 步，第一次 `wrangler deploy` 会自动创建。

---

## 三、配置绑定（**核心步骤**）

本项目的 **R2、D1、Secret 绑定不写在 `wrangler.jsonc` 里**（真实资源名和密钥永不进仓库），全部在 Cloudflare 控制台配置。代码里固定引用的绑定名：

| 绑定名 | 类型 | 说明 | 是否必填 |
|---|---|---|---|
| `r2` | R2 Bucket | 实际存文件的桶 | ✅ 必填 |
| `db` | D1 Database | 元数据、日志、设置 | ✅ 必填 |
| `admin` | Secret | 管理后台登录密钥 | ✅ 必填 |
| `totp_recovery` | Secret | 2FA 万能恢复码 | ❌ 可选 |
| `turnstile_sitekey` | Secret | Turnstile 前端 sitekey | ❌ 可选 |
| `turnstile_secret` | Secret | Turnstile 后端 secret | ❌ 可选（不配则 Turnstile 整体禁用） |

### 3.1 命令行配置（推荐）

```bash
# R2 绑定（绑定名必须是 r2，桶名用你刚创建的）
npx wrangler r2 binding put r2 --bucket-name cloud-r2pan

# D1 绑定（绑定名必须是 db，database_id 用第 2.4 步的值）
npx wrangler d1 binding put db --database-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx --database-name cloud-r2pan
```

> ⚠️ 如果 `wrangler r2 binding` / `wrangler d1 binding` 在你当前 wrangler 版本不可用，请直接用控制台（见 3.2）。

### 3.2 控制台配置（备选）

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)
2. **Workers & Pages** → 找到 `cloud-r2pan` Worker → 点进去
3. **Settings** → **Bindings** → **Add binding**，依次添加：
   - **R2 Bucket**：Variable name 填 `r2`，选 `cloud-r2pan`
   - **D1 Database**：Variable name 填 `db`，选 `cloud-r2pan`

### 3.3 设置 Secret

```bash
# 必填：管理后台密钥（会交互式输入，输入内容不回显）
npx wrangler secret put admin

# 可选：2FA 万能恢复码（忘记 Authenticator 时可直接登录并重置 2FA）
npx wrangler secret put totp_recovery

# 可选：Turnstile（Cloudflare 控制台申请：Turnstile → Add site → 拿 sitekey 和 secret key）
npx wrangler secret put turnstile_sitekey
npx wrangler secret put turnstile_secret
```

控制台方式：同一 Worker → **Settings** → **Variables and Secrets** → **Add** → **Secret**。

---

## 四、部署

```bash
npm run deploy
# 等价于：npx wrangler deploy
```

首次部署会自动在 Cloudflare 创建 Worker，之后每次运行都是更新代码。

### 访问地址

部署成功后输出里会有 `https://cloud-r2pan.<你的账号>.workers.dev`：

| 路径 | 用途 |
|---|---|
| `/` | 自动 302 跳转到 `/admin` |
| `/admin` | 管理后台 SPA（用第 3.3 步的 `admin` 密钥登录） |
| `/s/:token` | 公开分享页（访客下载入口） |

### 数据库建表

**无需手动导入 SQL**。首次访问分享页或管理 API 时，Worker 会执行 `ensureSchema`：

- `CREATE TABLE IF NOT EXISTS` 保证幂等，反复执行安全
- 8 张表：files、shares、download_logs、login_logs、turnstile_visits、banned_ips、settings、traffic_stats
- 旧库有 `ALTER TABLE ADD COLUMN` 迁移

---

## 五、本地开发预览

```bash
npm run dev
# 等价于：npx wrangler dev
```

启动后默认地址：`http://localhost:8787`。

本地 D1/R2 由 Miniflare 模拟，不会写真实数据。如需本地登录，在项目根目录新建 `.dev.vars`：

```bash
echo 'admin=本地测试密码' > .dev.vars
```

> ⚠️ `.gitignore` 已包含 `.dev.vars`，**不要提交**。

---

## 六、自定义域名（可选）

Worker → **Settings** → **Domains & Routes**：

- **Worker Domain**：直接绑一个域名子域（如 `pan.yourdomain.com`）
- **Routes**：更灵活，可配 `yourdomain.com/* → cloud-r2pan`

要求 DNS 在 Cloudflare 托管。

---

## 七、GitHub Actions CI/CD（可选）

在仓库根目录新建 `.github/workflows/deploy.yml`：

```yaml
name: Deploy Worker

on:
  push:
    branches: [main]
  workflow_dispatch:        # 允许在 GitHub 页面手动触发

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm

      - run: npm ci

      - name: Deploy to Cloudflare Workers
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CF_API_TOKEN }}
          command: deploy
```

### 需要的 GitHub Secrets

| 名称 | 类型 | 获取方式 |
|---|---|---|
| `CF_API_TOKEN` | Secret | Cloudflare Dashboard → My Profile → API Tokens → Create Token，选 "Edit Cloudflare Workers" 模板，并额外勾选 R2、D1 权限 |

> `admin`、`totp_recovery`、`turnstile_*` 等 Secret 建议**不要**放进 workflow。它们属于 Cloudflare Secret，在 Cloudflare 控制台配置一次即可持久化，CI 只负责代码部署。

---

## 八、运维命令速查

```bash
# 查看线上实时日志（排查报错必备）
npm run tail

# 重置本月流量（管理后台设置里也能点）
# 直接调 API：POST /api/admin/traffic/reset

# 查看所有绑定
npx wrangler bindings list

# 删除 Secret（会立即生效，无法恢复）
npx wrangler secret delete admin

# 导出 D1 数据（需要 d1-database-id）
npx wrangler d1 export cloud-r2pan --output dump.sql
```

---

## 九、常见问题排查

### 首页 500 / D1 报错
**症状**：打开 `/admin` 返回 500，tail 日志里有 `Error: D1 binding not found`

**原因**：Worker 里没绑 D1，或绑定名不叫 `db`

**修复**：控制台 → Bindings → 检查 D1 绑定，Variable name 必须是 `db`

---

### 登录一直失败
**症状**：管理后台输入密码后一直提示"管理密钥错误"

**原因**：Secret `admin` 没设，或输入的值和 `wrangler secret put admin` 时输入的不一致

**排查**：
```bash
# 检查本地是否真的已设置
npx wrangler secret list
```

---

### 上传文件后 R2 里找不到
**症状**：管理后台显示文件已上传，但 Cloudflare R2 控制台看不到对象

**排查**：
1. 确认 R2 绑定 Variable name 是 `r2`
2. 确认绑定到正确的桶（不是空桶或其他桶）
3. tail 日志看有没有 R2 Put 成功日志

---

### 分享链接 404 或下载报错
**症状**：`/s/xxxxx` 打不开或点下载失败

**排查**：
- **404**：token 不存在，或链接已撤销（revoked）
- **已过期**：`expires_at` 过了
- **下载满**：`download_count >= max_downloads`
- **Turnstile 报错**：tail 搜 `turnstile`，看是 token 没传还是 siteverify 返回 errorcodes

---

### D1 / R2 绑定名为什么不写进 wrangler.jsonc？

本项目选择 **控制台手动配置绑定** 而非 `wrangler.jsonc` 声明，原因：

1. **database_id、桶名、Secret 都属于真实生产值**，不应该进仓库
2. `.gitignore` 虽然能挡 `.dev.vars`，但挡不住团队成员误提交生产配置
3. 控制台配置一次即可，wrangler.jsonc 保持只描述构建规则（TypeScript + HTML 文本模块）

如果你更喜欢命令行风格，可以把下面这段加回 `wrangler.jsonc`：

```jsonc
"d1_databases": [{
  "binding": "db",
  "database_name": "cloud-r2pan",
  "database_id": "你的真实 database_id"
}],
"r2_buckets": [{
  "binding": "r2",
  "bucket_name": "cloud-r2pan"
}]
```

但这样 `database_id` 会出现在 git 历史里，需自行评估。

---

### Worker 报 "Turnstile Required" 403

说明管理员在设置里开了 Turnstile（on_download 或 both 模式），但下载请求没带 `?cf=` 参数。**正常流程**下前端会在点下载时自动渲染 Turnstile widget 并把 token 拼到 URL 上，出现这个报错通常是：

- 前端没加载 Turnstile 脚本（浏览器广告拦截器）
- `turnstile_secret` 已过期或配错

排查：tail 搜 `siteverify` 看后端返回了什么 errorcodes（如 `invalid-input-secret`、`timeout-or-duplicate`）。

---

### 2FA 启用后 Google Authenticator 扫不了

确保二维码里的 URI 格式正确：`otpauth://totp/cloud-r2pan%3A%20admin?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30`。用手机相机直接扫，或手动在 Authenticator 里输入 secret。

如果 Authenticator 里时间漂移太离谱，验证时会连续失败 3 次，尝试用 **恢复码** 登录并重置 2FA。

---

## 十、升级注意事项

Worker 代码升级走 `npm run deploy`，数据库由 `ensureSchema` 自动处理：

- 新增列：`ALTER TABLE ADD COLUMN` 幂等迁移，不会丢数据
- 新增表：`CREATE TABLE IF NOT EXISTS`
- **不自动删列 / 删表**：Worker 代码不再引用的旧数据会留在库里，不会影响运行

建议每次升级前备份 D1：`npx wrangler d1 export cloud-r2pan --output backup-$(date +%Y%m%d).sql`
