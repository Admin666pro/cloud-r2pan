# 部署步骤

## 1. 安装 & 登录

```bash
npm install
npx wrangler login
```

## 2. 创建资源

```bash
# R2 存储桶
npx wrangler r2 bucket create cloud-r2pan

# D1 数据库（记下输出里的 database_id）
npx wrangler d1 create cloud-r2pan
```

## 3. 绑定资源（Cloudflare 控制台）

Worker → Settings → Bindings → Add binding：

| Variable name | 类型 | 选择 |
|---|---|---|
| `r2` | R2 Bucket | cloud-r2pan |
| `db` | D1 Database | cloud-r2pan |

## 4. 设置 Secret

```bash
# 必填：管理后台密码
npx wrangler secret put admin

# 可选：2FA 万能恢复码
npx wrangler secret put totp_recovery

# 可选：Turnstile（Cloudflare 控制台申请 sitekey / secret）
npx wrangler secret put turnstile_sitekey
npx wrangler secret put turnstile_secret
```

## 5. 部署

```bash
npm run deploy
```

部署后访问 `https://cloud-r2pan.<账号>.workers.dev/admin`，用第 4 步设置的 `admin` 密码登录。

数据库首次访问时自动建表，无需手动 SQL。

## 本地开发

```bash
# .dev.vars 里写 admin=测试密码
echo 'admin=xxx' > .dev.vars
npm run dev
```

## 日志

```bash
npm run tail
```
