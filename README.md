# Crystal Drive

iOS 26 液态玻璃风格网盘分享系统，基于 **Cloudflare Workers + R2 + D1** 构建。
支持文件上传、分享链接（有效期/次数/访问密码）、流量限额、单 IP 限流与自动封禁、下载日志、中英双语。

---

## 一、项目结构

```
.
├── src/
│   ├── index.ts        # 入口与路由
│   ├── admin.ts        # 管理后台 API
│   ├── public.ts       # 公开分享/下载/密码校验
│   ├── pages.ts        # 页面渲染（后台页、分享页、错误页）
│   ├── db.ts           # D1 建表与迁移
│   ├── settings.ts     # 站点配置与流量统计
│   ├── auth.ts         # 登录会话 / IP 识别
│   ├── ua.ts           # 浏览器与系统解析
│   └── i18n.ts         # 后端语言检测（Accept-Language + 时区）
├── public/
│   ├── admin.html      # 管理后台（前端）
│   └── share.html      # 分享页（前端）
├── wrangler.jsonc      # Worker 配置与绑定
├── .dev.vars           # 本地开发环境变量（勿提交！）
└── package.json
```

---

## 二、绑定名称（Binding 一览）

这些名称在代码中直接使用，改绑定名需同步改代码，请保持一致。

| 绑定名称 | 类型 | 资源名称 | 作用 |
|---|---|---|---|
| `BUCKET` | R2 Bucket | `crystal-drive` | 存储上传的文件对象 |
| `DB` | D1 Database | `crystal-drive` | 元数据、分享、日志、配置、流量统计 |
| `ADMIN_KEY` | Secret（环境变量） | — | 管理后台登录密钥 |

> Worker 名称：`crystal-drive`；入口：`src/index.ts`。

---

## 三、首次部署准备（一次性）

### 0. 前置条件
- 一个 [Cloudflare](https://dash.cloudflare.com) 账户
- 本地安装 [Node.js](https://nodejs.org)（≥ 18，推荐 20/22）与 npm
- 本项目依赖：`npm install`（只需 `wrangler` + `@cloudflare/workers-types` + `typescript`）

### 1. 登录 Cloudflare（会打开浏览器授权）
```bash
npx wrangler login
```

### 2. 创建 R2 存储桶
```bash
npx wrangler r2 bucket create crystal-drive
```

### 3. 创建 D1 数据库，并记录返回的 `database_id`
```bash
npx wrangler d1 create crystal-drive
```
输出中会出现类似：
```
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### 4. 把 `database_id` 填进 `wrangler.jsonc`
打开 [wrangler.jsonc](wrangler.jsonc)，把 `d1_databases[].database_id` 从占位符 `LOCAL_PLACEHOLDER` 改成上一步真实值：
```jsonc
"d1_databases": [
  { "binding": "DB", "database_name": "crystal-drive", "database_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" }
]
```
> 数据库的建表（`files` / `shares` / `download_logs` / `banned_ips` / `settings` / `traffic_stats`）会在首次请求时由 `ensureSchema` 自动创建，无需手动导入 SQL。

### 5. 设置管理后台密钥 `ADMIN_KEY`
```bash
# 交互式输入（输入的内容不会被回显）
npx wrangler secret put ADMIN_KEY
```
> `ADMIN_KEY` 是登录管理后台的唯一密钥，请务必设置，并妥善保管。

---

## 四、部署指令（手动部署）

### 本地开发预览
启动本地开发服务器（本地会用 `.dev.vars` 里的 `ADMIN_KEY`，D1/R2 为本地模拟）：
```bash
npm run dev
# 或 npx wrangler dev
```
默认地址：`http://localhost:8787`（首页会自动跳转到 `/admin` 管理后台）。

### 正式部署到 Cloudflare
```bash
npm run deploy
# 或 npx wrangler deploy
```
等价于 `npx wrangler deploy`，会使用 [wrangler.jsonc](wrangler.jsonc) 的配置打包部署 worker `crystal-drive`。

### 查看线上日志
```bash
npm run tail
# 或 npx wrangler tail
```

### 首次访问
部署成功后：
- 管理后台：`https://crystal-drive.<你的账号>.workers.dev/admin`
- 用 `ADMIN_KEY` 登录
- 分享页格式：`https://crystal-drive.<你的账号>.workers.dev/s/<token>`

---

## 五、图形化 Web 部署（Cloudflare 控制台）

这套流程全部在**浏览器里的 Cloudflare 控制台（Dashboard）**完成，适合不熟悉命令行、或想用网页界面管理资源的人。它和上面的命令行部署是**等价、二选一**的关系。

> ⚠️ 提醒：本项目源码是 **TypeScript + 多个 `.html` 文本模块**（`wrangler.jsonc` 里配了 `rules`），Cloudflare 网页编辑器无法直接打包这类工程。因此**「建 Worker + 建资源 + 配绑定 + 配密钥」用网页完成**，最后把代码推上去仍需一次 `npm run deploy`（详见步骤 5.6）。这一步只依赖你电脑上已有的 npm，资源管理平时都在网页端看。

### 5.0 准备
- 一个已登录的 [Cloudflare 控制台](https://dash.cloudflare.com)

### 5.1 创建 R2 存储桶
1. 左侧菜单 → **R2** → **Create bucket**
2. 名称填 `crystal-drive` → 选区域 → **Create bucket**

### 5.2 创建 D1 数据库
1. 左侧菜单 → **D1** → **Create database**
2. 名称填 `crystal-drive` → **Create**
3. **复制页面上的 `database_id`**（形如 UUID），下面绑定要用

### 5.3 创建 Worker
1. 左侧菜单 → **Workers & Pages** → **Create** → **Worker**
2. 名称填 `crystal-drive` → **Deploy** → 进入该 Worker 页面

### 5.4 添加绑定（Bindings）
1. 在该 Worker 里 → **Settings** → **Bindings** → **Add binding**
2. 添加 **R2 Bucket**：
   - **Variable name** 填 `BUCKET`（绑定名固定，勿改）
   - R2 bucket 选 `crystal-drive`
3. 添加 **D1 Database**：
   - **Variable name** 填 `DB`（绑定名固定，勿改）
   - 选 `crystal-drive`（或直接粘贴第 5.2 步的 `database_id`）

### 5.5 设置管理密钥 ADMIN_KEY
1. 同一个 Worker → **Settings** → **Variables and Secrets** → **Add** → **Secret**
2. Variable name 填 `ADMIN_KEY`，值填你的管理密码 → **Deploy**

### 5.6 上传代码（网页版最后一步）
本地一次命令完成代码部署（网页端负责资源/绑定/密钥）：
```bash
cd 项目目录
npm install
npm run deploy
```

### 5.7 访问
- 管理后台：`https://crystal-drive.<你的账号>.workers.dev/admin`（用 `ADMIN_KEY` 登录）
- 分享页格式：`https://crystal-drive.<你的账号>.workers.dev/s/<token>`

> 日常用网页端查看：**Workers → crystal-drive → Console / Logs / Metrics**（日志、监控）、**Settings → Variables/Bindings**（改密钥/绑定）。

---

## 六、工作流部署（CI/CD · GitHub Actions）

项目目前**尚未**包含工作流文件。以下为推荐配置，可按需创建
`.github/workflows/deploy.yml`。

工作机制：
1. 推送到 `main` 分支（或手动触发 `workflow_dispatch`）时自动部署
2. CI 内用 `cloudflare/wrangler-action@v3` 调用 `wrangler deploy`
3. D1 迁移（占位符注入）由 `sed` 在 CI 中完成

### 5.1 需要在 GitHub 配置的 Secret / Variable

| 名称 | 类型 | 说明 |
|---|---|---|
| `CF_API_TOKEN` | Secret | Cloudflare API 令牌，需有 `Workers Scripts: Edit`、`Workers R2`、`Workers D1` 权限 |
| `CF_ACCOUNT_ID` | Secret | 你的 Cloudflare 账户 ID（账户首页右下角可查） |
| `D1_DATABASE_ID` | Secret | 上面第 3 步 D1 的 `database_id`，用于 CI 替换占位符 |
| —— | —— | **`ADMIN_KEY` 建议在 CI 外手动设置一次**（见下方说明） |

> 获取 `CF_API_TOKEN`：Cloudflare Dashboard → 右上角「My Profile」→ 「API Tokens」→ 创建，模板选
> 「Edit Cloudflare Workers」，再勾选 R2 / D1 权限。

### 5.2 workflow 内容（`.github/workflows/deploy.yml`）

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

      - name: Install dependencies
        run: npm ci

      # 用 GitHub Secrets 注入 D1 database_id，替换 wrangler.jsonc 占位符
      - name: Inject D1 database_id
        shell: bash
        run: |
          sed -i "s/LOCAL_PLACEHOLDER/${{ secrets.D1_DATABASE_ID }}/g" wrangler.jsonc
          grep -n "database_id" wrangler.jsonc

      - name: Deploy to Cloudflare Workers
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CF_API_TOKEN }}
          accountId: ${{ secrets.CF_ACCOUNT_ID }}
          command: deploy
```

### 5.3 关于 `ADMIN_KEY` 的 CI 处理

`ADMIN_KEY` 通过 `wrangler secret put` 设置，属于 Cloudflare Secret，**不建议**放到 Git 仓库。
推荐二选一：

- **方案 A（推荐）**：在 CI 外手动执行一次（见「三.5」），CI 只负责代码部署；密钥已持久化在 Cloudflare，无需重复设置。
- **方案 B（可选）**：若想完全自动化，改用一个独立 job 内联设置（注意：secret 一旦已有则保留旧值，幂等）：
  ```yaml
  - name: Ensure ADMIN_KEY secret
    env:
      CF_ACCOUNT_ID: ${{ secrets.CF_ACCOUNT_ID }}
      CF_API_TOKEN: ${{ secrets.CF_API_TOKEN }}
    run: |
      echo "${{ secrets.ADMIN_KEY }}" | npx wrangler secret put ADMIN_KEY --name crystal-drive
  ```
  需要额外在仓库配置一个 `ADMIN_KEY` Secret。

---

## 七、环境差异与注意事项

- **本地开发**：绑定在本地无真实资源，D1 / R2 由 Miniflare 模拟；`.dev.vars` 提供 `ADMIN_KEY`。
  请把 `.dev.vars` 加入 `.gitignore`，不要提交到仓库。
- **数据库迁移**：`ensureSchema` 使用 `CREATE TABLE IF NOT EXISTS`，并对 `shares` 表执行
  `ADD COLUMN password_hash` 幂等迁移（重复执行安全）。
- **绑定名与资源名**：绑定名（`BUCKET` / `DB`）是代码里用的名字；资源名同取 `crystal-drive`。
  若改用其他资源名，只需改 `wrangler.jsonc`，但 Database ID 必须对应你的 D1 实例。
- **尺寸限制**：单文件上传上限 100 MB（Worker 请求体限制），超过会被前端拦截提示。
- **自定义域名（可选）**：在 Worker 的「Settings → Domains & Routes」添加自定义域名（需 DNS 在 Cloudflare），
  或旧式 Routes 绑定。

---

## 八、常见问题

| 问题 | 处理 |
|---|---|
| 首页 500 / D1 报错 | 确认 `wrangler.jsonc` 的 `database_id` 已替换为真实 ID |
| 登录一直失败 | 确认已执行 `npx wrangler secret put ADMIN_KEY`，输入与 `ADMIN_KEY` 一致 |
| 上传对象在 R2 找不到 | 确认 R2 桶名 `crystal-drive` 已创建且与配置一致 |
| 想部署到其它名称 | 改 `wrangler.jsonc` 的 `name` 字段 |
| 网页端建了资源，代码还没生效 | 控制台只负责 R2/D1/绑定/密钥，代码需在本地执行一次 `npm run deploy` |