# Crystal Drive 部署文档

Cloudflare Workers + R2 + D1 的网盘分享系统（上传文件、分享链接、访问密码、流量限额、下载日志、双语）。

***

## 1. 绑定名称（速查，勿改）

| 绑定名         | 类型     | 资源名             | 作用           |
| ----------- | ------ | --------------- | ------------ |
| `BUCKET`    | R2     | `crystal-drive` | 存文件          |
| `DB`        | D1     | `crystal-drive` | 元数据/分享/日志/配置 |
| `ADMIN_KEY` | Secret | —               | 后台登录密钥       |

> Worker 名：`crystal-drive`｜入口：`src/index.ts`｜绑定名是代码里写死的，改绑名须同步改代码。

***

## 2. 常用命令

| 命令               | 作用                                           |
| ---------------- | -------------------------------------------- |
| `npm install`    | 装依赖（`wrangler`、`typescript`、`workers-types`） |
| `npm run dev`    | 本地开发预览（`http://localhost:8787`）              |
| `npm run build`  | **类型检查 + 打包**到 `dist/`（不部署，见第 4 节）           |
| `npm run deploy` | 构建并上传部署到 Cloudflare                          |
| `npm run tail`   | 实时查看线上日志                                     |

> `deploy` 内部会自动打包；`build` 只打包不上传，用于本地确认产物 / CI 检查。

***

## 3. 首次初始化（一次性）

前置：Cloudflare 账户 + 本机 Node ≥ 18、npm。

```bash
npm install
npx wrangler login              # 浏览器授权
npx wrangler r2 bucket create crystal-drive
npx wrangler d1 create crystal-drive   # 记住输出的 database_id
```

把上一步的 `database_id` 填进 [wrangler.jsonc](wrangler.jsonc)（现在占位符是 `LOCAL_PLACEHOLDER`），再设置密钥：

```bash
npx wrangler secret put ADMIN_KEY    # 输入后台登录密码
```

> 已初始化过的部署不需要重复；数据库建表会在首次请求时自动完成。

***

## 4. 构建与打包（build）

本项目源码是 **TypeScript + 多个** **`.html`** **文本模块**，浏览器不能直接跑，需要 wrangler（内置 esbuild）打包成一个 Worker。

```bash
npm run build   # 等价: tsc --noEmit && wrangler deploy --dry-run --outdir=dist
```

产物在 `dist/`：`dist/index.js`（被打包的入口）+ `dist/*.html`（文本模块），约 120 KB / gzip 33 KB。`dist/` 已在 `.gitignore`，不会提交。

- **想确认代码能通过类型检查和打包** → 用 `npm run build`。

- **想直接上线** → 用 `npm run deploy`（内部已自动打包+上传，无需先手动 build）。

***

## 5. 部署后访问 & 自定义域名

### 5.1 访问地址

- 后台：`https://crystal-drive.<你的账号>.workers.dev/admin`（用 `ADMIN_KEY` 登录）

- 分享页：`https://crystal-drive.<你的账号>.workers.dev/s/<token>`

### 5.2 绑定自定义域名

1. 控制台 **Workers & Pages → crystal-drive → Settings → Domains & Routes → Add → Custom domain**
2. 输入子域（如 `dl.example.com`），要求该域名 DNS 在 Cloudflare，保存后自动配好 CNAME 与证书
3. 完成后即用 `https://dl.example.com/admin` 访问

***

## 6. 两种部署方式（二选一）

### 方式 A：命令行（推荐）

```bash
npm run dev      # 开发
npm run deploy   # 上线
```

### 方式 B：图形化网页（Cloudflare 控制台）

全部在浏览器完成，最后一步仍需本地 `npm run deploy`（网页编辑打不了 TS 包）：

1. **R2** → Create bucket → 名 `crystal-drive`
2. **D1** → Create database → 名 `crystal-drive`，复制 `database_id`
3. **Workers & Pages** → Create → Worker → 名 `crystal-drive`
4. 该 Worker → **Settings → Bindings**

   - Add **R2 Bucket**：变量名 `BUCKET`，选 `crystal-drive`

   - Add **D1 Database**：变量名 `DB`，填 `database_id`
5. **Settings → Variables and Secrets → Add → Secret**：变量名 `ADMIN_KEY`
6. 本地 `npm install && npm run deploy` 上传代码
7. 之后在网页端查看 **Console / Logs / Metrics**、改绑定/密钥

> 方式 A、B 等价，可混用；本仓库的 `wrangler.jsonc` 已配好绑定，方式 A 更省事。

***

## 7. CI/CD 工作流（可选 · GitHub Actions）

推送 `main`（或手动触发 `workflow_dispatch`）自动部署。仓库需配置 Secret：`CF_API_TOKEN`、`CF_ACCOUNT_ID`、`D1_DATABASE_ID`（`ADMIN_KEY` 建议首次手动设一次，见第 3 节）。建 `.github/workflows/deploy.yml`：

```yaml
name: Deploy Worker
on: { push: { branches: [main] }, workflow_dispatch: {} }
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22, cache: npm }
      - run: npm ci
      # 把 D1 占位符换成真实 database_id
      - run: sed -i "s/LOCAL_PLACEHOLDER/${{ secrets.D1_DATABASE_ID }}/g" wrangler.jsonc
      - uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CF_API_TOKEN }}
          accountId: ${{ secrets.CF_ACCOUNT_ID }}
          command: deploy
```

***

## 8. 常见问题

| 问题             | 解决                                            |
| -------------- | --------------------------------------------- |
| 首页 500 / D1 报错 | `wrangler.jsonc` 的 `database_id` 还没换成真实值      |
| 登录失败           | 确认已 `npx wrangler secret put ADMIN_KEY` 且输入一致 |
| R2 存不进         | 桶名 `crystal-drive` 是否已建、与配置一致                 |
| 网页端建好资源代码却不生效  | 控制台不含打包，需本地 `npm run deploy`                  |
| 单文件>100MB 传不了  | 这是 Worker 请求体上限，超出会被前端拦截                      |

