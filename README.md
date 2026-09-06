# cloud-r2pan

iOS 26 液态玻璃风格网盘分享系统，基于 **Cloudflare Workers + R2 + D1** 构建。
支持文件上传、分享链接（有效期/次数/访问密码）、流量限额、单 IP 限流与自动封禁、下载日志、中英双语。

***

## 一、绑定名称（速查，勿改）

绑定名在代码中直接使用，改绑定名需同步改代码，请保持一致。

| 绑定名     | 类型           | 资源名           | 作用                |
| ------- | ------------ | ------------- | ----------------- |
| `r2`    | R2 Bucket    | `cloud-r2pan` | 存储上传的文件对象         |
| `db`    | D1 Database  | `cloud-r2pan` | 元数据、分享、日志、配置、流量统计 |
| `admin` | Secret（环境变量） | —             | 管理后台登录密钥          |

> Worker 名称：`cloud-r2pan`；入口：`src/index.ts`。示例资源名与仓库名保持一致，可自行改 `wrangler.jsonc`。

***

## 二、首次初始化（一次性）

前置：Cloudflare 账户 + 本机 Node ≥ 18、npm。

```bash
npm install
npx wrangler login                     # 浏览器授权
npx wrangler r2 bucket create cloud-r2pan
npx wrangler d1 create cloud-r2pan     # 记住输出的 database_id
```

把上一步的 `database_id` 填进 [wrangler.jsonc](wrangler.jsonc)（当前占位符为 `LOCAL_PLACEHOLDER`），再设置登录密钥：

```bash
npx wrangler secret put admin          # 输入后台登录密码
```

> 数据库建表（`files`/`shares`/`download_logs`/`banned_ips`/`settings`/`traffic_stats`）在首次请求时自动完成，无需手动导 SQL。

***

## 三、常用命令

| 命令               | 作用                                            |
| ---------------- | --------------------------------------------- |
| `npm run dev`    | 本地开发预览（`http://localhost:8787`，自动跳转 `/admin`） |
| `npm run build`  | 类型检查 + 打包到 `dist/`（不上传）                       |
| `npm run deploy` | 构建并上传部署                                       |
| `npm run tail`   | 实时查看线上日志                                      |

> 本源码是 **TS + 多个** **`.html`** **文本模块**，浏览器不能直接跑，由 wrangler 内置打包。`deploy` 内部自动打包；`build`（`tsc --noEmit && wrangler deploy --dry-run --outdir=dist`）只打包不上传，用于本地确认产物 / CI 检查。

***

## 四、部署方式（二选一）

### 方式 A：命令行（推荐）

```bash
npm run dev       # 开发
npm run deploy    # 上线
```

### 方式 B：图形化 Web（Cloudflare 控制台）

全部在浏览器完成，最后一步仍需本地 `npm run deploy`（网页编辑器打不了 TS 包）：

1. **R2** → Create bucket → 名称 `cloud-r2pan`
2. **D1** → Create database → 名称 `cloud-r2pan`，复制 `database_id`
3. **Workers & Pages** → Create → Worker → 名称 `cloud-r2pan`
4. 该 Worker → **Settings → Bindings**：

   - Add **R2 Bucket**：变量名 `r2`，选 `cloud-r2pan`

   - Add **D1 Database**：变量名 `db`，填 `database_id`
5. **Settings → Variables and Secrets → Add → Secret**：变量名 `admin`
6. 本地 `npm install && npm run deploy` 上传代码
7. 日常在网页端查看 **Console / Logs / Metrics**、改绑定/密钥

> 两种方式等价，可混用；本仓库 `wrangler.jsonc` 已配好绑定，方式 A 更省事。

***

## 五、访问 & 自定义域名

- 管理后台：`https://cloud-r2pan.<你的账号>.workers.dev/admin`（用 `admin` 登录）

- 分享页格式：`https://cloud-r2pan.<你的账号>.workers.dev/s/<token>`

绑定自定义域名：Workers → `cloud-r2pan` → **Settings → Domains & Routes → Add → Custom domain**，输入子域（如 `dl.example.com`，需 DNS 在 Cloudflare），保存后自动配好 CNAME 与证书。

***

## 六、CI/CD 工作流（可选 · GitHub Actions）

推送 `main`（或手动触发 `workflow_dispatch`）自动部署。仓库需配置 Secret：`CF_API_TOKEN`、`CF_ACCOUNT_ID`、`D1_DATABASE_ID`（`admin` 密钥建议首次手动设一次，见第 2 节）。建 `.github/workflows/deploy.yml`：

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
      # 用 GitHub Secret 注入 D1 database_id
      - run: sed -i "s/LOCAL_PLACEHOLDER/${{ secrets.D1_DATABASE_ID }}/g" wrangler.jsonc
      - uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CF_API_TOKEN }}
          accountId: ${{ secrets.CF_ACCOUNT_ID }}
          command: deploy
```

***

## 七、常见问题

| 问题             | 处理                                        |
| -------------- | ----------------------------------------- |
| 首页 500 / D1 报错 | `wrangler.jsonc` 的 `database_id` 还没换成真实值  |
| 登录一直失败         | 确认已 `npx wrangler secret put admin` 且输入一致 |
| 上传对象在 R2 找不到   | 确认 R2 桶名 `cloud-r2pan` 已创建且与配置一致          |
| 想部署到其它名称       | 改 `wrangler.jsonc` 的 `name` 字段及资源名        |
| 网页端建了资源、代码不生效  | 控制台不打包，需本地 `npm run deploy`               |
| 单文件 >100MB 传不了 | Worker 请求体上限，超出会被前端拦截                     |

