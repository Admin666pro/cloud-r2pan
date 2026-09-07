# cloud-r2pan

iOS 26 液态玻璃风格网盘分享系统，基于 **Cloudflare Workers + R2 + D1**。
支持文件上传、分享链接（有效期/次数/访问密码）、流量限额、单 IP 限流与自动封禁、下载日志、中英双语。

> 隐私说明：`wrangler.jsonc` **不声明** R2/D1 绑定，真实 `database_id` 只在 Cloudflare 控制台里自动管理。克隆仓库拿不到任何敏感 ID，部署也不需要填 database\_id。

***

## 一、绑定名称（在 Cloudflare 控制台手动配置，勿改名）

Worker → **Settings → Bindings** 手动添加：

| 绑定名     | 类型          | 资源名/值         | 作用           |
| ------- | ----------- | ------------- | ------------ |
| `r2`    | R2 Bucket   | `cloud-r2pan` | 存储上传的文件      |
| `db`    | D1 Database | `cloud-r2pan` | 元数据、分享、日志、配置 |
| `admin` | Secret 密钥   | 你的管理密码        | 管理后台登录密钥     |

> Worker 名称：`cloud-r2pan`；入口：`src/index.ts`。

***

## 二、部署步骤（全程不用手写 database\_id）

因为绑定放在网页手动管理，部署分两步，都很简单。

### ① 建资源 + 加绑定（浏览器里一次搞定）

1. 建 **R2 存储桶**：控制台 → **R2** → **Create bucket** → 名称 `cloud-r2pan`。
2. 建 **D1 数据库**：控制台 → **D1** → **Create database** → 名称 `cloud-r2pan`。
3. 建并配置 **Worker**：控制台 → **Workers & Pages** → **Create** → **Worker** → 名称 `cloud-r2pan`。
   进入该 Worker → **Settings** → **Bindings** → **Add binding**：

   - **R2 Bucket**：Variable name 填 `r2`，bucket 下拉选 `cloud-r2pan`。

   - **D1 Database**：Variable name 填 `db`，数据库下拉选 `cloud-r2pan`（**ID 由页面自动填，不用你抄**）。
4. **Settings → Variables and Secrets** → **Add → Secret**：Variable name 填 `admin`，值填你的管理密码。

### ② 上传代码（本地执行，无需任何 ID）

网页编辑器编不了 TypeScript + `.html` 工程，代码用本机一次命令部署（改代码后重复这条即可）：

```bash
npm install
npm run deploy      # 上传代码版本，不含绑定声明，因此不需要 database_id
```

部署即成功，不再出现 `10021` 报错。

### 访问

- 管理后台：`https://cloud-r2pan.<你的账号>.workers.dev/admin`（用 `admin` 密钥登录）

- 分享页：`https://cloud-r2pan.<你的账号>.workers.dev/s/<token>`

***

## 三、本地开发

```bash
npm install
npm run dev      # 默认 http://localhost:8787，自动跳到 /admin
```

> 当前 `wrangler.jsonc` 未声明 R2/D1 绑定，本地 `npm run dev` 没有数据库/存储模拟，主要用来调页面与联调、主流程请以线上为准。
> 若确需本地模拟：临时在 `wrangler.jsonc` 加回 `d1_databases`/`r2_buckets` 段（用占位 id），部署前再删掉。

数据库表（`files` / `shares` / `download_logs` / `banned_ips` / `settings` / `traffic_stats`）会在首次请求时由 `ensureSchema` 自动创建，无需手动导 SQL。

***

## 四、常见问题

| 问题                  | 处理                                                                        |
| ------------------- | ------------------------------------------------------------------------- |
| 之前报 `10021`         | 那是旧配置把绑定写进 `wrangler.jsonc` 导致。现在绑定走网页，`npm run deploy` 不再需要 database\_id |
| 首页/D1 500           | 确认 Worker 的 `db`（D1）绑定已添加且选的库是 `cloud-r2pan`                              |
| 登录一直失败              | 确认设置了 `admin` Secret，并和管理后台输入一致                                           |
| 上传对象在 R2 找不到        | 确认 Worker 的 `r2` 绑定已添加且桶名是 `cloud-r2pan`                                  |
| 本地 dev 报 no binding | 见「本地开发」说明：本地默认无模拟，需要时临时加回绑定段                                              |
| 单文件上传大小             | Worker 请求体上限 100 MB，超过会被前端拦截提示                                            |
| 自定义域名（可选）           | Worker → Settings → Domains & Routes 添加（域名需在 Cloudflare）                  |

> 日常用网页端：**Workers → cloud-r2pan → Console / Logs / Metrics** 看日志与监控。

