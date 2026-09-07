# cloud-r2pan

iOS 26 液态玻璃风格网盘分享系统，运行在 **Cloudflare Workers + R2 + D1** 上。
支持文件上传、分享链接（有效期 / 次数 / 访问密码）、流量限额、单 IP 限流与自动封禁、下载日志、中英双语。

## 快速启动

首次部署只需五步命令（在项目目录执行）：

```bash
npm install                     # 1. 装依赖
npx wrangler login              # 2. 登录 Cloudflare（会打开浏览器）
npx wrangler r2 bucket create cloud-r2pan   # 3. 建存储桶
npx wrangler d1 create cloud-r2pan          # 4. 建数据库，记下返回的 database_id
npx wrangler secret put admin   # 5. 设置后台登录密钥（输入时不会回显）
```

第 4 步会输出类似 `database_id = "xxxxxxxx-xxxx-..."` 的值。打开 `wrangler.jsonc`，把
`d1_databases[0].database_id` 从 `LOCAL_PLACEHOLDER` 替换成那个 id。

然后部署：

```bash
npm run deploy
```

部署成功后访问：

```text
管理后台  https://cloud-r2pan.<你的账号>.workers.dev/admin
分享页    https://cloud-r2pan.<你的账号>.workers.dev/s/<token>
```

用第 5 步设置的 `admin` 密钥登录后台。数据库表会在首次访问时自动创建，无需手动导入 SQL。

## 绑定与资源

`wrangler.jsonc` 里已配好，部署时无需改动绑定名。资源名统一为 `cloud-r2pan`。

| 绑定名     | 类型          | 资源名           | 作用                |
| ------- | ----------- | ------------- | ----------------- |
| `r2`    | R2 Bucket   | `cloud-r2pan` | 存上传的文件            |
| `db`    | D1 Database | `cloud-r2pan` | 元数据、分享、日志、配置、流量统计 |
| `admin` | Secret      | —             | 管理后台登录密钥          |

绑定名是代码里写死的，改它要同步改 `src/types.ts` 和全部 `env.*` 引用。

## 常用命令

| 命令                 | 作用                                          |
| ------------------ | ------------------------------------------- |
| `npm run dev`      | 本地开发（`http://localhost:8787`，自动跳转 `/admin`） |
| `npm run deploy`   | 打包并部署到 Cloudflare                           |
| `npm run tail`     | 查看线上实时日志                                    |
| `npx tsc --noEmit` | 只做类型检查，不上传                                  |

`deploy` 会自动打包 TS + `public/*.html` 后上传，无需手动构建中间产物。

## 网页版部署（可选）

如果你不习惯命令行，可在 [Cloudflare 控制台](https://dash.cloudflare.com) 操作：

1. **R2** → Create bucket → 名称 `cloud-r2pan`
2. **D1** → Create database → 名称 `cloud-r2pan` → 复制页面上的 `database_id`
3. **Workers & Pages** → Create → Worker → 名称 `cloud-r2pan`
4. 进入该 Worker → **Settings → Bindings**：加 R2（绑定名 `r2`）、D1（绑定名 `db`）
5. **Settings → Variables and Secrets**：加 Secret `admin`
6. 最后仍需在本地执行一次 `npm run deploy` 把代码传上去（网页端不托管 TS 工程）

网页与命令行两套等价，选一即可。

## 注意事项

- `database_id` 必须是 `wrangler.jsonc` 里的真实值，否则部署报错 `10021`。

- 单文件上传上限 100 MB（Worker 请求体限制）。

- 自定义域名：在 Worker 的 Settings → Domains & Routes 添加（需域名在 Cloudflare）。

- 想换资源名：改 `wrangler.jsonc` 的 `dag name` / bucket / database 名，并同步网页端资源即可。

## 常见问题

| 现象             | 处理                                                 |
| -------------- | -------------------------------------------------- |
| 部署报 `10021`    | `wrangler.jsonc` 里 `database_id` 还是占位符，换成第 4 步的 id |
| 把 `admin` 输错   | 重新 `npx wrangler secret put admin`                 |
| 网页端建了资源但页面还是旧的 | 网页只负责资源，代码需在本地再跑一次 `npm run deploy`                |

