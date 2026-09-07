# cloud-r2pan

iOS 26 液态玻璃风格网盘分享系统，基于 **Cloudflare Workers + R2 + D1**。
支持文件上传、分享链接（有效期/次数/访问密码）、流量限额、单 IP 限流与自动封禁、下载日志、中英双语。

> 隐私说明：真实的 D1 数据库 ID 通过**环境变量注入**，不会写进本仓库。任何人 clone 你的仓库都拿不到你的敏感 ID。

***

## 一、绑定名称（代码里直接用，勿改）

| 绑定名     | 类型           | 资源名           | 作用                |
| ------- | ------------ | ------------- | ----------------- |
| `r2`    | R2 Bucket    | `cloud-r2pan` | 存储上传的文件对象         |
| `db`    | D1 Database  | `cloud-r2pan` | 元数据、分享、日志、配置、流量统计 |
| `admin` | Secret（环境变量） | —             | 管理后台登录密钥          |

- Worker 名称：`cloud-r2pan`；入口：`src/index.ts`。

- Worker 发送所有网络请求，依赖以上三个绑定。

***

## 二、部署（二选一）

> 推荐用**网页手动部署**：在浏览器里下拉选择资源，全程不用手写数据库 ID。

### 方式 A：网页手动部署（不手写 ID，推荐）

全部在 [Cloudflare 控制台](https://dash.cloudflare.com) 完成，适合不想碰命令行序列、或想直观管理资源的人。

**1. 创建 R2 存储桶**
左侧菜单 → **R2** → **Create bucket** → 名称填 `cloud-r2pan` → **Create bucket**。

**2. 创建 D1 数据库**
左侧菜单 → **D1** → **Create database** → 名称填 `cloud-r2pan` → **Create**。

**3. 创建 Worker**
左侧菜单 → **Workers & Pages** → **Create** → **Worker** → 名称填 `cloud-r2pan` → **Deploy**。

**4. 添加绑定（Bindings）**
进入该 Worker → **Settings** → **Bindings** → **Add binding**：

- 添加 **R2 Bucket**：**Variable name** 填 `r2`，R2 bucket 下拉选 `cloud-r2pan`。

- 添加 **D1 Database**：**Variable name** 填 `db`，数据库**下拉选** **`cloud-r2pan`**（ID 由页面自动填，不用你手抄）。

**5. 设置管理密钥**
**Settings** → **Variables and Secrets** → **Add** → **Secret**：Variable name 填 `admin`，值填你的管理密码 → **Deploy**。

**6. 上传代码（网页版最后一步）**
网页编辑器编不了 TypeScript + `.html` 模块工程，代码需要在本地部署一次（只需一次，后面改代码也用它）：

```bash
npm install
```

在项目根目录新建 `.env`，填入你建 D1 数据库时看到的 `database_id`：

```env
D1_DATABASE_ID="你的database_id"
```

然后：

```bash
npm run deploy
```

> 这个 ID 只写在本地 `.env`（已被 `.gitignore` 忽略，不提交仓库），你只需填这一回，之后更新代码都不再碰它。**网页上的资源/绑定/密钥全部是下拉/点选，已经无需你手抄 ID。**

**访问**：管理后台 `https://cloud-r2pan.<你的账号>.workers.dev/admin`（用 `admin` 密钥登录）。

***

### 方式 B：命令行部署

需要先在本地准备好两个环境变量（**都在本地文件里，不进仓库**）。

**1. 登录与安装**

```bash
npm install
npx wrangler login
```

**2. 创建并记录资源**

```bash
npx wrangler r2 bucket create cloud-r2pan
npx wrangler d1 create cloud-r2pan       # 输出里记下 database_id
```

**3. 把 ID 存到本地** **`.env`（一次性）**

在项目根目录新建 `.env`（已被 `.gitignore` 忽略，不会提交）：

```env
D1_DATABASE_ID="你的真实database_id"
```

> 配置 [wrangler.jsonc](wrangler.jsonc) 里的 `database_id` 引用的是环境变量 `${D1_DATABASE_ID}`，这里填一次即可，之后部署都能读到。

**4. 设置管理密钥**

```bash
npx wrangler secret put admin       # 交互输入，不会回显
```

**5. 部署**

```bash
npm run deploy      # 等价于 npx wrangler deploy
```

`npm run dev` 本地预览用 `.dev.vars` 的占位 ID，不需要真实值。

***

## 三、本地开发

```bash
npm install
npm run dev          # 默认 http://localhost:8787，自动跳到 /admin
```

数据库建表（`files` / `shares` / `download_logs` / `banned_ips` / `settings` / `traffic_stats`）会在首次请求时由 `ensureSchema` 自动创建，无需手动导 SQL。

***

## 四、常见问题

| 问题             | 处理                                                         |
| -------------- | ---------------------------------------------------------- |
| 网页绑定了资源，代码还没生效 | 控制台只负责 R2/D1/绑定/密钥，代码还需本地一次部署（见方式 A 第 6 步）                 |
| 想部署到其它名称       | 改 `wrangler.jsonc` 的 `name`，并同步改资源名/绑定                     |
| 首页 500 / D1 报错 | 确认 `.env` 的 `D1_DATABASE_ID` 是你的真实 ID（方式 B）                |
| 登录一直失败         | 确认已执行 `npx wrangler secret put admin`，且与控制台一致              |
| 单文件上传大小限制      | Worker 请求体上限 100 MB，超过会被前端拦截提示                             |
| 自定义域名（可选）      | Worker → Settings → Domains & Routes 添加，需 DNS 在 Cloudflare |

> 日常用网页端：**Workers → cloud-r2pan → Console / Logs / Metrics** 查看日志与监控。

