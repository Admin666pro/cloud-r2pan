# cloud-r2pan

A file-sharing system styled after the iOS 26 liquid-glass aesthetic, built on **Cloudflare Workers + R2 + D1**.
Features: file uploads, share links (expiration / download limit / access password), traffic quotas, per-IP rate limiting with auto-ban, download logs, and Chinese/English localization.

> Privacy note: your real D1 `database_id` is injected via a local environment variable and is never committed to this repo. Cloning the repo gives no one your sensitive IDs.

## Bindings (referenced directly in code — do not rename)

| Binding | Type | Resource | Purpose |
| --- | --- | --- | --- |
| `r2` | R2 Bucket | `cloud-r2pan` | Stores uploaded files |
| `db` | D1 Database | `cloud-r2pan` | Metadata, shares, logs, settings, traffic stats |
| `admin` | Secret (env var) | — | Admin login key |

- Worker name: `cloud-r2pan`; entry point: `src/index.ts`.

## Deploy (pick one)

> Recommended: **Web UI deployment** — pick resources from dropdowns, no need to type the database ID by hand.

### Option A: Web UI Deployment (no hand-typed ID, recommended)

All done in the [Cloudflare dashboard](https://dash.cloudflare.com):

1. **Create the R2 bucket** — **R2** → **Create bucket** → name `cloud-r2pan` → **Create bucket**.
2. **Create the D1 database** — **D1** → **Create database** → name `cloud-r2pan` → **Create**.
3. **Create the Worker** — **Workers & Pages** → **Create** → **Worker** → name `cloud-r2pan` → **Deploy**.
4. **Add bindings** — open the Worker → **Settings** → **Bindings** → **Add binding**:
   - **R2 Bucket**: Variable name `r2`, pick `cloud-r2pan` from the bucket dropdown.
   - **D1 Database**: Variable name `db`, pick `cloud-r2pan` from the database dropdown (the ID is filled in automatically).
5. **Set the admin secret** — **Settings** → **Variables and Secrets** → **Add** → **Secret**: name `admin`, value your admin password → **Deploy**.
6. **Upload the code (final step).** The dashboard editor can't build a TypeScript + `.html` module project, so deploy once from your machine:

   ```bash
   npm install
   ```

   Create a `.env` file (git-ignored, never committed) in the project root with the `database_id` you saw when creating the D1 database:

   ```env
   D1_DATABASE_ID="your-database-id"
   ```

   Then:

   ```bash
   npm run deploy
   ```

   > This ID lives only in your local `.env` and is needed once; later code updates don't touch it. The dashboards for resources / bindings / secrets are all dropdowns and clicks — no hand-typed ID.

Access: `https://cloud-r2pan.<your-account>.workers.dev/admin` (log in with the `admin` key).

### Option B: Command-Line Deployment

**1. Install & log in**

```bash
npm install
npx wrangler login
```

**2. Create and record resources**

```bash
npx wrangler r2 bucket create cloud-r2pan
npx wrangler d1 create cloud-r2pan        # note the returned database_id
```

**3. Store the ID in a local `.env` (one-time)**

In the project root, create `.env` (git-ignored, not committed):

```env
D1_DATABASE_ID="your-database-id"
```

The `database_id` in `wrangler.jsonc` references the environment variable `${D1_DATABASE_ID}`, so this single fill-in is all you need.

**4. Set the admin secret**

```bash
npx wrangler secret put admin            # interactive, not echoed
```

**5. Deploy**

```bash
npm run deploy        # equivalent to npx wrangler deploy
```

`npm run dev` uses the placeholder ID in `.dev.vars` and does not need a real value.

## Local Development

```bash
npm install
npm run dev           # http://localhost:8787, redirects to /admin
```

Database tables (`files` / `shares` / `download_logs` / `banned_ips` / `settings` / `traffic_stats`) are created automatically by `ensureSchema` on the first request; no manual SQL import is needed.

## FAQ

| Issue | Fix |
| --- | --- |
| Resources exist in the dashboard but the page is stale | The dashboard manages resources/bindings/secrets; run `npm run deploy` once locally |
| Deploy fails / D1 error 500 | Make sure `D1_DATABASE_ID` in `.env` is your real database ID (Option B) |
| `admin` key rejected | Run `npx wrangler secret put admin` again and keep it consistent with the dashboard |
| Single-file upload size | Capped at 100 MB (Workers request body limit); rejected on the frontend |
| Custom domain (optional) | Worker → Settings → Domains & Routes (domain must be on Cloudflare) |

> Manage daily: **Workers → cloud-r2pan → Console / Logs / Metrics**.