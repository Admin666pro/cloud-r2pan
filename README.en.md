# cloud-r2pan

A file-sharing system styled after the iOS 26 liquid-glass aesthetic, built on **Cloudflare Workers + R2 + D1**.
Features: file uploads, share links (expiration / download limit / access password), traffic quotas, per-IP rate limiting with auto-ban, download logs, and Chinese/English localization.

> Privacy note: `wrangler.jsonc` does **not** declare the R2/D1 bindings. The real `database_id` is managed inside the Cloudflare dashboard, so cloning this repo exposes no sensitive ID and deploying needs no `database_id`.

## Bindings (configure manually in the dashboard — do not rename)

Worker → **Settings → Bindings**:

| Binding | Type | Resource / value | Purpose |
| --- | --- | --- | --- |
| `r2` | R2 Bucket | `cloud-r2pan` | Stores uploaded files |
| `db` | D1 Database | `cloud-r2pan` | Metadata, shares, logs, settings |
| `admin` | Secret | your admin password | Admin login key |

- Worker name: `cloud-r2pan`; entry point: `src/index.ts`.

## Deployment (no hand-typed database_id anywhere)

Bindings are managed on the dashboard, so setup splits into two easy steps.

### Step ① — Create resources & add bindings (all in the browser)

1. **R2 bucket** — **R2** → **Create bucket** → name `cloud-r2pan`.
2. **D1 database** — **D1** → **Create database** → name `cloud-r2pan`.
3. **Worker** — **Workers & Pages** → **Create** → **Worker** → name `cloud-r2pan`.
   Open the Worker → **Settings** → **Bindings** → **Add binding**:
   - **R2 Bucket**: Variable name `r2`, pick `cloud-r2pan` in the bucket dropdown.
   - **D1 Database**: Variable name `db`, pick `cloud-r2pan` in the database dropdown (the ID is filled in automatically).
4. **Settings → Variables and Secrets** → **Add → Secret**: Variable name `admin`, value your admin password.

### Step ② — Upload the code (from your machine, no ID needed)

The dashboard editor can't build a TypeScript + `.html` project, so push the code with one command (repeat it after any code change):

```bash
npm install
npm run deploy      # uploads a code version with no binding declaration → no database_id needed
```

Deployment succeeds without the `10021` error.

### Access

- Admin console: `https://cloud-r2pan.<your-account>.workers.dev/admin` (log in with the `admin` key)
- Share page: `https://cloud-r2pan.<your-account>.workers.dev/s/<token>`

## Local Development

```bash
npm install
npm run dev      # http://localhost:8787, redirects to /admin
```

> Because `wrangler.jsonc` declares no R2/D1 bindings, local `npm run dev` has no local database/storage emulation — use it mainly for UI tweaks; the live worker is the source of truth.
> For local emulation, temporarily add `d1_databases`/`r2_buckets` back to `wrangler.jsonc` (placeholder id), then remove before deploying.

Database tables (`files` / `shares` / `download_logs` / `banned_ips` / `settings` / `traffic_stats`) are created automatically by `ensureSchema` on the first request; no manual SQL import is needed.

## FAQ

| Issue | Fix |
| --- | --- |
| Previous `10021` error | That came from declaring bindings inside `wrangler.jsonc`. Now bindings live on the dashboard, so `npm run deploy` needs no `database_id` |
| Home / D1 returns 500 | Make sure the Worker's `db` (D1) binding is added and points to `cloud-r2pan` |
| `admin` key rejected | Confirm the `admin` Secret is set and matches your input |
| Can't find objects in R2 | Confirm the Worker's `r2` binding is added and the bucket is `cloud-r2pan` |
| Local dev reports no binding | See "Local Development": local emulation is off by default; add bindings temporarily if needed |
| Single-file upload size | Capped at 100 MB (Workers request body limit); rejected on the frontend |
| Custom domain (optional) | Worker → Settings → Domains & Routes (domain must be on Cloudflare) |

> Manage daily: **Workers → cloud-r2pan → Console / Logs / Metrics**.