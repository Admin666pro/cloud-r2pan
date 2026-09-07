# cloud-r2pan

A file-sharing system styled after the iOS 26 liquid-glass aesthetic, built on **Cloudflare Workers + R2 + D1**.
Features: file uploads, share links (expiration / download limit / access password), traffic quotas, per-IP rate limiting with auto-ban, download logs, and Chinese/English localization.

## Quick Start

The first deployment takes five commands (run in the project directory):

```bash
npm install                           # 1. Install dependencies
npx wrangler login                    # 2. Log in to Cloudflare (opens your browser)
npx wrangler r2 bucket create cloud-r2pan    # 3. Create the storage bucket
npx wrangler d1 create cloud-r2pan           # 4. Create the database; note the returned database_id
npx wrangler secret put admin         # 5. Set the admin login key (input is not shown)
```

Step 4 prints a value like `database_id = "xxxxxxxx-xxxx-..."`. Open `wrangler.jsonc` and replace the `LOCAL_PLACEHOLDER` value of `d1_databases[0].database_id` with that id.

Then deploy:

```bash
npm run deploy
```

After deploying, visit:

```text
Admin console  https://cloud-r2pan.<your-account>.workers.dev/admin
Share page     https://cloud-r2pan.<your-account>.workers.dev/s/<token>
```

Log in with the `admin` key from step 5. Database tables are created automatically on the first request; no manual SQL import is needed.

## Bindings & Resources

These are already configured in `wrangler.jsonc`; you don't need to touch the binding names at deploy time. The resource name is `cloud-r2pan` everywhere.

| Binding | Type | Resource | Purpose |
| --- | --- | --- | --- |
| `r2` | R2 Bucket | `cloud-r2pan` | Stores uploaded files |
| `db` | D1 Database | `cloud-r2pan` | Metadata, shares, logs, settings, traffic stats |
| `admin` | Secret | — | Admin login key |

Binding names are referenced directly in the code. To rename one, you must also update `src/types.ts` and every `env.*` reference.

## Common Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Local development (`http://localhost:8787`, redirects to `/admin`) |
| `npm run deploy` | Bundle and deploy to Cloudflare |
| `npm run tail` | Stream live production logs |
| `npx tsc --noEmit` | Type-check only, no upload |

`deploy` bundles the TypeScript plus `public/*.html` and uploads them automatically; no manual build step is required.

## Web UI Deployment (Optional)

If you prefer not to use the command line, you can use the [Cloudflare dashboard](https://dash.cloudflare.com):

1. **R2** → Create bucket → name `cloud-r2pan`
2. **D1** → Create database → name `cloud-r2pan` → copy the `database_id` from the page
3. **Workers & Pages** → Create → Worker → name `cloud-r2pan`
4. Open the Worker → **Settings → Bindings**: add R2 (binding `r2`) and D1 (binding `db`)
5. **Settings → Variables and Secrets**: add the `admin` secret
6. Finally, still run `npm run deploy` locally once to upload the code (the dashboard does not host the TypeScript project)

Both flows are equivalent; pick either one.

## Notes

- The `database_id` in `wrangler.jsonc` must be a real value, otherwise deployment fails with error `10021`.
- Single-file upload is capped at 100 MB (Workers request body limit).
- Custom domain: add it under the Worker's Settings → Domains & Routes (domain must be on Cloudflare).
- To change the resource name: update `name` / the bucket / the database in `wrangler.jsonc`, and the matching resources in the dashboard.

## FAQ

| Issue | Fix |
| --- | --- |
| Deploy fails with `10021` | `database_id` in `wrangler.jsonc` is still a placeholder; use the id from step 4 |
| `admin` key rejected | Run `npx wrangler secret put admin` again |
| Resources exist in the dashboard but the page is stale | The dashboard only manages resources; run `npm run deploy` locally once more |