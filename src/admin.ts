import type { Env } from "./types";
import { ensureSchema, randomId } from "./db";
import { getSettings, updateSettings } from "./settings";
import { checkAdminKey, createSession, verifySession, clientIp, rateLimitLogin } from "./auth";
import { pickLang } from "./i18n";
import { hashPassword } from "./public";

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json;charset=utf-8", "cache-control": "no-store" },
  });

/** API 错误消息跟随请求语言（浏览器 fetch 自动携带 Accept-Language） */
const msg = (req: Request, zh: string, en: string) => (pickLang(req) === "zh" ? zh : en);

/** 安全解析 JSON body（失败返回空对象） */
async function readJson<T>(req: Request): Promise<Partial<T>> {
  try {
    return (await req.json()) as Partial<T>;
  } catch {
    return {};
  }
}

/** 文件名清洗：去路径分隔符 / 控制字符，限长 */
function sanitizeName(name: string): string {
  const cleaned = name
    .replace(/[\\/]/g, "_")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, 180);
  return cleaned || "unnamed";
}

async function requireAuth(req: Request, env: Env): Promise<Response | null> {
  if (!(await verifySession(req, env))) {
    return json({ error: "unauthorized" }, 401);
  }
  return null;
}

export async function handleAdminApi(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  path: string
): Promise<Response> {
  await ensureSchema(env);
  const method = req.method;
  const url = new URL(req.url);

  // ── 登录（无需会话） ──────────────────────────────
  if (path === "/api/admin/login" && method === "POST") {
    const ip = clientIp(req);
    if (!rateLimitLogin(ip))
      return json({ error: msg(req, "尝试过于频繁，请稍后再试", "Too many attempts. Please try again later.") }, 429);
    if (!env.ADMIN_KEY)
      return json({ error: msg(req, "未设置 ADMIN_KEY 密钥，请先执行 npx wrangler secret put ADMIN_KEY", "ADMIN_KEY is not set. Run: npx wrangler secret put ADMIN_KEY") }, 500);
    const body = await readJson<{ key: string }>(req);
    if (!body.key || !(await checkAdminKey(env, body.key))) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json;charset=utf-8",
        "set-cookie": await createSession(env),
        "cache-control": "no-store",
      },
    });
  }

  // ── 以下全部需要会话 ──────────────────────────────
  const unauthorized = await requireAuth(req, env);
  if (unauthorized) return unauthorized;

  // 登出
  if (path === "/api/admin/logout" && method === "POST") {
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json;charset=utf-8",
        "set-cookie": "cd_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
      },
    });
  }

  // 会话检查
  if (path === "/api/admin/session" && method === "GET") {
    return json({ ok: true, site_title: (await getSettings(env)).siteTitle });
  }

  // ── 概览统计 ──────────────────────────────────────
  if (path === "/api/admin/stats" && method === "GET") {
    const s = await getSettings(env);
    const month = new Date().toISOString().slice(0, 7);
    if (s.trafficMonth !== month && s.trafficUsedBytes > 0) {
      // 跨月自动归零（首次请求时兜底）
      await updateSettings(env, { traffic_used_bytes: "0", traffic_month: month });
      s.trafficUsedBytes = 0;
      s.trafficMonth = month;
    }
    const [files, shares, activeShares, totalDownloads, todayStat, chartRows, recent, banned] =
      await Promise.all([
        env.DB.prepare("SELECT COUNT(*) AS c FROM files").first<{ c: number }>(),
        env.DB.prepare("SELECT COUNT(*) AS c FROM shares").first<{ c: number }>(),
        env.DB.prepare(
          "SELECT COUNT(*) AS c FROM shares WHERE revoked = 0 AND (expires_at IS NULL OR expires_at > ?1) AND (max_downloads IS NULL OR download_count < max_downloads)"
        )
          .bind(Date.now())
          .first<{ c: number }>(),
        env.DB.prepare("SELECT COALESCE(SUM(downloads), 0) AS c FROM traffic_stats").first<{ c: number }>(),
        env.DB.prepare("SELECT bytes, downloads FROM traffic_stats WHERE day = ?1")
          .bind(new Date().toISOString().slice(0, 10))
          .first<{ bytes: number; downloads: number }>(),
        env.DB.prepare(
          "SELECT day, bytes, downloads FROM traffic_stats WHERE day >= date('now', '-13 days') ORDER BY day"
        ).all<{ day: string; bytes: number; downloads: number }>(),
        env.DB.prepare(
          "SELECT file_name, ip, browser, os, country, bytes, created_at FROM download_logs ORDER BY id DESC LIMIT 10"
        ).all(),
        env.DB.prepare("SELECT COUNT(*) AS c FROM banned_ips").first<{ c: number }>(),
      ]);

    // 补齐 14 天（无数据的天补 0）
    const chartMap = new Map((chartRows.results ?? []).map((r) => [r.day, r]));
    const chart: { day: string; downloads: number; bytes: number }[] = [];
    for (let i = 13; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400_000).toISOString().slice(0, 10);
      const r = chartMap.get(d);
      chart.push({ day: d, downloads: r?.downloads ?? 0, bytes: r?.bytes ?? 0 });
    }

    const quotaExceeded = s.trafficLimitBytes > 0 && s.trafficUsedBytes >= s.trafficLimitBytes;
    return json({
      traffic: {
        used: s.trafficUsedBytes,
        limit: s.trafficLimitBytes,
        percent:
          s.trafficLimitBytes > 0
            ? Math.min(100, Math.round((s.trafficUsedBytes / s.trafficLimitBytes) * 100))
            : 0,
        month: s.trafficMonth,
        quota_exceeded: quotaExceeded,
      },
      counts: {
        files: files?.c ?? 0,
        shares: shares?.c ?? 0,
        active_shares: activeShares?.c ?? 0,
        downloads_total: totalDownloads?.c ?? 0,
        downloads_today: todayStat?.downloads ?? 0,
        bytes_today: todayStat?.bytes ?? 0,
        banned: banned?.c ?? 0,
      },
      chart,
      recent: recent.results ?? [],
    });
  }

  // ── 文件列表 ──────────────────────────────────────
  if (path === "/api/admin/files" && method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT f.id, f.name, f.size, f.mime, f.uploaded_at,
              (SELECT COUNT(*) FROM shares s WHERE s.file_id = f.id) AS share_count,
              (SELECT COALESCE(SUM(s.download_count), 0) FROM shares s WHERE s.file_id = f.id) AS download_count
       FROM files f ORDER BY f.uploaded_at DESC`
    ).all();
    return json({ files: results ?? [] });
  }

  // ── 上传文件（原始流式 body，文件名放 X-File-Name 头） ──
  if (path === "/api/admin/upload" && method === "POST") {
    const rawName = req.headers.get("x-file-name");
    if (!rawName) return json({ error: msg(req, "缺少 X-File-Name 头", "Missing X-File-Name header") }, 400);
    let name: string;
    try {
      name = sanitizeName(decodeURIComponent(rawName));
    } catch {
      name = sanitizeName(rawName);
    }
    if (!req.body) return json({ error: msg(req, "请求体为空", "Empty request body") }, 400);
    const id = randomId(14);
    const key = `files/${id}`;
    const mime = req.headers.get("content-type") || "application/octet-stream";
    const obj = await env.BUCKET.put(key, req.body, {
      httpMetadata: { contentType: mime, contentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(name)}` },
    });
    await env.DB.prepare(
      "INSERT INTO files(id, key, name, size, mime, uploaded_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6)"
    )
      .bind(id, key, name, obj.size, mime, Date.now())
      .run();
    return json({ ok: true, id, name, size: obj.size }, 201);
  }

  // ── 删除文件（连带 R2 对象、分享、日志） ──────────
  const fileMatch = /^\/api\/admin\/files\/([^/]+)$/.exec(path);
  if (fileMatch && method === "DELETE") {
    const fileId = fileMatch[1];
    const file = await env.DB.prepare("SELECT key FROM files WHERE id = ?1").bind(fileId).first<{ key: string }>();
    if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM shares WHERE file_id = ?1").bind(fileId),
      env.DB.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(fileId),
      env.DB.prepare("DELETE FROM files WHERE id = ?1").bind(fileId),
    ]);
    ctx.waitUntil(env.BUCKET.delete(file.key));
    return json({ ok: true });
  }

  // ── 创建分享 ──────────────────────────────────────
  if (path === "/api/admin/shares" && method === "POST") {
    const body = await readJson<{ file_id: string; expires_hours: number | null; max_downloads: number | null; password: string | null }>(req);
    if (!body.file_id) return json({ error: msg(req, "缺少 file_id", "Missing file_id") }, 400);
    const file = await env.DB.prepare("SELECT id FROM files WHERE id = ?1").bind(body.file_id).first();
    if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
    const expiresAt =
      body.expires_hours && body.expires_hours > 0 ? Date.now() + body.expires_hours * 3600_000 : null;
    const maxDownloads =
      body.max_downloads && body.max_downloads > 0 ? Math.floor(body.max_downloads) : null;
    const password =
      typeof body.password === "string" && body.password.trim() ? body.password.trim() : null;
    const passwordHash = password ? await hashPassword(password) : null;
    const id = randomId(10);
    await env.DB.prepare(
      "INSERT INTO shares(id, file_id, created_at, expires_at, max_downloads, password_hash) VALUES(?1, ?2, ?3, ?4, ?5, ?6)"
    )
      .bind(id, body.file_id, Date.now(), expiresAt, maxDownloads, passwordHash)
      .run();
    return json({ ok: true, id, url: `/s/${id}` }, 201);
  }

  // ── 分享列表 ──────────────────────────────────────
  if (path === "/api/admin/shares" && method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT s.id, s.file_id, s.created_at, s.expires_at, s.max_downloads, s.download_count, s.revoked,
              s.password_hash, f.name AS file_name, f.size AS file_size
       FROM shares s JOIN files f ON f.id = s.file_id
       ORDER BY s.created_at DESC`
    ).all();
    const now = Date.now();
    const shares = (results ?? []).map((s: any) => ({
      ...s,
      has_password: !!s.password_hash,
      password_hash: undefined,
      status: s.revoked
        ? "revoked"
        : s.expires_at && s.expires_at < now
          ? "expired"
          : s.max_downloads && s.download_count >= s.max_downloads
            ? "maxed"
            : "active",
    }));
    return json({ shares });
  }

  // ── 清理失效分享（过期 / 已撤销 / 达上限） ────────
  if (path === "/api/admin/shares/cleanup" && method === "POST") {
    const now = Date.now();
    const r = await env.DB.prepare(
      "DELETE FROM shares WHERE revoked = 1 OR (expires_at IS NOT NULL AND expires_at < ?1) OR (max_downloads IS NOT NULL AND download_count >= max_downloads)"
    )
      .bind(now)
      .run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 撤销/删除分享 ─────────────────────────────────
  const shareMatch = /^\/api\/admin\/shares\/([^/]+)$/.exec(path);
  if (shareMatch && method === "DELETE") {
    const r = await env.DB.prepare("DELETE FROM shares WHERE id = ?1").bind(shareMatch[1]).run();
    if ((r.meta.changes ?? 0) === 0) return json({ error: msg(req, "分享不存在", "Share not found") }, 404);
    return json({ ok: true });
  }

  // ── 下载记录（分页 + 筛选） ────────────────────────
  if (path === "/api/admin/logs" && method === "GET") {
    const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
    const perPage = Math.min(100, Math.max(10, Number(url.searchParams.get("per_page")) || 20));
    const q = url.searchParams.get("q")?.trim();
    const where: string[] = [];
    const binds: (string | number)[] = [];
    if (q) {
      where.push("(ip LIKE ?1 OR file_name LIKE ?1)");
      binds.push(`%${q}%`);
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const [total, rows] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) AS c FROM download_logs ${whereSql}`)
        .bind(...binds)
        .first<{ c: number }>(),
      env.DB.prepare(
        `SELECT id, share_id, file_name, ip, browser, os, country, bytes, created_at
         FROM download_logs ${whereSql} ORDER BY id DESC LIMIT ?${binds.length + 1} OFFSET ?${binds.length + 2}`
      )
        .bind(...binds, perPage, (page - 1) * perPage)
        .all(),
    ]);
    return json({
      logs: rows.results ?? [],
      total: total?.c ?? 0,
      page,
      per_page: perPage,
      pages: Math.max(1, Math.ceil((total?.c ?? 0) / perPage)),
    });
  }

  // ── 清除记录（全部 / N 天前） ──────────────────────
  if (path === "/api/admin/logs" && method === "DELETE") {
    const mode = url.searchParams.get("mode") ?? "all";
    let sql: string;
    const binds: number[] = [];
    if (mode === "older") {
      const days = Math.max(1, Number(url.searchParams.get("days")) || 30);
      sql = "DELETE FROM download_logs WHERE created_at < ?1";
      binds.push(Date.now() - days * 86400_000);
    } else {
      sql = "DELETE FROM download_logs";
    }
    const r = await env.DB.prepare(sql).bind(...binds).run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 封禁列表 ──────────────────────────────────────
  if (path === "/api/admin/bans" && method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT ip, reason, banned_at, expires_at FROM banned_ips ORDER BY banned_at DESC"
    ).all();
    return json({ bans: results ?? [] });
  }

  // ── 手动封禁 ──────────────────────────────────────
  if (path === "/api/admin/bans" && method === "POST") {
    const body = await readJson<{ ip: string; reason: string; hours: number | null }>(req);
    const ip = body.ip?.trim();
    if (!ip || !/^[0-9a-fA-F:.]{3,45}$/.test(ip)) return json({ error: msg(req, "IP 格式无效", "Invalid IP format") }, 400);
    const expiresAt = body.hours && body.hours > 0 ? Date.now() + body.hours * 3600_000 : null;
    await env.DB.prepare(
      `INSERT INTO banned_ips(ip, reason, banned_at, expires_at) VALUES(?1, ?2, ?3, ?4)
       ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, banned_at = excluded.banned_at, expires_at = excluded.expires_at`
    )
      .bind(ip, body.reason?.slice(0, 200) || "管理员手动封禁", Date.now(), expiresAt)
      .run();
    return json({ ok: true }, 201);
  }

  // ── 解封 ──────────────────────────────────────────
  const banMatch = /^\/api\/admin\/bans\/([^/]+)$/.exec(path);
  if (banMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM banned_ips WHERE ip = ?1").bind(decodeURIComponent(banMatch[1])).run();
    return json({ ok: true });
  }

  // ── 读取设置 ──────────────────────────────────────
  if (path === "/api/admin/settings" && method === "GET") {
    const s = await getSettings(env);
    return json({
      site_title: s.siteTitle,
      traffic_limit_gb: s.trafficLimitBytes / 1024 ** 3,
      max_downloads_per_ip: s.maxDownloadsPerIp,
      count_window_hours: s.countWindowHours,
      auto_ban: s.autoBan,
      ban_hours: s.banHours,
      traffic_used_bytes: s.trafficUsedBytes,
    });
  }

  // ── 更新设置（可调常数） ──────────────────────────
  if (path === "/api/admin/settings" && method === "PUT") {
    const body = await readJson<Record<string, unknown>>(req);
    const patch: Record<string, string> = {};
    if (typeof body.site_title === "string" && body.site_title.trim())
      patch.site_title = body.site_title.trim().slice(0, 50);
    const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : null);
    const gb = num(body.traffic_limit_gb);
    if (gb !== null) patch.traffic_limit_bytes = String(Math.round(gb * 1024 ** 3));
    const perIp = num(body.max_downloads_per_ip);
    if (perIp !== null) patch.max_downloads_per_ip = String(Math.floor(perIp));
    const window = num(body.count_window_hours);
    if (window !== null) patch.count_window_hours = String(Math.floor(window));
    const banHours = num(body.ban_hours);
    if (banHours !== null) patch.ban_hours = String(Math.floor(banHours));
    if (typeof body.auto_ban === "boolean") patch.auto_ban = body.auto_ban ? "1" : "0";
    await updateSettings(env, patch);
    return json({ ok: true });
  }

  // ── 重置本月流量 ──────────────────────────────────
  if (path === "/api/admin/traffic/reset" && method === "POST") {
    await updateSettings(env, {
      traffic_used_bytes: "0",
      traffic_month: new Date().toISOString().slice(0, 7),
    });
    return json({ ok: true });
  }

  return json({ error: "not_found" }, 404);
}
