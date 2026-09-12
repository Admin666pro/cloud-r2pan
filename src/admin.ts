import type { Env } from "./types";
import { ensureSchema, randomId } from "./db";
import { getSettings, updateSettings } from "./settings";
import { checkAdminKey, createSession, verifySession, clientIp, rateLimitLogin } from "./auth";
import { pickLang } from "./i18n";
import { hashPassword } from "./public";
import { parseUA } from "./ua";
import { encryptSecret, decryptSecret, totpGenerateSecret, totpVerify, totpUri, totpGenerateRecoveryCodes, sha256Hex, safeEqual } from "./crypto";

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

/** 写入登录安全日志 —— 登录/登出/失败/限流 全部走这里 */
async function writeLoginLog(
  env: Env,
  req: Request,
  action: string,
  result: string,
  reason: string | null = null
): Promise<void> {
  try {
    const ua = req.headers.get("user-agent") ?? "";
    const { browser, os } = parseUA(ua);
    // Cloudflare 下 country 由 CF-IPCountry 头提供
    const country = req.headers.get("cf-ipcountry") ?? null;
    await env.db
      .prepare(
        "INSERT INTO login_logs(action, ip, ua, browser, os, country, result, reason, created_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
      )
      .bind(action, clientIp(req), ua || null, browser, os, country, result, reason, Date.now())
      .run();
  } catch {
    // 日志写入失败不影响主流程
  }
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

  // ── 登录（支持 2FA 两阶段） ──────────────────────────────
  if (path === "/api/admin/login" && method === "POST") {
    const ip = clientIp(req);
    if (!rateLimitLogin(ip)) {
      ctx.waitUntil(writeLoginLog(env, req, "login", "fail", "rate_limited"));
      return json({ error: msg(req, "尝试过于频繁，请稍后再试", "Too many attempts. Please try again later.") }, 429);
    }
    if (!env.admin)
      return json({ error: msg(req, "未设置 admin 密钥，请先执行 npx wrangler secret put admin", "admin is not set. Run: npx wrangler secret put admin") }, 500);
    const body = await readJson<{ key: string; code?: string }>(req);
    if (!body.key || !checkAdminKey(env, body.key)) {
      ctx.waitUntil(writeLoginLog(env, req, "login", "fail", "invalid_key"));
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }

    // 密码正确 —— 检查是否需要 2FA
    const s = await getSettings(env);
    const needsTotp = s.totpEnabled && s.totpSecretCipher;

    if (needsTotp) {
      // 没带 code → 要求 2FA
      if (!body.code) {
        return json({ need_2fa: true });
      }

      // 先尝试 TOTP
      const totpSecret = await decryptSecret(s.totpSecretCipher!, env.admin);
      const totpOk = totpSecret ? await totpVerify(totpSecret, body.code) : false;

      if (totpOk) {
        ctx.waitUntil(writeLoginLog(env, req, "login", "success", "2fa_totp"));
        return new Response(JSON.stringify({ ok: true }), {
          headers: {
            "content-type": "application/json;charset=utf-8",
            "set-cookie": await createSession(env, url.protocol === "https:"),
            "cache-control": "no-store",
          },
        });
      }

      // TOTP 失败 → 尝试恢复码（两种来源：Cloudflare Secret 优先 → D1 恢复码）
      const normalized = body.code.replace(/\s+/g, "").toUpperCase();

      // 1) Cloudflare Secret 恢复码（超级恢复，用一次不消耗）
      const cloudflareRecovery = env.totp_recovery?.trim();
      if (cloudflareRecovery && safeEqual(normalized, cloudflareRecovery.replace(/\s+/g, "").toUpperCase())) {
        // 用了云变量恢复码 —— 自动重置 2FA（因为 secret 可能丢了）
        await updateSettings(env, {
          totp_enabled: "0",
          totp_secret_cipher: "",
          totp_recovery_hash: "",
        });
        ctx.waitUntil(writeLoginLog(env, req, "login", "success", "recovery_cloudflare"));
        return new Response(JSON.stringify({ ok: true, recovery_used: true, totp_reset: true }), {
          headers: {
            "content-type": "application/json;charset=utf-8",
            "set-cookie": await createSession(env, url.protocol === "https:"),
            "cache-control": "no-store",
          },
        });
      }

      // 2) D1 存储的恢复码列表（消耗型，用一次删一次）
      if (s.totpRecoveryHash) {
        const hashes = s.totpRecoveryHash.split(",").filter(Boolean);
        const inputHash = await sha256Hex(normalized);
        let matched = -1;
        for (let i = 0; i < hashes.length; i++) {
          if (safeEqual(inputHash, hashes[i])) { matched = i; break; }
        }
        if (matched >= 0) {
          // 从列表中移除已使用的恢复码
          hashes.splice(matched, 1);
          await updateSettings(env, { totp_recovery_hash: hashes.join(",") });
          // 恢复码通过 → 自动重置 2FA
          await updateSettings(env, {
            totp_enabled: "0",
            totp_secret_cipher: "",
          });
          ctx.waitUntil(writeLoginLog(env, req, "login", "success", "recovery_code"));
          return new Response(JSON.stringify({ ok: true, recovery_used: true, totp_reset: true }), {
            headers: {
              "content-type": "application/json;charset=utf-8",
              "set-cookie": await createSession(env, url.protocol === "https:"),
              "cache-control": "no-store",
            },
          });
        }
      }

      // 都不对
      ctx.waitUntil(writeLoginLog(env, req, "login", "fail", "invalid_2fa"));
      return json({ error: msg(req, "2FA 验证失败", "Invalid 2FA code") }, 401);
    }

    // 无需 2FA → 直接登录成功
    ctx.waitUntil(writeLoginLog(env, req, "login", "success"));
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json;charset=utf-8",
        "set-cookie": await createSession(env, url.protocol === "https:"),
        "cache-control": "no-store",
      },
    });
  }

  // ── 以下全部需要会话 ──────────────────────────────
  const unauthorized = await requireAuth(req, env);
  if (unauthorized) return unauthorized;

  // 登出
  if (path === "/api/admin/logout" && method === "POST") {
    const secure = url.protocol === "https:";
    ctx.waitUntil(writeLoginLog(env, req, "logout", "success"));
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json;charset=utf-8",
        "set-cookie": `cd_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`,
      },
    });
  }

  // 会话检查
  if (path === "/api/admin/session" && method === "GET") {
    const s = await getSettings(env);
    return json({
      ok: true,
      site_title: s.siteTitle,
      totp_enabled: s.totpEnabled,
      cloudflare_recovery: !!env.totp_recovery,
      recovery_remaining: s.totpRecoveryHash ? s.totpRecoveryHash.split(",").filter(Boolean).length : 0,
    });
  }

  // ── 概览统计 ──────────────────────────────────────
  if (path === "/api/admin/stats" && method === "GET") {
    // getSettings 内部已做跨月自动兜底，无需此处重复检查和 DB 写入
    const s = await getSettings(env);
    const [files, shares, activeShares, totalDownloads, todayStat, chartRows, recent, banned] =
      await Promise.all([
        env.db.prepare("SELECT COUNT(*) AS c FROM files").first<{ c: number }>(),
        env.db.prepare("SELECT COUNT(*) AS c FROM shares").first<{ c: number }>(),
        env.db.prepare(
          "SELECT COUNT(*) AS c FROM shares WHERE revoked = 0 AND (expires_at IS NULL OR expires_at > ?1) AND (max_downloads IS NULL OR download_count < max_downloads)"
        )
          .bind(Date.now())
          .first<{ c: number }>(),
        env.db.prepare("SELECT COALESCE(SUM(downloads), 0) AS c FROM traffic_stats").first<{ c: number }>(),
        env.db.prepare("SELECT bytes, downloads FROM traffic_stats WHERE day = ?1")
          .bind(new Date().toISOString().slice(0, 10))
          .first<{ bytes: number; downloads: number }>(),
        env.db.prepare(
          "SELECT day, bytes, downloads FROM traffic_stats WHERE day >= date('now', '-13 days') ORDER BY day"
        ).all<{ day: string; bytes: number; downloads: number }>(),
        env.db.prepare(
          "SELECT file_name, ip, browser, os, country, bytes, created_at FROM download_logs ORDER BY id DESC LIMIT 10"
        ).all(),
        env.db.prepare("SELECT COUNT(*) AS c FROM banned_ips").first<{ c: number }>(),
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
    const { results } = await env.db.prepare(
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
    const obj = await env.r2.put(key, req.body, {
      httpMetadata: { contentType: mime, contentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(name)}` },
    });
    // ── Bug #4 修复：D1 写入失败时清理已写入的 R2 对象 ──
    // R2 写入在 D1 之前，D1 一旦失败就会产生孤儿 R2 对象。
    // 用 waitUntil 异步清理，让响应尽快返回给前端，不阻塞。
    try {
      await env.db.prepare(
        "INSERT INTO files(id, key, name, size, mime, uploaded_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6)"
      )
        .bind(id, key, name, obj.size, mime, Date.now())
        .run();
    } catch (dbErr) {
      ctx.waitUntil(env.r2.delete(key).catch(() => {}));
      console.error("upload: D1 insert failed, cleaned up R2 object:", dbErr);
      return json({ error: msg(req, "数据库写入失败，请重试", "Database write failed. Please retry.") }, 500);
    }
    return json({ ok: true, id, name, size: obj.size }, 201);
  }

  // ── 删除文件（连带 R2 对象、分享、日志） ──────────
  const fileMatch = /^\/api\/admin\/files\/([^/]+)$/.exec(path);
  if (fileMatch && method === "DELETE") {
    const fileId = fileMatch[1];
    const file = await env.db.prepare("SELECT key FROM files WHERE id = ?1").bind(fileId).first<{ key: string }>();
    if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
    await env.db.batch([
      env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(fileId),
      env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(fileId),
      env.db.prepare("DELETE FROM files WHERE id = ?1").bind(fileId),
    ]);
    ctx.waitUntil(env.r2.delete(file.key));
    return json({ ok: true });
  }

  // ── 创建分享 ──────────────────────────────────────
  if (path === "/api/admin/shares" && method === "POST") {
    const body = await readJson<{ file_id: string; expires_hours: number | null; max_downloads: number | null; password: string | null }>(req);
    if (!body.file_id) return json({ error: msg(req, "缺少 file_id", "Missing file_id") }, 400);
    const file = await env.db.prepare("SELECT id FROM files WHERE id = ?1").bind(body.file_id).first();
    if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
    const expiresAt =
      body.expires_hours && body.expires_hours > 0 ? Date.now() + body.expires_hours * 3600_000 : null;
    const maxDownloads =
      body.max_downloads && body.max_downloads > 0 ? Math.floor(body.max_downloads) : null;
    const password =
      typeof body.password === "string" && body.password.trim() ? body.password.trim() : null;
    const passwordHash = password ? await hashPassword(password) : null;
    // 可逆加密存储密码明文，管理员之后可查看
    const passwordCipher = password ? await encryptSecret(password, env.admin) : null;
    const id = randomId(10);
    await env.db.prepare(
      "INSERT INTO shares(id, file_id, created_at, expires_at, max_downloads, password_hash, password_cipher) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    )
      .bind(id, body.file_id, Date.now(), expiresAt, maxDownloads, passwordHash, passwordCipher)
      .run();
    return json({ ok: true, id, url: `/s/${id}` }, 201);
  }

  // ── 分享列表 ──────────────────────────────────────
  if (path === "/api/admin/shares" && method === "GET") {
    const { results } = await env.db.prepare(
      `SELECT s.id, s.file_id, s.created_at, s.expires_at, s.max_downloads, s.download_count, s.revoked,
              s.password_hash, s.password_cipher, f.name AS file_name, f.size AS file_size
       FROM shares s JOIN files f ON f.id = s.file_id
       ORDER BY s.created_at DESC`
    ).all();
    const now = Date.now();
    // 并行解密所有密码明文
    const shares = await Promise.all(
      (results ?? []).map(async (s: any) => ({
        ...s,
        has_password: !!s.password_hash,
        // 解密密码明文（如果有 cipher 则尝试解密）
        password_plain: s.password_cipher ? await decryptSecret(s.password_cipher, env.admin) : null,
        password_hash: undefined,
        password_cipher: undefined,
        status: s.revoked
          ? "revoked"
          : s.expires_at && s.expires_at < now
            ? "expired"
            : s.max_downloads && s.download_count >= s.max_downloads
              ? "maxed"
              : "active",
      }))
    );
    return json({ shares });
  }

  // ── 清理失效分享（过期 / 已撤销 / 达上限） + 孤儿 files + 孤儿 R2 对象 ──
  if (path === "/api/admin/shares/cleanup" && method === "POST") {
    const now = Date.now();
    // 1. 删除失效 shares
    const deleted = await env.db.prepare(
      "DELETE FROM shares WHERE revoked = 1 OR (expires_at IS NOT NULL AND expires_at < ?1) OR (max_downloads IS NOT NULL AND download_count >= max_downloads)"
    )
      .bind(now)
      .run();

    // 2. 查出孤儿 files：没有任何 share 引用的文件（LEFT JOIN 反查）
    const orphans = await env.db.prepare(
      `SELECT f.id, f.key FROM files f
       LEFT JOIN shares s ON s.file_id = f.id
       WHERE s.id IS NULL`
    ).all<{ id: string; key: string }>();

    const orphanIds = (orphans.results ?? []).map((o) => o.id);
    const orphanKeys = (orphans.results ?? []).map((o) => o.key);

    // 3. 删除孤儿 files 的 DB 记录 + 关联 download_logs
    if (orphanIds.length > 0) {
      // D1 支持 IN (...) 参数绑定
      const placeholders = orphanIds.map((_, i) => `?${i + 1}`).join(", ");
      await env.db.batch([
        env.db.prepare(`DELETE FROM download_logs WHERE file_id IN (${placeholders})`).bind(...orphanIds),
        env.db.prepare(`DELETE FROM files WHERE id IN (${placeholders})`).bind(...orphanIds),
      ]);
    }

    // 4. 异步清理孤儿 R2 对象（不阻塞响应，R2 批量删除可能慢）
    if (orphanKeys.length > 0) {
      ctx.waitUntil(
        (async () => {
          for (const key of orphanKeys) {
            try {
              await env.r2.delete(key);
            } catch {
              // R2 delete 失败不影响 DB 清理结果，静默跳过
            }
          }
        })()
      );
    }

    return json({
      ok: true,
      deleted_shares: deleted.meta.changes ?? 0,
      deleted_orphan_files: orphanIds.length,
    });
  }

  // ── 撤销/删除分享 ─────────────────────────────────
  const shareMatch = /^\/api\/admin\/shares\/([^/]+)$/.exec(path);
  if (shareMatch && method === "DELETE") {
    const r = await env.db.prepare("DELETE FROM shares WHERE id = ?1").bind(shareMatch[1]).run();
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
      env.db.prepare(`SELECT COUNT(*) AS c FROM download_logs ${whereSql}`)
        .bind(...binds)
        .first<{ c: number }>(),
      env.db.prepare(
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
    const r = await env.db.prepare(sql).bind(...binds).run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 封禁列表 ──────────────────────────────────────
  if (path === "/api/admin/bans" && method === "GET") {
    const { results } = await env.db.prepare(
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
    await env.db.prepare(
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
    await env.db.prepare("DELETE FROM banned_ips WHERE ip = ?1").bind(decodeURIComponent(banMatch[1])).run();
    return json({ ok: true });
  }

  // ── 登录安全日志（分页 + 筛选） ────────────────────────
  if (path === "/api/admin/login-logs" && method === "GET") {
    const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
    const perPage = Math.min(100, Math.max(10, Number(url.searchParams.get("per_page")) || 20));
    const q = url.searchParams.get("q")?.trim();
    const action = url.searchParams.get("action")?.trim();
    const result = url.searchParams.get("result")?.trim();
    const where: string[] = [];
    const binds: (string | number)[] = [];
    let idx = 1;
    if (q) {
      where.push(`(ip LIKE ?${idx} OR browser LIKE ?${idx} OR os LIKE ?${idx})`);
      binds.push(`%${q}%`);
      idx++;
    }
    if (action) {
      where.push(`action = ?${idx}`);
      binds.push(action);
      idx++;
    }
    if (result) {
      where.push(`result = ?${idx}`);
      binds.push(result);
      idx++;
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const [total, rows] = await Promise.all([
      env.db.prepare(`SELECT COUNT(*) AS c FROM login_logs ${whereSql}`).bind(...binds).first<{ c: number }>(),
      env.db
        .prepare(
          `SELECT id, action, ip, browser, os, country, result, reason, created_at
           FROM login_logs ${whereSql} ORDER BY id DESC LIMIT ?${idx} OFFSET ?${idx + 1}`
        )
        .bind(...binds, perPage, (page - 1) * perPage)
        .all(),
    ]);
    // 统计：最近 24h 登录失败次数
    const fail24h = await env.db
      .prepare(
        "SELECT COUNT(*) AS c FROM login_logs WHERE action = 'login' AND result = 'fail' AND created_at >= ?1"
      )
      .bind(Date.now() - 24 * 3600_000)
      .first<{ c: number }>();
    return json({
      logs: rows.results ?? [],
      total: total?.c ?? 0,
      page,
      per_page: perPage,
      pages: Math.max(1, Math.ceil((total?.c ?? 0) / perPage)),
      fail_last_24h: fail24h?.c ?? 0,
    });
  }

  // ── 清除登录日志（全部 / N 天前） ──────────────────────
  if (path === "/api/admin/login-logs" && method === "DELETE") {
    const mode = url.searchParams.get("mode") ?? "all";
    let sql: string;
    const binds: number[] = [];
    if (mode === "older") {
      const days = Math.max(1, Number(url.searchParams.get("days")) || 30);
      sql = "DELETE FROM login_logs WHERE created_at < ?1";
      binds.push(Date.now() - days * 86400_000);
    } else {
      sql = "DELETE FROM login_logs";
    }
    const r = await env.db.prepare(sql).bind(...binds).run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 2FA 状态查询 ───────────────────────────────────
  if (path === "/api/admin/2fa/status" && method === "GET") {
    const s = await getSettings(env);
    return json({
      enabled: s.totpEnabled && !!s.totpSecretCipher,
      cloudflare_recovery: !!env.totp_recovery,
      recovery_remaining: s.totpRecoveryHash ? s.totpRecoveryHash.split(",").filter(Boolean).length : 0,
    });
  }

  // ── 2FA Setup：生成新 secret（未启用，需要 verify+enable 才生效） ──
  if (path === "/api/admin/2fa/setup" && method === "POST") {
    const body = await readJson<{ admin_key: string }>(req);
    if (!body.admin_key || !checkAdminKey(env, body.admin_key)) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    // 如果已经启用，需要先 disable 再 setup（或者覆盖）
    const secret = totpGenerateSecret();
    const s = await getSettings(env);
    const siteTitle = s.siteTitle || "cloud-r2pan";
    const uri = totpUri(secret, siteTitle, "admin");
    return json({
      secret, // 仅本次返回，前端展示二维码用
      uri,
    });
  }

  // ── 2FA Enable：验证通过后写入 settings（加密存储）并生成恢复码 ──
  if (path === "/api/admin/2fa/enable" && method === "POST") {
    const body = await readJson<{ admin_key: string; code: string; secret: string }>(req);
    if (!body.admin_key || !checkAdminKey(env, body.admin_key)) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    if (!/^[A-Z2-7]{16,}$/.test((body.secret || "").toUpperCase())) {
      return json({ error: msg(req, "Secret 格式无效", "Invalid secret format") }, 400);
    }
    const code = (body.code || "").trim();
    if (!/^\d{6}$/.test(code)) {
      return json({ error: msg(req, "请输入 6 位验证码", "Please enter 6-digit code") }, 400);
    }
    const secret = body.secret!.toUpperCase();
    const ok = await totpVerify(secret, code);
    if (!ok) {
      return json({ error: msg(req, "验证码错误", "Invalid verification code") }, 401);
    }
    // 验证通过 → 加密存 secret + 生成恢复码
    const cipher = await encryptSecret(secret, env.admin);
    const recoveryCodes = totpGenerateRecoveryCodes(8);
    const recoveryHash = (await Promise.all(recoveryCodes.map((c) => sha256Hex(c.replace(/\s+/g, ""))))).join(",");
    await updateSettings(env, {
      totp_enabled: "1",
      totp_secret_cipher: cipher,
      totp_recovery_hash: recoveryHash,
    });
    return json({
      ok: true,
      recovery_codes: recoveryCodes, // 只这一次明文返回，前端提示用户保存
    });
  }

  // ── 2FA Disable：关闭 2FA（需验证 admin key） ──
  if (path === "/api/admin/2fa/disable" && method === "POST") {
    const body = await readJson<{ admin_key: string }>(req);
    if (!body.admin_key || !checkAdminKey(env, body.admin_key)) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    await updateSettings(env, {
      totp_enabled: "0",
      totp_secret_cipher: "",
      totp_recovery_hash: "",
    });
    return json({ ok: true });
  }

  // ── 重新生成恢复码（覆盖旧的，旧的全部失效） ──
  if (path === "/api/admin/2fa/regen-recovery" && method === "POST") {
    const body = await readJson<{ admin_key: string }>(req);
    if (!body.admin_key || !checkAdminKey(env, body.admin_key)) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    const s = await getSettings(env);
    if (!s.totpEnabled || !s.totpSecretCipher) {
      return json({ error: msg(req, "2FA 未启用", "2FA is not enabled") }, 400);
    }
    const recoveryCodes = totpGenerateRecoveryCodes(8);
    const recoveryHash = (await Promise.all(recoveryCodes.map((c) => sha256Hex(c.replace(/\s+/g, ""))))).join(",");
    await updateSettings(env, { totp_recovery_hash: recoveryHash });
    return json({ ok: true, recovery_codes: recoveryCodes });
  }

  // ── 读取设置 ──────────────────────────────────────
  if (path === "/api/admin/settings" && method === "GET") {
    const s = await getSettings(env);
    // 读 OAuth2 providers 列表给前端展示卡片
    const providers = await env.db
      .prepare("SELECT id, label, provider_type, client_id, scope, enabled, updated_at FROM oauth_providers ORDER BY updated_at DESC")
      .all<{ id: string; label: string; provider_type: string; client_id: string; scope: string; enabled: number; updated_at: number }>();
    const enabledProviders = providers.results.filter((p) => p.enabled);
    return json({
      site_title: s.siteTitle,
      traffic_limit_gb: s.trafficLimitBytes / 1024 ** 3,
      max_downloads_per_ip: s.maxDownloadsPerIp,
      count_window_hours: s.countWindowHours,
      auto_ban: s.autoBan,
      ban_hours: s.banHours,
      traffic_used_bytes: s.trafficUsedBytes,
      // Turnstile
      turnstile_mode: s.turnstileMode,
      turnstile_threshold: s.turnstileThreshold,
      turnstile_sitekey_override: s.turnstileSitekeyOverride,
      cloudflare_turnstile_sitekey: !!env.turnstile_sitekey,
      cloudflare_turnstile_secret: !!env.turnstile_secret,
      turnstile_secret_configured: !!s.turnstileSecretCipher,
      // OAuth2 总开关 + providers 概要
      oauth_enabled: s.oauthEnabled,
      oauth_providers: providers.results.map((p) => ({
        id: p.id,
        label: p.label,
        provider_type: p.provider_type,
        client_id: p.client_id,
        scope: p.scope,
        enabled: !!p.enabled,
        secret_configured: true, // 列表里不暴露 secret 是否配，只在详情里展示
      })),
      oauth_has_enabled_providers: enabledProviders.length > 0,
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
    // Turnstile
    if (typeof body.turnstile_mode === "string") {
      const m = body.turnstile_mode as string;
      if (["off", "on_share", "on_download", "both"].includes(m)) {
        patch.turnstile_mode = m;
      }
    }
    const th = num(body.turnstile_threshold);
    if (th !== null) patch.turnstile_threshold = String(Math.floor(th));
    if (typeof body.turnstile_sitekey_override === "string") {
      // 允许清空
      patch.turnstile_sitekey_override = body.turnstile_sitekey_override.trim();
    }
    // Turnstile Secret —— 如果 Modal 里传了新密码则加密存；空字符串则清掉；__keep__ 表示保留
    if (typeof body.turnstile_secret === "string") {
      const raw = body.turnstile_secret.trim();
      if (raw === "") {
        patch.turnstile_secret_cipher = "";
      } else if (raw !== "__keep__") {
        const cipher = await encryptSecret(raw, env.admin);
        if (cipher) patch.turnstile_secret_cipher = cipher;
      }
      // raw === "__keep__" 或不传 → 保留原值不动
    }
    // OAuth2 总开关（具体 provider 配置由 /api/admin/oauth/providers CRUD 管理）
    if (typeof body.oauth_enabled === "boolean") patch.oauth_enabled = body.oauth_enabled ? "1" : "0";

    await updateSettings(env, patch);
    return json({ ok: true });
  }

  // ── 清空 Turnstile 访问计数 ────────────────────────
  if (path === "/api/admin/turnstile/visits" && method === "DELETE") {
    const days = Number(new URL(req.url).searchParams.get("days"));
    const before = days > 0 ? new Date(Date.now() - days * 86400_000).toISOString().slice(0, 10) : null;
    const r = before
      ? await env.db.prepare("DELETE FROM turnstile_visits WHERE day < ?1").bind(before).run()
      : await env.db.prepare("DELETE FROM turnstile_visits").run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 重置本月流量 ──────────────────────────────────
  if (path === "/api/admin/traffic/reset" && method === "POST") {
    await updateSettings(env, {
      traffic_used_bytes: "0",
      traffic_month: new Date().toISOString().slice(0, 7),
    });
    return json({ ok: true });
  }

  // ══════════════════════════════════════════════════════
  // OAuth2 Provider CRUD —— 多 Provider 管理
  //   GET    /api/admin/oauth/providers             列表
  //   POST   /api/admin/oauth/providers             创建
  //   GET    /api/admin/oauth/providers/:id          详情
  //   PUT    /api/admin/oauth/providers/:id          更新
  //   DELETE /api/admin/oauth/providers/:id          删除
  //   POST   /api/admin/oauth/providers/:id/toggle   启用/禁用
  // ══════════════════════════════════════════════════════

  const oauthProvidersPath = "/api/admin/oauth/providers";
  const m = path.match(/^\/api\/admin\/oauth\/providers\/([^/]+)(\/(toggle))?$/);

  // GET /api/admin/oauth/providers —— 列表（返回不含 secret 的安全摘要）
  if (path === oauthProvidersPath && method === "GET") {
    const rows = await env.db
      .prepare("SELECT id, label, provider_type, client_id, scope, custom_authorize_url, custom_token_url, custom_userinfo_url, custom_token_field, enabled, client_secret_cipher IS NOT NULL as has_secret, created_at, updated_at FROM oauth_providers ORDER BY updated_at DESC")
      .all<{ id: string; label: string; provider_type: string; client_id: string; scope: string; custom_authorize_url: string; custom_token_url: string; custom_userinfo_url: string; custom_token_field: string; enabled: number; has_secret: number; created_at: number; updated_at: number }>();
    return json({
      providers: rows.results.map((p) => ({
        id: p.id,
        label: p.label,
        provider_type: p.provider_type,
        client_id: p.client_id,
        scope: p.scope,
        custom_authorize_url: p.custom_authorize_url,
        custom_token_url: p.custom_token_url,
        custom_userinfo_url: p.custom_userinfo_url,
        custom_token_field: p.custom_token_field,
        enabled: !!p.enabled,
        secret_configured: !!p.has_secret,
        created_at: p.created_at,
        updated_at: p.updated_at,
      })),
    });
  }

  // POST /api/admin/oauth/providers —— 创建
  if (path === oauthProvidersPath && method === "POST") {
    const body = await readJson<{
      label?: string;
      provider_type?: string;
      client_id?: string;
      client_secret?: string;
      scope?: string;
      custom_authorize_url?: string;
      custom_token_url?: string;
      custom_userinfo_url?: string;
      custom_token_field?: string;
      enabled?: boolean;
    }>(req);
    const validTypes = ["github", "google", "microsoft", "discord", "custom"];
    const providerType = (body.provider_type && validTypes.includes(body.provider_type))
      ? body.provider_type
      : "github";
    const label = (body.label || providerType).trim().slice(0, 40);
    const clientId = (body.client_id || "").trim();
    if (!clientId) return json({ error: "client_id_required" }, 400);
    const scope = (body.scope || "").trim() || "openid email profile";
    const now = Date.now();
    const id = randomId();
    let secretCipher: string | null = null;
    if (body.client_secret && body.client_secret.trim()) {
      secretCipher = await encryptSecret(body.client_secret.trim(), env.admin);
      if (!secretCipher) return json({ error: "secret_encrypt_failed" }, 500);
    }
    await env.db
      .prepare(
        `INSERT INTO oauth_providers(id, label, provider_type, client_id, client_secret_cipher, scope,
            custom_authorize_url, custom_token_url, custom_userinfo_url, custom_token_field,
            enabled, created_at, updated_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)`
      )
      .bind(
        id,
        label,
        providerType,
        clientId,
        secretCipher,
        scope,
        (body.custom_authorize_url || "").trim(),
        (body.custom_token_url || "").trim(),
        (body.custom_userinfo_url || "").trim(),
        (body.custom_token_field || "access_token").trim(),
        body.enabled === false ? 0 : 1,
        now,
        now
      )
      .run();
    return json({ ok: true, id });
  }

  // PUT /api/admin/oauth/providers/:id —— 更新
  if (m && !m[3] && method === "PUT") {
    const id = m[1];
    const row = await env.db
      .prepare("SELECT * FROM oauth_providers WHERE id = ?1")
      .bind(id)
      .first<Record<string, unknown>>();
    if (!row) return json({ error: "not_found" }, 404);
    const body = await readJson<{
      label?: string;
      provider_type?: string;
      client_id?: string;
      client_secret?: string; // 非空=更新；空字符串=清除；不传=保留
      scope?: string;
      custom_authorize_url?: string;
      custom_token_url?: string;
      custom_userinfo_url?: string;
      custom_token_field?: string;
      enabled?: boolean;
    }>(req);

    const now = Date.now();
    const updates: string[] = ["updated_at = ?1"];
    const values: unknown[] = [now];

    if (typeof body.label === "string" && body.label.trim()) {
      updates.push("label = ?" + (values.length + 1));
      values.push(body.label.trim().slice(0, 40));
    }
    if (typeof body.provider_type === "string") {
      const valid = ["github", "google", "microsoft", "discord", "custom"];
      if (valid.includes(body.provider_type)) {
        updates.push("provider_type = ?" + (values.length + 1));
        values.push(body.provider_type);
      }
    }
    if (typeof body.client_id === "string") {
      updates.push("client_id = ?" + (values.length + 1));
      values.push(body.client_id.trim());
    }
    if (typeof body.scope === "string") {
      updates.push("scope = ?" + (values.length + 1));
      values.push(body.scope.trim());
    }
    if (typeof body.custom_authorize_url === "string") {
      updates.push("custom_authorize_url = ?" + (values.length + 1));
      values.push(body.custom_authorize_url.trim());
    }
    if (typeof body.custom_token_url === "string") {
      updates.push("custom_token_url = ?" + (values.length + 1));
      values.push(body.custom_token_url.trim());
    }
    if (typeof body.custom_userinfo_url === "string") {
      updates.push("custom_userinfo_url = ?" + (values.length + 1));
      values.push(body.custom_userinfo_url.trim());
    }
    if (typeof body.custom_token_field === "string" && body.custom_token_field.trim()) {
      updates.push("custom_token_field = ?" + (values.length + 1));
      values.push(body.custom_token_field.trim());
    }
    if (typeof body.enabled === "boolean") {
      updates.push("enabled = ?" + (values.length + 1));
      values.push(body.enabled ? 1 : 0);
    }
    // Client secret：三种处理模式
    if (typeof body.client_secret === "string") {
      if (body.client_secret === "") {
        // 显式清除
        updates.push("client_secret_cipher = NULL");
      } else if (body.client_secret.trim() !== "__keep__") {
        // 更新为新密码
        const cipher = await encryptSecret(body.client_secret.trim(), env.admin);
        if (!cipher) return json({ error: "secret_encrypt_failed" }, 500);
        updates.push("client_secret_cipher = ?" + (values.length + 1));
        values.push(cipher);
      }
      // 其他情况（undefined 或 __keep__）：保留原值不动
    }

    values.push(id);
    const sql = `UPDATE oauth_providers SET ${updates.join(", ")} WHERE id = ?${values.length}`;
    await env.db.prepare(sql).bind(...values).run();
    return json({ ok: true });
  }

  // DELETE /api/admin/oauth/providers/:id
  if (m && !m[3] && method === "DELETE") {
    const id = m[1];
    await env.db.prepare("DELETE FROM oauth_providers WHERE id = ?1").bind(id).run();
    return json({ ok: true });
  }

  // POST /api/admin/oauth/providers/:id/toggle —— 切换启用/禁用
  if (m && m[3] === "toggle" && method === "POST") {
    const id = m[1];
    await env.db
      .prepare("UPDATE oauth_providers SET enabled = 1 - enabled, updated_at = ?1 WHERE id = ?2")
      .bind(Date.now(), id)
      .run();
    return json({ ok: true });
  }

  return json({ error: "not_found" }, 404);
}
