import type { Env, ShareWithFile } from "./types";
import { getSettings, addTraffic } from "./settings";
import { parseUA } from "./ua";
import { clientIp } from "./auth";
import { errorPage } from "./pages";
import { hmacHex, sha256Hex, randomHex, safeEqual } from "./crypto";

/** 解析 Range 头 → {offset, length}，无效返回 null */
function parseRange(header: string | null, size: number): { offset: number; length: number } | null {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m || (m[1] === "" && m[2] === "")) return null;
  let offset: number, length: number;
  if (m[1] === "") {
    // 后缀范围: bytes=-N
    const n = Math.min(Number(m[2]), size);
    offset = size - n;
    length = n;
  } else {
    offset = Number(m[1]);
    const end = m[2] === "" ? size - 1 : Math.min(Number(m[2]), size - 1);
    length = end - offset + 1;
  }
  if (offset >= size || length <= 0) return null;
  return { offset, length };
}

/* ═══════════ 分享密码 & 下载授权令牌 ═══════════
 * 密码存储为加盐 SHA-256（salt:sha256(salt:password)）；下载授权用 HMAC 签名携带过期时间，
 * 避免把明文密码拼进下载 URL。HMAC 密钥复用 admin，无需新增 Secret，密钥轮换时短时令牌即失效。
 */
/** 加盐与密码哈希串（salt:hashhex） */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomHex();
  return salt + ":" + await sha256Hex(salt + ":" + password);
}
/** 常数时间校验密码 */
async function verifyPassword(stored: string, password: string): Promise<boolean> {
  const i = stored.indexOf(":");
  if (i < 0) return false;
  const salt = stored.slice(0, i);
  const want = stored.slice(i + 1);
  const got = await sha256Hex(salt + ":" + password);
  return safeEqual(want, got);
}
/** 颁发短时下载授权令牌：格式 `${到期时间戳}.${HMAC}` */
async function issueToken(env: Env, token: string): Promise<string> {
  const exp = Date.now() + TOKEN_TTL_MS;
  const sig = await hmacHex(env.admin, `${token}:${exp}`);
  return `${exp}.${sig}`;
}
/** 校验下载授权令牌（存在于 URL query string 中） */
async function verifyShareToken(env: Env, token: string, query: string): Promise<boolean> {
  const t = new URLSearchParams(query).get("t");
  if (!t) return false;
  const i = t.indexOf(".");
  if (i < 0) return false;
  const exp = Number(t.slice(0, i));
  if (!Number.isFinite(exp) || exp < Date.now()) return false;
  const want = await hmacHex(env.admin, `${token}:${exp}`);
  return safeEqual(t.slice(i + 1), want);
}

const TOKEN_TTL_MS = 24 * 3600_000; // 授权令牌有效期 24h

/** GET /s/:token —— 分享页元信息（供前端渲染） */
export async function handleShareInfo(req: Request, env: Env, token: string): Promise<Response> {
  const row = await getShare(env, token);
  if (!row) return Response.json({ error: "not_found" }, { status: 404 });
  const settings = await getSettings(env);
  const quotaExceeded =
    settings.trafficLimitBytes > 0 && settings.trafficUsedBytes >= settings.trafficLimitBytes;
  let status: "ok" | "gone" | "expired" | "maxed" = "ok";
  if (row.revoked) status = "gone";
  else if (row.expires_at && row.expires_at < Date.now()) status = "expired";
  else if (row.max_downloads && row.download_count >= row.max_downloads) status = "maxed";
  return Response.json({
    status,
    name: row.name,
    size: row.size,
    mime: row.mime,
    downloads: row.download_count,
    created_at: row.created_at,
    expires_at: row.expires_at,
    max_downloads: row.max_downloads,
    needs_password: !!row.password_hash,
    quota_exceeded: quotaExceeded,
    site_title: settings.siteTitle,
  });
}

async function getShare(env: Env, token: string): Promise<ShareWithFile | null> {
  return await env.db.prepare(
    `SELECT s.id, s.file_id, s.created_at, s.expires_at, s.max_downloads, s.download_count, s.revoked, s.password_hash,
            f.key, f.name, f.size, f.mime
     FROM shares s JOIN files f ON f.id = s.file_id
     WHERE s.id = ?1`
  )
    .bind(token)
    .first<ShareWithFile>();
}

/** POST /s/:token/verify —— 校验分享密码，成功后颁发短时下载授权令牌 */
export async function handleVerify(req: Request, env: Env, token: string): Promise<Response> {
  if (req.method !== "POST") return Response.json({ error: "method_not_allowed" }, { status: 405 });
  const row = await getShare(env, token);
  if (!row) return Response.json({ error: "not_found" }, { status: 404 });
  if (!row.password_hash) return Response.json({ ok: true, url: `/s/${token}/download` });
  let body: { password?: string } = {};
  try {
    body = await req.json();
  } catch {}
  if (!(await verifyPassword(row.password_hash, String(body.password ?? ""))))
    return Response.json({ error: "bad_password" }, { status: 401 });
  const ticket = await issueToken(env, token);
  return Response.json({ ok: true, url: `/s/${token}/download?t=${ticket}` });
}

/** GET /s/:token/download —— 下载主流程：封禁检查 → 有效性检查 → 流量限额 → 重复下载封禁 → 流式输出 */
export async function handleDownload(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  token: string
): Promise<Response> {
  const ip = clientIp(req);
  const ua = req.headers.get("user-agent") ?? "";
  const country = req.headers.get("cf-ipcountry") ?? "";

  // 1. 封禁检查（过期自动解封）
  const ban = await env.db.prepare(
    "SELECT reason, expires_at FROM banned_ips WHERE ip = ?1"
  )
    .bind(ip)
    .first<{ reason: string | null; expires_at: number | null }>();
  if (ban) {
    if (ban.expires_at && ban.expires_at < Date.now()) {
      await env.db.prepare("DELETE FROM banned_ips WHERE ip = ?1").bind(ip).run();
    } else {
      return errorPage(
        req,
        403,
        { zh: "访问已被封禁", en: "Access Banned" },
        {
          zh: ban.reason || "由于重复下载行为，该 IP 已被暂时封禁。",
          en: ban.reason || "This IP has been temporarily banned due to repeated download behavior.",
        }
      );
    }
  }

  // 2. 分享有效性
  const row = await getShare(env, token);
  if (!row)
    return errorPage(
      req,
      404,
      { zh: "链接不存在", en: "Link Not Found" },
      { zh: "该分享链接无效，或已被管理员删除。", en: "This share link is invalid or has been removed." }
    );
  if (row.revoked)
    return errorPage(
      req,
      410,
      { zh: "链接已失效", en: "Link Revoked" },
      { zh: "该分享已被管理员撤销。", en: "This share has been revoked by the administrator." }
    );
  if (row.expires_at && row.expires_at < Date.now())
    return errorPage(
      req,
      410,
      { zh: "链接已过期", en: "Link Expired" },
      { zh: "该分享已超过有效期，无法继续下载。", en: "This share has expired and is no longer available." }
    );
  if (row.max_downloads && row.download_count >= row.max_downloads)
    return errorPage(
      req,
      410,
      { zh: "下载次数已达上限", en: "Download Limit Reached" },
      {
        zh: `该资源允许下载 ${row.max_downloads} 次，名额已用完。`,
        en: `This resource allows ${row.max_downloads} downloads and the quota is used up.`,
      }
    );

  // 2.5 密码校验：需先解锁（POST /s/:token/verify 获取授权令牌）
  if (row.password_hash && !(await verifyShareToken(env, token, new URL(req.url).search))) {
    return errorPage(
      req,
      403,
      { zh: "需要访问密码", en: "Password Required" },
      { zh: "该分享受密码保护，请输入访问密码后再下载。", en: "This share is password-protected. Enter the access password to download." }
    );
  }

  const settings = await getSettings(env);

  // 3. 流量限额：达到预设上限立即暂停所有下载（防止流量超额扣费）
  if (settings.trafficLimitBytes > 0 && settings.trafficUsedBytes >= settings.trafficLimitBytes) {
    return errorPage(
      req,
      503,
      { zh: "下载已暂停", en: "Downloads Paused" },
      {
        zh: "本月流量已达预设限额，为避免产生额外费用，下载服务已自动暂停。请联系管理员调整限额或重置流量。",
        en: "The monthly traffic quota has been reached. To avoid extra charges, downloads are automatically paused. Please contact the administrator to raise the quota or reset traffic.",
      },
      { siteTitle: settings.siteTitle }
    );
  }

  // 4. 单 IP 重复下载检查 + 自动封禁
  if (settings.maxDownloadsPerIp > 0) {
    const since =
      settings.countWindowHours > 0 ? Date.now() - settings.countWindowHours * 3600_000 : 0;
    const { c } =
      (await env.db.prepare(
        "SELECT COUNT(*) AS c FROM download_logs WHERE share_id = ?1 AND ip = ?2 AND created_at > ?3"
      )
        .bind(token, ip, since)
        .first<{ c: number }>()) ?? { c: 0 };
    if (c >= settings.maxDownloadsPerIp) {
      if (settings.autoBan) {
        const expiresAt =
          settings.banHours > 0 ? Date.now() + settings.banHours * 3600_000 : null;
        await env.db.prepare(
          `INSERT INTO banned_ips(ip, reason, banned_at, expires_at) VALUES(?1, ?2, ?3, ?4)
           ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, banned_at = excluded.banned_at, expires_at = excluded.expires_at`
        )
          .bind(
            ip,
            `重复下载「${row.name}」超过 ${settings.maxDownloadsPerIp} 次`,
            Date.now(),
            expiresAt
          )
          .run();
      }
      return errorPage(
        req,
        403,
        { zh: "重复下载被拦截", en: "Duplicate Download Blocked" },
        {
          zh:
            `同一 IP 在统计窗口内下载此资源的次数已达上限（${settings.maxDownloadsPerIp} 次）。` +
            (settings.autoBan ? "该 IP 已被自动封禁。" : ""),
          en:
            `This IP has reached the download limit for this resource within the counting window (${settings.maxDownloadsPerIp}).` +
            (settings.autoBan ? " The IP has been automatically banned." : ""),
        },
        { siteTitle: settings.siteTitle }
      );
    }
  }

  // 5. 从 R2 读取（支持断点续传 Range）
  const range = parseRange(req.headers.get("range"), row.size);
  let obj: R2ObjectBody;
  try {
    obj = (await env.r2.get(row.key, range ? { range } : undefined)) as R2ObjectBody;
  } catch {
    return errorPage(
      req,
      416,
      { zh: "请求范围无效", en: "Invalid Range" },
      { zh: "Range 请求无法满足，请重新下载。", en: "The range request cannot be satisfied. Please restart the download." }
    );
  }
  if (!obj)
    return errorPage(
      req,
      404,
      { zh: "文件不存在", en: "File Not Found" },
      { zh: "文件可能已被删除，请联系管理员。", en: "The file may have been deleted. Please contact the administrator." }
    );

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  headers.set("accept-ranges", "bytes");
  headers.set("cache-control", "no-store");
  headers.set(
    "content-disposition",
    `attachment; filename*=UTF-8''${encodeURIComponent(row.name)}`
  );
  // 注意: R2 分片读取后 obj.size 仍是整个对象的大小，实际分片长度需自行计算
  const servedLen = range ? range.length : row.size;
  headers.set("content-length", String(servedLen));
  if (range) {
    headers.set("content-range", `bytes ${range.offset}-${range.offset + servedLen - 1}/${row.size}`);
  }

  // 6. 后台记录：下载日志 + 计数 + 流量（不阻塞响应）
  const bytes = servedLen;
  ctx.waitUntil(
    (async () => {
      const { browser, os } = parseUA(ua);
      await env.db.batch([
        env.db.prepare(
          `INSERT INTO download_logs(share_id, file_id, file_name, ip, ua, browser, os, country, bytes, created_at)
           VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`
        ).bind(token, row.file_id, row.name, ip, ua.slice(0, 500), browser, os, country, bytes, Date.now()),
        env.db.prepare("UPDATE shares SET download_count = download_count + 1 WHERE id = ?1").bind(token),
      ]);
      await addTraffic(env, bytes);
    })()
  );

  return new Response(obj.body, { status: range ? 206 : 200, headers });
}
