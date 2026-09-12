import type { Env, ShareWithFile } from "./types";
import { getSettings, addTraffic } from "./settings";
import { parseUA } from "./ua";
import { clientIp, isAdminWhitelisted } from "./auth";
import { errorPage } from "./pages";
import { hmacHex, sha256Hex, randomHex, safeEqual, decryptSecret } from "./crypto";
import { verifyOAuthSession } from "./oauth";

const TOKEN_TTL_MS = 24 * 3600_000; // 授权令牌有效期 24h

/* ═══════════ Turnstile 辅助函数 ═══════════ */

/**
 * 计算一个 IP 今天已访问过多少次分享页 → 判断是否需要弹 Turnstile。
 * 同时把计数 +1 写回（用 UPSERT 单次 SQL 原子完成）。
 */
async function trackAndGetVisits(env: Env, ip: string): Promise<number> {
  const day = new Date().toISOString().slice(0, 10);
  // 先查 +1
  const upsert = env.db.prepare(
    `INSERT INTO turnstile_visits(ip, day, count) VALUES(?1, ?2, 1)
     ON CONFLICT(ip, day) DO UPDATE SET count = count + 1`
  );
  await upsert.bind(ip, day).run();
  const row = await env.db
    .prepare("SELECT count FROM turnstile_visits WHERE ip = ?1 AND day = ?2")
    .bind(ip, day)
    .first<{ count: number }>();
  return row?.count ?? 1;
}

/** 从 env 或 settings.cipher 拿到最终的 Turnstile Secret（优先 env） */
async function getTurnstileSecret(env: Env, settings: { turnstileSecretCipher: string | null }): Promise<string | null> {
  if (env.turnstile_secret) return env.turnstile_secret;
  if (settings.turnstileSecretCipher) return await decryptSecret(settings.turnstileSecretCipher, env.admin);
  return null;
}

/** 判断当前 Turnstile 是否可用（secret 必须在 env 或 settings 里配） */
export async function isTurnstileEnabled(
  env: Env,
  settings: { turnstileMode: string; turnstileThreshold: number; turnstileSecretCipher: string | null }
): Promise<boolean> {
  const secret = await getTurnstileSecret(env, settings);
  if (!secret) return false;
  if (settings.turnstileMode === "off") return false;
  return true;
}

/**
 * 返回 Turnstile 状态 + sitekey（前端渲染 widget 用）。
 * 如果 sitekey 没配 → 前端根本不会调 Turnstile 脚本。
 */
export function getTurnstileInfo(
  env: Env,
  settings: { turnstileMode: string; turnstileSitekeyOverride: string | null }
): { sitekey: string | null; mode: string } {
  const sitekey = env.turnstile_sitekey || settings.turnstileSitekeyOverride || null;
  return { sitekey, mode: settings.turnstileMode };
}

/**
 * 验证 Turnstile token —— 向 Cloudflare siteverify 发 POST。
 * 官方要求 POST application/x-www-form-urlencoded: secret + token
 */
export async function verifyTurnstileToken(
  env: Env,
  settings: { turnstileSecretCipher: string | null },
  token: string,
  remoteip: string
): Promise<boolean> {
  const secret = await getTurnstileSecret(env, settings);
  if (!secret || !token) return false;
  try {
    const form = new URLSearchParams({
      secret,
      response: token,
      remoteip,
    });
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    if (!r.ok) return false;
    const j = (await r.json()) as { success?: boolean; errorcodes?: string[] };
    return !!j.success;
  } catch {
    return false;
  }
}

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

/** GET /s/:token —— 分享页元信息（供前端渲染） */
export async function handleShareInfo(req: Request, env: Env, token: string): Promise<Response> {
  const row = await getShare(env, token);
  if (!row) return Response.json({ error: "not_found" }, { status: 404 });
  const settings = await getSettings(env);
  const ip = clientIp(req);
  const isWhitelisted = isAdminWhitelisted(ip, settings.adminIps);
  const quotaExceeded =
    !isWhitelisted && settings.trafficLimitBytes > 0 && settings.trafficUsedBytes >= settings.trafficLimitBytes;
  let status: "ok" | "gone" | "expired" | "maxed" = "ok";
  if (row.revoked) status = "gone";
  else if (row.expires_at && row.expires_at < Date.now()) status = "expired";
  else if (row.max_downloads && row.download_count >= row.max_downloads) status = "maxed";

  // Turnstile：在 share 页面加载时统计一次访问，判断是否需要弹
  const enabled = await isTurnstileEnabled(env, settings);
  let needsTurnstile = false;
  let visitCount = 0;
  let sitekey: string | null = null;
  if (enabled) {
    const { sitekey: sk, mode } = getTurnstileInfo(env, settings);
    sitekey = sk;
    // on_share / both 模式都在此时判断
    if (mode === "on_share" || mode === "both") {
      visitCount = await trackAndGetVisits(env, ip);
      needsTurnstile = visitCount > settings.turnstileThreshold;
    }
  }

  // OAuth2：检查是否已登录
  let oauthAuthed = false;
  let oauthProvider = settings.oauthEnabled ? settings.oauthProvider : "";
  if (settings.oauthEnabled) {
    const oauthCheck = await verifyOAuthSession(env, req.headers.get("cookie"));
    oauthAuthed = oauthCheck.ok;
  }

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
    turnstile: {
      enabled,
      sitekey,
      mode: settings.turnstileMode,
      threshold: settings.turnstileThreshold,
      needs_now: needsTurnstile,
      visit_count: visitCount,
    },
    oauth: {
      enabled: settings.oauthEnabled,
      provider: oauthProvider,
      client_id: settings.oauthClientId,
      authed: oauthAuthed,
    },
  });
}

async function getShare(env: Env, token: string): Promise<ShareWithFile | null> {
  return await env.db.prepare(
    `SELECT s.id, s.file_id, s.created_at, s.expires_at, s.max_downloads, s.download_count, s.revoked, s.password_hash,
            s.download_name, f.key, f.name, f.size, f.mime
     FROM shares s JOIN files f ON f.id = s.file_id
     WHERE s.id = ?1`
  )
    .bind(token)
    .first<ShareWithFile>();
}

/** POST /s/:token/verify —— 校验分享密码 + 可选 Turnstile，成功后颁发下载令牌 */
export async function handleVerify(req: Request, env: Env, token: string): Promise<Response> {
  if (req.method !== "POST") return Response.json({ error: "method_not_allowed" }, { status: 405 });
  const row = await getShare(env, token);
  if (!row) return Response.json({ error: "not_found" }, { status: 404 });
  let body: { password?: string; turnstile?: string } = {};
  try {
    body = await req.json();
  } catch {}

  const settings = await getSettings(env);
  const ip = clientIp(req);
  const turnstileOn = await isTurnstileEnabled(env, settings) && (settings.turnstileMode === "both");

  // Turnstile 校验（both 模式下必须有有效 token）
  if (turnstileOn) {
    const pass = await verifyTurnstileToken(env, settings, String(body.turnstile ?? ""), ip);
    if (!pass) {
      return Response.json({ error: "turnstile_failed" }, { status: 403 });
    }
  }

  // 密码校验
  if (!row.password_hash) {
    // 无密码分享 → 如果 Turnstile 通过 + 没密码，直接给下载地址
    return Response.json({ ok: true, url: `/s/${token}/download` });
  }
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

  // 🔴 Bug A 修复：主流程原子扣减下载次数 —— 超卖拦截
  //
  // 原实现在 L175 用 row.download_count（旧值）拦截，计数更新在 waitUntil 里，
  // 响应发出后才 +1 → 并发 20 个请求全过，max=3 形同虚设。
  //
  // 修复：把 UPDATE 挪到主流程、R2 读取之前，用 SQL 条件原子完成：
  //   UPDATE shares SET download_count = download_count + 1
  //   WHERE id = ? AND (max_downloads IS NULL OR download_count < max_downloads)
  // changes = 0  → 已达上限，拦截
  // changes = 1  → 原子成功，继续读取 R2
  if (row.max_downloads) {
    const r = await env.db
      .prepare(
        `UPDATE shares SET download_count = download_count + 1
         WHERE id = ?1 AND download_count < ?2`
      )
      .bind(token, row.max_downloads)
      .run();
    if ((r.meta.changes ?? 0) === 0) {
      return errorPage(
        req,
        410,
        { zh: "下载次数已达上限", en: "Download Limit Reached" },
        {
          zh: `该资源允许下载 ${row.max_downloads} 次，名额已用完。`,
          en: `This resource allows ${row.max_downloads} downloads and the quota is used up.`,
        }
      );
    }
  }

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

  // 2.6 OAuth2 下载鉴权
  if (settings.oauthEnabled) {
    const oauthResult = await verifyOAuthSession(env, req.headers.get("cookie"));
    if (!oauthResult.ok) {
      const providerName = settings.oauthProvider === "custom" ? "OAuth" : settings.oauthProvider;
      const startUrl = `/oauth/start?provider=${encodeURIComponent(settings.oauthProvider)}&redirect=${encodeURIComponent("/s/" + token)}`;
      return errorPage(
        req,
        401,
        { zh: "需要登录", en: "OAuth Login Required" },
        {
          zh: `该资源需要通过 ${providerName} 账号登录后才能下载。`,
          en: `This resource requires login with ${providerName} to download.`,
        },
        {
          siteTitle: settings.siteTitle,
          oauth_login_url: startUrl,
        }
      );
    }
  }

  // 2.7 Turnstile 下载验证码（on_download / both 模式）
  if (await isTurnstileEnabled(env, settings)) {
    const url = new URL(req.url);
    const mode = settings.turnstileMode;
    const downloadGate = mode === "on_download" || mode === "both";
    if (downloadGate) {
      const turnstileToken = url.searchParams.get("cf");
      // on_download 模式下：没传 token → 弹 Turnstile
      // both 模式下：token 必须已由 verify 阶段校验，这里只是双重兜底
      if (!turnstileToken) {
        return errorPage(
          req,
          403,
          { zh: "需要验证码", en: "Turnstile Required" },
          {
            zh: "点击下载前需要先通过人机验证。请刷新页面重试。",
            en: "Please complete the human verification before downloading. Refresh and try again.",
          },
          { siteTitle: settings.siteTitle }
        );
      }
      const pass = await verifyTurnstileToken(env, settings, turnstileToken, ip);
      if (!pass) {
        return errorPage(
          req,
          403,
          { zh: "验证码校验失败", en: "Turnstile Failed" },
          { zh: "人机验证未通过，请刷新页面重试。", en: "Human verification failed. Please refresh and try again." },
          { siteTitle: settings.siteTitle }
        );
      }
    }
  }

  // 3. 流量限额：达到预设上限立即暂停所有下载（防止流量超额扣费）
  //    白名单 IP 不受此限制
  {
    const whitelisted = isAdminWhitelisted(ip, settings.adminIps);
    if (!whitelisted && settings.trafficLimitBytes > 0 && settings.trafficUsedBytes >= settings.trafficLimitBytes) {
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
  const displayName = (row as any).download_name || row.name;
  headers.set(
    "content-disposition",
    `attachment; filename*=UTF-8''${encodeURIComponent(displayName)}`
  );
  // 注意: R2 分片读取后 obj.size 仍是整个对象的大小，实际分片长度需自行计算
  const servedLen = range ? range.length : row.size;
  headers.set("content-length", String(servedLen));
  if (range) {
    headers.set("content-range", `bytes ${range.offset}-${range.offset + servedLen - 1}/${row.size}`);
  }

  // 6. 后台记录：下载日志 + 流量（计数已在主流程原子扣减完成）
  const bytes = servedLen;
  ctx.waitUntil(
    (async () => {
      const { browser, os } = parseUA(ua);
      await env.db.prepare(
        `INSERT INTO download_logs(share_id, file_id, file_name, ip, ua, browser, os, country, bytes, created_at)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`
      )
        .bind(token, row.file_id, row.name, ip, ua.slice(0, 500), browser, os, country, bytes, Date.now())
        .run();
      await addTraffic(env, bytes);
    })()
  );

  return new Response(obj.body, { status: range ? 206 : 200, headers });
}
