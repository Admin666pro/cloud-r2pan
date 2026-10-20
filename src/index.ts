import type { Env } from "./types";
import { ensureSchema, writeErrorLog } from "./db";
import { parseUA } from "./ua";
import { handleAdminApi } from "./admin";
import { handleDownload, handleDirectDownload, handleShareInfo, handleVerify, handlePreviewOpen, handlePreviewRaw, handlePreviewZip } from "./public";
import { serveAdminPage, serveSharePage, serveMarketPage, errorPage } from "./pages";
// 全球分布地球仪的内置地球贴图（二进制模块，见 wrangler 的 Data 规则）
import earthDayTexture from "./assets/earth-day.jpg";
import {
  handleOAuthStart,
  handleOAuthCallback,
  handleOAuthSession,
  handleOAuthLogout,
  handleOAuthProviders,
} from "./oauth_handlers";
import { handleAdminOauthStart, handleAdminOauthCallback } from "./admin_oauth";
import { findCodeByString, formatCodeStatus, checkCodeUsable, isCodeLenientFormat } from "./codes";

/** 客户端真实 IP：从 CF 头或连接地址取 */
function clientIp(req: Request): string {
  const fwd = req.headers.get("cf-connecting-ip");
  if (fwd) return fwd.split(",")[0].trim();
  return req.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
}

/**
 * IP 限流（Worker 内存实现）：
 *   - 只限制公开敏感端点（激活码查询）
 *   - 1 分钟窗口内最多 30 次请求
 *   - 超过返回 429；连续超限自动封禁 5 分钟
 *
 * ⚠️ Worker 无状态，内存会在隔离重启时清空。
 *    这只是加重爆破成本，不是精确计费。要严格限流请用 KV/D1。
 */
const RATE_LIMIT_WINDOW_MS = 60 * 1000;        // 1 分钟窗口
const RATE_LIMIT_MAX = 30;                     // 窗口内最多 30 次
const RATE_LIMIT_BAN_MS = 5 * 60 * 1000;       // 超限后封禁 5 分钟
interface RateEntry { count: number; windowStart: number; bannedUntil: number; }
const rateLimitMap = new Map<string, RateEntry>();
function checkRateLimit(ip: string): { ok: boolean; retryAfterSec?: number } {
  const now = Date.now();
  let entry = rateLimitMap.get(ip);
  if (!entry) {
    entry = { count: 0, windowStart: now, bannedUntil: 0 };
    rateLimitMap.set(ip, entry);
  }
  // 封禁中
  if (entry.bannedUntil > now) {
    return { ok: false, retryAfterSec: Math.ceil((entry.bannedUntil - now) / 1000) };
  }
  // 重置窗口
  if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    entry.count = 0;
    entry.windowStart = now;
  }
  entry.count++;
  if (entry.count > RATE_LIMIT_MAX) {
    entry.bannedUntil = now + RATE_LIMIT_BAN_MS;
    return { ok: false, retryAfterSec: Math.ceil(RATE_LIMIT_BAN_MS / 1000) };
  }
  // 顺便清理老条目（简单版：超过 1 分钟没访问就清掉）
  for (const [k, v] of rateLimitMap) {
    if (now - v.windowStart > RATE_LIMIT_WINDOW_MS * 3 && v.bannedUntil === 0) {
      rateLimitMap.delete(k);
    }
  }
  return { ok: true };
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await route(req, env, ctx);
    } catch (err: any) {
      console.error("unhandled error:", err);
      // 未捕获异常落库（错误日志），方便开发者排查
      try {
        const ua = req.headers.get("user-agent") ?? "";
        const { browser, os } = parseUA(ua);
        ctx.waitUntil(
          writeErrorLog(env, {
            source: "backend",
            message: String(err?.message ?? err),
            stack: err?.stack ?? null,
            path: new URL(req.url).pathname,
            url: req.url,
            ua,
            browser,
            os,
            country: req.headers.get("cf-ipcountry") ?? null,
            ip: clientIp(req),
          })
        );
      } catch {
        /* 日志失败不影响错误页返回 */
      }
      return errorPage(
        req,
        500,
        { zh: "服务出错了", en: "Something Went Wrong" },
        { zh: "服务器内部错误，请稍后重试。", en: "An internal server error occurred. Please try again later." }
      );
    }
  },
};

async function route(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  // 首页：根据管理员设置决定去向（默认 → /admin；开启后 → /market）
  if (path === "/") {
    await ensureSchema(env);
    const { getSettings } = await import("./settings");
    const s = await getSettings(env);
    const target = s.homeRedirectMarket ? "/market" : "/admin";
    return Response.redirect(new URL(target, url).toString(), 302);
  }

  // 全球分布地球仪的内置地球贴图 —— 同源提供，不依赖外部 CDN。
  // 外部 CDN 在部分网络环境会加载失败，echarts-gl 会退回渲染成纯白色球体（看起来像月亮）。
  if (path === "/assets/earth-day.jpg" && (req.method === "GET" || req.method === "HEAD")) {
    return new Response(earthDayTexture, {
      headers: {
        "content-type": "image/jpeg",
        // 内容随代码内置、不会变化，可长效强缓存
        "cache-control": "public, max-age=31536000, immutable",
      },
    });
  }

  // 管理后台页面（/admin/apple 是隐藏的 Apple 玻璃风）
  if (path === "/admin" || path === "/admin/" || path.startsWith("/admin/apple")) {
    return serveAdminPage();
  }

  // 管理员第三方 OAuth2 登录 / 绑定回调（与访客下载的 /oauth/* 独立）
  //   /admin/oauth/:provider/start   provider ∈ github / google / microsoft
  //   /admin/oauth/callback          统一回调，Provider 编码在 state 里
  const adminOauthStart = /^\/admin\/oauth\/([a-z]+)\/start$/.exec(path);
  if (adminOauthStart && req.method === "GET") {
    await ensureSchema(env);
    return handleAdminOauthStart(req, env, adminOauthStart[1]);
  }
  if (path === "/admin/oauth/callback" && req.method === "GET") {
    await ensureSchema(env);
    return handleAdminOauthCallback(req, env);
  }

  // 管理 API
  if (path.startsWith("/api/admin/")) {
    return handleAdminApi(req, env, ctx, path);
  }

  // ══════════════ OAuth2 路由 ══════════════
  await ensureSchema(env);

  if (path === "/oauth/providers" && req.method === "GET") {
    return handleOAuthProviders(req, env);
  }
  if (path === "/oauth/start" && req.method === "GET") {
    return handleOAuthStart(req, env);
  }
  if (path === "/oauth/callback" && req.method === "GET") {
    return handleOAuthCallback(req, env);
  }
  if (path === "/oauth/session" && req.method === "GET") {
    return handleOAuthSession(req, env);
  }
  if (path === "/oauth/logout" && (req.method === "POST" || req.method === "GET")) {
    return handleOAuthLogout(req);
  }

  // ══════════════════════════════════════════════════════════════
  // 公开激活码查询接口（任何人可以查某个码的余额 / 状态）
  // GET /api/codes/status?code=R2PAN-XXXX-XXXX-XXXX
  // ══════════════════════════════════════════════════════════════
  if (path === "/api/codes/status" && req.method === "GET") {
    await ensureSchema(env);
    // ① IP 限流 —— 公开端点，防枚举爆破
    const ip = clientIp(req);
    const limit = checkRateLimit(ip);
    if (!limit.ok) {
      return Response.json(
        { ok: false, error: "rate_limited", message: "请求过于频繁，请稍后再试" },
        { status: 429, headers: { "Retry-After": String(limit.retryAfterSec ?? 60) } }
      );
    }
    const code = (new URL(req.url).searchParams.get("code") || "").trim().toUpperCase();
    if (!code) {
      return Response.json({ ok: false, error: "missing_code" }, { status: 400 });
    }
    // ② 格式校验 —— 纯垃圾字符直接 400，不消耗限流配额也不查 DB
    if (!isCodeLenientFormat(code)) {
      return Response.json({ ok: false, error: "bad_format", message: "激活码格式不正确" }, { status: 400 });
    }
    const row = await findCodeByString(env, code);
    if (!row) {
      return Response.json({ ok: false, error: "not_found", message: "码不存在" }, { status: 404 });
    }
    const check = checkCodeUsable(row as any);
    const status = formatCodeStatus(row as any);
    return Response.json({
      ok: true,
      code: row.code,
      usable: check.ok,
      reason: check.reason,
      message: check.message,
      status,
    });
  }

  // ══════════════════════════════════════════════════════════════
  // 下载市场 —— 公开页面 + API
  // ══════════════════════════════════════════════════════════════
  // 市场 HTML 页面
  if ((path === "/market" || path === "/market/") && (req.method === "GET" || req.method === "HEAD")) {
    return serveMarketPage(req);
  }
  // 市场搜索/排序 API
  if (path === "/api/market" && req.method === "GET") {
    await ensureSchema(env);
    const url = new URL(req.url);
    const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
    const perPage = Math.min(50, Math.max(6, Number(url.searchParams.get("size")) || 12));
    const q = url.searchParams.get("q")?.trim();
    const sort = url.searchParams.get("sort") || "hot"; // hot | newest | downloads | views
    const now = Date.now();
    // 只返回有效分享：is_market=1, revoked=0, 没过期, 没达上限, 有密码的隐藏
    // ⚠️ SQLite + D1 只支持纯 ? 占位符，不支持 ?N1 / ?Q1 / ?2 这类扩展语法
    const activeFilter = ` AND s.is_market = 1 AND s.revoked = 0
      AND (s.expires_at IS NULL OR s.expires_at > ?)
      AND (s.max_downloads IS NULL OR s.download_count < s.max_downloads)
      AND s.password_hash IS NULL`;
    // SQL LIKE 通配符转义：把用户输入中的 \ % _ 都转义，防止用户靠输入 % 列出所有文件
    const qEsc = q ? q.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_") : null;
    const qFilter = qEsc
      ? ` AND (f.name LIKE ? ESCAPE '\\' OR COALESCE(s.market_title,'') LIKE ? ESCAPE '\\' OR COALESCE(s.market_desc,'') LIKE ? ESCAPE '\\')`
      : "";
    // 构建绑定数组：顺序必须严格匹配 SQL 中 ? 出现的顺序
    // activeFilter 贡献 1 个 ?，qFilter 贡献 3 个 ?
    const qLike = qEsc ? `%${qEsc}%` : null;
    const countBinds: any[] = [now];
    const listBinds: any[] = [now];
    if (qLike) {
      // qFilter 有 3 个 ?（同一个值复用三次）
      countBinds.push(qLike, qLike, qLike);
      listBinds.push(qLike, qLike, qLike);
    }
    // LIMIT / OFFSET 额外两个参数
    listBinds.push(perPage, (page - 1) * perPage);
    const sortMap: Record<string, string> = {
      hot:   "(s.market_views + s.download_count * 3) DESC",
      newest: "s.created_at DESC",
      downloads: "s.download_count DESC",
      views: "s.market_views DESC",
    };
    const orderBy = sortMap[sort] || sortMap.hot;
    const countRow: any = await env.db.prepare(
      `SELECT COUNT(*) AS c FROM shares s JOIN files f ON f.id = s.file_id WHERE 1=1 ${activeFilter} ${qFilter}`
    ).bind(...countBinds).first();
    const total = countRow?.c ?? 0;
    const { results }: any = await env.db.prepare(
      `SELECT s.id AS share_id, s.created_at, s.download_count, s.market_views, s.market_title, s.market_desc,
              f.name AS file_name, f.size AS file_size, f.mime AS file_mime
       FROM shares s JOIN files f ON f.id = s.file_id
       WHERE 1=1 ${activeFilter} ${qFilter}
       ORDER BY ${orderBy}
       LIMIT ? OFFSET ?`
    ).bind(...listBinds).all();
    return Response.json({
      ok: true, total, page, size: perPage, sort,
      items: (results ?? []).map((r: any) => ({
        ...r,
        // 前端算热度就够了，这里也给一个数值方便
        heat: (r.market_views || 0) + (r.download_count || 0) * 3,
        url: `/s/${r.share_id}`,
      })),
    });
  }

  // 公开分享页 /s/:token[...]
  const shareMatch = /^\/s\/([A-Za-z0-9]+)(\/.*)?$/.exec(path);
  if (shareMatch) {
    await ensureSchema(env);
    const token = shareMatch[1];
    const sub = shareMatch[2] ?? "";
    if (sub === "" || sub === "/") {
      if (req.method !== "GET" && req.method !== "HEAD") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      return serveSharePage(req);
    }
    if (sub === "/info") {
      return handleShareInfo(req, env, token);
    }
    if (sub === "/verify") {
      if (req.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      return handleVerify(req, env, token);
    }
    if (sub === "/download") {
      if (req.method !== "GET" && req.method !== "HEAD") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      return handleDownload(req, env, ctx, token);
    }
    // ── 在线预览 ──
    //   /preview      打开预览（计次）
    //   /preview/raw  内联流式原始文件（Range 支持）
    //   /preview/zip  解析 ZIP 内部结构
    if (sub === "/preview") {
      // 仅允许 GET —— 预览是"计次"操作，HEAD 不应消耗全站预览额度
      if (req.method !== "GET") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      return handlePreviewOpen(req, env, token);
    }
    if (sub === "/preview/raw") {
      if (req.method !== "GET") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      return handlePreviewRaw(req, env, ctx, token);
    }
    if (sub === "/preview/zip") {
      if (req.method !== "GET") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      return handlePreviewZip(req, env, token);
    }
    return notFound(req);
  }

  // ══════════════════════════════════════════════════════════════
  // 直链 /d/:id —— 独立入口，走 direct_links 表
  // 与分享链接 /s/:id 是完全独立的 API、独立的 token、独立的鉴权
  // 创建直链: POST /api/admin/direct-links
  // URL 格式：/d/{token}  或  /d/{token}/{filename}（带文件名后缀，向下兼容）
  // ══════════════════════════════════════════════════════════════
  const directMatch = /^\/d\/([A-Za-z0-9]+)(?:\/.*)?$/.exec(path);
  if (directMatch) {
    if (req.method !== "GET" && req.method !== "HEAD") {
      return new Response("Method Not Allowed", { status: 405 });
    }
    await ensureSchema(env);
    return handleDirectDownload(req, env, ctx, directMatch[1]);
  }

  // ══════════════════════════════════════════════════════════════
  // WebDAV 服务 —— 挂载点 /webdav/*
  // 通过 HTTP Basic Auth 保护，启用后可在 Finder/Explorer 等直接挂载
  // ══════════════════════════════════════════════════════════════
  if (path.startsWith("/webdav")) {
    await ensureSchema(env);
    const { handleWebDAV } = await import("./webdav");
    return handleWebDAV(req, env, ctx);
  }

  return notFound(req);
}

function notFound(req: Request): Response {
  return errorPage(
    req,
    404,
    { zh: "页面不存在", en: "Not Found" },
    { zh: "请求的地址无效。", en: "The requested address is invalid." }
  );
}
