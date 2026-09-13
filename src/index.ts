import type { Env } from "./types";
import { ensureSchema } from "./db";
import { handleAdminApi } from "./admin";
import { handleDownload, handleShareInfo, handleVerify } from "./public";
import { serveAdminPage, serveSharePage, serveMarketPage, errorPage } from "./pages";
import {
  handleOAuthStart,
  handleOAuthCallback,
  handleOAuthSession,
  handleOAuthLogout,
  handleOAuthProviders,
} from "./oauth_handlers";
import { findCodeByString, formatCodeStatus, checkCodeUsable } from "./codes";
import { logError, extractError } from "./logger";

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await route(req, env, ctx);
    } catch (err) {
      const { message, stack } = extractError(err);
      const url = new URL(req.url);
      // 同步 await 保证日志不会丢（在 catch 块里，response 还没发）
      await logError(env, {
        tag: "index.fetch",
        message,
        stack,
        url: url.pathname,
        method: req.method,
        ip: req.headers.get("cf-connecting-ip") ?? undefined,
      });
      console.error("unhandled error:", err);
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

  // 管理后台页面
  if (path === "/admin" || path === "/admin/") {
    return serveAdminPage();
  }

  // 管理 API
  if (path.startsWith("/api/admin/")) {
    return handleAdminApi(req, env, ctx, path);
  }

  // ══════════════════════════════════════════════════════════════
  // 客户端错误上报 —— 前端 window.onerror / unhandledrejection POST 到这里
  // 不需要登录，任何人都能上报（但只存到 D1）
  // ══════════════════════════════════════════════════════════════
  if (path === "/api/log/client" && req.method === "POST") {
    try {
      await ensureSchema(env);
      const body: any = await req.json();
      await logError(env, {
        source: "client",
        level: body.level ?? "error",
        tag: body.tag ?? "window.onerror",
        message: String(body.message ?? "unknown"),
        stack: body.stack,
        url: body.url ?? (new URL(req.url)).pathname,
        method: "POST",
        ip: req.headers.get("cf-connecting-ip") ?? undefined,
        ua: req.headers.get("user-agent") ?? undefined,
        extra: body.extra ? JSON.stringify(body.extra).slice(0, 2000) : undefined,
      });
    } catch {
      // 日志自己不能抛
    }
    return Response.json({ ok: true });
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
    const code = (new URL(req.url).searchParams.get("code") || "").trim().toUpperCase();
    if (!code) {
      return Response.json({ ok: false, error: "missing_code" }, { status: 400 });
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
    return serveMarketPage();
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
    const qFilter = q
      ? ` AND (f.name LIKE ? OR COALESCE(s.market_title,'') LIKE ? OR COALESCE(s.market_desc,'') LIKE ?)`
      : "";
    // 构建绑定数组：顺序必须严格匹配 SQL 中 ? 出现的顺序
    // activeFilter 贡献 1 个 ?，qFilter 贡献 3 个 ?
    const qLike = q ? `%${q}%` : null;
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
      return serveSharePage();
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
    return notFound(req);
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
