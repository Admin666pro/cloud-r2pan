import type { Env } from "./types";
import { ensureSchema } from "./db";
import { handleAdminApi } from "./admin";
import { handleDownload, handleShareInfo } from "./public";
import { serveAdminPage, serveSharePage, errorPage } from "./pages";

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await route(req, env, ctx);
    } catch (err) {
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

  // 首页 → 管理后台
  if (path === "/") {
    return Response.redirect(new URL("/admin", url).toString(), 302);
  }

  // 管理后台页面
  if (path === "/admin" || path === "/admin/") {
    return serveAdminPage();
  }

  // 管理 API
  if (path.startsWith("/api/admin/")) {
    return handleAdminApi(req, env, ctx, path);
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
