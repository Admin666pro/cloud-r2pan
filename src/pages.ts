import adminHTML from "../public/admin.html";
import shareHTML from "../public/share.html";
import marketHTML from "../public/market.html";
import { pickLang, type L10n } from "./i18n";

/**
 * 统一安全响应头 —— 加在所有 HTML / JSON / 下载响应上。
 * 零成本，浏览器级防护：
 *   - CSP：允许 self + Turnstile CDN（所有页面都可能用到），允许 inline（单文件 SPA 权衡）
 *   - X-Frame-Options：防点击劫持
 *   - X-Content-Type-Options：防 MIME 嗅探
 *   - Referrer-Policy：最小泄露
 *   - Permissions-Policy：禁用不需要的浏览器能力
 *
 * 注意：download 响应是流式的，这里的 headers 同样适用。
 *
 * opts.allowEval：仅管理后台需要。echarts-gl 内部 EffectCompositor 在构造 ViewGL 时
 *   会用 new Function() 动态编译 'expr(...)' 字符串（球的每个 bloom 节点都硬编码了这种表达式），
 *   CSP 里没有 'unsafe-eval' 时会被浏览器拦截并抛出 "Invalid expression."，导致地球仪不渲染。
 *   —— 因此只有 /admin 页面放开 'unsafe-eval'，公开页面（share / market / error）保持严格。
 */
export function addSecurityHeaders(headers: Headers, opts: { isDownload?: boolean; allowEval?: boolean } = {}): void {
  // CSP —— Turnstile 需要 challenges.cloudflare.com 的 script/frame/connect
  // 'unsafe-inline' 是必要的：三个 HTML 页面都是单文件 inline JS SPA
  // 'unsafe-eval'：仅管理页（echarts-gl 3D 地球仪需要）
  const scriptSrc =
    "script-src 'self' 'unsafe-inline'" +
    (opts.allowEval ? " 'unsafe-eval'" : "") +
    " https://challenges.cloudflare.com https://cdn.jsdelivr.net";
  const csp = opts.isDownload
    ? "default-src 'none'; style-src 'none'; script-src 'none'; frame-src 'none'; connect-src 'none'"
    : [
        "default-src 'self'",
        // ECharts + echarts-gl 从 jsdelivr CDN 加载（用于全球分布地球仪）
        scriptSrc,
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "frame-src 'self' https://challenges.cloudflare.com",
        "connect-src 'self' https://challenges.cloudflare.com https://api.github.com https://api.google.com https://graph.microsoft.com https://discord.com",
        // ECharts 3D 地球仪需要加载地球纹理贴图（图片）
        "img-src 'self' data: https: https://cdn.jsdelivr.net",
        "form-action 'self'",
        "base-uri 'self'",
      ].join("; ");

  headers.set("Content-Security-Policy", csp);
  headers.set("X-Frame-Options", "DENY"); // 禁止被 iframe 嵌入（防点击劫持）
  headers.set("X-Content-Type-Options", "nosniff"); // 防 MIME 嗅探
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()");
}

/** 带安全头的 JSON 响应（API 统一用这个） */
export function json(body: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers ?? {});
  if (!headers.has("content-type")) headers.set("content-type", "application/json;charset=utf-8");
  addSecurityHeaders(headers);
  return new Response(JSON.stringify(body), { ...init, headers });
}

export function serveAdminPage(): Response {
  const headers = new Headers({ "content-type": "text/html;charset=utf-8", "cache-control": "no-store" });
  // 管理页需要 'unsafe-eval'：echarts-gl 3D 地球仪内部用 new Function() 编译表达式
  addSecurityHeaders(headers, { allowEval: true });
  return new Response(adminHTML, { headers });
}

/**
 * 带 ETag 协商缓存的静态 HTML 服务。
 * market.html / share.html 是 bundle 里的固定字符串，不会在运行时变。
 * 用内容 hash 做 ETag，Cache-Control: max-age=0 让浏览器每次都校验。
 * 如果 If-None-Match 命中 → 返回 304（空 body），节省 15-45KB 带宽。
 * Worker 重新部署后 HTML 变了 → ETag 自然变 → 浏览器自动拿新版本。
 *
 * 安全考虑：内容是 bundle 里固定的，没有安全风险。admin.html 不走这个（必须 no-store）。
 */
async function serveStaticHTML(html: string, req: Request): Promise<Response> {
  // 用 SHA-256 前 16 字符当 ETag —— 轻量且足够唯一
  const encoder = new TextEncoder();
  const hashBytes = await crypto.subtle.digest("SHA-256", encoder.encode(html));
  let etag = '"';
  const bytes = new Uint8Array(hashBytes);
  for (let i = 0; i < 8; i++) etag += bytes[i].toString(16).padStart(2, "0");
  etag += '"';

  // 协商缓存命中 → 304 Not Modified
  const ifNoneMatch = req.headers.get("if-none-match");
  if (ifNoneMatch && ifNoneMatch.includes(etag)) {
    const headers = new Headers({
      "etag": etag,
      "cache-control": "public, max-age=0, must-revalidate",
    });
    addSecurityHeaders(headers);
    return new Response(null, { status: 304, headers });
  }

  const headers = new Headers({
    "content-type": "text/html;charset=utf-8",
    "cache-control": "public, max-age=0, must-revalidate",
    "etag": etag,
  });
  addSecurityHeaders(headers);
  return new Response(html, { headers });
}

export async function serveSharePage(req?: Request): Promise<Response> {
  if (req) return serveStaticHTML(shareHTML, req);
  const headers = new Headers({ "content-type": "text/html;charset=utf-8", "cache-control": "no-store" });
  addSecurityHeaders(headers);
  return new Response(shareHTML, { headers });
}

export async function serveMarketPage(req?: Request): Promise<Response> {
  if (req) return serveStaticHTML(marketHTML, req);
  const headers = new Headers({ "content-type": "text/html;charset=utf-8", "cache-control": "no-store" });
  addSecurityHeaders(headers);
  return new Response(marketHTML, { headers });
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!)
  );
}

/** iOS 26 液态玻璃风格的错误/状态页（封禁、过期、限额等），文案跟随访客语言 */
export function errorPage(
  req: Request,
  status: number,
  title: L10n,
  message: L10n,
  opts: { siteTitle?: string; oauth_login_url?: string } = {}
): Response {
  const lang = pickLang(req);
  const site = esc(opts.siteTitle ?? "cloud-r2pan");
  const icons: Record<number, string> = {
    401: "🔐",
    403: "🚫",
    404: "🔍",
    410: "⏳",
    416: "📏",
    503: "🛑",
  };
  const loginBtn = opts.oauth_login_url
    ? `<div style="margin-top:28px"><a href="${esc(opts.oauth_login_url)}" style="display:inline-block;padding:14px 40px;border-radius:18px;background:linear-gradient(180deg,#3d9bff,#0a7cff);color:#fff;text-decoration:none;font-weight:600;font-size:16px;box-shadow:0 12px 28px rgba(10,124,255,.4);transition:transform .15s" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='none'">${lang === "zh" ? "登录下载" : "Login to Download"}</a></div>`
    : "";
  const html = `<!DOCTYPE html>
<html lang="${lang === "zh" ? "zh-CN" : "en"}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${esc(title[lang])} · ${site}</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
html, body { height: 100%; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "PingFang SC", "Helvetica Neue", "Microsoft YaHei", sans-serif;
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  padding: 24px; color: #fff; overflow: hidden; position: relative;
  background: linear-gradient(160deg, #0b1026 0%, #1a1240 45%, #2a1045 100%);
}
.orb { position: fixed; border-radius: 50%; filter: blur(90px); opacity: .5; pointer-events: none; animation: drift 18s ease-in-out infinite alternate; }
.o1 { width: 46vmax; height: 46vmax; background: #38bdf8; top: -18%; left: -14%; }
.o2 { width: 40vmax; height: 40vmax; background: #8b5cf6; bottom: -20%; right: -10%; animation-delay: -6s; }
.o3 { width: 30vmax; height: 30vmax; background: #ec4899; top: 55%; left: 8%; animation-delay: -12s; opacity: .35; }
@keyframes drift { from { transform: translate(0, 0) scale(1); } to { transform: translate(6vw, -5vh) scale(1.12); } }
.card {
  position: relative; width: 100%; max-width: 420px; text-align: center;
  padding: 56px 36px 44px; border-radius: 32px;
  background: linear-gradient(145deg, rgba(255,255,255,.16), rgba(255,255,255,.05));
  backdrop-filter: blur(32px) saturate(180%); -webkit-backdrop-filter: blur(32px) saturate(180%);
  border: 1px solid rgba(255,255,255,.28);
  box-shadow: 0 24px 60px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.35);
  animation: rise .6s cubic-bezier(.22,1.2,.36,1) both;
}
@keyframes rise { from { opacity: 0; transform: translateY(24px) scale(.96); } to { opacity: 1; transform: none; } }
.icon {
  width: 84px; height: 84px; margin: 0 auto 22px; border-radius: 26px;
  display: flex; align-items: center; justify-content: center; font-size: 42px;
  background: linear-gradient(145deg, rgba(255,255,255,.25), rgba(255,255,255,.08));
  border: 1px solid rgba(255,255,255,.3);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.4), 0 10px 26px rgba(0,0,0,.3);
}
h1 { font-size: 24px; font-weight: 700; letter-spacing: -.02em; margin-bottom: 12px; }
p { font-size: 15px; line-height: 1.65; color: rgba(255,255,255,.78); }
.code { margin-top: 22px; font-size: 13px; color: rgba(255,255,255,.45); font-family: ui-monospace, "SF Mono", monospace; }
.brand { position: fixed; bottom: 22px; left: 0; right: 0; text-align: center; font-size: 13px; color: rgba(255,255,255,.4); letter-spacing: .08em; }
</style>
</head>
<body>
<div class="orb o1"></div><div class="orb o2"></div><div class="orb o3"></div>
<div class="card">
  <div class="icon">${icons[status] ?? "⚠️"}</div>
  <h1>${esc(title[lang])}</h1>
  <p>${esc(message[lang])}</p>
  ${loginBtn}
  ${status >= 400 ? `<div class="code">HTTP ${status}</div>` : ""}
</div>
<div class="brand">Powered by ${site}</div>
</body>
</html>`;
  const headers = new Headers({ "content-type": "text/html;charset=utf-8", "cache-control": "no-store" });
  addSecurityHeaders(headers);
  return new Response(html, { status, headers });
}
