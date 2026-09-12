import adminHTML from "../public/admin.html";
import shareHTML from "../public/share.html";
import { pickLang, type L10n } from "./i18n";

export function serveAdminPage(): Response {
  return new Response(adminHTML, {
    headers: { "content-type": "text/html;charset=utf-8", "cache-control": "no-store" },
  });
}

export function serveSharePage(): Response {
  return new Response(shareHTML, {
    headers: { "content-type": "text/html;charset=utf-8", "cache-control": "no-store" },
  });
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
  <div class="code">HTTP ${status}</div>
</div>
<div class="brand">Powered by ${site}</div>
</body>
</html>`;
  return new Response(html, {
    status,
    headers: { "content-type": "text/html;charset=utf-8", "cache-control": "no-store" },
  });
}
