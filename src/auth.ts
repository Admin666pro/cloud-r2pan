import type { Env } from "./types";

const COOKIE_NAME = "cd_admin";
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000; // 7 天

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmac(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return b64url(new Uint8Array(sig));
}

/** 恒定时间字符串比较，防时序攻击 */
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

function getCookie(req: Request, name: string): string | null {
  const cookies = req.headers.get("cookie") ?? "";
  for (const part of cookies.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

/** 登录成功后签发会话 Cookie（不加 Secure 以兼容本地 http 调试） */
export async function createSession(env: Env): Promise<string> {
  const exp = Date.now() + SESSION_TTL_MS;
  const sig = await hmac(env.admin, String(exp));
  const token = `${exp}.${sig}`;
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}`;
}

/** 校验会话 Cookie，返回是否有效 */
export async function verifySession(req: Request, env: Env): Promise<boolean> {
  const token = getCookie(req, COOKIE_NAME);
  if (!token) return false;
  const dot = token.indexOf(".");
  if (dot < 0) return false;
  const exp = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  const expect = await hmac(env.admin, exp);
  return safeEqual(sig, expect);
}

/** 校验登录密钥（恒定时间比较） */
export async function checkAdminKey(env: Env, input: string): Promise<boolean> {
  if (!env.admin) return false;
  const a = await hmac(env.admin, input);
  const b = await hmac(env.admin, env.admin);
  return safeEqual(a, b);
}

/** 登录接口的简易限流（每 isolate 内存计数，防暴力破解） */
const attempts = new Map<string, { count: number; resetAt: number }>();

export function rateLimitLogin(ip: string, limit = 8, windowMs = 60_000): boolean {
  const now = Date.now();
  const rec = attempts.get(ip);
  if (!rec || rec.resetAt < now) {
    attempts.set(ip, { count: 1, resetAt: now + windowMs });
    return true;
  }
  rec.count++;
  return rec.count <= limit;
}

/** 获取客户端真实 IP（Cloudflare 环境下 CF-Connecting-IP 不可伪造） */
export function clientIp(req: Request): string {
  return (
    req.headers.get("cf-connecting-ip") ??
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "127.0.0.1"
  );
}
