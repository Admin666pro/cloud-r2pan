import type { Env } from "./types";
import { hmacB64url, safeEqual } from "./crypto";

const COOKIE_NAME = "cd_admin";
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000; // 7 天

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
  const sig = await hmacB64url(env.admin, String(exp));
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
  const expect = await hmacB64url(env.admin, exp);
  return safeEqual(sig, expect);
}

/** 校验登录密钥（恒定时间比较） */
export async function checkAdminKey(env: Env, input: string): Promise<boolean> {
  if (!env.admin) return false;
  const a = await hmacB64url(env.admin, input);
  const b = await hmacB64url(env.admin, env.admin);
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
