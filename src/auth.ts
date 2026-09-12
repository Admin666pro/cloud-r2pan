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

/** 登录成功后签发会话 Cookie */
export async function createSession(env: Env, secure = false): Promise<string> {
  const exp = Date.now() + SESSION_TTL_MS;
  const sig = await hmacB64url(env.admin, String(exp));
  const token = `${exp}.${sig}`;
  // Secure 标志仅在 HTTPS 下追加，兼容本地 http 调试
  const secureFlag = secure ? "; Secure" : "";
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}${secureFlag}`;
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

/** 校验登录密钥（恒定时间比较，直接比字符串即可，无需 HMAC 包装） */
export function checkAdminKey(env: Env, input: string): boolean {
  if (!env.admin) return false;
  return safeEqual(input, env.admin);
}

/**
 * 登录接口的简易限流（每 isolate 内存计数，防暴力破解）。
 *
 * ── Bug #3 修复：Map 永不清理的内存泄漏 ──
 * 原实现每次过期 entry 都 set 新值而非 delete，且永不清理已过期的其他 IP 记录。
 * 恶意扫描 10 万个不同 IP 会吃光 isolate 内存。
 *
 * 修复：
 *   1. 命中过期 entry → 先 delete 再 set（覆盖也 OK 但 delete 更明确）
 *   2. 每 100 次调用触发一次全量 sweep，清理所有过期 entry
 */
const attempts = new Map<string, { count: number; resetAt: number }>();
let rateLimitCallCount = 0;

export function rateLimitLogin(ip: string, limit = 8, windowMs = 60_000): boolean {
  const now = Date.now();
  const rec = attempts.get(ip);
  if (!rec || rec.resetAt < now) {
    // 过期或首次：先清掉旧 entry（如果有），再创建新的
    if (rec) attempts.delete(ip);
    attempts.set(ip, { count: 1, resetAt: now + windowMs });
  } else {
    rec.count++;
  }

  // 每 100 次调用触发一次全量 sweep，防止长期积累的过期 entry 占内存
  if (++rateLimitCallCount % 100 === 0) {
    for (const [key, val] of attempts) {
      if (val.resetAt < now) attempts.delete(key);
    }
  }

  const current = attempts.get(ip)!;
  return current.count <= limit;
}

/** 获取客户端真实 IP（Cloudflare 环境下 CF-Connecting-IP 不可伪造） */
export function clientIp(req: Request): string {
  return (
    req.headers.get("cf-connecting-ip") ??
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "127.0.0.1"
  );
}
