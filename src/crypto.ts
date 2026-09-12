/**
 * 共享加密原语 —— 收敛 auth.ts 和 public.ts 中重复实现的工具函数。
 *
 * ── Bug #6 修复 ───────────────────────────────────────────────
 * 原来 safeEqual / hmac 等在 auth.ts 和 public.ts 各有一份，
 * 且两个 hmac 返回不同编码（base64url vs hex），命名相同但行为不同，
 * 极易在维护时漏改或误用。此处统一实现，按用途命名。
 */

/** 恒定时间字符串比较，防时序攻击 */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** HMAC-SHA256，hex 编码 —— 公开分享令牌签名用（public.ts） */
export async function hmacHex(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** HMAC-SHA256，base64url 编码 —— 管理后台会话签名用（auth.ts） */
export async function hmacB64url(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  let bin = "";
  for (const b of new Uint8Array(sig)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** SHA-256，hex 编码 —— 分享密码哈希用 */
export async function sha256Hex(data: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** 生成指定长度的随机十六进制串 —— 密码盐值生成用 */
export function randomHex(n = 16): string {
  const bytes = crypto.getRandomValues(new Uint8Array(n));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * 用 admin key 派生出 AES-GCM 密钥 —— 加密分享密码明文用。
 * 密钥派生: HKDF-SHA256(info = "share-password-v1")
 */
let cachedAesKey: CryptoKey | null = null;
let cachedAesKeySecret = "";

async function getAesKey(secret: string): Promise<CryptoKey> {
  if (cachedAesKey && cachedAesKeySecret === secret) return cachedAesKey;
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(16), info: new TextEncoder().encode("share-password-v1") },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  cachedAesKey = key;
  cachedAesKeySecret = secret;
  return key;
}

/**
 * AES-GCM 加密。返回格式: "base64(nonce).base64(ciphertext+tag)"
 * 失败时（如 key 未就绪）返回空字符串。
 */
export async function encryptSecret(plain: string, secret: string): Promise<string> {
  if (!plain) return "";
  const key = await getAesKey(secret);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, new TextEncoder().encode(plain));
  const toB64 = (u8: Uint8Array) => btoa(String.fromCharCode(...u8)).replace(/=+$/, "");
  return toB64(nonce) + "." + toB64(new Uint8Array(ct));
}

/** AES-GCM 解密。格式不匹配或密钥错误时返回 null。 */
export async function decryptSecret(payload: string, secret: string): Promise<string | null> {
  if (!payload) return null;
  const parts = payload.split(".");
  if (parts.length !== 2) return null;
  try {
    const key = await getAesKey(secret);
    const fromB64 = (s: string) => {
      const pad = "=".repeat((4 - (s.length % 4)) % 4);
      const bin = atob(s + pad);
      return new Uint8Array(bin.length).map((_, i) => bin.charCodeAt(i));
    };
    const nonce = fromB64(parts[0]);
    const ct = fromB64(parts[1]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct);
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}
