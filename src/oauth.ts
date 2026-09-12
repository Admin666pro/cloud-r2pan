/**
 * OAuth2 授权码流程 —— 零依赖实现
 *
 * 提供:
 *   - 预配置 Provider 列表（GitHub / Google / Microsoft / Discord / Custom）
 *   - state 生成 & 校验（D1 存储，5 分钟 TTL，一次性消费）
 *   - 授权 URL 构造
 *   - code → access_token 交换
 *   - userinfo 拉取
 *   - 会话 Cookie（HMAC-SHA256 签名，复用 admin key）
 *
 * 所有 Provider 都走标准 OAuth2 Authorization Code flow。
 */

import type { Env } from "./types";
import { safeEqual, hmacHex, randomHex, hmacB64url } from "./crypto";

/* ═══════════ Provider 类型 & 预配置 ═══════════ */

export interface OAuthProvider {
  /** 内部标识（唯一） */
  id: string;
  /** 显示名 */
  name: string;
  /** OAuth 授权端点 */
  authorize_url: string;
  /** code → token 端点 */
  token_url: string;
  /** 用户信息端点（返回 userinfo JSON） */
  userinfo_url: string;
  /** 默认 scope */
  default_scope: string;
  /** OAuth2 回调返回的字段名：access_token / token_type / userinfo 中 id 字段 */
  token_field: string;
  /** 是否需要 client_secret 在 token 请求 body 中（全部主流都需要） */
  needs_basic_auth?: boolean;
}

/** 主流 Provider 预设 —— 管理员可直接选择，只需填 client_id / client_secret */
export const BUILTIN_PROVIDERS: OAuthProvider[] = [
  {
    id: "github",
    name: "GitHub",
    authorize_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token",
    userinfo_url: "https://api.github.com/user",
    default_scope: "user:email",
    token_field: "access_token",
  },
  {
    id: "google",
    name: "Google",
    authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo",
    default_scope: "openid email profile",
    token_field: "access_token",
  },
  {
    id: "microsoft",
    name: "Microsoft",
    authorize_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    userinfo_url: "https://graph.microsoft.com/v1.0/me",
    default_scope: "openid email profile User.Read",
    token_field: "access_token",
  },
  {
    id: "discord",
    name: "Discord",
    authorize_url: "https://discord.com/api/oauth2/authorize",
    token_url: "https://discord.com/api/oauth2/token",
    userinfo_url: "https://discord.com/api/users/@me",
    default_scope: "identify email",
    token_field: "access_token",
  },
  {
    id: "custom",
    name: "自定义 / Custom",
    authorize_url: "",
    token_url: "",
    userinfo_url: "",
    default_scope: "openid email profile",
    token_field: "access_token",
  },
];

export function getBuiltinProvider(id: string): OAuthProvider | undefined {
  return BUILTIN_PROVIDERS.find((p) => p.id === id);
}

/* ═════════── State 管理（D1 表 oauth_states） ═══════════
 * state = 随机 32 字符 hex，存储在 D1 里，5 分钟 TTL，一次性消费防 CSRF。
 */

const STATE_TTL_MS = 5 * 60_000; // 5 分钟

/** 生成一个 state 并存入 D1，返回 state 值 */
export async function createOAuthState(
  env: Env,
  providerId: string,
  redirect: string // 原始 redirect URI（必须与 callback endpoint 完全一致）
): Promise<string> {
  const state = randomHex(16); // 32 字符 hex
  const expiresAt = Date.now() + STATE_TTL_MS;
  await env.db
    .prepare(
      `INSERT INTO oauth_states(state, provider_id, redirect_uri, expires_at) VALUES(?1, ?2, ?3, ?4)
       ON CONFLICT(state) DO UPDATE SET provider_id = excluded.provider_id, redirect_uri = excluded.redirect_uri, expires_at = excluded.expires_at`
    )
    .bind(state, providerId, redirect, expiresAt)
    .run();
  return state;
}

/**
 * 校验 state：一次性消费 + TTL 检查。
 * 返回 { ok, provider_id, redirect_uri }，失败时 ok=false。
 */
export async function verifyOAuthState(
  env: Env,
  state: string
): Promise<{ ok: boolean; provider_id?: string; redirect_uri?: string }> {
  if (!state) return { ok: false };
  const row = await env.db
    .prepare("SELECT provider_id, redirect_uri, expires_at FROM oauth_states WHERE state = ?1")
    .bind(state)
    .first<{ provider_id: string; redirect_uri: string; expires_at: number }>();
  if (!row) return { ok: false };
  // 一次性消费：立刻删除
  await env.db.prepare("DELETE FROM oauth_states WHERE state = ?1").bind(state).run();
  if (row.expires_at < Date.now()) return { ok: false };
  return { ok: true, provider_id: row.provider_id, redirect_uri: row.redirect_uri };
}

/* ═══════════ 构造授权 URL ═══════════ */

export function buildAuthorizeUrl(
  provider: OAuthProvider,
  clientId: string,
  redirectUri: string,
  scope: string,
  state: string
): string {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: scope || provider.default_scope,
    state,
    // 某些 Provider 需要 prompt / access_type / include_granted_scopes
  });
  if (provider.id === "google") params.set("access_type", "offline");
  return `${provider.authorize_url}?${params.toString()}`;
}

/* ═════════── code → access_token ────────────────────── */

export async function exchangeCode(
  provider: OAuthProvider,
  code: string,
  redirectUri: string,
  clientId: string,
  clientSecret: string
): Promise<{ accessToken: string; tokenType: string; scope: string } | null> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    client_secret: clientSecret,
  });
  try {
    const resp = await fetch(provider.token_url, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: body.toString(),
    });
    if (!resp.ok) return null;
    const json = (await resp.json()) as Record<string, unknown>;
    const token = String(json[provider.token_field] || json.access_token || "");
    if (!token) return null;
    return {
      accessToken: token,
      tokenType: String(json.token_type || "Bearer"),
      scope: String(json.scope || ""),
    };
  } catch {
    return null;
  }
}

/* ═════════── 拉取用户信息 ────────────────────────────── */

export interface OAuthUser {
  id: string;
  email: string;
  name: string;
  avatar: string | null;
  provider: string;
}

export async function fetchUserInfo(
  provider: OAuthProvider,
  accessToken: string
): Promise<OAuthUser | null> {
  try {
    const resp = await fetch(provider.userinfo_url, {
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json",
      },
    });
    if (!resp.ok) return null;
    const json = (await resp.json()) as Record<string, unknown>;
    // 不同 provider 返回字段名不同
    let id = String(
      json.sub ?? json.id ?? json.user_id ?? json.login ?? json.discord_id ?? ""
    );
    let email = String(json.email ?? json.mail ?? "");
    // Microsoft Graph: userPrincipalName / mail
    if (!email && (json.userPrincipalName as string)) email = String(json.userPrincipalName);
    // GitHub: 不一定返回 email（如果 scope 不够），用 login 代替
    let name = String(json.name ?? json.login ?? json.preferred_username ?? (email || id));
    // Microsoft Graph: displayName
    if (!name && (json.displayName as string)) name = String(json.displayName);
    const avatar =
      (json.avatar_url as string) || (json.picture as string) || null;
    if (!id) return null;
    return { id, email, name, avatar, provider: provider.id };
  } catch {
    return null;
  }
}

/* ═══════════ 下载会话 Cookie（OAuth2 通过后发的短期 Cookie） ═══════════
 * Cookie 名字: cd_oauth
 * 签名方式: HMAC-SHA256(admin, `${provider}:${userId}:${exp}`) → base64url
 * 值格式:  `provider.userId.expiry.sig`
 * 有效期: 1 小时（够下完文件就行）
 */

export const OAUTH_COOKIE = "cd_oauth";
const OAUTH_TTL_MS = 60 * 3600_000; // 1 小时

export async function signOAuthSession(
  env: Env,
  providerId: string,
  userId: string
): Promise<{ cookie: string; secure: boolean; expiresAt: number }> {
  const exp = Date.now() + OAUTH_TTL_MS;
  const sig = await hmacB64url(env.admin, `${providerId}:${userId}:${exp}`);
  const value = `${providerId}.${userId}.${exp}.${sig}`;
  const secure = true; // 必须在 https 下；本地 dev 用 http 时需降级由调用方判断
  return { cookie: `${OAUTH_COOKIE}=${value}`, secure, expiresAt: exp };
}

export async function verifyOAuthSession(
  env: Env,
  cookieHeader: string | null
): Promise<{ ok: boolean; providerId: string; userId: string }> {
  if (!cookieHeader) return { ok: false, providerId: "", userId: "" };
  const match = new RegExp(`${OAUTH_COOKIE}=([^;]+)`).exec(cookieHeader);
  if (!match) return { ok: false, providerId: "", userId: "" };
  const raw = match[1];
  const parts = raw.split(".");
  if (parts.length !== 4) return { ok: false, providerId: "", userId: "" };
  const [providerId, userId, expStr, sig] = parts;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp < Date.now()) return { ok: false, providerId: "", userId: "" };
  const want = await hmacB64url(env.admin, `${providerId}:${userId}:${exp}`);
  if (!safeEqual(sig, want)) return { ok: false, providerId: "", userId: "" };
  return { ok: true, providerId, userId };
}

/** 根据当前请求推导 redirect_uri（保持跨域正确性） */
export function deriveRedirectUri(req: Request): string {
  const url = new URL(req.url);
  // 用当前 origin + /oauth/callback
  return `${url.origin}/oauth/callback`;
}
