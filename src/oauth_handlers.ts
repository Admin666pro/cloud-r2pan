/**
 * OAuth2 HTTP 处理函数 —— 被 index.ts 路由调用
 *
 * 路由:
 *   GET  /oauth/start?provider=xxx          → 重定向到 Provider 授权页
 *   GET  /oauth/callback?code=...&state=...  → Provider 回调，换 token，拉用户，发 Cookie，回分享页
 *   GET  /oauth/session                     → 返回当前 OAuth 会话状态（JSON）
 *   POST /oauth/logout                      → 清除 OAuth Cookie
 */

import type { Env } from "./types";
import { getSettings } from "./settings";
import { decryptSecret } from "./crypto";
import {
  getBuiltinProvider,
  BUILTIN_PROVIDERS,
  createOAuthState,
  verifyOAuthState,
  buildAuthorizeUrl,
  exchangeCode,
  fetchUserInfo,
  signOAuthSession,
  verifyOAuthSession,
  deriveRedirectUri,
  type OAuthProvider,
} from "./oauth";

const OAUTH_START_PARAMS = ["provider", "redirect"]; // 预设 query 参数名

function buildEffectiveProvider(env: Env, providerId: string, s: {
  oauthCustomAuthorizeUrl: string;
  oauthCustomTokenUrl: string;
  oauthCustomUserinfoUrl: string;
  oauthCustomTokenField: string;
}): OAuthProvider | null {
  const builtin = getBuiltinProvider(providerId);
  if (!builtin) return null;
  if (providerId === "custom") {
    // 自定义 Provider —— 用 settings 里填的 URL
    const p = { ...builtin };
    if (s.oauthCustomAuthorizeUrl) p.authorize_url = s.oauthCustomAuthorizeUrl;
    if (s.oauthCustomTokenUrl) p.token_url = s.oauthCustomTokenUrl;
    if (s.oauthCustomUserinfoUrl) p.userinfo_url = s.oauthCustomUserinfoUrl;
    if (s.oauthCustomTokenField) p.token_field = s.oauthCustomTokenField;
    // 任何必填 URL 都不能空
    if (!p.authorize_url || !p.token_url || !p.userinfo_url) return null;
    return p;
  }
  return builtin;
}

/** GET /oauth/providers —— 返回所有可用 provider 列表（不含敏感信息） */
export async function handleOAuthProviders(): Promise<Response> {
  return Response.json({
    providers: BUILTIN_PROVIDERS.map((p) => ({ id: p.id, name: p.name })),
  });
}

/**
 * GET /oauth/start?provider=xxx&redirect=/s/token
 *
 * @param redirect  —— OAuth 完成后回跳到哪个页面（一般是分享页 URL）
 */
export async function handleOAuthStart(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const providerId = url.searchParams.get("provider") || "";
  const redirectTo = url.searchParams.get("redirect") || "/";

  const s = await getSettings(env);
  if (!s.oauthEnabled) {
    return Response.json({ error: "oauth_disabled" }, { status: 400 });
  }

  const provider = buildEffectiveProvider(env, providerId, s);
  if (!provider) {
    return Response.json({ error: "invalid_provider" }, { status: 400 });
  }
  if (!s.oauthClientId) {
    return Response.json({ error: "client_id_missing" }, { status: 500 });
  }

  const redirectUri = deriveRedirectUri(req);
  const state = await createOAuthState(env, providerId, redirectUri);
  const authorizeUrl = buildAuthorizeUrl(
    provider,
    s.oauthClientId,
    redirectUri,
    s.oauthScope || provider.default_scope,
    state
  );

  // 把 redirectTo 写进 Cookie —— callback 成功后跳回去
  const cookie = `cd_oauth_redirect=${encodeURIComponent(redirectTo)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`;
  return new Response(null, {
    status: 302,
    headers: {
      location: authorizeUrl,
      "set-cookie": cookie,
    },
  });
}

/** GET /oauth/callback?code=xxx&state=yyy */
export async function handleOAuthCallback(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code") || "";
  const state = url.searchParams.get("state") || "";
  const error = url.searchParams.get("error");
  if (error) {
    return redirectBackWithMsg(req, "oauth_error: " + error);
  }
  if (!code || !state) {
    return redirectBackWithMsg(req, "oauth_missing_code");
  }

  // 1. 校验 state（一次性消费 + TTL）
  const verify = await verifyOAuthState(env, state);
  if (!verify.ok || !verify.provider_id) {
    return redirectBackWithMsg(req, "oauth_state_invalid");
  }

  const s = await getSettings(env);
  const providerId = verify.provider_id;
  const provider = buildEffectiveProvider(env, providerId, s);
  if (!provider) {
    return redirectBackWithMsg(req, "oauth_provider_broken");
  }
  if (!s.oauthClientId || !s.oauthClientSecretCipher) {
    return redirectBackWithMsg(req, "oauth_credentials_missing");
  }

  // 2. 解密 Client Secret
  const clientSecret = await decryptSecret(s.oauthClientSecretCipher, env.admin);
  if (!clientSecret) {
    return redirectBackWithMsg(req, "oauth_secret_decrypt_failed");
  }

  // 3. code → access_token
  const redirectUri = verify.redirect_uri!; // ok=true 时必存在
  const token = await exchangeCode(provider, code, redirectUri, s.oauthClientId, clientSecret);
  if (!token) {
    return redirectBackWithMsg(req, "oauth_exchange_failed");
  }

  // 4. 拉用户信息
  const user = await fetchUserInfo(provider, token.accessToken);
  if (!user) {
    return redirectBackWithMsg(req, "oauth_userinfo_failed");
  }

  // 5. 发 OAuth 会话 Cookie
  const { cookie, secure } = await signOAuthSession(env, providerId, user.id);
  // 读取原始 redirect 目标
  const originalRedirect = parseCookie(req.headers.get("cookie"), "cd_oauth_redirect") || "/";

  // 组装 Set-Cookie 头
  const setCookieParts: string[] = [
    cookie,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=3600`,
  ];
  if (url.protocol === "https:" && secure) setCookieParts.push("Secure");
  const setCookie = setCookieParts.join("; ");

  // 清掉 cd_oauth_redirect
  const clearRedirect = "cd_oauth_redirect=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";

  return new Response(null, {
    status: 302,
    headers: {
      location: originalRedirect,
      "set-cookie": [setCookie, clearRedirect].join(", "),
    },
  });
}

/** GET /oauth/session —— 返回当前 OAuth 会话状态 */
export async function handleOAuthSession(req: Request, env: Env): Promise<Response> {
  const result = await verifyOAuthSession(env, req.headers.get("cookie"));
  if (!result.ok) {
    return Response.json({ authenticated: false });
  }
  return Response.json({
    authenticated: true,
    provider: result.providerId,
    user_id: result.userId,
  });
}

/** POST /oauth/logout —— 清除 OAuth Cookie */
export async function handleOAuthLogout(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const secure = url.protocol === "https:";
  const cookie = `cd_oauth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`;
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "content-type": "application/json",
      "set-cookie": cookie,
      "cache-control": "no-store",
    },
  });
}

/* ═══════════ 辅助函数 ═══════════ */

/** 从 Cookie header 中读取指定 name 的值 */
function parseCookie(header: string | null, name: string): string {
  if (!header) return "";
  const re = new RegExp(`(?:^|;\\s*)${name}=([^;]*)`);
  const m = re.exec(header);
  return m ? decodeURIComponent(m[1]) : "";
}

/** callback 失败时重定向回分享页（通过 CDN 错误参数传递信息） */
function redirectBackWithMsg(req: Request, msg: string): Response {
  const redirectTo = parseCookie(req.headers.get("cookie"), "cd_oauth_redirect") || "/";
  const url = new URL(redirectTo, "https://localhost");
  url.searchParams.set("oauth_error", msg);
  const setCookie = "cd_oauth_redirect=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
  return new Response(null, {
    status: 302,
    headers: {
      location: `${url.pathname}${url.search}`,
      "set-cookie": setCookie,
    },
  });
}
