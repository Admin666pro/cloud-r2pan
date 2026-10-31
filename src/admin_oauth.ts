/**
 * 管理员第三方 OAuth2 登录 —— 支持 GitHub / Google / Microsoft，与访客下载鉴权（oauth_handlers.ts）完全独立。
 *
 * 功能:
 *   - 管理员在「登录方式」标签页绑定 GitHub / Google / Microsoft 账号
 *   - 绑定后，登录后台可直接用对应账号登录，无需输入 admin 密钥
 *
 * 路由:
 *   GET  /admin/oauth/:provider/start   未登录时发起第三方登录（provider ∈ github/google/microsoft）
 *   GET  /admin/oauth/callback          统一的回调入口（登录 / 绑定共用，Provider 编码在 state 里）
 *
 * 绑定入口走已鉴权的 POST /api/admin/oauth/providers/bind-start（见 admin.ts），
 * 由它调用 buildAdminOauthAuthorizeUrl 生成授权 URL —— 这样 state 本身即代表
 * 一次已登录管理员的授权发起，回调时无需依赖 cd_admin Cookie
 * （cd_admin 是 SameSite=Strict，跨站顶层跳转回来时不会携带）。
 *
 * 复用 oauth_states 表存 state（5 分钟 TTL、一次性消费防 CSRF），
 * 其 provider_id 字段存 `provider:intent`（intent = login / bind）。
 *
 * ── 为什么之前 GitHub 绑定「总是失败」 ────────────────────────────────
 * 旧实现把第三方返回的失败（如 redirect_uri_mismatch / bad_verification_code /
 * incorrect_client_credentials）统一吞成 exchange_failed，前端只能弹一句泛化错误，
 * 用户无从得知真实原因。现在把 Provider 返回的 error / error_description 原样透出到
 * 回调 query（oauth_error / oauth_error_desc），前端直接展示，定位问题一目了然。
 */

import type { Env } from "./types";
import {
  getSettings,
  updateSettings,
  parseAdminOauth,
  serializeAdminOauth,
  ADMIN_OAUTH_PROVIDER_IDS,
} from "./settings";
import { decryptSecret } from "./crypto";
import { createSession, clientIp, passwordFingerprint } from "./auth";
import { createOAuthState, verifyOAuthState, getBuiltinProvider } from "./oauth";
import { parseUA } from "./ua";

/** state 意图 —— 与 providerId 一起存进 oauth_states.provider_id（格式 `provider:intent`） */
export const ADMIN_OAUTH_INTENT_LOGIN = "login";
export const ADMIN_OAUTH_INTENT_BIND = "bind";

/** 各 Provider 的管理员登录 scope（管理员只需读取本人最低限度的身份信息） */
const ADMIN_SCOPES: Record<string, string> = {
  github: "read:user",
  google: "openid email profile",
  microsoft: "openid email profile User.Read",
};

/** 是否受支持的管理员 Provider */
export function isAdminOauthProvider(id: string): boolean {
  return (ADMIN_OAUTH_PROVIDER_IDS as readonly string[]).includes(id);
}

/** 管理员 OAuth 回调地址（必须在各 Provider 后台登记为 Redirect URI） */
export function adminOauthCallbackUrl(req: Request): string {
  return `${new URL(req.url).origin}/admin/oauth/callback`;
}

/** 生成 state 并构造授权 URL；未配置 Client ID 时返回 null */
export async function buildAdminOauthAuthorizeUrl(
  env: Env,
  req: Request,
  providerId: string,
  intent: string
): Promise<string | null> {
  const provider = getBuiltinProvider(providerId);
  if (!provider || !provider.authorize_url) return null;
  const s = await getSettings(env);
  const cfg = parseAdminOauth(s.adminOauth)[providerId];
  if (!cfg?.clientId) return null;

  const redirectUri = adminOauthCallbackUrl(req);
  const state = await createOAuthState(env, `${providerId}:${intent}`, redirectUri);
  const params = new URLSearchParams({
    client_id: cfg.clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: ADMIN_SCOPES[providerId] ?? provider.default_scope,
    state,
  });
  // Google 需要 access_type 才能拿到刷新令牌（登录场景无影响，保持一致行为）
  if (providerId === "google") params.set("access_type", "offline");
  return `${provider.authorize_url}?${params.toString()}`;
}

/** GET /admin/oauth/:provider/start —— 未登录时发起第三方登录 */
export async function handleAdminOauthStart(req: Request, env: Env, providerId: string): Promise<Response> {
  if (!isAdminOauthProvider(providerId)) {
    return redirectToAdmin(req, { oauth_error: "unsupported", oauth_provider: providerId });
  }
  const s = await getSettings(env);
  const cfg = parseAdminOauth(s.adminOauth)[providerId];
  if (!cfg.enabled || !cfg.uid || !cfg.clientId || !cfg.secretCipher) {
    return redirectToAdmin(req, { oauth_error: "not_available", oauth_provider: providerId });
  }
  const authorizeUrl = await buildAdminOauthAuthorizeUrl(env, req, providerId, ADMIN_OAUTH_INTENT_LOGIN);
  if (!authorizeUrl) return redirectToAdmin(req, { oauth_error: "not_available", oauth_provider: providerId });
  return new Response(null, { status: 302, headers: { location: authorizeUrl, "cache-control": "no-store" } });
}

/** GET /admin/oauth/callback —— 统一回调（登录 / 绑定共用） */
export async function handleAdminOauthCallback(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const providerError = url.searchParams.get("error");
  const providerErrorDesc = url.searchParams.get("error_description") ?? "";
  const code = url.searchParams.get("code") || "";
  const state = url.searchParams.get("state") || "";

  // ① Provider 在授权阶段直接返回错误（最常见的 redirect_uri_mismatch / access_denied）
  if (providerError) {
    return redirectToAdmin(req, {
      oauth_error: providerError,
      oauth_error_desc: providerErrorDesc,
      oauth_provider: "",
    });
  }
  if (!code || !state) return redirectToAdmin(req, { oauth_error: "missing_code" });

  // ② 校验 state（一次性消费 + TTL），其中编码了 provider 与意图
  const verify = await verifyOAuthState(env, state);
  if (!verify.ok || !verify.provider_id) return redirectToAdmin(req, { oauth_error: "state_invalid" });
  const [providerId, intent] = verify.provider_id.split(":");
  if (!isAdminOauthProvider(providerId) || !intent) {
    return redirectToAdmin(req, { oauth_error: "bad_intent", oauth_provider: providerId || "" });
  }
  const provider = getBuiltinProvider(providerId);
  if (!provider || !provider.authorize_url) {
    return redirectToAdmin(req, { oauth_error: "unsupported", oauth_provider: providerId });
  }

  const redirectUri = verify.redirect_uri || adminOauthCallbackUrl(req);

  const s = await getSettings(env);
  const cfg = parseAdminOauth(s.adminOauth)[providerId];
  if (!cfg.clientId || !cfg.secretCipher) {
    return redirectToAdmin(req, { oauth_error: "not_configured", oauth_provider: providerId });
  }
  const clientSecret = await decryptSecret(cfg.secretCipher, env.admin);
  if (!clientSecret) return redirectToAdmin(req, { oauth_error: "secret_decrypt_failed", oauth_provider: providerId });

  // ③ code → access_token（失败时透出 Provider 原始错误）
  const tok = await exchangeAdminCode(provider, cfg.clientId, clientSecret, code, redirectUri);
  if (!tok.ok) {
    return redirectToAdmin(req, {
      oauth_error: tok.error || "exchange_failed",
      oauth_error_desc: tok.errorDescription || "",
      oauth_provider: providerId,
    });
  }

  // ④ 拉取第三方用户信息
  const user = await fetchAdminUser(provider, tok.accessToken!);
  if (!user) return redirectToAdmin(req, { oauth_error: "userinfo_failed", oauth_provider: providerId });

  // ── 绑定流程 ──
  if (intent === ADMIN_OAUTH_INTENT_BIND) {
    const next = parseAdminOauth(s.adminOauth);
    next[providerId] = {
      ...next[providerId],
      uid: user.id,
      login: user.login,
      name: user.name,
      avatar: user.avatar,
      boundAt: Date.now(),
    };
    await updateSettings(env, { admin_oauth: serializeAdminOauth(next) });
    return redirectToAdmin(req, { oauth_bound: providerId });
  }

  // ── 登录流程 ──
  if (intent !== ADMIN_OAUTH_INTENT_LOGIN) {
    return redirectToAdmin(req, { oauth_error: "bad_intent", oauth_provider: providerId });
  }
  if (!cfg.enabled) return redirectToAdmin(req, { oauth_error: "disabled", oauth_provider: providerId });
  if (!cfg.uid || cfg.uid !== user.id) {
    await writeLoginLog(env, req, "fail", `${providerId}_not_bound`);
    return redirectToAdmin(req, { oauth_error: "not_bound", oauth_provider: providerId });
  }

  // 签发管理员会话 Cookie（绑定当前登录密码指纹）
  const cookie = await createSession(env, url.protocol === "https:", await passwordFingerprint(await getSettings(env)));
  await writeLoginLog(env, req, "success", `${providerId}_oauth`);
  return new Response(null, {
    status: 302,
    headers: { location: "/admin", "set-cookie": cookie, "cache-control": "no-store" },
  });
}

/* ═══════════ 辅助 ═══════════ */

interface AdminOauthUser {
  id: string;
  login: string;
  name: string;
  avatar: string;
}

interface ExchangeResult {
  ok: boolean;
  accessToken?: string;
  error?: string;
  errorDescription?: string;
}

/** code → access_token；失败时返回 Provider 的 error / error_description */
async function exchangeAdminCode(
  provider: { token_url: string; token_field: string },
  clientId: string,
  clientSecret: string,
  code: string,
  redirectUri: string
): Promise<ExchangeResult> {
  try {
    const resp = await fetch(provider.token_url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        client_secret: clientSecret,
      }).toString(),
    });
    const text = await resp.text();
    // 有的 Provider 返回 JSON，有的（旧版 GitHub）返回表单编码 —— 两种都兜住
    let json: Record<string, unknown> = {};
    try {
      json = JSON.parse(text) as Record<string, unknown>;
    } catch {
      json = Object.fromEntries(new URLSearchParams(text)) as Record<string, unknown>;
    }
    if (!resp.ok) {
      return {
        ok: false,
        error: String(json.error ?? `http_${resp.status}`),
        errorDescription: String(json.error_description ?? ""),
      };
    }
    const token = String(json[provider.token_field] ?? json.access_token ?? "");
    if (!token) {
      return {
        ok: false,
        error: String(json.error ?? "no_token"),
        errorDescription: String(json.error_description ?? ""),
      };
    }
    return { ok: true, accessToken: token };
  } catch (e) {
    return { ok: false, error: "exchange_network_error", errorDescription: String((e as Error).message ?? "") };
  }
}

/** 拉取第三方用户信息，归一化出 id / login / name / avatar */
async function fetchAdminUser(
  provider: { userinfo_url: string },
  accessToken: string
): Promise<AdminOauthUser | null> {
  try {
    const resp = await fetch(provider.userinfo_url, {
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json",
        // GitHub API 强制要求 User-Agent
        "user-agent": "cloud-r2pan",
      },
    });
    if (!resp.ok) return null;
    const j = (await resp.json()) as Record<string, unknown>;
    // GitHub: id / login；Google: sub / email；Microsoft Graph: id / userPrincipalName
    const id = String(j.sub ?? j.id ?? j.user_id ?? j.login ?? "");
    if (!id) return null;
    const login = String(
      j.login ?? j.email ?? j.preferred_username ?? j.userPrincipalName ?? j.mail ?? j.displayName ?? id
    );
    const name = String(j.name ?? j.displayName ?? j.login ?? j.preferred_username ?? login);
    const avatar = String((j.avatar_url as string) ?? (j.picture as string) ?? "");
    return { id, login, name, avatar };
  } catch {
    return null;
  }
}

function redirectToAdmin(req: Request, params: Record<string, string>): Response {
  const clean: Record<string, string> = {};
  for (const [k, v] of Object.entries(params)) if (v) clean[k] = v;
  const qs = new URLSearchParams(clean).toString();
  return new Response(null, {
    status: 302,
    headers: { location: `/admin${qs ? "?" + qs : ""}`, "cache-control": "no-store" },
  });
}

/** 写登录安全日志（失败不影响主流程） */
async function writeLoginLog(env: Env, req: Request, result: string, reason: string): Promise<void> {
  try {
    const ua = req.headers.get("user-agent") ?? "";
    const { browser, os } = parseUA(ua);
    const country = req.headers.get("cf-ipcountry") ?? null;
    await env.db
      .prepare(
        "INSERT INTO login_logs(action, ip, ua, browser, os, country, result, reason, created_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
      )
      .bind("login", clientIp(req), ua || null, browser, os, country, result, reason, Date.now())
      .run();
  } catch {
    /* ignore */
  }
}
