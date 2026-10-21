import type { Env } from "./types";
import { ensureSchema, randomId, getSchemaStatus, repairDatabase, writeErrorLog } from "./db";
import { generateCodes, makeBatchId, formatCodeStatus, findCodeByString } from "./codes";
import { getSettings, updateSettings, parseAdminOauth, serializeAdminOauth, ADMIN_OAUTH_PROVIDER_IDS } from "./settings";
import { checkAdminKey, createSession, verifySession, clientIp, rateLimitLogin, requireAdminIp } from "./auth";
import { pickLang } from "./i18n";
import { hashPassword } from "./public";
import { parseUA } from "./ua";
import { encryptSecret, decryptSecret, totpGenerateSecret, totpVerify, totpUri, totpGenerateRecoveryCodes, sha256Hex, safeEqual } from "./crypto";
import { createStorageProvider, type StorageProvider } from "./storage";
import { buildAdminOauthAuthorizeUrl, ADMIN_OAUTH_INTENT_BIND, isAdminOauthProvider, adminOauthCallbackUrl } from "./admin_oauth";
import { getBuiltinProvider } from "./oauth";

/** 懒加载 StorageProvider —— 每次需要时从 settings 构造（settings 有 5s 缓存，成本低） */
let _storagePromise: Promise<StorageProvider> | null = null;
async function storage(env: Env): Promise<StorageProvider> {
  if (!_storagePromise) {
    _storagePromise = (async () => {
      const s = await getSettings(env);
      return createStorageProvider(env, s);
    })();
  }
  return _storagePromise;
}

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json;charset=utf-8", "cache-control": "no-store" },
  });

/** API 错误消息跟随请求语言（浏览器 fetch 自动携带 Accept-Language） */
const msg = (req: Request, zh: string, en: string) => (pickLang(req) === "zh" ? zh : en);

/** 安全解析 JSON body（失败返回空对象） */
async function readJson<T>(req: Request): Promise<Partial<T>> {
  try {
    return (await req.json()) as Partial<T>;
  } catch {
    return {};
  }
}

/** 文件名清洗：去路径分隔符 / 控制字符，限长 */
function sanitizeName(name: string): string {
  const cleaned = name
    .replace(/[\\/]/g, "_")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, 180);
  return cleaned || "unnamed";
}

/* ═══════════ 虚拟目录路径工具 ═══════════
 * 约定（与 WebDAV 完全一致，两者共用同一套数据）：
 *   · directories.path —— 目录路径，根目录为 "/"，如 "/docs"、"/docs/2026"
 *   · files.path       —— 文件的**全路径**（含文件名），如 "/a.txt"、"/docs/a.txt"
 * 旧的 admin 上传把 files.path 留成了默认值 "/"，导致文件在 WebDAV 树里消失；
 * 现在统一走 joinFullPath() 计算，并在迁移里把历史 "/" 行补齐。
 */
function normDir(p: string | null | undefined): string {
  let s = (p ?? "").trim();
  if (!s) return "/";
  if (!s.startsWith("/")) s = "/" + s;
  s = s.replace(/\/+/g, "/");
  if (s.length > 1 && s.endsWith("/")) s = s.slice(0, -1);
  return s;
}
/** 目录 + 文件名 → 文件全路径 */
function joinFullPath(dir: string, name: string): string {
  const d = normDir(dir);
  return d === "/" ? `/${name}` : `${d}/${name}`;
}
/** 文件全路径 → 所在目录 */
function dirOfFullPath(fullPath: string): string {
  const i = (fullPath || "").lastIndexOf("/");
  return i <= 0 ? "/" : fullPath.slice(0, i);
}
/** 路径合法性：绝对、无 ".."、无控制字符 */
function isSafePath(p: string): boolean {
  return p.startsWith("/") && !p.includes("..") && !/[\u0000-\u001f\u007f]/.test(p);
}
/** 目录是否存在（directories 表，或已有文件位于其下） */
async function dirExists(env: Env, dir: string): Promise<boolean> {
  const d = normDir(dir);
  if (d === "/") return true;
  const one = await env.db.prepare("SELECT 1 FROM directories WHERE path = ?1").bind(d).first();
  if (one) return true;
  const child = await env.db.prepare("SELECT 1 FROM files WHERE path LIKE ?1 ESCAPE '\\' LIMIT 1").bind(likePrefix(d + "/")).first();
  return !!child;
}
/** 逐级补齐目录行（如 /a/b/c → /a、/a/b、/a/b/c），供上传/移动时自动建目录 */
async function ensureDirChain(env: Env, dir: string): Promise<void> {
  const d = normDir(dir);
  if (d === "/") return;
  const now = Date.now();
  const stmts = [];
  const parts = d.split("/").filter(Boolean);
  let acc = "";
  for (const p of parts) {
    acc += "/" + p;
    stmts.push(
      env.db
        .prepare("INSERT INTO directories(path, created_at) VALUES(?1, ?2) ON CONFLICT(path) DO NOTHING")
        .bind(acc, now)
    );
  }
  if (stmts.length) await env.db.batch(stmts);
}
/** 列出某目录的直接子目录与直接子文件（与 WebDAV listDirChildren 同源逻辑） */
async function listDir(env: Env, dir: string): Promise<{ files: any[]; dirs: { path: string; name: string }[] }> {
  const d = normDir(dir);
  const prefix = d === "/" ? "/" : d + "/";
  const { results } = await env.db
    .prepare(
      `SELECT f.id, f.name, f.size, f.mime, f.uploaded_at, f.path,
              (SELECT COUNT(*) FROM shares s WHERE s.file_id = f.id) AS share_count,
              (SELECT COALESCE(SUM(s.download_count), 0) FROM shares s WHERE s.file_id = f.id) AS download_count
       FROM files f WHERE f.path LIKE ?1 ESCAPE '\\'`
    )
    .bind(prefix === "/" ? "/%" : likePrefix(prefix))
    .all<any>();
  const dirSet = new Set<string>();
  const files: any[] = [];
  for (const f of results ?? []) {
    // 兼容历史脏数据：早期 admin 上传把 path 留成了默认值 "/"，这里按 "name" 还原到根目录
    let full = (f.path as string) || "/";
    if (full === "/") full = "/" + f.name;
    const rest = d === "/" ? full.slice(1) : full.slice(prefix.length);
    if (!rest) continue;
    const slash = rest.indexOf("/");
    if (slash < 0) files.push({ ...f, path: full });   // 直接子文件
    else dirSet.add(prefix + rest.slice(0, slash));    // 更深层 → 归属某个子目录
  }
  files.sort((a, b) => (b.uploaded_at ?? 0) - (a.uploaded_at ?? 0));
  // directories 表里显式创建（可能是空目录）的后代
  const { results: dirRows } = await env.db
    .prepare("SELECT path FROM directories WHERE path LIKE ?1 ESCAPE '\\' AND path != ?2")
    .bind(prefix === "/" ? "/%" : likePrefix(prefix), d)
    .all<{ path: string }>();
  for (const r of dirRows ?? []) {
    const rest = (r.path as string).slice(prefix.length);
    if (!rest) continue;
    const slash = rest.indexOf("/");
    dirSet.add(prefix + (slash < 0 ? rest : rest.slice(0, slash)));
  }
  const dirs = Array.from(dirSet)
    .sort()
    .map((p) => ({ path: p, name: p.split("/").filter(Boolean).pop() || p }));
  return { files, dirs };
}

/** 按全路径查文件（path 即含文件名的全路径） */
async function findFileByPath(env: Env, fullPath: string): Promise<{ id: string; key: string } | null> {
  return await env.db
    .prepare("SELECT id, key FROM files WHERE path = ?1")
    .bind(fullPath)
    .first<{ id: string; key: string }>();
}
/** 某路径上是否已存在文件 */
async function fileExistsAt(env: Env, fullPath: string): Promise<boolean> {
  const row = await env.db.prepare("SELECT 1 FROM files WHERE path = ?1").bind(fullPath).first();
  return !!row;
}

/**
 * 预检目标全路径是否被占用 —— 防止「文件 / 目录同名」造成数据不一致。
 * 上传用 fileOnly=true（同名目录会阻断），移动/改名用 fileOnly=false（任何占用都阻断）。
 *
 * 为什么需要：files.path 与 directories.path 是两套键，若同一路径既是文件又是目录，
 * listDir 里该名字会**同时**出现成文件行和目录行，删除时哪个先命中也无法确定 —— 是典型的数据损坏源。
 */
async function pathTaken(env: Env, fullPath: string, fileOnly: boolean): Promise<"file" | "dir" | null> {
  if (await fileExistsAt(env, fullPath)) return "file";
  if (!fileOnly && (await dirExists(env, fullPath))) return "dir";
  return null;
}

/** 目录链上是否有某个祖先已经是文件（否则会出现「文件里面再建目录」的非法状态） */
async function findAncestorFile(env: Env, dir: string): Promise<string | null> {
  const parts = normDir(dir).split("/").filter(Boolean);
  let acc = "";
  for (const p of parts) {
    acc += "/" + p;
    if (await fileExistsAt(env, acc)) return acc;
  }
  return null;
}

/** 目录下是否还有文件或子目录（用于移动时避免静默覆盖非空目录） */
async function dirHasChildren(env: Env, dir: string): Promise<boolean> {
  const like = likePrefix(normDir(dir) + "/");
  const f = await env.db.prepare("SELECT 1 FROM files WHERE path LIKE ?1 ESCAPE '\\' LIMIT 1").bind(like).first();
  if (f) return true;
  const d = await env.db.prepare("SELECT 1 FROM directories WHERE path LIKE ?1 ESCAPE '\\' LIMIT 1").bind(like).first();
  return !!d;
}

/** LIKE 前缀转义：把路径里的 \ % _ 转义，避免 "%" 被当成通配符误伤其它目录 */
function likePrefix(prefix: string): string {
  return prefix.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_") + "%";
}

/** D1 batch 单次语句数有上限，按块提交 */
async function runBatched(env: Env, stmts: D1PreparedStatement[], chunk = 60): Promise<void> {
  for (let i = 0; i < stmts.length; i += chunk) {
    await env.db.batch(stmts.slice(i, i + chunk));
  }
}

/**
 * 删除一个路径（文件或目录）。
 *   · 文件 → 连带 shares / download_logs / 存储对象
 *   · 目录 → 递归删除其下所有文件与子目录记录（含空的显式目录）
 * 返回是否真的删掉了东西。
 */
async function fsDeletePath(env: Env, target: string): Promise<boolean> {
  const st = await storage(env);

  // ① 精确匹配到文件
  const file = await findFileByPath(env, target);
  if (file) {
    await env.db.batch([
      env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(file.id),
      env.db.prepare("DELETE FROM direct_links WHERE file_id = ?1").bind(file.id),
      env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(file.id),
      env.db.prepare("DELETE FROM files WHERE id = ?1").bind(file.id),
    ]);
    await st.delete(file.key).catch(() => {});
    return true;
  }

  // ② 目录（directories 表记录，或只是有文件在它下面）
  const existed = await dirExists(env, target);
  if (!existed) return false;

  const childLike = likePrefix(target + "/");
  const { results: files } = await env.db
    .prepare("SELECT id, key FROM files WHERE path LIKE ?1 ESCAPE '\\'")
    .bind(childLike)
    .all<{ id: string; key: string }>();
  const stmts: D1PreparedStatement[] = [];
  const keys: string[] = [];
  for (const f of files ?? []) {
    stmts.push(env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(f.id));
    stmts.push(env.db.prepare("DELETE FROM direct_links WHERE file_id = ?1").bind(f.id));
    stmts.push(env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(f.id));
    stmts.push(env.db.prepare("DELETE FROM files WHERE id = ?1").bind(f.id));
    keys.push(f.key);
  }
  stmts.push(env.db.prepare("DELETE FROM directories WHERE path = ?1 OR path LIKE ?2 ESCAPE '\\'").bind(target, childLike));
  await runBatched(env, stmts);
  await Promise.all(keys.map((k) => st.delete(k).catch(() => {})));
  return true;
}

/**
 * 移动 / 重命名一个路径（文件或目录，from / to 都是全路径）。
 * 目录会连同所有后代一起迁移（递归改 path 前缀 + directories 记录）。
 */
async function fsMoveEntry(env: Env, from: string, to: string): Promise<void> {
  const nameOf = (p: string) => p.split("/").filter(Boolean).pop() || "unnamed";

  // ① 文件
  const file = await findFileByPath(env, from);
  if (file) {
    await env.db
      .prepare("UPDATE files SET path = ?1, name = ?2 WHERE id = ?3")
      .bind(to, nameOf(to), file.id)
      .run();
    return;
  }

  // ② 目录 —— 递归改所有后代文件的 path
  const childLike = likePrefix(from + "/");
  const stmts: D1PreparedStatement[] = [];
  const { results: files } = await env.db
    .prepare("SELECT id, path FROM files WHERE path LIKE ?1 ESCAPE '\\'")
    .bind(childLike)
    .all<{ id: string; path: string }>();
  for (const f of files ?? []) {
    stmts.push(env.db.prepare("UPDATE files SET path = ?1 WHERE id = ?2").bind(to + f.path.slice(from.length), f.id));
  }

  // 子目录记录：先删旧路径再插新路径（path 是主键，直接改会冲突）
  const { results: dirs } = await env.db
    .prepare("SELECT path FROM directories WHERE path = ?2 OR path LIKE ?1 ESCAPE '\\'")
    .bind(childLike, from)
    .all<{ path: string }>();
  for (const d of dirs ?? []) {
    stmts.push(env.db.prepare("DELETE FROM directories WHERE path = ?1").bind(d.path));
    stmts.push(
      env.db
        .prepare("INSERT INTO directories(path, created_at) VALUES(?1, ?2) ON CONFLICT(path) DO NOTHING")
        .bind(to + d.path.slice(from.length), Date.now())
    );
  }
  await runBatched(env, stmts);
}


/** 生成带文件名后缀的直链 URL：/d/{token}/{filename}，文件名做 URL 编码 */
function buildDirectUrl(token: string, fileName?: string | null, downloadName?: string | null): string {
  const displayName = downloadName?.trim() || fileName?.trim();
  if (!displayName) return `/d/${token}`;
  const safe = displayName.replace(/[\\/]/g, "_");
  return `/d/${token}/${encodeURIComponent(safe)}`;
}

async function requireAuth(req: Request, env: Env): Promise<Response | null> {
  if (!(await verifySession(req, env))) {
    return json({ error: "unauthorized" }, 401);
  }
  return null;
}

/** 写入登录安全日志 —— 登录/登出/失败/限流 全部走这里 */
async function writeLoginLog(
  env: Env,
  req: Request,
  action: string,
  result: string,
  reason: string | null = null
): Promise<void> {
  try {
    const ua = req.headers.get("user-agent") ?? "";
    const { browser, os } = parseUA(ua);
    // Cloudflare 下 country 由 CF-IPCountry 头提供
    const country = req.headers.get("cf-ipcountry") ?? null;
    await env.db
      .prepare(
        "INSERT INTO login_logs(action, ip, ua, browser, os, country, result, reason, created_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
      )
      .bind(action, clientIp(req), ua || null, browser, os, country, result, reason, Date.now())
      .run();
  } catch {
    // 日志写入失败不影响主流程
  }
}

export async function handleAdminApi(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  path: string
): Promise<Response> {
  try {
  await ensureSchema(env);
  const method = req.method;
  const url = new URL(req.url);

  // ── IP 白名单门禁 ── 空 = 不限制；非空 = 仅白名单 IP 能访问所有 /api/admin/*
  {
    const s = await getSettings(env);
    const denied = requireAdminIp(clientIp(req), s.adminIps);
    if (denied) return denied;
  }

  // ── 登录（支持 2FA 两阶段） ──────────────────────────────
  if (path === "/api/admin/login" && method === "POST") {
    const ip = clientIp(req);
    if (!rateLimitLogin(ip)) {
      ctx.waitUntil(writeLoginLog(env, req, "login", "fail", "rate_limited"));
      return json({ error: msg(req, "尝试过于频繁，请稍后再试", "Too many attempts. Please try again later.") }, 429);
    }
    if (!env.admin)
      return json({ error: msg(req, "未设置 admin 密钥，请先执行 npx wrangler secret put admin", "admin is not set. Run: npx wrangler secret put admin") }, 500);
    const body = await readJson<{ key: string; code?: string }>(req);
    if (!body.key || !checkAdminKey(env, body.key)) {
      ctx.waitUntil(writeLoginLog(env, req, "login", "fail", "invalid_key"));
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }

    // 密码正确 —— 检查是否需要 2FA
    const s = await getSettings(env);
    const needsTotp = s.totpEnabled && s.totpSecretCipher;

    if (needsTotp) {
      // 没带 code → 要求 2FA
      if (!body.code) {
        return json({ need_2fa: true });
      }

      // 先尝试 TOTP
      const totpSecret = await decryptSecret(s.totpSecretCipher!, env.admin);
      const totpOk = totpSecret ? await totpVerify(totpSecret, body.code) : false;

      if (totpOk) {
        ctx.waitUntil(writeLoginLog(env, req, "login", "success", "2fa_totp"));
        return new Response(JSON.stringify({ ok: true }), {
          headers: {
            "content-type": "application/json;charset=utf-8",
            "set-cookie": await createSession(env, url.protocol === "https:"),
            "cache-control": "no-store",
          },
        });
      }

      // TOTP 失败 → 尝试恢复码（两种来源：Cloudflare Secret 优先 → D1 恢复码）
      const normalized = body.code.replace(/\s+/g, "").toUpperCase();

      // 1) Cloudflare Secret 恢复码（超级恢复，用一次不消耗）
      const cloudflareRecovery = env.totp_recovery?.trim();
      if (cloudflareRecovery && safeEqual(normalized, cloudflareRecovery.replace(/\s+/g, "").toUpperCase())) {
        // 用了云变量恢复码 —— 自动重置 2FA（因为 secret 可能丢了）
        await updateSettings(env, {
          totp_enabled: "0",
          totp_secret_cipher: "",
          totp_recovery_hash: "",
        });
        ctx.waitUntil(writeLoginLog(env, req, "login", "success", "recovery_cloudflare"));
        return new Response(JSON.stringify({ ok: true, recovery_used: true, totp_reset: true }), {
          headers: {
            "content-type": "application/json;charset=utf-8",
            "set-cookie": await createSession(env, url.protocol === "https:"),
            "cache-control": "no-store",
          },
        });
      }

      // 2) D1 存储的恢复码列表（消耗型，用一次删一次）
      if (s.totpRecoveryHash) {
        const hashes = s.totpRecoveryHash.split(",").filter(Boolean);
        const inputHash = await sha256Hex(normalized);
        let matched = -1;
        for (let i = 0; i < hashes.length; i++) {
          if (safeEqual(inputHash, hashes[i])) { matched = i; break; }
        }
        if (matched >= 0) {
          // 从列表中移除已使用的恢复码
          hashes.splice(matched, 1);
          await updateSettings(env, { totp_recovery_hash: hashes.join(",") });
          // 恢复码通过 → 自动重置 2FA
          await updateSettings(env, {
            totp_enabled: "0",
            totp_secret_cipher: "",
          });
          ctx.waitUntil(writeLoginLog(env, req, "login", "success", "recovery_code"));
          return new Response(JSON.stringify({ ok: true, recovery_used: true, totp_reset: true }), {
            headers: {
              "content-type": "application/json;charset=utf-8",
              "set-cookie": await createSession(env, url.protocol === "https:"),
              "cache-control": "no-store",
            },
          });
        }
      }

      // 都不对
      ctx.waitUntil(writeLoginLog(env, req, "login", "fail", "invalid_2fa"));
      return json({ error: msg(req, "2FA 验证失败", "Invalid 2FA code") }, 401);
    }

    // 无需 2FA → 直接登录成功
    ctx.waitUntil(writeLoginLog(env, req, "login", "success"));
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json;charset=utf-8",
        "set-cookie": await createSession(env, url.protocol === "https:"),
        "cache-control": "no-store",
      },
    });
  }

  // ── 登录方式探测（公开，无需会话）——
  //    登录页据此决定显示哪些「使用 XX 登录」按钮。
  //    ⚠️ 故意不返回已绑定的用户名 / 昵称等身份信息：此接口对所有访客开放，
  //       返回身份信息等于把你的第三方账号名公开，会被拿来骚扰/钓鱼。
  if (path === "/api/admin/auth-methods" && method === "GET") {
    const s = await getSettings(env);
    const cfg = parseAdminOauth(s.adminOauth);
    const providers: Record<string, { enabled: boolean }> = {};
    for (const id of ADMIN_OAUTH_PROVIDER_IDS) {
      const p = cfg[id];
      providers[id] = {
        enabled: p.enabled && !!p.uid && !!p.clientId && !!p.secretCipher,
      };
    }
    return json({ providers });
  }

  // ── 错误日志上报（公开，无需会话）─────────────────────
  //    前端（含登录页、未登录态）发生未捕获异常时上报到这里，方便反馈给开发者。
  //    ⚠️ 刻意放在 requireAuth 之前：登录页出错时还没有会话，也需要能记录。
  //    防滥用：按 IP 限流（30 次/分钟）；所有字段在 writeErrorLog 内裁剪长度。
  if (path === "/api/admin/errors" && method === "POST") {
    const ip = clientIp(req);
    // 用 "err:" 前缀与登录限流隔离，互不影响
    if (!rateLimitLogin("err:" + ip, 30, 60_000)) {
      return json({ ok: false, error: "rate_limited" }, 429);
    }
    const body = await readJson<{
      message?: string;
      stack?: string;
      source?: string;
      path?: string;
      url?: string;
      line?: number;
      col?: number;
      context?: string;
    }>(req);
    const message = String(body.message ?? "").trim();
    if (!message) return json({ ok: false, error: "empty_message" }, 400);

    const ua = req.headers.get("user-agent") ?? "";
    const { browser, os } = parseUA(ua);
    const num = (v: unknown) => (Number.isFinite(Number(v)) ? Number(v) : null);
    const src = body.source === "frontend" || body.source === "backend" ? body.source : "frontend";

    ctx.waitUntil(
      writeErrorLog(env, {
        source: src,
        message,
        stack: typeof body.stack === "string" ? body.stack : null,
        path: typeof body.path === "string" ? body.path : null,
        url: typeof body.url === "string" ? body.url : null,
        line: num(body.line),
        col: num(body.col),
        ua,
        browser,
        os,
        country: req.headers.get("cf-ipcountry") ?? null,
        ip,
        context: typeof body.context === "string" ? body.context : null,
      })
    );
    return json({ ok: true });
  }

  // ── 以下全部需要会话 ──────────────────────────────
  const unauthorized = await requireAuth(req, env);
  if (unauthorized) return unauthorized;

  // 登出
  if (path === "/api/admin/logout" && method === "POST") {
    const secure = url.protocol === "https:";
    ctx.waitUntil(writeLoginLog(env, req, "logout", "success"));
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json;charset=utf-8",
        "set-cookie": `cd_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`,
      },
    });
  }

  // 会话检查
  if (path === "/api/admin/session" && method === "GET") {
    const s = await getSettings(env);
    return json({
      ok: true,
      site_title: s.siteTitle,
      totp_enabled: s.totpEnabled,
      cloudflare_recovery: !!env.totp_recovery,
      recovery_remaining: s.totpRecoveryHash ? s.totpRecoveryHash.split(",").filter(Boolean).length : 0,
      ui_theme: s.uiTheme,
      admin_tab_config: s.adminTabConfig,
    });
  }

  // ══════════════════════════════════════════════════════════════
  // 管理员第三方 OAuth2 登录（登录方式标签页）
  //   GET    /api/admin/login-methods               全部 Provider 配置 + 绑定状态
  //   PUT    /api/admin/login-methods               保存某 Provider 的 Client ID / Secret / 开关
  //   POST   /api/admin/login-methods/bind-start    生成某 Provider 的绑定授权 URL
  //   POST   /api/admin/login-methods/unbind        解绑某 Provider
  //
  // ⚠️ 注意：这里刻意不用 /api/admin/oauth/providers —— 那个路径已被「访客下载鉴权」
  //    的 OAuth2 Provider CRUD（下面的 oauth_providers 表管理）占用，两者语义完全不同，
  //    共用会导致 GET 列表被后者覆盖（先前 GitHub 绑定相关的诡异失败部分源于此）。
  // ══════════════════════════════════════════════════════════════
  if (path === "/api/admin/login-methods" && method === "GET") {
    const s = await getSettings(env);
    const cfg = parseAdminOauth(s.adminOauth);
    const callbackUrl = adminOauthCallbackUrl(req);
    const providers = ADMIN_OAUTH_PROVIDER_IDS.map((id) => {
      const p = cfg[id];
      const builtin = getBuiltinProvider(id);
      return {
        id,
        name: builtin?.name ?? id,
        client_id: p.clientId,
        secret_configured: !!p.secretCipher,
        enabled: p.enabled,
        bound: !!p.uid,
        login: p.uid ? p.login : "",
        nickname: p.uid ? p.name : "",
        avatar: p.uid ? p.avatar : "",
        bound_at: p.uid ? p.boundAt : 0,
        ready: !!p.clientId && !!p.secretCipher,
        callback_url: callbackUrl,
      };
    });
    return json({ providers });
  }

  if (path === "/api/admin/login-methods" && method === "PUT") {
    const body = await readJson<{ provider?: string; client_id?: string; client_secret?: string; enabled?: boolean }>(req);
    const providerId = String(body.provider ?? "");
    if (!isAdminOauthProvider(providerId)) return json({ error: msg(req, "不支持的登录方式", "Unsupported provider") }, 400);

    const s = await getSettings(env);
    const cfg = parseAdminOauth(s.adminOauth);
    const cur = cfg[providerId];

    if (typeof body.client_id === "string") cur.clientId = body.client_id.trim();
    if (typeof body.client_secret === "string") {
      const raw = body.client_secret.trim();
      if (raw === "") {
        cur.secretCipher = ""; // 显式清空
      } else if (raw !== "__keep__") {
        const cipher = await encryptSecret(raw, env.admin);
        // 加密失败必须报错 —— 之前静默吞掉会让用户以为已保存，随后绑定必然失败
        if (!cipher) return json({ error: msg(req, "密钥加密失败，请重试", "Failed to encrypt the secret") }, 500);
        cur.secretCipher = cipher;
      }
    }
    if (typeof body.enabled === "boolean") {
      // 未绑定账号时不允许开启登录，避免把自己锁在门外
      if (body.enabled && !cur.uid) return json({ error: msg(req, "请先绑定账号", "Bind an account first") }, 400);
      cur.enabled = body.enabled;
    }
    await updateSettings(env, { admin_oauth: serializeAdminOauth(cfg) });
    return json({ ok: true });
  }

  if (path === "/api/admin/login-methods/bind-start" && method === "POST") {
    const body = await readJson<{ provider?: string }>(req);
    const providerId = String(body.provider ?? "");
    if (!isAdminOauthProvider(providerId)) return json({ error: msg(req, "不支持的登录方式", "Unsupported provider") }, 400);

    const s = await getSettings(env);
    const cfg = parseAdminOauth(s.adminOauth)[providerId];
    if (!cfg.clientId || !cfg.secretCipher) {
      return json({ error: msg(req, "请先保存该登录方式的 Client ID / Secret", "Save the Client ID / Secret first") }, 400);
    }
    const authorizeUrl = await buildAdminOauthAuthorizeUrl(env, req, providerId, ADMIN_OAUTH_INTENT_BIND);
    if (!authorizeUrl) return json({ error: msg(req, "无法生成授权链接", "Cannot build authorize URL") }, 500);
    return json({ ok: true, authorize_url: authorizeUrl });
  }

  if (path === "/api/admin/login-methods/unbind" && method === "POST") {
    const body = await readJson<{ provider?: string }>(req);
    const providerId = String(body.provider ?? "");
    if (!isAdminOauthProvider(providerId)) return json({ error: msg(req, "不支持的登录方式", "Unsupported provider") }, 400);

    const s = await getSettings(env);
    const cfg = parseAdminOauth(s.adminOauth);
    cfg[providerId] = { ...cfg[providerId], enabled: false, uid: "", login: "", name: "", avatar: "", boundAt: 0 };
    await updateSettings(env, { admin_oauth: serializeAdminOauth(cfg) });
    return json({ ok: true });
  }

  // ── 概览统计 ──────────────────────────────────────
  if (path === "/api/admin/stats" && method === "GET") {
    // getSettings 内部已做跨月自动兜底，无需此处重复检查和 DB 写入
    const s = await getSettings(env);
    const [files, shares, activeShares, totalDownloads, todayStat, chartRows, recent, banned] =
      await Promise.all([
        env.db.prepare("SELECT COUNT(*) AS c FROM files").first<{ c: number }>(),
        env.db.prepare("SELECT COUNT(*) AS c FROM shares").first<{ c: number }>(),
        env.db.prepare(
          "SELECT COUNT(*) AS c FROM shares WHERE revoked = 0 AND (expires_at IS NULL OR expires_at > ?1) AND (max_downloads IS NULL OR download_count < max_downloads)"
        )
          .bind(Date.now())
          .first<{ c: number }>(),
        env.db.prepare("SELECT COALESCE(SUM(downloads), 0) AS c FROM traffic_stats").first<{ c: number }>(),
        env.db.prepare("SELECT bytes, downloads FROM traffic_stats WHERE day = ?1")
          .bind(new Date().toISOString().slice(0, 10))
          .first<{ bytes: number; downloads: number }>(),
        env.db.prepare(
          "SELECT day, bytes, downloads FROM traffic_stats WHERE day >= date('now', '-13 days') ORDER BY day"
        ).all<{ day: string; bytes: number; downloads: number }>(),
        env.db.prepare(
          "SELECT file_name, ip, browser, os, country, bytes, created_at FROM download_logs ORDER BY id DESC LIMIT 10"
        ).all(),
        env.db.prepare("SELECT COUNT(*) AS c FROM banned_ips").first<{ c: number }>(),
      ]);

    // 补齐 14 天（无数据的天补 0）
    const chartMap = new Map((chartRows.results ?? []).map((r) => [r.day, r]));
    const chart: { day: string; downloads: number; bytes: number }[] = [];
    for (let i = 13; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400_000).toISOString().slice(0, 10);
      const r = chartMap.get(d);
      chart.push({ day: d, downloads: r?.downloads ?? 0, bytes: r?.bytes ?? 0 });
    }

    const quotaExceeded = s.trafficLimitBytes > 0 && s.trafficUsedBytes >= s.trafficLimitBytes;
    return json({
      traffic: {
        used: s.trafficUsedBytes,
        limit: s.trafficLimitBytes,
        percent:
          s.trafficLimitBytes > 0
            ? Math.min(100, Math.round((s.trafficUsedBytes / s.trafficLimitBytes) * 100))
            : 0,
        month: s.trafficMonth,
        quota_exceeded: quotaExceeded,
      },
      counts: {
        files: files?.c ?? 0,
        shares: shares?.c ?? 0,
        active_shares: activeShares?.c ?? 0,
        downloads_total: totalDownloads?.c ?? 0,
        downloads_today: todayStat?.downloads ?? 0,
        bytes_today: todayStat?.bytes ?? 0,
        banned: banned?.c ?? 0,
      },
      chart,
      recent: recent.results ?? [],
    });
  }

  // ── 文件列表 ──────────────────────────────────────
  //   GET /api/admin/files                  → 根目录内容（子目录 + 子文件）
  //   GET /api/admin/files?path=/docs       → 指定目录内容
  //   GET /api/admin/files?q=keyword        → 全盘按文件名搜索
  if (path === "/api/admin/files" && method === "GET") {
    const u = new URL(req.url);
    const q = (u.searchParams.get("q") ?? "").trim();
    if (q) {
      const esc = q.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
      const { results } = await env.db.prepare(
        `SELECT f.id, f.name, f.size, f.mime, f.uploaded_at, f.path,
                (SELECT COUNT(*) FROM shares s WHERE s.file_id = f.id) AS share_count,
                (SELECT COALESCE(SUM(s.download_count), 0) FROM shares s WHERE s.file_id = f.id) AS download_count
         FROM files f WHERE f.name LIKE ?1 ESCAPE '\\' ORDER BY f.uploaded_at DESC LIMIT 200`
      ).bind(`%${esc}%`).all();
      return json({ files: results ?? [], dirs: [], path: "/", search: q });
    }
    const dir = normDir(u.searchParams.get("path"));
    if (!isSafePath(dir)) return json({ error: msg(req, "路径不合法", "Invalid path") }, 400);
    const { files, dirs } = await listDir(env, dir);
    return json({ files, dirs, path: dir });
  }

  // ── 上传文件（原始流式 body，文件名放 X-File-Name 头，目标目录放 ?path=） ──
  //   POST /api/admin/upload                        → 上传到根目录
  //   POST /api/admin/upload?path=/docs/2026        → 上传到指定目录（目录链自动创建）
  //   同名文件已存在时覆盖（连带清理旧文件记录 / 分享 / 存储对象）
  if (path === "/api/admin/upload" && method === "POST") {
    const rawName = req.headers.get("x-file-name");
    if (!rawName) return json({ error: msg(req, "缺少 X-File-Name 头", "Missing X-File-Name header") }, 400);
    let name: string;
    try {
      name = sanitizeName(decodeURIComponent(rawName));
    } catch {
      name = sanitizeName(rawName);
    }
    const dir = normDir(new URL(req.url).searchParams.get("path"));
    if (!isSafePath(dir)) return json({ error: msg(req, "路径不合法", "Invalid path") }, 400);
    if (!req.body) return json({ error: msg(req, "请求体为空", "Empty request body") }, 400);
    // 目标目录链上不能已经有同名文件，否则会造出「文件里建目录」的非法结构
    const dirConflict = await findAncestorFile(env, dir);
    if (dirConflict)
      return json({ error: msg(req, `路径「${dirConflict}」已是一个文件`, `Path "${dirConflict}" is a file`) }, 409);
    const fullPath = joinFullPath(dir, name);
    // 同名目录已存在 → 拒绝（否则同一路径既是文件又是目录，列表/删除都会错乱）
    if (await dirExists(env, fullPath))
      return json({ error: msg(req, "同名文件夹已存在", "A folder with the same name exists") }, 409);
    // 自动补建目标目录链（/a/b/c → /a、/a/b、/a/b/c）
    await ensureDirChain(env, dir);
    const st = await storage(env);
    // 同名覆盖：先删掉旧文件（含 shares / download_logs / 旧存储对象），避免同名重复条目
    const existing = await findFileByPath(env, fullPath);
    if (existing) {
      await env.db.batch([
        env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(existing.id),
        env.db.prepare("DELETE FROM direct_links WHERE file_id = ?1").bind(existing.id),
        env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(existing.id),
        env.db.prepare("DELETE FROM files WHERE id = ?1").bind(existing.id),
      ]);
      ctx.waitUntil(st.delete(existing.key).catch(() => {}));
    }
    const id = randomId(14);
    const key = `files/${id}`;
    const mime = req.headers.get("content-type") || "application/octet-stream";
    // 请求体真实长度（浏览器上传时总会带 Content-Length）—— 用于兜底校正存储层返回的大小。
    const declaredLen = parseInt(req.headers.get("content-length") || "", 10) || 0;
    let resultSize = 0;
    try {
      const res = await st.put(key, req.body, {
        contentType: mime,
        contentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(name)}`,
      });
      resultSize = res.size;
      // 某些存储后端（WebDAV / 部分 S3 兼容实现）对流式 PUT 无法取到大小而返回 0，
      // 若直接落库会让下载端 content-length=0 —— 文件"下出来是空的"。用请求头 / HEAD 兜底。
      if (resultSize <= 0) {
        if (declaredLen > 0) resultSize = declaredLen;
        else {
          const meta = await st.head(key).catch(() => null);
          if (meta?.size) resultSize = meta.size;
        }
      }
    } catch (err: any) {
      return json({ error: msg(req, "存储写入失败", "Storage write failed"), detail: String(err?.message || err) }, 500);
    }
    // ── Bug #4 修复：D1 写入失败时清理已写入的 storage 对象 ──
    try {
      await env.db.prepare(
        "INSERT INTO files(id, key, name, size, mime, path, uploaded_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)"
      )
        .bind(id, key, name, resultSize, mime, fullPath, Date.now())
        .run();
    } catch (dbErr) {
      ctx.waitUntil(st.delete(key).catch(() => {}));
      console.error("upload: D1 insert failed, cleaned up storage object:", dbErr);
      return json({ error: msg(req, "数据库写入失败，请重试", "Database write failed. Please retry.") }, 500);
    }
    return json({ ok: true, id, name, size: resultSize, path: fullPath }, 201);
  }

  // ── 新建目录 ──────────────────────────────────────
  //   POST /api/admin/dirs  { dir, name } → 在 dir 下新建 name 目录（父目录链自动创建）
  if (path === "/api/admin/dirs" && method === "POST") {
    const body = await readJson<{ dir?: string; name?: string }>(req);
    const dir = normDir(body.dir);
    const name = sanitizeName(String(body.name ?? "").trim());
    if (!name || !isSafePath(dir)) return json({ error: msg(req, "目录名不合法", "Invalid folder name") }, 400);
    const full = joinFullPath(dir, name);
    const occupied = await pathTaken(env, full, false);
    if (occupied === "file") return json({ error: msg(req, "同名文件已存在", "A file with the same name exists") }, 409);
    if (occupied === "dir") return json({ ok: true, path: full, existed: true }, 200); // 幂等 mkdir
    await ensureDirChain(env, full);
    return json({ ok: true, path: full }, 201);
  }

  // ── 移动 / 重命名（文件或目录，全路径 from → to） ──
  //   POST /api/admin/fs/move  { from, to }
  //   · 目录连同其下所有子项一起移动（递归改 path 前缀）
  //   · 目标父目录不存在时自动创建；目标已存在时覆盖
  if (path === "/api/admin/fs/move" && method === "POST") {
    const body = await readJson<{ from?: string; to?: string }>(req);
    const from = normDir(body.from);
    const to = normDir(body.to);
    if (!isSafePath(from) || !isSafePath(to) || from === "/" || to === "/")
      return json({ error: msg(req, "路径不合法", "Invalid path") }, 400);
    if (from === to) return json({ ok: true, from, to });
    // 禁止把目录移动进它自己的子目录（否则会形成自引用 / 数据丢失）
    if (to.startsWith(from + "/"))
      return json({ error: msg(req, "不能移动到自身子目录", "Cannot move into its own subfolder") }, 400);
    const srcIsFile = await fileExistsAt(env, from);
    const srcIsDir = await dirExists(env, from);
    if (!srcIsFile && !srcIsDir) return json({ error: msg(req, "源不存在", "Source not found") }, 404);
    // 目标父目录自动补建 —— 但父链上不能有同名文件（否则会出现「文件里建目录」的非法状态）
    const parent = dirOfFullPath(to);
    const anc = await findAncestorFile(env, parent);
    if (anc) return json({ error: msg(req, `目标父路径「${anc}」已是一个文件`, `Target parent path "${anc}" is a file`) }, 409);
    await ensureDirChain(env, parent);
    // 目标已存在 → 拒绝，绝不静默覆盖 / 删除（旧实现会直接把目标删掉，极易误删数据）
    const toTaken = await pathTaken(env, to, false);
    if (toTaken === "file")
      return json({ error: msg(req, "目标路径已存在同名文件", "A file already exists at the target path") }, 409);
    if (toTaken === "dir") {
      if (srcIsFile)
        return json({ error: msg(req, "目标路径已存在同名目录", "A folder already exists at the target path") }, 409);
      // 目录 → 已有目录：允许将空目录并入；两侧都有内容时拒绝，避免同名文件互相覆盖
      if ((await dirHasChildren(env, to)) && (await dirHasChildren(env, from)))
        return json({ error: msg(req, "目标目录非空，无法合并", "Target folder is not empty") }, 409);
    }
    await fsMoveEntry(env, from, to);
    return json({ ok: true, from, to });
  }

  // ── 批量删除（文件 / 目录，按全路径；目录递归删除） ──
  //   POST /api/admin/fs/delete  { paths: ["/a.txt", "/docs"] }
  if (path === "/api/admin/fs/delete" && method === "POST") {
    const body = await readJson<{ paths?: unknown }>(req);
    const raw = Array.isArray(body.paths) ? body.paths : [];
    const targets = (raw as unknown[])
      .map((p) => normDir(typeof p === "string" ? p : ""))
      .filter((p) => p !== "/" && isSafePath(p));
    if (!targets.length) return json({ error: msg(req, "缺少有效路径", "No valid paths") }, 400);
    let deleted = 0;
    for (const t of targets) {
      if (await fsDeletePath(env, t)) deleted++;
    }
    return json({ ok: true, deleted });
  }

  // ── 删除文件（连带存储对象、分享、日志） ──────────
  //   保留按 id 的旧接口，兼容旧前端
  const fileMatch = /^\/api\/admin\/files\/([^/]+)$/.exec(path);
  if (fileMatch && method === "DELETE") {
    const fileId = fileMatch[1];
    const file = await env.db.prepare("SELECT key FROM files WHERE id = ?1").bind(fileId).first<{ key: string }>();
    if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
    await env.db.batch([
      env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(fileId),
      env.db.prepare("DELETE FROM direct_links WHERE file_id = ?1").bind(fileId),
      env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(fileId),
      env.db.prepare("DELETE FROM files WHERE id = ?1").bind(fileId),
    ]);
    const st = await storage(env);
    ctx.waitUntil(st.delete(file.key).catch(() => {}));
    return json({ ok: true });
  }

  // ── 存储浏览（S3 / R2 bucket 内对象列表） ─────────
  if (path === "/api/admin/storage/objects" && method === "GET") {
    const prefix = new URL(req.url).searchParams.get("prefix") ?? "";
    const marker = new URL(req.url).searchParams.get("marker") ?? undefined;
    const limit = Math.min(500, parseInt(new URL(req.url).searchParams.get("limit") || "100", 10) || 100);
    try {
      const st = await storage(env);
      const result = await st.list({ prefix, marker, limit });
      return json({ ok: true, ...result, kind: st.kind });
    } catch (e: any) {
      return json({ ok: false, error: msg(req, `列存储对象失败: ${e?.message ?? e}`, `Storage list failed: ${e?.message ?? e}`) }, 500);
    }
  }

  // ── 删除存储对象（直接删 bucket 中 key；不碰 DB） ──
  const stDelMatch = /^\/api\/admin\/storage\/objects$/.exec(path);
  if (stDelMatch && method === "DELETE") {
    const body = await readJson<{ keys?: string[]; key?: string }>(req).catch(() => ({} as any));
    const rawKeys = body.keys ?? (body.key ? [body.key] : []);
    if (!Array.isArray(rawKeys) || rawKeys.length === 0) return json({ error: msg(req, "缺少 keys", "Missing keys") }, 400);
    // 安全校验：key 不能为空、不能以 / 开头
    const keys = rawKeys.filter((k: any) => typeof k === "string" && k.length > 0 && !k.startsWith("/"));
    if (keys.length === 0) return json({ error: msg(req, "无有效 key", "No valid keys") }, 400);
    try {
      const st = await storage(env);
      await Promise.all(keys.map((k) => st.delete(k).catch(() => {})));
      return json({ ok: true, deleted: keys.length });
    } catch (e: any) {
      return json({ ok: false, error: msg(req, `删除失败: ${e?.message ?? e}`, `Delete failed: ${e?.message ?? e}`) }, 500);
    }
  }

  // ── 创建分享 ──────────────────────────────────────
  if (path === "/api/admin/shares" && method === "POST") {
    const body = await readJson<{
      file_id: string;
      expires_hours: number | null;
      max_downloads: number | null;
      password: string | null;
      download_name?: string | null;
      is_market?: boolean;
      market_title?: string | null;
      market_desc?: string | null;
    }>(req);
    if (!body.file_id) return json({ error: msg(req, "缺少 file_id", "Missing file_id") }, 400);
    const file = await env.db.prepare("SELECT id FROM files WHERE id = ?1").bind(body.file_id).first();
    if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
    const expiresAt =
      body.expires_hours && body.expires_hours > 0 ? Date.now() + body.expires_hours * 3600_000 : null;
    const maxDownloads =
      body.max_downloads && body.max_downloads > 0 ? Math.floor(body.max_downloads) : null;
    const password =
      typeof body.password === "string" && body.password.trim() ? body.password.trim() : null;
    const passwordHash = password ? await hashPassword(password) : null;
    // 可逆加密存储密码明文，管理员之后可查看
    const passwordCipher = password ? await encryptSecret(password, env.admin) : null;
    const downloadName =
      typeof body.download_name === "string" && body.download_name.trim() ? body.download_name.trim() : null;
    const isMarket = body.is_market ? 1 : 0;
    const marketTitle =
      typeof body.market_title === "string" && body.market_title.trim() ? body.market_title.trim() : null;
    const marketDesc =
      typeof body.market_desc === "string" && body.market_desc.trim() ? body.market_desc.trim() : null;
    const id = randomId(10);
    await env.db.prepare(
      `INSERT INTO shares(id, file_id, created_at, expires_at, max_downloads, password_hash, password_cipher, download_name, is_market, market_title, market_desc)
       VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
    )
      .bind(id, body.file_id, Date.now(), expiresAt, maxDownloads, passwordHash, passwordCipher, downloadName, isMarket, marketTitle, marketDesc)
      .run();
    return json({ ok: true, id, url: `/s/${id}` }, 201);
  }

  // ── 分享列表 ──────────────────────────────────────
  if (path === "/api/admin/shares" && method === "GET") {
    const { results } = await env.db.prepare(
      `SELECT s.id, s.file_id, s.created_at, s.expires_at, s.max_downloads, s.download_count,
              s.max_previews, s.preview_count, s.revoked,
              s.password_hash, s.password_cipher, s.download_name,
              s.is_market, s.market_views, s.market_title, s.market_desc,
              f.name AS file_name, f.size AS file_size, f.mime AS file_mime
       FROM shares s JOIN files f ON f.id = s.file_id
       ORDER BY s.created_at DESC`
    ).all();
    const now = Date.now();
    // 并行解密所有密码明文
    const shares = await Promise.all(
      (results ?? []).map(async (s: any) => ({
        ...s,
        has_password: !!s.password_hash,
        password_plain: s.password_cipher ? await decryptSecret(s.password_cipher, env.admin) : null,
        password_hash: undefined,
        password_cipher: undefined,
        url: `/s/${s.id}`,
        status: s.revoked
          ? "revoked"
          : s.expires_at && s.expires_at < now
            ? "expired"
            : s.max_downloads && s.download_count >= s.max_downloads
              ? "maxed"
              : "active",
      }))
    );
    return json({ shares });
  }

  // ── 清理失效分享（过期 / 已撤销 / 达上限） ──
  // ⚠️ 只删分享链接，**绝不删文件**：文件管理是独立功能，一个文件可能还没有创建分享，
  //    也可能只被直链引用。旧实现把"没有 share 引用的文件"当孤儿一并删除（含存储对象），
  //    点一次清理就会把刚上传、尚未分享的文件以及仅直链使用的文件全部删掉。
  if (path === "/api/admin/shares/cleanup" && method === "POST") {
    const now = Date.now();
    const deleted = await env.db.prepare(
      "DELETE FROM shares WHERE revoked = 1 OR (expires_at IS NOT NULL AND expires_at < ?1) OR (max_downloads IS NOT NULL AND download_count >= max_downloads)"
    )
      .bind(now)
      .run();
    return json({ ok: true, deleted_shares: deleted.meta.changes ?? 0 });
  }

  // ── 撤销/删除分享 ─────────────────────────────────
  const shareMatch = /^\/api\/admin\/shares\/([^/]+)$/.exec(path);
  if (shareMatch && method === "DELETE") {
    const r = await env.db.prepare("DELETE FROM shares WHERE id = ?1").bind(shareMatch[1]).run();
    if ((r.meta.changes ?? 0) === 0) return json({ error: msg(req, "分享不存在", "Share not found") }, 404);
    return json({ ok: true });
  }

  // ── 编辑市场字段（开关 + 标题 + 描述） ────────────
  const shareMarketMatch = /^\/api\/admin\/shares\/([^/]+)\/market$/.exec(path);
  if (shareMarketMatch && method === "PUT") {
    const id = shareMarketMatch[1];
    const body = await readJson<{ is_market?: boolean; market_title?: string | null; market_desc?: string | null }>(req);
    const existing = await env.db.prepare("SELECT id FROM shares WHERE id = ?1").bind(id).first();
    if (!existing) return json({ error: msg(req, "分享不存在", "Share not found") }, 404);
    const isMarket = body.is_market === undefined ? null : (body.is_market ? 1 : 0);
    const mTitle = typeof body.market_title === "string" ? (body.market_title.trim() || null) : null;
    const mDesc = typeof body.market_desc === "string" ? (body.market_desc.trim() || null) : null;
    // 动态拼 SQL，只更新传入的字段
    const sets: string[] = [];
    const binds: any[] = [];
    if (isMarket !== null) { sets.push("is_market = ?" + (binds.length + 1)); binds.push(isMarket); }
    if (body.market_title !== undefined) { sets.push("market_title = ?" + (binds.length + 1)); binds.push(mTitle); }
    if (body.market_desc !== undefined) { sets.push("market_desc = ?" + (binds.length + 1)); binds.push(mDesc); }
    if (sets.length === 0) return json({ ok: true });
    binds.push(id);
    await env.db.prepare(`UPDATE shares SET ${sets.join(", ")} WHERE id = ?${binds.length}`).bind(...binds).run();
    return json({ ok: true });
  }

  // ── 管理端市场列表 ──────────────────────────────────
  if (path === "/api/admin/market" && method === "GET") {
    const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
    const perPage = Math.min(100, Math.max(10, Number(url.searchParams.get("size")) || 20));
    const q = url.searchParams.get("q")?.trim();
    const filterOnly = url.searchParams.get("only") === "market" ? " AND s.is_market = 1" : "";
    const where = q
      ? ` AND (f.name LIKE ?1 OR COALESCE(s.market_title, '') LIKE ?1 OR COALESCE(s.market_desc, '') LIKE ?1)`
      : "";
    const base = `FROM shares s JOIN files f ON f.id = s.file_id WHERE s.revoked = 0${filterOnly}${where}`;
    const countRow: any = await env.db.prepare(`SELECT COUNT(*) AS c ${base}`).bind(...(q ? [`%${q}%`] : [])).first();
    const total = countRow?.c ?? 0;
    const { results }: any = await env.db.prepare(
      `SELECT s.id, s.file_id, s.created_at, s.download_count, s.is_market, s.market_views, s.market_title, s.market_desc,
              f.name AS file_name, f.size AS file_size
       ${base} ORDER BY s.created_at DESC LIMIT ?${q ? 2 : 1} OFFSET ?${q ? 3 : 2}`
    ).bind(...(q ? [`%${q}%`, perPage, (page - 1) * perPage] : [perPage, (page - 1) * perPage])).all();
    return json({ total, page, size: perPage, rows: results ?? [] });
  }

  // ── 下载记录（分页 + 筛选） ────────────────────────
  if (path === "/api/admin/logs" && method === "GET") {
    const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
    const perPage = Math.min(100, Math.max(10, Number(url.searchParams.get("per_page")) || 20));
    const q = url.searchParams.get("q")?.trim();
    const where: string[] = [];
    const binds: (string | number)[] = [];
    if (q) {
      where.push("(ip LIKE ?1 OR file_name LIKE ?1)");
      binds.push(`%${q}%`);
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const [total, rows] = await Promise.all([
      env.db.prepare(`SELECT COUNT(*) AS c FROM download_logs ${whereSql}`)
        .bind(...binds)
        .first<{ c: number }>(),
      env.db.prepare(
        `SELECT id, share_id, file_name, ip, browser, os, country, bytes, created_at
         FROM download_logs ${whereSql} ORDER BY id DESC LIMIT ?${binds.length + 1} OFFSET ?${binds.length + 2}`
      )
        .bind(...binds, perPage, (page - 1) * perPage)
        .all(),
    ]);
    return json({
      logs: rows.results ?? [],
      total: total?.c ?? 0,
      page,
      per_page: perPage,
      pages: Math.max(1, Math.ceil((total?.c ?? 0) / perPage)),
    });
  }

  // ── 清除记录（全部 / N 天前） ──────────────────────
  if (path === "/api/admin/logs" && method === "DELETE") {
    const mode = url.searchParams.get("mode") ?? "all";
    let sql: string;
    const binds: number[] = [];
    if (mode === "older") {
      const days = Math.max(1, Number(url.searchParams.get("days")) || 30);
      sql = "DELETE FROM download_logs WHERE created_at < ?1";
      binds.push(Date.now() - days * 86400_000);
    } else {
      sql = "DELETE FROM download_logs";
    }
    const r = await env.db.prepare(sql).bind(...binds).run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 错误日志（分页 + 筛选） ────────────────────────
  if (path === "/api/admin/errors" && method === "GET") {
    const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
    const perPage = Math.min(100, Math.max(10, Number(url.searchParams.get("per_page")) || 20));
    const q = url.searchParams.get("q")?.trim();
    const source = url.searchParams.get("source")?.trim();
    const where: string[] = [];
    const binds: (string | number)[] = [];
    let idx = 1;
    if (q) {
      where.push(`(message LIKE ?${idx} OR context LIKE ?${idx} OR path LIKE ?${idx})`);
      binds.push(`%${q}%`);
      idx++;
    }
    if (source) {
      where.push(`source = ?${idx}`);
      binds.push(source);
      idx++;
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const [total, rows] = await Promise.all([
      env.db.prepare(`SELECT COUNT(*) AS c FROM error_logs ${whereSql}`).bind(...binds).first<{ c: number }>(),
      env.db
        .prepare(
          `SELECT id, source, message, stack, path, url, line, col, browser, os, country, ip, context, created_at
           FROM error_logs ${whereSql} ORDER BY id DESC LIMIT ?${idx} OFFSET ?${idx + 1}`
        )
        .bind(...binds, perPage, (page - 1) * perPage)
        .all(),
    ]);
    // 统计：最近 24h 报错数（给前端做红色告警）
    const last24h = await env.db
      .prepare("SELECT COUNT(*) AS c FROM error_logs WHERE created_at >= ?1")
      .bind(Date.now() - 24 * 3600_000)
      .first<{ c: number }>();
    return json({
      errors: rows.results ?? [],
      total: total?.c ?? 0,
      page,
      per_page: perPage,
      pages: Math.max(1, Math.ceil((total?.c ?? 0) / perPage)),
      last_24h: last24h?.c ?? 0,
    });
  }

  // ── 清除错误日志（全部 / N 天前） ──────────────────
  if (path === "/api/admin/errors" && method === "DELETE") {
    const mode = url.searchParams.get("mode") ?? "all";
    let sql: string;
    const binds: number[] = [];
    if (mode === "older") {
      const days = Math.max(1, Number(url.searchParams.get("days")) || 30);
      sql = "DELETE FROM error_logs WHERE created_at < ?1";
      binds.push(Date.now() - days * 86400_000);
    } else {
      sql = "DELETE FROM error_logs";
    }
    const r = await env.db.prepare(sql).bind(...binds).run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 封禁列表 ──────────────────────────────────────
  if (path === "/api/admin/bans" && method === "GET") {
    const { results } = await env.db.prepare(
      "SELECT ip, reason, banned_at, expires_at FROM banned_ips ORDER BY banned_at DESC"
    ).all();
    return json({ bans: results ?? [] });
  }

  // ── 手动封禁 ──────────────────────────────────────
  if (path === "/api/admin/bans" && method === "POST") {
    const body = await readJson<{ ip: string; reason: string; hours: number | null }>(req);
    const ip = body.ip?.trim();
    if (!ip || !/^[0-9a-fA-F:.]{3,45}$/.test(ip)) return json({ error: msg(req, "IP 格式无效", "Invalid IP format") }, 400);
    const expiresAt = body.hours && body.hours > 0 ? Date.now() + body.hours * 3600_000 : null;
    await env.db.prepare(
      `INSERT INTO banned_ips(ip, reason, banned_at, expires_at) VALUES(?1, ?2, ?3, ?4)
       ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, banned_at = excluded.banned_at, expires_at = excluded.expires_at`
    )
      .bind(ip, body.reason?.slice(0, 200) || "管理员手动封禁", Date.now(), expiresAt)
      .run();
    return json({ ok: true }, 201);
  }

  // ── 解封 ──────────────────────────────────────────
  const banMatch = /^\/api\/admin\/bans\/([^/]+)$/.exec(path);
  if (banMatch && method === "DELETE") {
    await env.db.prepare("DELETE FROM banned_ips WHERE ip = ?1").bind(decodeURIComponent(banMatch[1])).run();
    return json({ ok: true });
  }

  // ── 登录安全日志（分页 + 筛选） ────────────────────────
  if (path === "/api/admin/login-logs" && method === "GET") {
    const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
    const perPage = Math.min(100, Math.max(10, Number(url.searchParams.get("per_page")) || 20));
    const q = url.searchParams.get("q")?.trim();
    const action = url.searchParams.get("action")?.trim();
    const result = url.searchParams.get("result")?.trim();
    const where: string[] = [];
    const binds: (string | number)[] = [];
    let idx = 1;
    if (q) {
      where.push(`(ip LIKE ?${idx} OR browser LIKE ?${idx} OR os LIKE ?${idx})`);
      binds.push(`%${q}%`);
      idx++;
    }
    if (action) {
      where.push(`action = ?${idx}`);
      binds.push(action);
      idx++;
    }
    if (result) {
      where.push(`result = ?${idx}`);
      binds.push(result);
      idx++;
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const [total, rows] = await Promise.all([
      env.db.prepare(`SELECT COUNT(*) AS c FROM login_logs ${whereSql}`).bind(...binds).first<{ c: number }>(),
      env.db
        .prepare(
          `SELECT id, action, ip, browser, os, country, result, reason, created_at
           FROM login_logs ${whereSql} ORDER BY id DESC LIMIT ?${idx} OFFSET ?${idx + 1}`
        )
        .bind(...binds, perPage, (page - 1) * perPage)
        .all(),
    ]);
    // 统计：最近 24h 登录失败次数
    const fail24h = await env.db
      .prepare(
        "SELECT COUNT(*) AS c FROM login_logs WHERE action = 'login' AND result = 'fail' AND created_at >= ?1"
      )
      .bind(Date.now() - 24 * 3600_000)
      .first<{ c: number }>();
    return json({
      logs: rows.results ?? [],
      total: total?.c ?? 0,
      page,
      per_page: perPage,
      pages: Math.max(1, Math.ceil((total?.c ?? 0) / perPage)),
      fail_last_24h: fail24h?.c ?? 0,
    });
  }

  // ── 清除登录日志（全部 / N 天前） ──────────────────────
  if (path === "/api/admin/login-logs" && method === "DELETE") {
    const mode = url.searchParams.get("mode") ?? "all";
    let sql: string;
    const binds: number[] = [];
    if (mode === "older") {
      const days = Math.max(1, Number(url.searchParams.get("days")) || 30);
      sql = "DELETE FROM login_logs WHERE created_at < ?1";
      binds.push(Date.now() - days * 86400_000);
    } else {
      sql = "DELETE FROM login_logs";
    }
    const r = await env.db.prepare(sql).bind(...binds).run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 2FA 状态查询 ───────────────────────────────────
  if (path === "/api/admin/2fa/status" && method === "GET") {
    const s = await getSettings(env);
    return json({
      enabled: s.totpEnabled && !!s.totpSecretCipher,
      cloudflare_recovery: !!env.totp_recovery,
      recovery_remaining: s.totpRecoveryHash ? s.totpRecoveryHash.split(",").filter(Boolean).length : 0,
    });
  }

  // ── 2FA Setup：生成新 secret（未启用，需要 verify+enable 才生效） ──
  if (path === "/api/admin/2fa/setup" && method === "POST") {
    const body = await readJson<{ admin_key: string }>(req);
    if (!body.admin_key || !checkAdminKey(env, body.admin_key)) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    // 如果已经启用，需要先 disable 再 setup（或者覆盖）
    const secret = totpGenerateSecret();
    const s = await getSettings(env);
    const siteTitle = s.siteTitle || "cloud-r2pan";
    const uri = totpUri(secret, siteTitle, "admin");
    return json({
      secret, // 仅本次返回，前端展示二维码用
      uri,
    });
  }

  // ── 2FA Enable：验证通过后写入 settings（加密存储）并生成恢复码 ──
  if (path === "/api/admin/2fa/enable" && method === "POST") {
    const body = await readJson<{ admin_key: string; code: string; secret: string }>(req);
    if (!body.admin_key || !checkAdminKey(env, body.admin_key)) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    if (!/^[A-Z2-7]{16,}$/.test((body.secret || "").toUpperCase())) {
      return json({ error: msg(req, "Secret 格式无效", "Invalid secret format") }, 400);
    }
    const code = (body.code || "").trim();
    if (!/^\d{6}$/.test(code)) {
      return json({ error: msg(req, "请输入 6 位验证码", "Please enter 6-digit code") }, 400);
    }
    const secret = body.secret!.toUpperCase();
    const ok = await totpVerify(secret, code);
    if (!ok) {
      return json({ error: msg(req, "验证码错误", "Invalid verification code") }, 401);
    }
    // 验证通过 → 加密存 secret + 生成恢复码
    const cipher = await encryptSecret(secret, env.admin);
    const recoveryCodes = totpGenerateRecoveryCodes(8);
    const recoveryHash = (await Promise.all(recoveryCodes.map((c) => sha256Hex(c.replace(/\s+/g, ""))))).join(",");
    await updateSettings(env, {
      totp_enabled: "1",
      totp_secret_cipher: cipher,
      totp_recovery_hash: recoveryHash,
    });
    return json({
      ok: true,
      recovery_codes: recoveryCodes, // 只这一次明文返回，前端提示用户保存
    });
  }

  // ── 2FA Disable：关闭 2FA（需验证 admin key） ──
  if (path === "/api/admin/2fa/disable" && method === "POST") {
    const body = await readJson<{ admin_key: string }>(req);
    if (!body.admin_key || !checkAdminKey(env, body.admin_key)) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    await updateSettings(env, {
      totp_enabled: "0",
      totp_secret_cipher: "",
      totp_recovery_hash: "",
    });
    return json({ ok: true });
  }

  // ── 重新生成恢复码（覆盖旧的，旧的全部失效） ──
  if (path === "/api/admin/2fa/regen-recovery" && method === "POST") {
    const body = await readJson<{ admin_key: string }>(req);
    if (!body.admin_key || !checkAdminKey(env, body.admin_key)) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    const s = await getSettings(env);
    if (!s.totpEnabled || !s.totpSecretCipher) {
      return json({ error: msg(req, "2FA 未启用", "2FA is not enabled") }, 400);
    }
    const recoveryCodes = totpGenerateRecoveryCodes(8);
    const recoveryHash = (await Promise.all(recoveryCodes.map((c) => sha256Hex(c.replace(/\s+/g, ""))))).join(",");
    await updateSettings(env, { totp_recovery_hash: recoveryHash });
    return json({ ok: true, recovery_codes: recoveryCodes });
  }

  // ══════════════════════════════════════════════════════
  // 直链（Direct Link）CRUD —— 与分享链接完全独立
  //   POST   /api/admin/direct-links            创建
  //   GET    /api/admin/direct-links            列表
  //   GET    /api/admin/direct-links/:id        详情
  //   PUT    /api/admin/direct-links/:id        更新（过期/次数/撤销/备注）
  //   DELETE /api/admin/direct-links/:id        删除
  // ══════════════════════════════════════════════════════

  // ── 创建直链 ──
  if (path === "/api/admin/direct-links" && method === "POST") {
    const body = await readJson<{
      file_id: string;
      expires_hours: number | null;
      max_downloads: number | null;
      download_name?: string | null;
      notes?: string | null;
    }>(req);
    if (!body.file_id) return json({ error: msg(req, "缺少 file_id", "Missing file_id") }, 400);
    const file = await env.db.prepare("SELECT id, name FROM files WHERE id = ?1").bind(body.file_id).first<{ id: string; name: string }>();
    if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
    const expiresAt =
      body.expires_hours && body.expires_hours > 0 ? Date.now() + body.expires_hours * 3600_000 : null;
    const maxDownloads =
      body.max_downloads && body.max_downloads > 0 ? Math.floor(body.max_downloads) : null;
    const downloadName =
      typeof body.download_name === "string" && body.download_name.trim() ? body.download_name.trim() : null;
    const notes =
      typeof body.notes === "string" && body.notes.trim() ? body.notes.trim().slice(0, 200) : null;
    const id = randomId(12);
    await env.db.prepare(
      `INSERT INTO direct_links(id, file_id, created_at, expires_at, max_downloads, download_name, notes)
       VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)`
    )
      .bind(id, body.file_id, Date.now(), expiresAt, maxDownloads, downloadName, notes)
      .run();
    return json({ ok: true, id, url: buildDirectUrl(id, file.name, downloadName) }, 201);
  }

  // ── 直链列表 ──
  if (path === "/api/admin/direct-links" && method === "GET") {
    const q = new URL(req.url).searchParams.get("q")?.trim();
    const where = q
      ? ` AND (f.name LIKE ?1 OR COALESCE(dl.notes,'') LIKE ?1)`
      : "";
    const bindVals = q ? [`%${q}%`] : [];
    const { results } = await env.db
      .prepare(
        `SELECT dl.id, dl.file_id, dl.created_at, dl.expires_at, dl.max_downloads, dl.download_count, dl.revoked,
                dl.download_name, dl.notes,
                f.name AS file_name, f.size AS file_size, f.mime AS file_mime
         FROM direct_links dl JOIN files f ON f.id = dl.file_id
         WHERE 1=1 ${where}
         ORDER BY dl.created_at DESC`
      )
      .all();
    const now = Date.now();
    const list = (results ?? []).map((dl: any) => ({
      ...dl,
      url: buildDirectUrl(dl.id, dl.file_name, dl.download_name),
      status: dl.revoked
        ? "revoked"
        : dl.expires_at && dl.expires_at < now
          ? "expired"
          : dl.max_downloads && dl.download_count >= dl.max_downloads
            ? "maxed"
            : "active",
    }));
    return json({ direct_links: list });
  }

  // ── 直链详情 / 更新 / 删除 ──
  const dlMatch = /^\/api\/admin\/direct-links\/([^/]+)$/.exec(path);
  if (dlMatch) {
    const dlId = dlMatch[1];

    if (method === "GET") {
      const row = await env.db
        .prepare(
          `SELECT dl.*, f.name AS file_name, f.size AS file_size, f.mime AS file_mime
           FROM direct_links dl JOIN files f ON f.id = dl.file_id
           WHERE dl.id = ?1`
        )
        .bind(dlId)
        .first();
      if (!row) return json({ error: msg(req, "直链不存在", "Direct link not found") }, 404);
      return json({ ...row, url: buildDirectUrl((row as any).id, (row as any).file_name, (row as any).download_name) });
    }

    if (method === "PUT") {
      const body = await readJson<{
        expires_hours?: number | null;
        max_downloads?: number | null;
        download_name?: string | null;
        notes?: string | null;
        revoked?: boolean;
      }>(req);
      const row: any = await env.db.prepare("SELECT id FROM direct_links WHERE id = ?1").bind(dlId).first();
      if (!row) return json({ error: msg(req, "直链不存在", "Direct link not found") }, 404);

      const sets: string[] = [];
      const vals: any[] = [];

      if (body.expires_hours !== undefined) {
        const exp = body.expires_hours && body.expires_hours > 0
          ? Date.now() + body.expires_hours * 3600_000
          : null;
        sets.push("expires_at = ?" + (vals.length + 1));
        vals.push(exp);
      }
      if (body.max_downloads !== undefined) {
        const m = body.max_downloads && body.max_downloads > 0 ? Math.floor(body.max_downloads) : null;
        sets.push("max_downloads = ?" + (vals.length + 1));
        vals.push(m);
      }
      if (body.download_name !== undefined) {
        const v = typeof body.download_name === "string" && body.download_name.trim()
          ? body.download_name.trim()
          : null;
        sets.push("download_name = ?" + (vals.length + 1));
        vals.push(v);
      }
      if (body.notes !== undefined) {
        const v = typeof body.notes === "string" && body.notes.trim()
          ? body.notes.trim().slice(0, 200)
          : null;
        sets.push("notes = ?" + (vals.length + 1));
        vals.push(v);
      }
      if (typeof body.revoked === "boolean") {
        sets.push("revoked = ?" + (vals.length + 1));
        vals.push(body.revoked ? 1 : 0);
      }

      if (sets.length > 0) {
        vals.push(dlId);
        await env.db.prepare(
          `UPDATE direct_links SET ${sets.join(", ")} WHERE id = ?${vals.length}`
        ).bind(...vals).run();
      }
      return json({ ok: true });
    }

    if (method === "DELETE") {
      // 先查出关联的 file_id 用于清理孤儿
      const before: any = await env.db.prepare("SELECT file_id FROM direct_links WHERE id = ?1").bind(dlId).first();
      const r = await env.db.prepare("DELETE FROM direct_links WHERE id = ?1").bind(dlId).run();
      if ((r.meta.changes ?? 0) === 0) return json({ error: msg(req, "直链不存在", "Direct link not found") }, 404);
      // 清理孤儿：如果该 file_id 不再被任何 shares 或 direct_links 引用，不自动删（管理员可手动清理）
      void before;
      return json({ ok: true });
    }
  }

  // ── 清理失效直链 ──
  if (path === "/api/admin/direct-links/cleanup" && method === "POST") {
    const now = Date.now();
    const r = await env.db.prepare(
      `DELETE FROM direct_links WHERE revoked = 1
        OR (expires_at IS NOT NULL AND expires_at < ?1)
        OR (max_downloads IS NOT NULL AND download_count >= max_downloads)`
    ).bind(now).run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 读取设置 ──────────────────────────────────────
  if (path === "/api/admin/settings" && method === "GET") {
    const s = await getSettings(env);
    // 读 OAuth2 providers 列表给前端展示卡片
    const providers = await env.db
      .prepare("SELECT id, label, provider_type, client_id, scope, enabled, updated_at FROM oauth_providers ORDER BY updated_at DESC")
      .all<{ id: string; label: string; provider_type: string; client_id: string; scope: string; enabled: number; updated_at: number }>();
    const enabledProviders = providers.results.filter((p) => p.enabled);
    return json({
      site_title: s.siteTitle,
      traffic_limit_gb: s.trafficLimitBytes / 1024 ** 3,
      max_downloads_per_ip: s.maxDownloadsPerIp,
      preview_limit: s.previewLimit,
      preview_used: s.previewUsed,
      count_window_hours: s.countWindowHours,
      auto_ban: s.autoBan,
      ban_hours: s.banHours,
      traffic_used_bytes: s.trafficUsedBytes,
      // Turnstile
      turnstile_mode: s.turnstileMode,
      turnstile_threshold: s.turnstileThreshold,
      turnstile_sitekey_override: s.turnstileSitekeyOverride,
      cloudflare_turnstile_sitekey: !!env.turnstile_sitekey,
      cloudflare_turnstile_secret: !!env.turnstile_secret,
      turnstile_secret_configured: !!s.turnstileSecretCipher,
      // OAuth2 总开关 + providers 概要
      oauth_enabled: s.oauthEnabled,
      oauth_providers: providers.results.map((p) => ({
        id: p.id,
        label: p.label,
        provider_type: p.provider_type,
        client_id: p.client_id,
        scope: p.scope,
        enabled: !!p.enabled,
        secret_configured: true, // 列表里不暴露 secret 是否配，只在详情里展示
      })),
      oauth_has_enabled_providers: enabledProviders.length > 0,
      // IP 白名单
      admin_ips: s.adminIps,
      // 下载市场首页
      home_redirect_market: s.homeRedirectMarket,
      // 激活码浮动按钮
      codes_floating_button_enabled: s.codesFloatingButtonEnabled,
      codes_floating_button_position: s.codesFloatingButtonPosition,
      // 存储后端
      storage_provider: s.storageProvider || "r2",
      storage_has_r2: !!env.r2,
      s3_endpoint: s.s3Endpoint,
      s3_region: s.s3Region,
      s3_bucket: s.s3Bucket,
      s3_access_key_id: s.s3AccessKeyId,
      s3_addressing_style: s.s3AddressingStyle || "path",
      s3_secret_configured: !!s.s3SecretKeyCipher,
      // 远程 WebDAV 挂载（出站）
      storage_webdav_url: s.storageWebdavUrl,
      storage_webdav_username: s.storageWebdavUsername,
      storage_webdav_password_configured: !!s.storageWebdavPasswordCipher,
      // Analytics Engine
      analytics_engine_available: !!env.analytics,
      // UI 主题
      ui_theme: s.uiTheme,
      // 后台标签页自定义
      admin_tab_config: s.adminTabConfig,
      // WebDAV
      webdav_enabled: s.webdavEnabled,
      webdav_username: s.webdavUsername,
      webdav_root_path: s.webdavRootPath,
      webdav_password_configured: !!s.webdavPasswordHash,
    });
  }

  // ── 更新设置（可调常数） ──────────────────────────
  if (path === "/api/admin/settings" && method === "PUT") {
    const body = await readJson<Record<string, unknown>>(req);
    const patch: Record<string, string> = {};
    if (typeof body.site_title === "string" && body.site_title.trim())
      patch.site_title = body.site_title.trim().slice(0, 50);
    const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : null);
    const gb = num(body.traffic_limit_gb);
    if (gb !== null) patch.traffic_limit_bytes = String(Math.round(gb * 1024 ** 3));
    const perIp = num(body.max_downloads_per_ip);
    if (perIp !== null) patch.max_downloads_per_ip = String(Math.floor(perIp));
    const previewLimit = num(body.preview_limit);
    if (previewLimit !== null) patch.preview_limit = String(Math.floor(previewLimit));
    const window = num(body.count_window_hours);
    if (window !== null) patch.count_window_hours = String(Math.floor(window));
    const banHours = num(body.ban_hours);
    if (banHours !== null) patch.ban_hours = String(Math.floor(banHours));
    if (typeof body.auto_ban === "boolean") patch.auto_ban = body.auto_ban ? "1" : "0";
    // Turnstile
    if (typeof body.turnstile_mode === "string") {
      const m = body.turnstile_mode as string;
      if (["off", "on_share", "on_download", "both"].includes(m)) {
        patch.turnstile_mode = m;
      }
    }
    const th = num(body.turnstile_threshold);
    if (th !== null) patch.turnstile_threshold = String(Math.floor(th));
    if (typeof body.turnstile_sitekey_override === "string") {
      // 允许清空
      patch.turnstile_sitekey_override = body.turnstile_sitekey_override.trim();
    }
    // Turnstile Secret —— 如果 Modal 里传了新密码则加密存；空字符串则清掉；__keep__ 表示保留
    if (typeof body.turnstile_secret === "string") {
      const raw = body.turnstile_secret.trim();
      if (raw === "") {
        patch.turnstile_secret_cipher = "";
      } else if (raw !== "__keep__") {
        const cipher = await encryptSecret(raw, env.admin);
        if (cipher) patch.turnstile_secret_cipher = cipher;
      }
      // raw === "__keep__" 或不传 → 保留原值不动
    }
    // OAuth2 总开关（具体 provider 配置由 /api/admin/oauth/providers CRUD 管理）
    if (typeof body.oauth_enabled === "boolean") patch.oauth_enabled = body.oauth_enabled ? "1" : "0";

    // 管理员 IP 白名单
    if (typeof body.admin_ips === "string") {
      patch.admin_ips = body.admin_ips.trim();
    }

    // 下载市场作为首页
    if (typeof body.home_redirect_market === "boolean") {
      patch.home_redirect_market = body.home_redirect_market ? "1" : "0";
    }

    // 激活码浮动按钮
    if (typeof body.codes_floating_button_enabled === "boolean") {
      patch.codes_floating_button_enabled = body.codes_floating_button_enabled ? "1" : "0";
    }
    if (typeof body.codes_floating_button_position === "string") {
      const pos = body.codes_floating_button_position;
      if (pos === "top-right" || pos === "top-left") {
        patch.codes_floating_button_position = pos;
      }
    }

    // ── 存储后端 ──
    if (typeof body.storage_provider === "string") {
      const sp = body.storage_provider;
      if (sp === "r2" || sp === "s3" || sp === "webdav") {
        patch.storage_provider = sp;
      }
    }
    if (typeof body.s3_endpoint === "string") patch.s3_endpoint = body.s3_endpoint.trim();
    if (typeof body.s3_region === "string") patch.s3_region = body.s3_region.trim();
    if (typeof body.s3_bucket === "string") patch.s3_bucket = body.s3_bucket.trim();
    if (typeof body.s3_access_key_id === "string") patch.s3_access_key_id = body.s3_access_key_id.trim();
    if (typeof body.s3_addressing_style === "string") {
      const style = body.s3_addressing_style;
      if (style === "path" || style === "virtual") patch.s3_addressing_style = style;
    }
    // S3 Secret Access Key —— 和 turnstile_secret 同样的三种处理模式
    if (typeof body.s3_secret_key === "string") {
      const raw = body.s3_secret_key.trim();
      if (raw === "") {
        patch.s3_secret_key_cipher = "";
      } else if (raw !== "__keep__") {
        const cipher = await encryptSecret(raw, env.admin);
        if (cipher) patch.s3_secret_key_cipher = cipher;
      }
      // raw === "__keep__" 或不传 → 保留原值不动
    }
    // 远程 WebDAV 挂载
    if (typeof body.storage_webdav_url === "string") patch.storage_webdav_url = body.storage_webdav_url.trim().replace(/\/+$/, "");
    if (typeof body.storage_webdav_username === "string") patch.storage_webdav_username = body.storage_webdav_username.trim();
    if (typeof body.storage_webdav_password === "string") {
      const raw = body.storage_webdav_password;
      if (raw === "") {
        patch.storage_webdav_password_cipher = "";
      } else if (raw !== "__keep__") {
        const cipher = await encryptSecret(raw, env.admin);
        if (cipher) patch.storage_webdav_password_cipher = cipher;
      }
    }

    // UI 主题
    if (typeof body.ui_theme === "string") {
      const t = body.ui_theme;
      if (t === "light" || t === "dark") {
        patch.ui_theme = t;
      }
    }

    // 后台标签页自定义 —— 必须是合法 JSON 且含 groups 数组，否则拒绝
    if (typeof body.admin_tab_config === "string") {
      const raw = body.admin_tab_config.trim();
      if (raw === "") {
        patch.admin_tab_config = "";
      } else {
        let parsed: unknown = null;
        try {
          parsed = JSON.parse(raw);
        } catch {
          return json({ error: msg(req, "标签配置不是合法的 JSON", "Tab config is not valid JSON") }, 400);
        }
        const groups = (parsed as { groups?: unknown } | null)?.groups;
        if (!Array.isArray(groups)) {
          return json({ error: msg(req, "标签配置缺少 groups 数组", "Tab config must contain a groups array") }, 400);
        }
        patch.admin_tab_config = raw.slice(0, 20000);
      }
    }

    // ── WebDAV ──
    if (typeof body.webdav_enabled === "boolean") patch.webdav_enabled = body.webdav_enabled ? "1" : "0";
    if (typeof body.webdav_username === "string") {
      const u = body.webdav_username.trim();
      if (u) patch.webdav_username = u.slice(0, 64);
    }
    if (typeof body.webdav_root_path === "string") {
      const rp = body.webdav_root_path.trim();
      patch.webdav_root_path = rp.startsWith("/") ? rp : "/" + rp;
    }
    // WebDAV 密码：空字符串 = 清除；"__keep__" 或不传 = 保留；其他 = 重新 hash
    if (typeof body.webdav_password === "string") {
      const raw = body.webdav_password;
      if (raw === "") {
        patch.webdav_password_hash = "";
      } else if (raw !== "__keep__") {
        patch.webdav_password_hash = await hashPassword(raw);
      }
    }

    await updateSettings(env, patch);
    // storage 配置变了，清掉缓存的 storage provider 让下次请求用新配置
    _storagePromise = null;
    return json({ ok: true });
  }

  // ── 清空 Turnstile 访问计数 ────────────────────────
  if (path === "/api/admin/turnstile/visits" && method === "DELETE") {
    const days = Number(new URL(req.url).searchParams.get("days"));
    const before = days > 0 ? new Date(Date.now() - days * 86400_000).toISOString().slice(0, 10) : null;
    const r = before
      ? await env.db.prepare("DELETE FROM turnstile_visits WHERE day < ?1").bind(before).run()
      : await env.db.prepare("DELETE FROM turnstile_visits").run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 重置本月流量 ──────────────────────────────────
  if (path === "/api/admin/traffic/reset" && method === "POST") {
    await updateSettings(env, {
      traffic_used_bytes: "0",
      traffic_month: new Date().toISOString().slice(0, 7),
    });
    return json({ ok: true });
  }

  // ══════════════════════════════════════════════════════
  // OAuth2 Provider CRUD —— 多 Provider 管理
  //   GET    /api/admin/oauth/providers             列表
  //   POST   /api/admin/oauth/providers             创建
  //   GET    /api/admin/oauth/providers/:id          详情
  //   PUT    /api/admin/oauth/providers/:id          更新
  //   DELETE /api/admin/oauth/providers/:id          删除
  //   POST   /api/admin/oauth/providers/:id/toggle   启用/禁用
  // ══════════════════════════════════════════════════════

  const oauthProvidersPath = "/api/admin/oauth/providers";
  const m = path.match(/^\/api\/admin\/oauth\/providers\/([^/]+)(\/(toggle))?$/);

  // GET /api/admin/oauth/providers —— 列表（返回不含 secret 的安全摘要）
  if (path === oauthProvidersPath && method === "GET") {
    const rows = await env.db
      .prepare("SELECT id, label, provider_type, client_id, scope, custom_authorize_url, custom_token_url, custom_userinfo_url, custom_token_field, enabled, client_secret_cipher IS NOT NULL as has_secret, created_at, updated_at FROM oauth_providers ORDER BY updated_at DESC")
      .all<{ id: string; label: string; provider_type: string; client_id: string; scope: string; custom_authorize_url: string; custom_token_url: string; custom_userinfo_url: string; custom_token_field: string; enabled: number; has_secret: number; created_at: number; updated_at: number }>();
    return json({
      providers: rows.results.map((p) => ({
        id: p.id,
        label: p.label,
        provider_type: p.provider_type,
        client_id: p.client_id,
        scope: p.scope,
        custom_authorize_url: p.custom_authorize_url,
        custom_token_url: p.custom_token_url,
        custom_userinfo_url: p.custom_userinfo_url,
        custom_token_field: p.custom_token_field,
        enabled: !!p.enabled,
        secret_configured: !!p.has_secret,
        created_at: p.created_at,
        updated_at: p.updated_at,
      })),
    });
  }

  // POST /api/admin/oauth/providers —— 创建
  if (path === oauthProvidersPath && method === "POST") {
    const body = await readJson<{
      label?: string;
      provider_type?: string;
      client_id?: string;
      client_secret?: string;
      scope?: string;
      custom_authorize_url?: string;
      custom_token_url?: string;
      custom_userinfo_url?: string;
      custom_token_field?: string;
      enabled?: boolean;
    }>(req);
    const validTypes = ["github", "google", "microsoft", "discord", "custom"];
    const providerType = (body.provider_type && validTypes.includes(body.provider_type))
      ? body.provider_type
      : "github";
    const label = (body.label || providerType).trim().slice(0, 40);
    const clientId = (body.client_id || "").trim();
    if (!clientId) return json({ error: "client_id_required" }, 400);
    const scope = (body.scope || "").trim() || "openid email profile";
    const now = Date.now();
    const id = randomId();
    let secretCipher: string | null = null;
    if (body.client_secret && body.client_secret.trim()) {
      secretCipher = await encryptSecret(body.client_secret.trim(), env.admin);
      if (!secretCipher) return json({ error: "secret_encrypt_failed" }, 500);
    }
    await env.db
      .prepare(
        `INSERT INTO oauth_providers(id, label, provider_type, client_id, client_secret_cipher, scope,
            custom_authorize_url, custom_token_url, custom_userinfo_url, custom_token_field,
            enabled, created_at, updated_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)`
      )
      .bind(
        id,
        label,
        providerType,
        clientId,
        secretCipher,
        scope,
        (body.custom_authorize_url || "").trim(),
        (body.custom_token_url || "").trim(),
        (body.custom_userinfo_url || "").trim(),
        (body.custom_token_field || "access_token").trim(),
        body.enabled === false ? 0 : 1,
        now,
        now
      )
      .run();
    return json({ ok: true, id });
  }

  // PUT /api/admin/oauth/providers/:id —— 更新
  if (m && !m[3] && method === "PUT") {
    const id = m[1];
    const row = await env.db
      .prepare("SELECT * FROM oauth_providers WHERE id = ?1")
      .bind(id)
      .first<Record<string, unknown>>();
    if (!row) return json({ error: "not_found" }, 404);
    const body = await readJson<{
      label?: string;
      provider_type?: string;
      client_id?: string;
      client_secret?: string; // 非空=更新；空字符串=清除；不传=保留
      scope?: string;
      custom_authorize_url?: string;
      custom_token_url?: string;
      custom_userinfo_url?: string;
      custom_token_field?: string;
      enabled?: boolean;
    }>(req);

    const now = Date.now();
    const updates: string[] = ["updated_at = ?1"];
    const values: unknown[] = [now];

    if (typeof body.label === "string" && body.label.trim()) {
      updates.push("label = ?" + (values.length + 1));
      values.push(body.label.trim().slice(0, 40));
    }
    if (typeof body.provider_type === "string") {
      const valid = ["github", "google", "microsoft", "discord", "custom"];
      if (valid.includes(body.provider_type)) {
        updates.push("provider_type = ?" + (values.length + 1));
        values.push(body.provider_type);
      }
    }
    if (typeof body.client_id === "string") {
      updates.push("client_id = ?" + (values.length + 1));
      values.push(body.client_id.trim());
    }
    if (typeof body.scope === "string") {
      updates.push("scope = ?" + (values.length + 1));
      values.push(body.scope.trim());
    }
    if (typeof body.custom_authorize_url === "string") {
      updates.push("custom_authorize_url = ?" + (values.length + 1));
      values.push(body.custom_authorize_url.trim());
    }
    if (typeof body.custom_token_url === "string") {
      updates.push("custom_token_url = ?" + (values.length + 1));
      values.push(body.custom_token_url.trim());
    }
    if (typeof body.custom_userinfo_url === "string") {
      updates.push("custom_userinfo_url = ?" + (values.length + 1));
      values.push(body.custom_userinfo_url.trim());
    }
    if (typeof body.custom_token_field === "string" && body.custom_token_field.trim()) {
      updates.push("custom_token_field = ?" + (values.length + 1));
      values.push(body.custom_token_field.trim());
    }
    if (typeof body.enabled === "boolean") {
      updates.push("enabled = ?" + (values.length + 1));
      values.push(body.enabled ? 1 : 0);
    }
    // Client secret：三种处理模式
    if (typeof body.client_secret === "string") {
      if (body.client_secret === "") {
        // 显式清除
        updates.push("client_secret_cipher = NULL");
      } else if (body.client_secret.trim() !== "__keep__") {
        // 更新为新密码
        const cipher = await encryptSecret(body.client_secret.trim(), env.admin);
        if (!cipher) return json({ error: "secret_encrypt_failed" }, 500);
        updates.push("client_secret_cipher = ?" + (values.length + 1));
        values.push(cipher);
      }
      // 其他情况（undefined 或 __keep__）：保留原值不动
    }

    values.push(id);
    const sql = `UPDATE oauth_providers SET ${updates.join(", ")} WHERE id = ?${values.length}`;
    await env.db.prepare(sql).bind(...values).run();
    return json({ ok: true });
  }

  // DELETE /api/admin/oauth/providers/:id
  if (m && !m[3] && method === "DELETE") {
    const id = m[1];
    await env.db.prepare("DELETE FROM oauth_providers WHERE id = ?1").bind(id).run();
    return json({ ok: true });
  }

  // POST /api/admin/oauth/providers/:id/toggle —— 切换启用/禁用
  if (m && m[3] === "toggle" && method === "POST") {
    const id = m[1];
    await env.db
      .prepare("UPDATE oauth_providers SET enabled = 1 - enabled, updated_at = ?1 WHERE id = ?2")
      .bind(Date.now(), id)
      .run();
    return json({ ok: true });
  }

  // ─═════════════════════════════════════════════════════════════════
  // 激活码管理
  // ─═════════════════════════════════════════════════════════════════

  // POST /api/admin/codes/generate — 批量生成
  // body: { plan_name, traffic_bytes, days_valid, count, quota_message?, batch_id?, notes? }
  if (path === "/api/admin/codes/generate" && method === "POST") {
    const body = await readJson<{
      plan_name?: string;
      traffic_bytes?: number;
      days_valid?: number;
      count?: number;
      quota_message?: string;
      batch_id?: string;
      notes?: string;
    }>(req);
    const count = Math.max(1, Math.min(10000, Number(body.count) || 100));
    const traffic = Math.max(0, Number(body.traffic_bytes) || 0);
    const days = Math.max(0, Number(body.days_valid) || 0);
    if (traffic === 0 && days === 0) {
      return json({ error: msg(req, "至少设置流量额度或有效天数之一", "Set at least traffic OR days_valid") }, 400);
    }

    const batchIdRaw = (body.batch_id ?? "").trim();
    const batchId = batchIdRaw ? batchIdRaw : makeBatchId();
    const now = Date.now();
    const ids = generateCodes(count);

    // 用 batch 高效插入
    const stmts = ids.map((code) =>
      env.db
        .prepare(
          `INSERT INTO activation_codes
           (id, code, plan_id, traffic_bytes, used_bytes, days_valid, quota_message, status, batch_id, notes, created_at, activated_at, expires_at)
           VALUES(?1, ?2, ?3, ?4, 0, ?5, ?6, 'unused', ?7, ?8, ?9, NULL, NULL)`
        )
        .bind(
          randomId(12),
          code,
          body.plan_name || null,
          traffic,
          days,
          (typeof body.quota_message === "string" && body.quota_message.trim()) || null,
          batchId,
          (typeof body.notes === "string" && body.notes.trim()) || null,
          now
        )
    );
    await env.db.batch(stmts);
    return json({ ok: true, batch_id: batchId, count, codes: ids.slice(0, 50) });
  }

  // GET /api/admin/codes — 列表（支持 ?status=&batch_id=&plan=&page=&export=1）
  if (path === "/api/admin/codes" && method === "GET") {
    const sp = new URL(req.url).searchParams;
    const status = sp.get("status");
    const batchId = sp.get("batch_id");
    const plan = sp.get("plan");
    const q = sp.get("q");
    const exportCsv = sp.get("export") === "1";
    const page = Math.max(1, Number(sp.get("page")) || 1);
    const pageSize = Math.min(500, Math.max(10, Number(sp.get("size")) || 50));
    const offset = (page - 1) * pageSize;

    const where: string[] = [];
    const binds: any[] = [];
    // effective_status 表达式：revoked 优先，然后动态 expired/exhausted，否则取原始 status
    const effectiveStatusExpr = `CASE WHEN status = 'revoked' THEN 'revoked'
      WHEN expires_at IS NOT NULL AND expires_at < ? THEN 'expired'
      WHEN traffic_bytes > 0 AND used_bytes >= traffic_bytes THEN 'exhausted'
      ELSE status END`;
    const now = Date.now();
    if (status) { where.push(`(${effectiveStatusExpr}) = ?`); binds.push(now, status); }
    if (batchId) { where.push("batch_id = ?"); binds.push(batchId); }
    if (plan) { where.push("plan_id = ?"); binds.push(plan); }
    if (q) { where.push("(code LIKE ? OR notes LIKE ?)"); binds.push(`%${q}%`, `%${q}%`); }

    const whereSql = where.length ? "WHERE " + where.join(" AND ") : "";
    const countSql = `SELECT COUNT(*) AS c FROM activation_codes ${whereSql}`;
    const listSql = `SELECT * FROM activation_codes ${whereSql} ORDER BY created_at DESC LIMIT ? OFFSET ?`;

    const total = (await env.db.prepare(countSql).bind(...binds).first<{ c: number }>())?.c ?? 0;
    const results = (await env.db.prepare(listSql).bind(...binds, pageSize, offset).all()).results as any[];

    const rows = results.map((r) => {
      const status = formatCodeStatus(r);
      // 计算 effective status：在 DB status 基础上，叠加动态过期/耗尽判断
      let effectiveStatus: string = r.status;
      if (r.status !== "revoked") {
        if (r.expires_at && r.expires_at < now) effectiveStatus = "expired";
        else if (r.traffic_bytes > 0 && r.used_bytes >= r.traffic_bytes) effectiveStatus = "exhausted";
      }
      return {
        id: r.id,
        code: r.code,
        plan_id: r.plan_id,
        batch_id: r.batch_id,
        notes: r.notes,
        traffic_bytes: r.traffic_bytes,
        used_bytes: r.used_bytes,
        days_valid: r.days_valid,
        quota_message: r.quota_message,
        status: effectiveStatus,
        remaining: status?.remaining,
        pct: status?.pct,
        expired: status?.expired,
        created_at: r.created_at,
        activated_at: r.activated_at,
        expires_at: r.expires_at,
      };
    });

    if (exportCsv) {
      const csvRows = [
        "code,plan_id,batch_id,traffic_bytes,used_bytes,days_valid,status,quota_message,notes,created_at,activated_at,expires_at",
      ];
      const allResults = (await env.db.prepare(`SELECT * FROM activation_codes ${whereSql} ORDER BY created_at DESC`).bind(...binds).all()).results as any[];
      for (const r of allResults) {
        const esc = (v: any) => {
          if (v == null) return "";
          const s = String(v).replace(/"/g, '""');
          return /[",\n]/.test(s) ? `"${s}"` : s;
        };
        csvRows.push(
          [r.code, r.plan_id ?? "", r.batch_id ?? "", r.traffic_bytes, r.used_bytes, r.days_valid, r.status, esc(r.quota_message), esc(r.notes), r.created_at ?? "", r.activated_at ?? "", r.expires_at ?? ""].join(",")
        );
      }
      const body = csvRows.join("\n");
      const filename = `activation_codes_${new Date().toISOString().slice(0, 10)}.csv`;
      return new Response(body, {
        status: 200,
        headers: {
          "content-type": "text/csv;charset=utf-8",
          "content-disposition": `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`,
        },
      });
    }

    return json({ rows, total, page, page_size: pageSize });
  }

  // POST /api/admin/codes/:id/revoke — 作废一个码
  const codeRevokeMatch = /^\/api\/admin\/codes\/([^/]+)\/revoke$/.exec(path);
  if (codeRevokeMatch && method === "POST") {
    await env.db.prepare("UPDATE activation_codes SET status = 'revoked' WHERE id = ?1 AND status != 'revoked'").bind(codeRevokeMatch![1]).run();
    return json({ ok: true });
  }

  // POST /api/admin/codes/batch-revoke — 按 batch_id 整批作废
  if (path === "/api/admin/codes/batch-revoke" && method === "POST") {
    const body = await readJson<{ batch_id?: string; codes?: string[] }>(req);
    if (body.batch_id) {
      const r = await env.db.prepare("UPDATE activation_codes SET status = 'revoked' WHERE batch_id = ?1 AND status != 'revoked'").bind(body.batch_id).run();
      return json({ ok: true, updated: r.meta.changes ?? 0 });
    }
    const codes: string[] = (body.codes ?? []) as string[];
    if (codes.length > 0) {
      // 统一 trim + 大写，与 findCodeByString 的查询口径一致
      const normalized = codes.map((c) => c.trim().toUpperCase()).filter(Boolean);
      const stmts = normalized.map((c) =>
        env.db.prepare("UPDATE activation_codes SET status = 'revoked' WHERE code = ?1 AND status != 'revoked'").bind(c)
      );
      await env.db.batch(stmts);
      return json({ ok: true, count: normalized.length });
    }
    return json({ error: msg(req, "缺少 batch_id 或 codes", "Missing batch_id or codes") }, 400);
  }

  // GET /api/admin/codes/batches — 列出所有 batch_id（用于过滤 UI）
  if (path === "/api/admin/codes/batches" && method === "GET") {
    const rows = (await env.db.prepare(
      "SELECT batch_id, COUNT(*) AS n FROM activation_codes WHERE batch_id IS NOT NULL GROUP BY batch_id ORDER BY MAX(created_at) DESC"
    ).all()).results as any[];
    return json({ batches: rows.map((r) => ({ batch_id: r.batch_id, count: r.n })) });
  }

  // GET /api/admin/codes/usage?batch=&plan= — 流量用量汇总
  if (path === "/api/admin/codes/usage" && method === "GET") {
    const sp = new URL(req.url).searchParams;
    const where: string[] = [];
    const binds: any[] = [];
    if (sp.get("batch")) { where.push("batch_id = ?"); binds.push(sp.get("batch")); }
    if (sp.get("plan")) { where.push("plan_id = ?"); binds.push(sp.get("plan")); }
    const whereSql = where.length ? "WHERE " + where.join(" AND ") : "";

    // 用 effective status 替代原始 status，确保动态过期/耗尽的码也被正确统计
    const now = Date.now();
    const summary = await env.db.prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN status = 'revoked' THEN 0
                  WHEN expires_at IS NOT NULL AND expires_at < ? THEN 0
                  WHEN traffic_bytes > 0 AND used_bytes >= traffic_bytes THEN 0
                  WHEN status = 'unused' THEN 1 ELSE 0 END) AS unused,
         SUM(CASE WHEN status = 'revoked' THEN 0
                  WHEN expires_at IS NOT NULL AND expires_at < ? THEN 0
                  WHEN traffic_bytes > 0 AND used_bytes >= traffic_bytes THEN 0
                  WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
         SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END) AS revoked,
         SUM(CASE WHEN status = 'revoked' THEN 0
                  WHEN expires_at IS NOT NULL AND expires_at < ? THEN 1 ELSE 0 END) AS expired,
         SUM(CASE WHEN status = 'revoked' THEN 0
                  WHEN expires_at IS NOT NULL AND expires_at < ? THEN 0
                  WHEN traffic_bytes > 0 AND used_bytes >= traffic_bytes THEN 1 ELSE 0 END) AS exhausted,
         SUM(used_bytes) AS used_bytes,
         SUM(traffic_bytes) AS total_bytes
       FROM activation_codes ${whereSql}`
    ).bind(now, now, now, now, ...binds).first() as any;

    // 各 batch 汇总
    const batches = where.length ? [] : (await env.db.prepare(
      `SELECT batch_id, COUNT(*) AS n, SUM(used_bytes) AS used_bytes, SUM(traffic_bytes) AS total_bytes
       FROM activation_codes
       WHERE batch_id IS NOT NULL
       GROUP BY batch_id
       ORDER BY MAX(created_at) DESC`
    ).all()).results;

    return json({ summary, batches });
  }

  // ─══════════════════════════════════════════════════════════
  // 存储后端连通性测试
  // POST /api/admin/storage/test
  // body: { provider?, endpoint?, region?, bucket?, access_key_id?, secret_key?, addressing_style? }
  //   不传则使用 settings 里已配置的值
  // ─══════════════════════════════════════════════════════════
  if (path === "/api/admin/storage/test" && method === "POST") {
    const body = await readJson<any>(req);
    const s = await getSettings(env);

    // ① WebDAV 测试 —— 优先
    const useWebdav =
      (body.provider ?? s.storageProvider) === "webdav" &&
      (body.url ?? s.storageWebdavUrl) &&
      (body.username ?? s.storageWebdavUsername);

    if (useWebdav) {
      const { createWebDAVProvider } = await import("./storage");
      const password = body.password?.trim()
        ? body.password.trim()
        : (s.storageWebdavPasswordCipher ? await decryptSecret(s.storageWebdavPasswordCipher, env.admin) : null);
      if (!password) {
        return json({ ok: false, error: "missing_webdav_password" }, 400);
      }
      try {
        const prov = createWebDAVProvider({
          url: (body.url ?? s.storageWebdavUrl!).trim().replace(/\/+$/, ""),
          username: (body.username ?? s.storageWebdavUsername!).trim(),
          password,
        });
        // 先 list 一下根目录，确认认证 + PROPFIND 正常
        const listed = await prov.list({ prefix: "", limit: 5 });
        return json({
          ok: true,
          provider: "webdav",
          url: (body.url ?? s.storageWebdavUrl!).trim(),
          username: (body.username ?? s.storageWebdavUsername!).trim(),
          entries_found: listed.entries.length,
          truncated: listed.truncated,
        });
      } catch (err: any) {
        return json({
          ok: false,
          error: "webdav_test_failed",
          message: String(err?.message ?? err),
          detail: err?.stack ?? "",
        }, 502);
      }
    }

    // ② S3 测试
    const useS3 =
      (body.provider ?? s.storageProvider) === "s3" &&
      (body.endpoint ?? s.s3Endpoint) &&
      (body.bucket ?? s.s3Bucket);

    if (useS3) {
      const secret = body.secret_key?.trim()
        ? body.secret_key.trim()
        : (s.s3SecretKeyCipher ? await decryptSecret(s.s3SecretKeyCipher, env.admin) : null);
      if (!secret || !(body.access_key_id ?? s.s3AccessKeyId)) {
        return json({ ok: false, error: "missing_s3_credentials" }, 400);
      }
      const { createS3Provider } = await import("./storage");
      const cfg = {
        endpoint: body.endpoint ?? s.s3Endpoint!,
        region: body.region ?? s.s3Region ?? "us-east-1",
        bucket: body.bucket ?? s.s3Bucket!,
        accessKeyId: (body.access_key_id ?? s.s3AccessKeyId!).trim(),
        secretAccessKey: secret,
        addressingStyle: (body.addressing_style ?? s.s3AddressingStyle ?? "path") as "path" | "virtual",
      };
      try {
        const prov = createS3Provider(cfg);
        const testKey = `_r2pan-test-${Date.now()}`;
        // 写一个测试对象
        await prov.put(testKey, new TextEncoder().encode("cloud-r2pan storage test"), {
          contentType: "text/plain",
        });
        // 读回验证
        const obj = await prov.get(testKey);
        const head = await prov.head(testKey);
        // 清理
        await prov.delete(testKey);
        return json({
          ok: true,
          provider: "s3",
          endpoint: cfg.endpoint,
          bucket: cfg.bucket,
          head_ok: !!head,
          head_size: head?.size ?? 0,
        });
      } catch (err: any) {
        return json({
          ok: false,
          error: "s3_test_failed",
          message: String(err?.message ?? err),
          detail: err?.stack ?? "",
        }, 502);
      }
    } else {
      // R2 模式 —— 直接 head 一个已知 key 或 list 试一下
      if (!env.r2) {
        return json({ ok: false, error: "no_r2_binding_and_no_s3_configured" }, 400);
      }
      try {
        // 尝试 list（轻量，能连通就行）
        const listed = await env.r2.list({ limit: 1 });
        return json({
          ok: true,
          provider: "r2",
          bucket: "cloud-r2pan",
          objects_found: listed.objects?.length ?? 0,
          has_more: !!listed.truncated,
        });
      } catch (err: any) {
        return json({
          ok: false,
          error: "r2_test_failed",
          message: String(err?.message ?? err),
        }, 502);
      }
    }
  }

  // ─══════════════════════════════════════════════════════════
  // 全球分布统计 —— 用于「全球分布」Tab 的地球仪
  // GET /api/admin/global/stats?since_days=7
  //   返回每个国家的下载次数、字节数、活跃 IP 数
  // ─══════════════════════════════════════════════════════════
  if (path === "/api/admin/global/stats" && method === "GET") {
    const sinceDays = Math.min(365, Math.max(1, Number(new URL(req.url).searchParams.get("since_days")) || 30));
    const since = Date.now() - sinceDays * 86400_000;
    const countrySql = `
      SELECT
        COALESCE(NULLIF(country, ''), 'ZZ') AS country,
        COUNT(*) AS downloads,
        COALESCE(SUM(bytes), 0) AS bytes,
        COUNT(DISTINCT ip) AS unique_ips,
        COUNT(DISTINCT file_name) AS unique_files
      FROM download_logs
      WHERE created_at > ?1
      GROUP BY country
      ORDER BY downloads DESC
    `;
    const { results }: any = await env.db.prepare(countrySql).bind(since).all();
    const totalSql = `
      SELECT COUNT(*) AS total_downloads, COALESCE(SUM(bytes), 0) AS total_bytes, COUNT(DISTINCT COALESCE(NULLIF(country, ''), 'ZZ')) AS countries_seen
      FROM download_logs WHERE created_at > ?1
    `;
    const totals: any = await env.db.prepare(totalSql).bind(since).first();

    // Analytics Engine 可用性（给前端展示提示）
    return json({
      since_days: sinceDays,
      totals: {
        downloads: totals?.total_downloads ?? 0,
        bytes: totals?.total_bytes ?? 0,
        countries_seen: totals?.countries_seen ?? 0,
      },
      countries: (results ?? []).map((r: any) => ({
        country: r.country,
        downloads: r.downloads,
        bytes: r.bytes,
        unique_ips: r.unique_ips,
        unique_files: r.unique_files,
      })),
      analytics_engine_available: !!env.analytics,
      // Analytics Engine 绑定后，下次部署可以升级为经纬度精确查询
      geo_source: "d1_download_logs",
    });
  }

  // ─══════════════════════════════════════════════════════════
  //   数据库工具（设置页 —— 诊断 & 修复）
  // ─══════════════════════════════════════════════════════════

  // GET /api/admin/db/status —— 返回数据库当前 schema 健康状况
  if (path === "/api/admin/db/status" && method === "GET") {
    const status = await getSchemaStatus(env);
    return json(status);
  }

  // POST /api/admin/db/repair —— 强制跑 ensureSchema + 增量迁移
  if (path === "/api/admin/db/repair" && method === "POST") {
    const result = await repairDatabase(env);
    return json(result);
  }

  return json({ error: "not_found" }, 404);
  } catch (e: any) {
    console.error("[handleAdminApi]", e?.stack || e);
    // 顺带把 API 异常落到错误日志表，方便管理员在后台查看 / 反馈
    const ua = req.headers.get("user-agent") ?? "";
    const { browser, os } = parseUA(ua);
    ctx.waitUntil(
      writeErrorLog(env, {
        source: "api",
        message: String(e?.message ?? e),
        stack: e?.stack ?? null,
        path,
        url: req.url,
        ua,
        browser,
        os,
        country: req.headers.get("cf-ipcountry") ?? null,
        ip: clientIp(req),
      })
    );
    return json({
      error: "server_error",
      message: String(e?.message ?? e),
      stack: (e?.stack || "").split("\n").slice(0, 8).join("\n"),
    }, 500);
  }
}
