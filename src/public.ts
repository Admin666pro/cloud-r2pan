import type { Env, ShareWithFile, DirectLinkWithFile } from "./types";
import { getSettings, addTraffic, consumePreviewQuota } from "./settings";
import { parseUA } from "./ua";
import { clientIp, isAdminWhitelisted } from "./auth";
import { findCodeByString, checkCodeUsable, activateCodeIfNeeded, deductQuota, refundQuota, formatCodeStatus, type ActivationCodeRow } from "./codes";
import { errorPage, json } from "./pages";
import { hmacHex, sha256Hex, randomHex, safeEqual, decryptSecret } from "./crypto";
import { verifyOAuthSession } from "./oauth";
import { createStorageProvider, type StorageProvider } from "./storage";

/** 懒加载 StorageProvider —— 和 admin.ts 类似 */
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

const TOKEN_TTL_MS = 24 * 3600_000; // 授权令牌有效期 24h

/* ═══════════ Turnstile 辅助函数 ═══════════ */

/**
 * 计算一个 IP 今天已访问过多少次分享页 → 判断是否需要弹 Turnstile。
 * 同时把计数 +1 写回（用 UPSERT 单次 SQL 原子完成）。
 */
async function trackAndGetVisits(env: Env, ip: string): Promise<number> {
  const day = new Date().toISOString().slice(0, 10);
  // 先查 +1
  const upsert = env.db.prepare(
    `INSERT INTO turnstile_visits(ip, day, count) VALUES(?1, ?2, 1)
     ON CONFLICT(ip, day) DO UPDATE SET count = count + 1`
  );
  await upsert.bind(ip, day).run();
  const row = await env.db
    .prepare("SELECT count FROM turnstile_visits WHERE ip = ?1 AND day = ?2")
    .bind(ip, day)
    .first<{ count: number }>();
  return row?.count ?? 1;
}

/** 从 env 或 settings.cipher 拿到最终的 Turnstile Secret（优先 env） */
async function getTurnstileSecret(env: Env, settings: { turnstileSecretCipher: string | null }): Promise<string | null> {
  if (env.turnstile_secret) return env.turnstile_secret;
  if (settings.turnstileSecretCipher) return await decryptSecret(settings.turnstileSecretCipher, env.admin);
  return null;
}

/**
 * 判断当前 Turnstile 是否可用。
 * ⚠️ secret 与 sitekey **必须同时具备**才算启用：前端只有拿到 sitekey 才能渲染 widget 换取 cf 令牌。
 * 若只配了 secret 而没有 sitekey，前端拿不到令牌 → 服务端却强制要求 cf → 所有下载都会 403，
 * 形成"配置一半就把站点锁死"的坑。这里要求两者齐全，避免该锁死。
 */
export async function isTurnstileEnabled(
  env: Env,
  settings: { turnstileMode: string; turnstileThreshold: number; turnstileSecretCipher: string | null; turnstileSitekeyOverride: string | null }
): Promise<boolean> {
  const secret = await getTurnstileSecret(env, settings);
  if (!secret) return false;
  const sitekey = env.turnstile_sitekey || settings.turnstileSitekeyOverride || null;
  if (!sitekey) return false;
  if (settings.turnstileMode === "off") return false;
  return true;
}

/**
 * 返回 Turnstile 状态 + sitekey（前端渲染 widget 用）。
 * 如果 sitekey 没配 → 前端根本不会调 Turnstile 脚本。
 */
export function getTurnstileInfo(
  env: Env,
  settings: { turnstileMode: string; turnstileSitekeyOverride: string | null }
): { sitekey: string | null; mode: string } {
  const sitekey = env.turnstile_sitekey || settings.turnstileSitekeyOverride || null;
  return { sitekey, mode: settings.turnstileMode };
}

/**
 * 验证 Turnstile token —— 向 Cloudflare siteverify 发 POST。
 * 官方要求 POST application/x-www-form-urlencoded: secret + token
 */
export async function verifyTurnstileToken(
  env: Env,
  settings: { turnstileSecretCipher: string | null },
  token: string,
  remoteip: string
): Promise<boolean> {
  const secret = await getTurnstileSecret(env, settings);
  if (!secret || !token) return false;
  try {
    const form = new URLSearchParams({
      secret,
      response: token,
      remoteip,
    });
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    if (!r.ok) return false;
    const j = (await r.json()) as { success?: boolean; errorcodes?: string[] };
    return !!j.success;
  } catch {
    return false;
  }
}

/** 解析 Range 头 → {offset, length}，无效返回 null */
function parseRange(header: string | null, size: number): { offset: number; length: number } | null {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m || (m[1] === "" && m[2] === "")) return null;
  let offset: number, length: number;
  if (m[1] === "") {
    // 后缀范围: bytes=-N
    const n = Math.min(Number(m[2]), size);
    offset = size - n;
    length = n;
  } else {
    offset = Number(m[1]);
    const end = m[2] === "" ? size - 1 : Math.min(Number(m[2]), size - 1);
    length = end - offset + 1;
  }
  if (offset >= size || length <= 0) return null;
  return { offset, length };
}

/** 下载会话的存活窗口 —— 同一窗口内同一 (分享, IP) 的请求归并为同一次下载（持续有请求则不断续期） */
const DOWNLOAD_SESSION_MS = 10 * 60 * 1000;

/**
 * 是否为「探测性」Range 请求 —— 只请求**文件头部第 1 个字节**（`bytes=0-0`）。
 * 下载管理器 / 浏览器常用它来探测服务端是否支持断点续传（是否有 206）。
 *
 * ⚠️ 必须严格限定为 offset === 0、length === 1：
 *   若像早期实现那样把「任意 1 字节范围」都当作探测，攻击者就能用 `bytes=N-N` 逐字节
 *   把整个文件拉下来，而每一次都不占用下载名额 / 不触发每 IP 限次 —— 等于 max_downloads
 *   形同虚设。`bytes=0-0` 是业界通用探测头，只取首字节不会造成实际泄露。
 */
function isByteProbe(req: Request, size: number): boolean {
  const r = parseRange(req.headers.get("range"), size);
  return !!r && r.offset === 0 && r.length === 1;
}

/**
 * Range 语法合法、但起点已经越过文件末尾（或后缀长度为 0）→ 必须返回 416。
 *
 * 为什么不能像旧实现那样"解析失败就当整份下载"：下载器断点续传时若把本地已完成的
 * 偏移发给服务端，服务端却回 200 + 整份文件，下载器会把它当成新数据追加到已有文件后，
 * 得到一个**损坏的超大文件**；部分下载器则直接判定服务端不支持续传而放弃 —— 表现为
 * "下载到一半就再也下不动了"。
 */
function isUnsatisfiableRange(header: string | null, size: number): boolean {
  if (!header) return false;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m || (m[1] === "" && m[2] === "")) return false;
  if (m[1] === "") {
    const n = Number(m[2]);
    return !Number.isFinite(n) || n <= 0;
  }
  const offset = Number(m[1]);
  return Number.isFinite(offset) && offset >= size;
}

/**
 * 会话字节预算的「续传重叠余量」。
 *
 * 一次下载被中断后，客户端会从它"确定已收到"的偏移续传；而服务端在断流瞬间可能已经把
 * 若干数据块读进响应缓冲区（计入了 bytes）。两者之间的差值是**重复发送**的字节，
 * 若预算严格卡在 size，任何一次断线续传都会溢出 → 410，用户表现为"下到一半断了就再也下不了"。
 *
 * 余量限制在 2MB / 文件大小的 25% 以内：足够覆盖运行时缓冲与续传重叠，又不会让攻击者
 * 白嫖出第二份完整文件（最多多拿 2MB）。
 */
function sessionBudget(size: number): number {
  const cap = size > 0 ? size : 1;
  return cap + Math.min(2 * 1024 * 1024, Math.ceil(cap / 4));
}

interface SessionClaim {
  /** 是否开启了新会话（= 需要占用下载名额 / 计次 / 写日志） */
  isNew: boolean;
  /** 是否属于一次**已被准入**的下载（新会话准入，或已计数的既有会话续期） */
  admitted: boolean;
  /** 本次请求是否**已经预占了一个名额**（失败回滚时要退还） */
  claimed: boolean;
  /**
   * 本次准入对应会话行的 created_at。
   * 退还字节 / 退还会话时必须带上它做条件，否则一个**旧请求**迟到的退款
   * 会扣到同一 (分享, IP) 后来新建的会话上，凭空制造免费预算。
   */
  sessionAt: number | null;
}

/**
 * 原子认领一次下载会话 —— 「先抢名额，再建会话」+「会话字节预算」双重约束。
 *
 * ── 为什么旧实现会双向出问题 ─────────────────────────────────────
 * 旧实现只在「新建会话」时判断名额，且名额是在**后续请求**里才 +1 的：
 *   · 过松（= 无法下载）：多线程下载器把一次下载拆成 N 个**并发分片**几乎同时到达，
 *     多个分片同时看到 `download_count` 还是旧值 → 有的互相覆盖会话、有的在名额已被
 *     第一个分片占掉后直接 410。实测 max_downloads=1 时 4 个分片只有 1 个能下。
 *   · 过严（= 流量被刷光）：同一 (分享, IP) 在 10 分钟窗口内的**任意**后续请求都被
 *     当作"续传"免费放行 —— 攻击者点一次下载后，可在窗口内无限次重下整个文件。
 *
 * ── 现方案 ───────────────────────────────────────────────────────
 *   ① 已有被准入会话，且本次字节还在「一份文件」预算内 → 同步预占字节，免费放行；
 *   ② 否则原子抢占名额（`UPDATE ... WHERE 名额未满` + 会话插入 `ON CONFLICT DO NOTHING`），
 *      D1/SQLite 单写入者串行化，并发下只会有一个分片抢到，其余走 ① 变成同一会话的续传；
 *   ③ 名额已满 / 预算已耗尽 → 短暂等待确认没有并发分片刚建好会话，确实没有 → 拒绝。
 *
 * 字节预算（`download_sessions.bytes`）必须**同步**预占（在响应发出前落库），否则
 * 攻击者可以在后台记账落库之前流水线式发一堆请求，全部被判成"续传"白嫖。
 * 一个名额最多买下"一份文件"的字节量：并发分片之和 = size 只占 1 个名额；
 * 想要第二份拷贝（`bytes + len > size`）就必须重新抢名额。
 */
async function claimSession(
  env: Env,
  table: "shares" | "direct_links",
  id: string,
  ip: string,
  maxDownloads: number | null,
  size: number,
  len: number
): Promise<SessionClaim> {
  const now = Date.now();
  const fresh = now - DOWNLOAD_SESSION_MS; // created_at > fresh 才算"有效会话"
  const max = maxDownloads && maxDownloads > 0 ? Math.floor(maxDownloads) : 0; // 0 = 不限
  const cap = sessionBudget(size); // 一份文件 + 续传重叠余量
  // 预算按「至少 1 字节」计：否则 0 字节文件（或 bytes=0-0 之外的 0 长 Range）永远满足
  // `bytes + 0 <= cap`，可以无限次被当作"续传"免费放行，max_downloads 对空文件失效。
  const need = Math.max(1, len);

  // 0) 精准清理本 (分享, IP) 的过期会话行 —— 旧行不能影响本次判定
  await env.db
    .prepare("DELETE FROM download_sessions WHERE share_id = ?1 AND ip = ?2 AND created_at <= ?3")
    .bind(id, ip, fresh)
    .run()
    .catch(() => {});

  // ① 免费续传：已有被准入会话，且本次字节仍在「一份文件 + 重叠余量」预算内 → 原子预占字节。
  //    ⚠️ 不刷新 created_at：它是会话身份，退款/退还字节都靠它精确匹配。
  //    若每个并发分片都刷新，先结束的分片会因身份被改而退不掉「未发送字节」，
  //    空气字节会越积越多，最终把正常续传挤成 410。
  //    先 SELECT 拿到稳定身份，再带 `created_at = ?` 条件更新；会话若被并发替换，
  //    UPDATE 自然失败并重试，绝不会把字节记到别的会话上。
  for (let attempt = 0; attempt < 3; attempt++) {
    const sess = await env.db
      .prepare(
        `SELECT created_at FROM download_sessions
          WHERE share_id = ?1 AND ip = ?2 AND created_at > ?3
            AND counted = 1 AND bytes + ?4 <= ?5`
      )
      .bind(id, ip, fresh, need, cap)
      .first<{ created_at: number }>();
    if (!sess) break;
    const ext = await env.db
      .prepare(
        `UPDATE download_sessions SET bytes = bytes + ?4
          WHERE share_id = ?1 AND ip = ?2 AND created_at = ?3
            AND bytes + ?4 <= ?5`
      )
      .bind(id, ip, sess.created_at, need, cap)
      .run();
    if ((ext.meta.changes ?? 0) > 0)
      return { isNew: false, admitted: true, claimed: false, sessionAt: sess.created_at };
  }

  // ② 先原子抢名额 —— 只有真正抢到名额的请求才有权重建会话。
  //    ⚠️ 旧实现是「先删掉同 (分享, IP) 的旧会话再插新会话」：一个并发的重复请求
  //    （用户双击下载、下载器重试）会把**另一个正在下载的请求的会话删掉**，导致同一次
  //    多线程下载的其余分片随后被判 410 —— 典型的「正常用户无法下载」。
  //    现在失败者不会碰别人的会话，只会在 ③ 里短暂等待并尝试续传。
  const take = await env.db
    .prepare(
      `UPDATE ${table} SET download_count = download_count + 1
       WHERE id = ?1 AND (?2 = 0 OR download_count < ?2)`
    )
    .bind(id, max)
    .run();
  if ((take.meta.changes ?? 0) > 0) {
    // 抢到名额 → 用它开启一个全新的会话（旧的半截会话已由这个名额买断，可安全替换）
    try {
      await env.db.batch([
        env.db.prepare("DELETE FROM download_sessions WHERE share_id = ?1 AND ip = ?2").bind(id, ip),
        env.db
          .prepare(
            "INSERT INTO download_sessions(share_id, ip, created_at, counted, bytes) VALUES(?1, ?2, ?3, 1, ?4)"
          )
          .bind(id, ip, now, need),
      ]);
    } catch (err) {
      // 会话落库失败 → 退还刚抢到的名额，避免分享被无效请求慢慢锁死
      await env.db
        .prepare(
          `UPDATE ${table} SET download_count = CASE WHEN download_count > 0 THEN download_count - 1 ELSE 0 END WHERE id = ?1`
        )
        .bind(id)
        .run()
        .catch(() => {});
      return { isNew: false, admitted: false, claimed: false, sessionAt: null };
    }
    // 顺手清理早已过期的会话行，避免 download_sessions 无限膨胀
    await env.db
      .prepare("DELETE FROM download_sessions WHERE created_at < ?1")
      .bind(now - DOWNLOAD_SESSION_MS * 6)
      .run()
      .catch(() => {});
    return { isNew: true, admitted: true, claimed: true, sessionAt: now };
  }

  // ③ 没抢到名额：可能是同一批并发分片里有一个刚建好会话（本请求的判断略早），
  //    短暂等待后按「续传」原子预占，避免同一批分片被误杀。
  for (let i = 0; i < 5; i++) {
    await new Promise((r) => setTimeout(r, 40));
    const sess = await env.db
      .prepare(
        `SELECT created_at FROM download_sessions
          WHERE share_id = ?1 AND ip = ?2 AND created_at > ?3
            AND counted = 1 AND bytes + ?4 <= ?5`
      )
      .bind(id, ip, fresh, need, cap)
      .first<{ created_at: number }>();
    if (!sess) continue;
    const again = await env.db
      .prepare(
        `UPDATE download_sessions SET bytes = bytes + ?4
          WHERE share_id = ?1 AND ip = ?2 AND created_at = ?3
            AND bytes + ?4 <= ?5`
      )
      .bind(id, ip, sess.created_at, need, cap)
      .run();
    if ((again.meta.changes ?? 0) > 0)
      return { isNew: false, admitted: true, claimed: false, sessionAt: sess.created_at };
  }
  // 名额已满 / 预算已耗尽 → 拒绝（不占名额）
  return { isNew: false, admitted: false, claimed: false, sessionAt: null };
}

/** 退还预占的名额 + 删除会话 —— 请求未真正把文件发出去时调用 */
async function refundSlot(
  env: Env,
  table: "shares" | "direct_links",
  id: string,
  ip: string,
  sessionAt: number | null
): Promise<void> {
  const stmts = [
    env.db
      .prepare(
        `UPDATE ${table} SET download_count = CASE WHEN download_count > 0 THEN download_count - 1 ELSE 0 END WHERE id = ?1`
      )
      .bind(id),
  ];
  // 只在会话仍是这次请求创建的那一行时才删除 —— 避免误删并发分片刚建好的新会话
  if (sessionAt !== null) {
    stmts.push(
      env.db
        .prepare("DELETE FROM download_sessions WHERE share_id = ?1 AND ip = ?2 AND created_at = ?3")
        .bind(id, ip, sessionAt)
    );
  }
  await env.db.batch(stmts).catch(() => {});
}

/**
 * 释放会话里「预占但实际没发出去」的字节（客户端中途断开 / 流读取失败）。
 *
 * 为什么需要它：`claimSession` 在响应发出前就同步预占了本次请求的字节预算（防流水线白嫖），
 * 但客户端可能只读了一半就断开（暂停、切网、多线程分片提前结束）。若不退还，这部分
 * "空气字节"会永久占着该名额的预算 —— 用户重新点下载/断点续传时 `bytes + len > size`，
 * 被判定为"想要第二份拷贝"而 410，表现就是**正常用户无法下载**。
 *
 * 只退「未发送」的部分，已发送的字节仍然计入（流量本来就消耗了）。
 */
async function releaseSessionBytes(
  env: Env,
  id: string,
  ip: string,
  unsent: number,
  sessionAt: number
): Promise<void> {
  if (unsent <= 0) return;
  await env.db
    .prepare(
      "UPDATE download_sessions SET bytes = MAX(0, bytes - ?4) WHERE share_id = ?1 AND ip = ?2 AND created_at = ?3"
    )
    .bind(id, ip, sessionAt, unsent)
    .run()
    .catch(() => {});
}

/**
 * 把响应体包一层，统计真实发送字节；流被取消/读取失败时把未发送的预占额度退还给会话。
 * 正常读完整份 → 预占量 == 发送量，无需退还。
 */
function trackSentBytes(
  body: ReadableStream<Uint8Array>,
  onSettled: (sent: number, complete: boolean) => void
): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  let sent = 0;
  let settled = false;
  const settle = (complete: boolean) => {
    if (settled) return;
    settled = true;
    onSettled(sent, complete);
  };
  return new ReadableStream<Uint8Array>({
    async pull(ctrl) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          settle(true);
          ctrl.close();
          return;
        }
        sent += value.byteLength;
        ctrl.enqueue(value);
      } catch (err) {
        settle(false);
        ctrl.error(err);
      }
    },
    cancel(reason) {
      settle(false);
      return reader.cancel(reason);
    },
  });
}

interface DownloadSlot {
  /** 本次请求是否开启了一次「新的下载」（需要占用名额 / 计次 / 写日志） */
  consumesSlot: boolean;
  /** 本次请求是否**已被准入**（可为空名额之外的下载提供服务） */
  admitted: boolean;
  /** 本次请求是否预占了名额（失败/中止时必须退还） */
  claimed: boolean;
  /** 本次准入的会话时间戳（HEAD / 探测等未预占字节的请求为 null） */
  sessionAt: number | null;
}

/**
 * 判定一次下载请求是否占用下载名额 —— 只有「开启新下载会话」的那一次才占用：
 *   · HEAD：纯元数据探测 → 不占用
 *   · `bytes=0-0` 首字节探测 → 不占用
 *   · Range 已越过文件末尾（会收到 416）→ 不占用（没有发送任何内容）
 *   · 同一会话内（TTL 内已有会话、且未超出预算）的分片/续传 → 不占用
 *   · 其余：原子抢名额并开启新会话。
 *
 * 旧实现用 `download_logs` 判断续传，且**没有时间窗口**：任何历史下载记录都会让该 IP
 * 此后所有 `Range: bytes=N-` 请求永远免费 —— 只要下过一次，就能靠 `bytes=1-` 反复
 * 拉取整个文件，彻底绕过 max_downloads。现改为基于会话（带 TTL + 字节预算）判定。
 */
async function evaluateDownloadSlot(
  env: Env,
  req: Request,
  token: string,
  ip: string,
  size: number,
  maxDownloads: number | null,
  kind: "share" | "direct" = "share"
): Promise<DownloadSlot> {
  const skip = (): DownloadSlot => ({ consumesSlot: false, admitted: true, claimed: false, sessionAt: null });
  if (req.method === "HEAD") return skip();
  if (isByteProbe(req, size)) return skip();
  if (isUnsatisfiableRange(req.headers.get("range"), size)) return skip();
  // 本次请求实际要发送的字节数（无 Range = 整份文件）—— 作为会话的字节预算预占量。
  // ⚠️ 必须精确传入：预算 = 一个名额最多买下「一份文件」的字节。
  const range = parseRange(req.headers.get("range"), size);
  const len = range ? range.length : size;
  const claim = await claimSession(
    env,
    kind === "direct" ? "direct_links" : "shares",
    token,
    ip,
    maxDownloads,
    size,
    len
  );
  return {
    consumesSlot: claim.isNew,
    admitted: claim.admitted,
    claimed: claim.claimed,
    sessionAt: claim.sessionAt,
  };
}

/**
 * 历史脏数据兜底：早期 WebDAV / S3 流式上传会漏记 size（D1 里留成 0）。
 * 必须在**计算 Range / 预占字节预算之前**把真实大小补回来，否则：
 *   · 字节预算按 size=0 算成 1 字节 → 多线程 / 断点续传的第二个分片必然 410；
 *   · content-length 为 0 → 浏览器把文件当成空文件。
 */
async function resolveFileSize(
  env: Env,
  ctx: ExecutionContext,
  row: { file_id: string; key: string; size: number }
): Promise<void> {
  if (row.size > 0) return;
  try {
    const st = await storage(env);
    const meta = await st.head(row.key);
    if (meta && meta.size > 0) {
      row.size = meta.size;
      ctx.waitUntil(
        env.db
          .prepare("UPDATE files SET size = ?1 WHERE id = ?2 AND size <= 0")
          .bind(meta.size, row.file_id)
          .run()
          .catch(() => {})
      );
    }
  } catch {
    /* 存储不可用 / 对象不存在 → 保持 0，后续会走 404 / 502 分支 */
  }
}

/**
 * 激活码额度「预扣」—— 在响应发出前**同步**把本次要发送的字节记到码上。
 *
 * 为什么必须预扣而不能等流结束后再扣：
 *   · 额度不足一个完整文件的码（例如 1KB 的码下 1MB 文件）在旧的"事后扣减"里会扣减失败，
 *     但下载已经放行，且码仍被判定为"可用" → 可无限次下载，同时绕过月度流量限额与每 IP 限次，
 *     等于给了一个永久免费通行证。
 *   · 并发请求先读后写会互相覆盖（见 deductQuota 注释），实际只记了 1 份流量。
 *
 * 返回 `{ row: null }` 表示额度不足以覆盖本次请求 / 扣减失败 → 调用方必须回退普通通道门禁
 * （月度流量限额、每 IP 限次），绝不能把"半覆盖"的码当作免费通行证。
 */
async function prepayCodeQuota(
  env: Env,
  req: Request,
  size: number,
  codeRow: ActivationCodeRow | null
): Promise<{ row: ActivationCodeRow | null; bytes: number }> {
  if (!codeRow || req.method === "HEAD") return { row: codeRow, bytes: 0 };
  // 本次请求实际要发送的字节数；越界 Range 会收到 416（不发送内容），不占用额度
  if (isUnsatisfiableRange(req.headers.get("range"), size)) return { row: codeRow, bytes: 0 };
  const need = parseRange(req.headers.get("range"), size)?.length ?? size;
  if (need <= 0) return { row: codeRow, bytes: 0 };
  // 先激活（写入 activated_at / expires_at），再预扣，避免扣成 exhausted 后无法再激活导致永不过期
  await activateCodeIfNeeded(env, codeRow).catch(() => {});
  const dr = await deductQuota(env, codeRow, need);
  if (!dr.ok) {
    console.warn(`[code-prepay-decline] code=${codeRow.code} need=${need} reason=${dr.reason} msg=${dr.message}`);
    return { row: null, bytes: 0 };
  }
  return { row: codeRow, bytes: need };
}

/* ═══════════ 分享密码 & 下载授权令牌 ═══════════
 * 密码存储为加盐 SHA-256（salt:sha256(salt:password)）；下载授权用 HMAC 签名携带过期时间，
 * 避免把明文密码拼进下载 URL。HMAC 密钥复用 admin，无需新增 Secret，密钥轮换时短时令牌即失效。
 */
/** 加盐与密码哈希串（salt:hashhex） */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomHex();
  return salt + ":" + await sha256Hex(salt + ":" + password);
}
/** 常数时间校验密码 */
async function verifyPassword(stored: string, password: string): Promise<boolean> {
  const i = stored.indexOf(":");
  if (i < 0) return false;
  const salt = stored.slice(0, i);
  const want = stored.slice(i + 1);
  const got = await sha256Hex(salt + ":" + password);
  return safeEqual(want, got);
}
/** 颁发短时下载授权令牌：格式 `${到期时间戳}.${HMAC}` */
async function issueToken(env: Env, token: string): Promise<string> {
  const exp = Date.now() + TOKEN_TTL_MS;
  const sig = await hmacHex(env.admin, `${token}:${exp}`);
  return `${exp}.${sig}`;
}
/** 校验下载授权令牌（存在于 URL query string 中） */
async function verifyShareToken(env: Env, token: string, query: string): Promise<boolean> {
  const t = new URLSearchParams(query).get("t");
  if (!t) return false;
  const i = t.indexOf(".");
  if (i < 0) return false;
  const exp = Number(t.slice(0, i));
  if (!Number.isFinite(exp) || exp < Date.now()) return false;
  const want = await hmacHex(env.admin, `${token}:${exp}`);
  return safeEqual(t.slice(i + 1), want);
}

/* ═══════════ 在线预览 ═══════════
 * 预览次数为「全站共用」的月度总额度（settings.previewLimit），所有分享共享同一份，
 * 跨月自动重置。打开一次预览 = 计 1 次；预览原始流用短时 HMAC 令牌（pv）授权，
 * 避免被反复刷。
 */

/** 可预览类型 */
export type PreviewKind = "image" | "video" | "audio" | "pdf" | "text" | "zip" | "none";

const PREVIEW_IMAGE_EXT = ["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "avif", "ico"];
const PREVIEW_VIDEO_EXT = ["mp4", "webm", "mov", "m4v", "ogv", "mkv"];
const PREVIEW_AUDIO_EXT = ["mp3", "wav", "ogg", "oga", "m4a", "aac", "flac", "opus"];
const PREVIEW_TEXT_EXT = ["txt", "md", "markdown", "log", "csv", "tsv", "json", "xml", "yml", "yaml", "ini", "conf", "js", "ts", "css", "html", "htm", "svg"];
const PREVIEW_ZIP_EXT = ["zip"];

/**
 * 判断文件的在线预览类型。
 * 优先看扩展名（更可靠），MIME 作为兜底。
 */
export function previewKind(mime: string, name: string): PreviewKind {
  const ext = (/\.([a-z0-9]+)$/i.exec(name || "")?.[1] || "").toLowerCase();
  const m = (mime || "").toLowerCase();
  if (PREVIEW_ZIP_EXT.includes(ext)) return "zip";
  if (PREVIEW_IMAGE_EXT.includes(ext) || m.startsWith("image/")) return "image";
  if (PREVIEW_VIDEO_EXT.includes(ext) || m.startsWith("video/")) return "video";
  if (PREVIEW_AUDIO_EXT.includes(ext) || m.startsWith("audio/")) return "audio";
  if (ext === "pdf" || m === "application/pdf") return "pdf";
  if (PREVIEW_TEXT_EXT.includes(ext) || m.startsWith("text/") || m === "application/json") return "text";
  return "none";
}

/** 计算全局月度预览额度用量（limit<=0 表示不限） */
function globalPreviewUsage(settings: { previewLimit: number; previewUsed: number }): { limit: number; used: number; remaining: number; maxed: boolean } {
  const limit = settings.previewLimit;
  const used = settings.previewUsed;
  const maxed = limit > 0 && used >= limit;
  const remaining = limit > 0 ? Math.max(0, limit - used) : -1; // -1 = 不限
  return { limit, used, remaining, maxed };
}

const PREVIEW_TOKEN_TTL_MS = 3600_000; // 预览令牌 1h

/** 颁发预览专用令牌，命名空间与下载令牌隔离（pv:），防止互相冒用 */
async function issuePreviewToken(env: Env, token: string): Promise<string> {
  const exp = Date.now() + PREVIEW_TOKEN_TTL_MS;
  const sig = await hmacHex(env.admin, `pv:${token}:${exp}`);
  return `${exp}.${sig}`;
}

/** 校验预览令牌（?pv=） */
async function verifyPreviewToken(env: Env, token: string, query: string): Promise<boolean> {
  const t = new URLSearchParams(query).get("pv");
  if (!t) return false;
  const i = t.indexOf(".");
  if (i < 0) return false;
  const exp = Number(t.slice(0, i));
  if (!Number.isFinite(exp) || exp < Date.now()) return false;
  const want = await hmacHex(env.admin, `pv:${token}:${exp}`);
  return safeEqual(t.slice(i + 1), want);
}

/** GET /s/:token —— 分享页元信息（供前端渲染） */
export async function handleShareInfo(req: Request, env: Env, token: string): Promise<Response> {
  const row = await getShare(env, token);
  if (!row) return json({ error: "not_found" }, { status: 404 });
  const settings = await getSettings(env);
  const ip = clientIp(req);
  const isWhitelisted = isAdminWhitelisted(ip, settings.adminIps);
  const quotaExceeded =
    !isWhitelisted && settings.trafficLimitBytes > 0 && settings.trafficUsedBytes >= settings.trafficLimitBytes;
  let status: "ok" | "gone" | "expired" | "maxed" = "ok";
  if (row.revoked) status = "gone";
  else if (row.expires_at && row.expires_at < Date.now()) status = "expired";
  else if (row.max_downloads && row.download_count >= row.max_downloads) status = "maxed";

  // Turnstile：在 share 页面加载时统计一次访问，判断是否需要弹
  const enabled = await isTurnstileEnabled(env, settings);
  let needsTurnstile = false;
  let visitCount = 0;
  let sitekey: string | null = null;
  if (enabled) {
    const { sitekey: sk, mode } = getTurnstileInfo(env, settings);
    sitekey = sk;
    // on_share / both 模式都在此时判断
    if (mode === "on_share" || mode === "both") {
      visitCount = await trackAndGetVisits(env, ip);
      needsTurnstile = visitCount > settings.turnstileThreshold;
    }
  }

  // OAuth2：检查是否已登录
  let oauthAuthed = false;
  let oauthProvider = settings.oauthEnabled ? settings.oauthProvider : "";
  if (settings.oauthEnabled) {
    const oauthCheck = await verifyOAuthSession(env, req.headers.get("cookie"));
    oauthAuthed = oauthCheck.ok;
  }

  // 市场浏览量累加（仅对 is_market=1 的分享 + 有至少 500ms 间隔的轻量节流）
  if (!row.revoked && row.is_market) {
    env.db.prepare("UPDATE shares SET market_views = market_views + 1 WHERE id = ?1 AND is_market = 1")
      .bind(token).run().catch(() => {}); // 不 await，不阻塞响应
  }

  return json({
    status,
    name: row.name,
    size: row.size,
    mime: row.mime,
    downloads: row.download_count,
    created_at: row.created_at,
    expires_at: row.expires_at,
    max_downloads: row.max_downloads,
    needs_password: !!row.password_hash,
    quota_exceeded: quotaExceeded,
    site_title: settings.siteTitle,
    turnstile: {
      enabled,
      sitekey,
      mode: settings.turnstileMode,
      threshold: settings.turnstileThreshold,
      needs_now: needsTurnstile,
      visit_count: visitCount,
    },
    oauth: {
      enabled: settings.oauthEnabled,
      provider: oauthProvider,
      client_id: settings.oauthClientId,
      authed: oauthAuthed,
    },
    codes_floating_button: {
      enabled: settings.codesFloatingButtonEnabled,
      position: settings.codesFloatingButtonPosition,
    },
    preview: (() => {
      const kind = previewKind(row.mime, row.name);
      const usage = globalPreviewUsage(settings);
      return {
        enabled: kind !== "none" && status === "ok",
        kind,
        limit: usage.limit,
        used: usage.used,
        remaining: usage.remaining,
        maxed: usage.maxed,
      };
    })(),
  });
}

async function getShare(env: Env, token: string): Promise<ShareWithFile | null> {
  return await env.db.prepare(
    `SELECT s.id, s.file_id, s.created_at, s.expires_at, s.max_downloads, s.download_count,
            s.max_previews, s.preview_count, s.revoked, s.password_hash,
            s.download_name, f.key, f.name, f.size, f.mime
     FROM shares s JOIN files f ON f.id = s.file_id
     WHERE s.id = ?1`
  )
    .bind(token)
    .first<ShareWithFile>();
}

/** 从 direct_links 表查直链记录（独立表、独立 token） */
async function getDirectLink(env: Env, token: string): Promise<DirectLinkWithFile | null> {
  return await env.db.prepare(
    `SELECT dl.id, dl.file_id, dl.created_at, dl.expires_at, dl.max_downloads, dl.download_count, dl.revoked,
            dl.download_name, f.key, f.name, f.size, f.mime
     FROM direct_links dl JOIN files f ON f.id = dl.file_id
     WHERE dl.id = ?1`
  )
    .bind(token)
    .first<DirectLinkWithFile>();
}

/** POST /s/:token/verify —— 校验分享密码 + 可选 Turnstile，成功后颁发下载令牌 */
export async function handleVerify(req: Request, env: Env, token: string): Promise<Response> {
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, { status: 405 });
  const row = await getShare(env, token);
  if (!row) return json({ error: "not_found" }, { status: 404 });
  let body: { password?: string; turnstile?: string } = {};
  try {
    body = await req.json();
  } catch {}

  const settings = await getSettings(env);
  const ip = clientIp(req);
  const turnstileOn = await isTurnstileEnabled(env, settings) && (settings.turnstileMode === "both");

  // Turnstile 校验（both 模式下必须有有效 token）
  if (turnstileOn) {
    const pass = await verifyTurnstileToken(env, settings, String(body.turnstile ?? ""), ip);
    if (!pass) {
      return json({ error: "turnstile_failed" }, { status: 403 });
    }
  }

  // 密码校验
  if (!row.password_hash) {
    // 无密码分享 → 如果 Turnstile 通过 + 没密码，直接给下载地址
    return json({ ok: true, url: `/s/${token}/download` });
  }
  if (!(await verifyPassword(row.password_hash, String(body.password ?? ""))))
    return json({ error: "bad_password" }, { status: 401 });
  const ticket = await issueToken(env, token);
  return json({ ok: true, url: `/s/${token}/download?t=${ticket}` });
}

/**
 * GET /s/:token/download —— 分享链接下载主流程
 * 走 shares 表，带完整鉴权链（密码/过期/次数/流量/Turnstile/OAuth/重复下载）
 */
export async function handleDownload(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  token: string
): Promise<Response> {
  const ip = clientIp(req);
  const ua = req.headers.get("user-agent") ?? "";
  const country = req.headers.get("cf-ipcountry") ?? "";
  const settings = await getSettings(env);

  const urlCode = new URL(req.url).searchParams.get("code");
  const headerCode = req.headers.get("x-activation-code");
  const activationCode = (urlCode || headerCode || "").trim().toUpperCase() || null;

  const [foundCode, ban, row] = await Promise.all([
    activationCode ? findCodeByString(env, activationCode) : Promise.resolve(null),
    env.db.prepare("SELECT reason, expires_at FROM banned_ips WHERE ip = ?1")
      .bind(ip).first<{ reason: string | null; expires_at: number | null }>(),
    getShare(env, token),
  ]);

  // 激活码不可用（已作废 / 已过期 / 额度耗尽）时**不阻断下载**，直接忽略该码，
  // 回退到普通通道（照常受全局月度限额 / 每 IP 限次约束）。
  // 这与在线预览(handlePreviewOpen)的处理保持一致；只有可用状态的有效码才抵扣独立额度。
  // 若在此处返回错误页，会导致用户浏览器 localStorage 里残留的失效码把正常下载也一并卡死。
  let codeRow = foundCode && checkCodeUsable(foundCode as any).ok ? foundCode : null;

  if (ban) {
    if (ban.expires_at && ban.expires_at < Date.now()) {
      env.db.prepare("DELETE FROM banned_ips WHERE ip = ?1").bind(ip).run().catch(() => {});
    } else {
      return errorPage(req, 403, { zh: "访问已被封禁", en: "Access Banned" },
        { zh: ban.reason || "由于重复下载行为，该 IP 已被暂时封禁。", en: ban.reason || "This IP has been temporarily banned." });
    }
  }

  if (!row) return errorPage(req, 404, { zh: "链接不存在", en: "Link Not Found" },
    { zh: "该分享链接无效，或已被管理员删除。", en: "This share link is invalid or has been removed." });
  if (row.revoked) return errorPage(req, 410, { zh: "链接已失效", en: "Link Revoked" },
    { zh: "该分享已被管理员撤销。", en: "This share has been revoked." });
  if (row.expires_at && row.expires_at < Date.now()) return errorPage(req, 410, { zh: "链接已过期", en: "Link Expired" },
    { zh: "该分享已超过有效期。", en: "This share has expired." });
  // 历史脏数据兜底：size=0 的老文件先补回真实大小，再计算 Range / 会话字节预算
  await resolveFileSize(env, ctx, row);
  // 激活码额度同步预扣 —— 额度不足以覆盖本次请求时 codeRow 置空，回退普通通道门禁。
  // 必须在下面的「月度流量 / 每 IP 限次」判断**之前**完成，否则一个额度不够的码仍会
  // 被当作免费通行证（不受任何限额约束）。
  let codePrepaid = 0;
  {
    const paid = await prepayCodeQuota(env, req, row.size, codeRow);
    codeRow = paid.row;
    codePrepaid = paid.bytes;
  }
  // ── 判断本次请求是否"开启一次新下载" ────────────────────────────────
  //  · HEAD：纯元数据探测（浏览器预检 / 下载器探测 / 链接预览），不计次、不扣名额、不计流量；
  //  · 单字节探测 Range（如 bytes=0-0）：下载器/浏览器用它探测是否支持断点续传，
  //    若计次会把名额直接吃掉，导致真正的下载被 410 卡死；
  //  · 同一"下载会话"内的分片 / 断点续传：多线程下载器把一次下载拆成 N 个并发分片，
  //    逐个计次会瞬间刷爆 max_downloads 与每 IP 限次并触发自动封禁。
  //  会话由 download_sessions 表以 (分享, IP) 为键原子认领，只有"开启新会话"的那一次计次。
  const slot = await evaluateDownloadSlot(env, req, token, ip, row.size, row.max_downloads, "share");
  const consumesSlot = slot.consumesSlot;
  // 门禁拦截时退还刚预占的名额 —— 否则"未真正把文件发出去"的失败请求会白吃一个名额，
  // 分享会被无效请求慢慢锁死（410）。
  const refundIfClaimed = async (): Promise<void> => {
    if (slot.claimed) await refundSlot(env, "shares", token, ip, slot.sessionAt);
  };
  // 门禁拦截 / 请求失败时，把预扣的激活码额度一并退回（还没发出任何字节）
  const refundCodePrepaid = async (): Promise<void> => {
    if (codeRow && codePrepaid > 0) await refundQuota(env, codeRow.id, codePrepaid);
  };
  const block = async (resp: Response): Promise<Response> => {
    await refundIfClaimed();
    await refundCodePrepaid();
    return resp;
  };

  // 名额已满 / 会话预算已耗尽：`admitted=false` 已经由 claimSession 原子判定（它会重新读取
  // 实时 download_count 并原子抢名额）。⚠️ 不能再用上面查到的 row.download_count 判断 ——
  // 并发请求读到的都是**旧值**，两个请求会同时通过，出现"满额后还能再白嫖一次"。
  if (!slot.admitted)
    return block(errorPage(req, 410, { zh: "下载次数已达上限", en: "Download Limit Reached" },
      { zh: row.max_downloads
        ? `该资源允许下载 ${row.max_downloads} 次，名额已用完。`
        : "该资源本次下载名额已用完，请稍后重试。",
        en: row.max_downloads
          ? `Download limit (${row.max_downloads}) reached.`
          : "The download quota for this session is used up. Please retry later." }));

  // ⚠️ 下载名额的原子扣减**必须放在所有门禁通过之后**（见文件末尾「原子扣名额」）。
  // 旧实现在此提前扣减，导致密码错误 / 未登录 / 人机验证失败 / 流量超限 / 存储读失败等
  // 任何一次"没真正把文件发出去"的请求都会白白吃掉一个名额，最终把分享锁死（410）。

  if (row.password_hash && !(await verifyShareToken(env, token, new URL(req.url).search))) {
    return block(errorPage(req, 403, { zh: "需要访问密码", en: "Password Required" },
      { zh: "该分享受密码保护。", en: "This share is password-protected." }));
  }

  if (settings.oauthEnabled) {
    const oauthResult = await verifyOAuthSession(env, req.headers.get("cookie"));
    if (!oauthResult.ok) {
      const providerName = settings.oauthProvider === "custom" ? "OAuth" : settings.oauthProvider;
      const startUrl = `/oauth/start?provider=${encodeURIComponent(settings.oauthProvider)}&redirect=${encodeURIComponent("/s/" + token)}`;
      return block(errorPage(req, 401, { zh: "需要登录", en: "OAuth Login Required" },
        { zh: `该资源需要通过 ${providerName} 账号登录后才能下载。`, en: `This resource requires ${providerName} login.` },
        { siteTitle: settings.siteTitle, oauth_login_url: startUrl }));
    }
  }

  if (await isTurnstileEnabled(env, settings)) {
    const url = new URL(req.url);
    const mode = settings.turnstileMode;
    const downloadGate = mode === "on_download" || mode === "both";
    if (downloadGate) {
      const turnstileToken = url.searchParams.get("cf");
      if (!turnstileToken) {
        return block(errorPage(req, 403, { zh: "需要验证码", en: "Turnstile Required" },
          { zh: "请先通过人机验证。", en: "Please complete human verification." },
          { siteTitle: settings.siteTitle }));
      }
      const pass = await verifyTurnstileToken(env, settings, turnstileToken, ip);
      if (!pass) {
        return block(errorPage(req, 403, { zh: "验证码校验失败", en: "Turnstile Failed" },
          { zh: "人机验证未通过。", en: "Human verification failed." },
          { siteTitle: settings.siteTitle }));
      }
    }
  }

  {
    const whitelisted = isAdminWhitelisted(ip, settings.adminIps);
    const usingCode = !!codeRow;
    if (!whitelisted && !usingCode && settings.trafficLimitBytes > 0 && settings.trafficUsedBytes >= settings.trafficLimitBytes) {
      return block(errorPage(req, 503, { zh: "下载已暂停", en: "Downloads Paused" },
        { zh: "本月流量已达预设限额。", en: "Monthly traffic quota reached." },
        { siteTitle: settings.siteTitle }));
    }
  }

  {
    const whitelisted = isAdminWhitelisted(ip, settings.adminIps);
    const usingCode = !!codeRow;
    if (consumesSlot && !whitelisted && !usingCode && settings.maxDownloadsPerIp > 0) {
      const since = settings.countWindowHours > 0 ? Date.now() - settings.countWindowHours * 3600_000 : 0;
      const { c } = (await env.db.prepare(
        "SELECT COUNT(*) AS c FROM download_logs WHERE share_id = ?1 AND ip = ?2 AND created_at > ?3"
      ).bind(token, ip, since).first<{ c: number }>()) ?? { c: 0 };
      if (c >= settings.maxDownloadsPerIp) {
        if (settings.autoBan) {
          const expiresAt = settings.banHours > 0 ? Date.now() + settings.banHours * 3600_000 : null;
          await env.db.prepare(
            `INSERT INTO banned_ips(ip, reason, banned_at, expires_at) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, banned_at = excluded.banned_at, expires_at = excluded.expires_at`
          ).bind(ip, `重复下载「${row.name}」超过 ${settings.maxDownloadsPerIp} 次`, Date.now(), expiresAt).run();
        }
        return block(errorPage(req, 403, { zh: "重复下载被拦截", en: "Duplicate Download Blocked" },
          { zh: `同一 IP 在统计窗口内下载此资源的次数已达上限（${settings.maxDownloadsPerIp} 次）。`,
            en: `This IP has reached the download limit (${settings.maxDownloadsPerIp}).` },
          { siteTitle: settings.siteTitle }));
      }
    }
  }

  // ── 名额已在 claimSession 阶段原子预占 —— streamFile 只负责"没真正发出去时退还"，
  //    存储读失败 / 对象已被删除时退还名额，避免分享被无效请求慢慢锁死（410）。
  return streamFile(req, env, ctx, row, token, "share", consumesSlot, slot.sessionAt, codeRow, codePrepaid, refundIfClaimed);
}

/**
 * GET /d/:id —— 直链下载（独立入口，走 direct_links 表）
 * 轻量鉴权：封禁 → 过期/撤销/次数 → 原子扣次 → 流量限额 → 重复下载
 * 不走密码/Turnstile/OAuth（直链设计就是"拿了就能下"）
 */
export async function handleDirectDownload(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  token: string
): Promise<Response> {
  const ip = clientIp(req);
  const ua = req.headers.get("user-agent") ?? "";
  const country = req.headers.get("cf-ipcountry") ?? "";
  const settings = await getSettings(env);

  const urlCode = new URL(req.url).searchParams.get("code");
  const headerCode = req.headers.get("x-activation-code");
  const activationCode = (urlCode || headerCode || "").trim().toUpperCase() || null;

  const [foundCode, ban, row] = await Promise.all([
    activationCode ? findCodeByString(env, activationCode) : Promise.resolve(null),
    env.db.prepare("SELECT reason, expires_at FROM banned_ips WHERE ip = ?1")
      .bind(ip).first<{ reason: string | null; expires_at: number | null }>(),
    getDirectLink(env, token),
  ]);

  // 同 handleDownload：失效 / 耗尽的激活码不阻断直链下载，忽略并回退到普通通道。
  let codeRow = foundCode && checkCodeUsable(foundCode as any).ok ? foundCode : null;

  if (ban) {
    if (ban.expires_at && ban.expires_at < Date.now()) {
      env.db.prepare("DELETE FROM banned_ips WHERE ip = ?1").bind(ip).run().catch(() => {});
    } else {
      return errorPage(req, 403, { zh: "访问已被封禁", en: "Access Banned" },
        { zh: ban.reason || "该 IP 已被暂时封禁。", en: ban.reason || "This IP has been banned." });
    }
  }

  if (!row) return errorPage(req, 404, { zh: "直链不存在", en: "Not Found" },
    { zh: "该直链无效或已被管理员删除。", en: "Direct link invalid or removed." });
  if (row.revoked) return errorPage(req, 410, { zh: "直链已失效", en: "Link Revoked" },
    { zh: "该直链已被撤销。", en: "Direct link revoked." });
  if (row.expires_at && row.expires_at < Date.now()) return errorPage(req, 410, { zh: "直链已过期", en: "Link Expired" },
    { zh: "该直链已超过有效期。", en: "Direct link expired." });
  // 历史脏数据兜底（同 handleDownload）
  await resolveFileSize(env, ctx, row);
  // 激活码额度同步预扣（同 handleDownload；不足则回退普通通道门禁）
  let codePrepaid = 0;
  {
    const paid = await prepayCodeQuota(env, req, row.size, codeRow);
    codeRow = paid.row;
    codePrepaid = paid.bytes;
  }
  // ── 同 handleDownload：HEAD / 单字节探测 / 同一会话内的分片与续传不占名额，
  //    只有"开启新下载会话"的那一次计次（详见 handleDownload 与 evaluateDownloadSlot 注释）
  const slot = await evaluateDownloadSlot(env, req, token, ip, row.size, row.max_downloads, "direct");
  const consumesSlot = slot.consumesSlot;
  // 门禁拦截时退还刚预占的名额（同 handleDownload）。
  const refundIfClaimed = async (): Promise<void> => {
    if (slot.claimed) await refundSlot(env, "direct_links", token, ip, slot.sessionAt);
  };
  // 门禁拦截时退还预扣的激活码额度（同 handleDownload）
  const refundCodePrepaid = async (): Promise<void> => {
    if (codeRow && codePrepaid > 0) await refundQuota(env, codeRow.id, codePrepaid);
  };
  const block = async (resp: Response): Promise<Response> => {
    await refundIfClaimed();
    await refundCodePrepaid();
    return resp;
  };

  // 同 handleDownload：`admitted=false` 由 claimSession 原子判定（实时名额 + 会话预算），
  // 不能依赖上面查到的（并发下已过期的）row.download_count。
  if (!slot.admitted)
    return block(errorPage(req, 410, { zh: "下载次数已达上限", en: "Download Limit Reached" },
      { zh: row.max_downloads
        ? `该直链允许下载 ${row.max_downloads} 次，名额已用完。`
        : "该直链本次下载名额已用完，请稍后重试。",
        en: row.max_downloads
          ? `Download limit (${row.max_downloads}) reached.`
          : "The download quota for this session is used up. Please retry later." }));

  // ⚠️ 同 handleDownload：名额已在 claimSession 阶段预占，失败路径统一退还。

  {
    const whitelisted = isAdminWhitelisted(ip, settings.adminIps);
    const usingCode = !!codeRow;
    if (!whitelisted && !usingCode && settings.trafficLimitBytes > 0 && settings.trafficUsedBytes >= settings.trafficLimitBytes) {
      return block(errorPage(req, 503, { zh: "下载已暂停", en: "Downloads Paused" },
        { zh: "本月流量已达预设限额。", en: "Monthly traffic quota reached." },
        { siteTitle: settings.siteTitle }));
    }
  }

  {
    const whitelisted = isAdminWhitelisted(ip, settings.adminIps);
    const usingCode = !!codeRow;
    if (consumesSlot && !whitelisted && !usingCode && settings.maxDownloadsPerIp > 0) {
      const since = settings.countWindowHours > 0 ? Date.now() - settings.countWindowHours * 3600_000 : 0;
      const { c } = (await env.db.prepare(
        "SELECT COUNT(*) AS c FROM download_logs WHERE share_id = ?1 AND ip = ?2 AND created_at > ?3"
      ).bind(token, ip, since).first<{ c: number }>()) ?? { c: 0 };
      if (c >= settings.maxDownloadsPerIp) {
        if (settings.autoBan) {
          const expiresAt = settings.banHours > 0 ? Date.now() + settings.banHours * 3600_000 : null;
          await env.db.prepare(
            `INSERT INTO banned_ips(ip, reason, banned_at, expires_at) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, banned_at = excluded.banned_at, expires_at = excluded.expires_at`
          ).bind(ip, `重复下载直链「${row.name}」超过 ${settings.maxDownloadsPerIp} 次`, Date.now(), expiresAt).run();
        }
        return block(errorPage(req, 403, { zh: "重复下载被拦截", en: "Duplicate Download Blocked" },
          { zh: `同一 IP 在统计窗口内下载此资源的次数已达上限。`, en: `IP download limit reached.` },
          { siteTitle: settings.siteTitle }));
      }
    }
  }

  // ── 名额已在 claimSession 阶段原子预占 —— streamFile 只负责"没真正发出去时退还"
  return streamFile(req, env, ctx, row, token, "direct", consumesSlot, slot.sessionAt, codeRow, codePrepaid, refundIfClaimed);
}

/* ════════════════════════════════════════════════════════════════════
 * streamFile —— 共享的"从存储后端读取 → 流式输出 → 后台记日志"逻辑
 * handleDownload（分享链接）和 handleDirectDownload（直链）共用此函数
 * ════════════════════════════════════════════════════════════════════ */

interface StreamFileRow {
  file_id: string;
  key: string;
  name: string;
  size: number;
  mime: string;
  download_name?: string | null;
}

async function streamFile(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  row: StreamFileRow,
  token: string,
  kind: "share" | "direct",
  countAsDownload: boolean,
  /** 本次请求所属会话的创建时间（退款/退还字节时精确匹配，避免记到别的会话上） */
  sessionAt: number | null,
  /** 本次请求使用的激活码（已通过 checkCodeUsable；null = 未使用 / 额度不足回退普通通道） */
  codeRow: ActivationCodeRow | null,
  /** 已在响应发出前同步预扣的激活码额度（字节）；HEAD / 416 / 额度不足时为 0 */
  codePrepaid: number,
  /** 存储读失败 / 对象已被删除时调用：退还预占的下载名额（HEAD 等未占名额的请求内部会自行短路） */
  onAbort?: () => Promise<void>
): Promise<Response> {
  const ip = clientIp(req);
  const ua = req.headers.get("user-agent") ?? "";
  const country = req.headers.get("cf-ipcountry") ?? "";
  const settings = await getSettings(env);
  const isHead = req.method === "HEAD";

  // 存储读失败 / 对象不存在 → 退还预占的名额与已预扣的激活码额度（还没发出任何字节）
  const abortAll = async (): Promise<void> => {
    await onAbort?.();
    if (codeRow && codePrepaid > 0) await refundQuota(env, codeRow.id, codePrepaid);
  };

  // HEAD 请求只返回元数据（不读对象内容、不计流量、不写日志），用 head() 走轻量路径。
  let totalSize = row.size;
  let contentType = row.mime || "application/octet-stream";
  let etag = `"${row.file_id}"`;
  let body: ReadableStream<Uint8Array> | null = null;
  let range: { offset: number; length: number } | null = null;
  try {
    const st = await storage(env);
    // 历史脏数据兜底：早期 WebDAV / S3 流式上传会漏记 size（留成 0）。若直接按 0 计算，
    // content-length 会是 0，浏览器把文件当成空文件 —— 表现就是"下载下来是空的 / 下不动"。
    // 这里先向存储要真实大小并顺手回写 D1，让老文件也能正常下载。
    if (!isHead && totalSize <= 0) {
      const meta = await st.head(row.key).catch(() => null);
      if (meta && meta.size > 0) {
        totalSize = meta.size;
        ctx.waitUntil(
          env.db
            .prepare("UPDATE files SET size = ?1 WHERE id = ?2 AND size <= 0")
            .bind(totalSize, row.file_id)
            .run()
            .catch(() => {})
        );
      }
    }
    range = parseRange(req.headers.get("range"), totalSize);
    // Range 起点越过末尾 / 非法后缀 → 必须 416，绝不能回 200 + 整份文件
    // （否则断点续传的下载器会把整份文件追加到已下内容后面，得到损坏的超大文件）
    if (isUnsatisfiableRange(req.headers.get("range"), totalSize)) {
      await abortAll();
      return new Response(null, {
        status: 416,
        headers: {
          "content-range": `bytes */${totalSize}`,
          "accept-ranges": "bytes",
          "cache-control": "no-store",
        },
      });
    }
    if (isHead) {
      const meta = await st.head(row.key);
      if (!meta) {
        await abortAll();
        return errorPage(req, 404, { zh: "文件不存在", en: "File Not Found" },
          { zh: "文件可能已被删除。", en: "File may have been deleted." });
      }
      contentType = meta.contentType || contentType;
      if (totalSize <= 0) totalSize = meta.size;
    } else {
      const obj = await st.get(row.key, range ? { offset: range.offset, length: range.length } : undefined);
      if (!obj) {
        await abortAll();
        return errorPage(req, 404, { zh: "文件不存在", en: "File Not Found" },
          { zh: "文件可能已被删除。", en: "File may have been deleted." });
      }
      contentType = obj.contentType;
      etag = obj.etag;
      body = obj.body;
    }
  } catch (err: any) {
    console.error(`[download] storage error (${kind}):`, err);
    await abortAll();
    return errorPage(req, 502, { zh: "存储服务错误", en: "Storage Error" },
      { zh: "无法从存储后端读取文件。", en: "Cannot read file from storage." });
  }
  const servedLen = range ? range.length : totalSize;

  const headers = new Headers();
  headers.set("content-type", contentType);
  headers.set("etag", etag);
  headers.set("accept-ranges", "bytes");
  headers.set("cache-control", "no-store");
  const displayName = row.download_name || row.name;
  headers.set("content-disposition", `attachment; filename*=UTF-8''${encodeURIComponent(displayName)}`);
  const { addSecurityHeaders } = await import("./pages");
  addSecurityHeaders(headers, { isDownload: true });
  headers.set("content-length", String(servedLen));
  if (range) {
    headers.set("content-range", `bytes ${range.offset}-${range.offset + servedLen - 1}/${totalSize}`);
  }

  // ── 会话字节预算 ────────────────────────────────────────────────
  // claimSession 已在响应发出前**同步预占**了本次请求要发送的字节（`reserved = servedLen`），
  // 所以这里不再累加（累加会双重计数，导致合法的一次完整下载被算成两份、预算半途耗尽）。
  // 这里只做一件事：客户端中途断开 / 流读取失败时，把「预占但没真正发出去」的字节退还，
  // 避免 Air bytes 占着预算把正常用户锁死（重新下载/断点续传时被误判成第二份拷贝 → 410）。
  if (!isHead && body) {
    const reserved = servedLen;
    body = trackSentBytes(body, (sent, complete) => {
      const unsent = reserved - sent;
      if (complete || unsent <= 0) return;
      if (sessionAt !== null) ctx.waitUntil(releaseSessionBytes(env, token, ip, unsent, sessionAt));
      // 激活码额度同样是"预扣"的：客户端断流时退还「预扣但没发出去」的部分
      if (codeRow && codePrepaid > 0) ctx.waitUntil(refundQuota(env, codeRow.id, Math.min(unsent, codePrepaid)));
    });
  }

  // 后台记账：仅在真正把文件发出去时进行（HEAD 不计流量、不写日志）。
  //   · 流量按实际发送字节累加（续传分片也要计带宽）；
  //   · 下载记录 / 分析数据点只在「新下载」时写（续传复用同一次下载名额，不重复计数）；
  //   · 激活码额度已在响应发出前同步预扣，这里不再重复扣减。
  if (!isHead) {
    const bytes = servedLen;
    const codeId = codeRow ? codeRow.code : null;
    ctx.waitUntil(
      (async () => {
        const { browser, os } = parseUA(ua);

        await addTraffic(env, bytes);

        if (!countAsDownload) return;

        if (env.analytics) {
          try {
            const latitude = req.headers.get("cf-ip-latitude") ?? "";
            const longitude = req.headers.get("cf-ip-longitude") ?? "";
            env.analytics.writeDataPoint({
              blobs: [
                country, row.name, browser, os, token,
                codeId ?? "none", latitude, longitude,
                settings.storageProvider || "r2",
              ],
              doubles: [bytes, 1],
              indexes: [token],
            });
          } catch { /* ignore */ }
        }

        await env.db.prepare(
          `INSERT INTO download_logs(share_id, file_id, file_name, ip, ua, browser, os, country, bytes, created_at, activation_code)
           VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
        )
          // 直链也记 download_logs —— share_id 字段存 direct link token 方便追踪
          .bind(token, row.file_id, row.name, ip, ua.slice(0, 500), browser, os, country, bytes, Date.now(), codeId)
          .run();
      })()
    );
  }

  return new Response(body, { status: range ? 206 : 200, headers });
}

/* ════════════════════════════════════════════════════════════════════
 * 在线预览端点
 *   GET /s/:token/preview       —— 打开一次预览：门禁校验 + 预览次数原子自增，返回元信息与令牌化 URL
 *   GET /s/:token/preview/raw   —— 内联流式返回原始文件（支持 Range，供图片/视频/音频/PDF/文本渲染）
 *   GET /s/:token/preview/zip   —— 解析 ZIP 中央目录，返回压缩包内部文件结构
 *
 * 与下载完全独立：预览次数为「全站共用」的月度总额度（settings.previewLimit），
 * 所有分享共享同一份并跨月自动重置；不写入 download_logs、不消耗下载次数；
 * 但会累计月度流量（带宽成本一致），且预览流同样受月度流量限额约束。
 * ════════════════════════════════════════════════════════════════════ */

/** 读取存储对象的一段字节（用于解析 ZIP 中央目录）；失败返回 null */
async function readRange(env: Env, key: string, offset: number, length: number): Promise<Uint8Array | null> {
  try {
    const st = await storage(env);
    const obj = await st.get(key, { offset, length });
    if (!obj) return null;
    const buf = await new Response(obj.body).arrayBuffer();
    return new Uint8Array(buf);
  } catch {
    return null;
  }
}

interface ZipEntry {
  name: string;
  size: number;
  compressed_size: number;
  is_dir: boolean;
}

/** 解析 ZIP 内部结构（读取末尾 EOCD + 中央目录；支持 ZIP64 与分片读取） */
async function parseZipEntries(env: Env, key: string, size: number): Promise<{ entries: ZipEntry[]; truncated: boolean } | { error: string }> {
  const tailLen = Math.min(size, 22 + 65535);
  const tailOffset = Math.max(0, size - tailLen);
  const tail = await readRange(env, key, tailOffset, tailLen);
  if (!tail) return { error: "read_error" };

  // 从后往前定位 EOCD 签名 0x06054b50
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail[i] === 0x50 && tail[i + 1] === 0x4b && tail[i + 2] === 0x05 && tail[i + 3] === 0x06) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return { error: "not_zip" };

  const dv = new DataView(tail.buffer, tail.byteOffset, tail.byteLength);
  let totalEntries = dv.getUint16(eocd + 10, true);
  let cdSize = dv.getUint32(eocd + 12, true);
  let cdOffset = dv.getUint32(eocd + 16, true);

  // ZIP64：字段为占位符 0xFFFFFFFF / 0xFFFF 时，读 ZIP64 EOCD 记录
  if (cdOffset === 0xFFFFFFFF || cdSize === 0xFFFFFFFF || totalEntries === 0xFFFF) {
    const loc = eocd - 20;
    if (loc >= 0 && tail[loc] === 0x50 && tail[loc + 1] === 0x4b && tail[loc + 2] === 0x06 && tail[loc + 3] === 0x07) {
      const z64Rel = Number(dv.getBigUint64(loc + 8, true));
      const z64 = await readRange(env, key, z64Rel, 56);
      if (z64) {
        const zdv = new DataView(z64.buffer, z64.byteOffset, z64.byteLength);
        if (z64.byteLength >= 56 && zdv.getUint32(0, true) === 0x06064b50) {
          totalEntries = Number(zdv.getBigUint64(32, true));
          cdSize = Number(zdv.getBigUint64(40, true));
          cdOffset = Number(zdv.getBigUint64(48, true));
        }
      }
    }
    if (cdOffset === 0xFFFFFFFF) return { error: "zip64_unsupported" };
  }

  // 读取中央目录（上限 2MB，超大目录只解析前一部分）
  const MAX_CD = 2 * 1024 * 1024;
  const cdReadLen = Math.min(cdSize, MAX_CD);
  const truncated = cdSize > cdReadLen;
  const cd = await readRange(env, key, cdOffset, cdReadLen);
  if (!cd) return { error: "read_error" };

  const cv = new DataView(cd.buffer, cd.byteOffset, cd.byteLength);
  const entries: ZipEntry[] = [];
  const MAX_ENTRIES = 800;
  let p = 0;
  while (p + 46 <= cd.byteLength) {
    if (cv.getUint32(p, true) !== 0x02014b50) break; // 中央目录文件头签名
    let compSize = cv.getUint32(p + 20, true);
    let uncompSize = cv.getUint32(p + 24, true);
    const nameLen = cv.getUint16(p + 28, true);
    const extraLen = cv.getUint16(p + 30, true);
    const commentLen = cv.getUint16(p + 32, true);
    let name = "";
    try {
      name = new TextDecoder("utf-8").decode(cd.subarray(p + 46, p + 46 + nameLen));
    } catch {
      name = "";
    }
    // ZIP64 extra（id=0x0001）：size 字段为 0xFFFFFFFF 时从扩展区读取
    if (uncompSize === 0xFFFFFFFF || compSize === 0xFFFFFFFF) {
      let ep = p + 46 + nameLen;
      const epEnd = ep + extraLen;
      while (ep + 4 <= epEnd) {
        const hid = cv.getUint16(ep, true);
        const hsz = cv.getUint16(ep + 2, true);
        if (hid === 0x0001) {
          let q = ep + 4;
          if (uncompSize === 0xFFFFFFFF && q + 8 <= ep + 4 + hsz) { uncompSize = Number(cv.getBigUint64(q, true)); q += 8; }
          if (compSize === 0xFFFFFFFF && q + 8 <= ep + 4 + hsz) { compSize = Number(cv.getBigUint64(q, true)); q += 8; }
          break;
        }
        ep += 4 + hsz;
      }
    }
    entries.push({ name, size: uncompSize, compressed_size: compSize, is_dir: name.endsWith("/") });
    if (entries.length >= MAX_ENTRIES) return { entries, truncated: true };
    p += 46 + nameLen + extraLen + commentLen;
  }
  return { entries, truncated };
}

/**
 * GET /s/:token/preview —— 打开预览（全站月度总额度计 1 次）。
 * 门禁与下载一致：撤销/过期/满额/密码/OAuth/Turnstile/流量限额/激活码。
 * 成功后原子消费一次全站预览额度，超限则拒绝（自动停止预览）。
 */
export async function handlePreviewOpen(req: Request, env: Env, token: string): Promise<Response> {
  const settings = await getSettings(env);
  const ip = clientIp(req);
  const url = new URL(req.url);
  const codeParam = (url.searchParams.get("code") || req.headers.get("x-activation-code") || "").trim().toUpperCase() || null;

  const [row, codeRow] = await Promise.all([
    getShare(env, token),
    codeParam ? findCodeByString(env, codeParam) : Promise.resolve(null),
  ]);

  if (!row) return json({ ok: false, error: "not_found" }, { status: 404 });
  if (row.revoked) return json({ ok: false, error: "gone" }, { status: 410 });
  if (row.expires_at && row.expires_at < Date.now()) return json({ ok: false, error: "expired" }, { status: 410 });
  if (row.max_downloads && row.download_count >= row.max_downloads) return json({ ok: false, error: "maxed" }, { status: 410 });

  const kind = previewKind(row.mime, row.name);
  if (kind === "none") return json({ ok: false, error: "not_previewable" }, { status: 415 });

  // 访问密码：复用下载授权令牌 t（由 /verify 颁发）
  if (row.password_hash && !(await verifyShareToken(env, token, url.search))) {
    return json({ ok: false, error: "password_required" }, { status: 401 });
  }

  // OAuth2 登录校验
  if (settings.oauthEnabled) {
    const oauthResult = await verifyOAuthSession(env, req.headers.get("cookie"));
    if (!oauthResult.ok) return json({ ok: false, error: "oauth_required" }, { status: 401 });
  }

  // Turnstile（on_download / both 模式需要 cf 令牌）
  if (await isTurnstileEnabled(env, settings)) {
    const mode = settings.turnstileMode;
    if (mode === "on_download" || mode === "both") {
      const tsToken = url.searchParams.get("cf");
      if (!tsToken || !(await verifyTurnstileToken(env, settings, tsToken, ip))) {
        return json({ ok: false, error: "turnstile_required" }, { status: 403 });
      }
    }
  }

  // 月度流量限额（白名单 IP / 有效激活码不受限）
  {
    const whitelisted = isAdminWhitelisted(ip, settings.adminIps);
    const usingCode = !!codeRow && checkCodeUsable(codeRow as any).ok;
    if (!whitelisted && !usingCode && settings.trafficLimitBytes > 0 && settings.trafficUsedBytes >= settings.trafficLimitBytes) {
      return json({ ok: false, error: "traffic_exceeded" }, { status: 503 });
    }
  }

  // 全站月度预览总额度 —— 所有分享共用同一份，原子自增，超限即止（跨月自动重置）
  const quota = await consumePreviewQuota(env, settings.previewLimit);
  if (!quota.ok) {
    return json(
      { ok: false, error: "preview_limit_reached", limit: quota.limit, used: quota.limit, remaining: 0 },
      { status: 429 }
    );
  }

  const pv = await issuePreviewToken(env, token);
  const remaining = quota.limit > 0 ? Math.max(0, quota.limit - quota.used) : -1;
  const codeSuffix = codeParam ? `&code=${encodeURIComponent(codeParam)}` : "";
  return json({
    ok: true,
    kind,
    name: row.download_name || row.name,
    size: row.size,
    mime: row.mime,
    limit: quota.limit,
    used: quota.used,
    remaining,
    raw_url: `/s/${token}/preview/raw?pv=${encodeURIComponent(pv)}${codeSuffix}`,
    zip_url: kind === "zip" ? `/s/${token}/preview/zip?pv=${encodeURIComponent(pv)}` : null,
  });
}

/** GET /s/:token/preview/raw —— 内联流式预览（Range 支持），不重复计次 */
export async function handlePreviewRaw(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  token: string
): Promise<Response> {
  const row = await getShare(env, token);
  if (!row) return json({ error: "not_found" }, { status: 404 });
  const url = new URL(req.url);
  if (!(await verifyPreviewToken(env, token, url.search))) {
    return json({ error: "unauthorized" }, { status: 403 });
  }

  // 分享状态门禁：预览令牌有效期 1h，期间分享可能被撤销/过期/满额，必须一并拦截
  if (row.revoked) return json({ error: "gone" }, { status: 410 });
  if (row.expires_at && row.expires_at < Date.now()) return json({ error: "expired" }, { status: 410 });
  if (row.max_downloads && row.download_count >= row.max_downloads) return json({ error: "maxed" }, { status: 410 });

  const codeParam = (url.searchParams.get("code") || req.headers.get("x-activation-code") || "").trim().toUpperCase() || null;
  let codeRow = codeParam ? await findCodeByString(env, codeParam) : null;
  // 预览同样要按真实大小计算 Range / 额度（历史脏数据 size=0 时不能把整份文件当成空）
  await resolveFileSize(env, ctx, row);
  const range = parseRange(req.headers.get("range"), row.size);
  // 激活码额度同步预扣：额度不足以覆盖本次预览字节时回退普通通道（受月度流量限额约束），
  // 否则一个额度不够的码会变成永久免费通行证（同 handleDownload）。
  let codePrepaid = 0;
  {
    // 注意：预览对非法 Range 不做 416，而是回退成整份文件（200），所以这里按实际发送量预扣
    const need = range ? range.length : row.size;
    if (codeRow && need > 0) {
      await activateCodeIfNeeded(env, codeRow).catch(() => {});
      const dr = await deductQuota(env, codeRow, need);
      if (dr.ok) codePrepaid = need;
      else {
        console.warn(`[preview-code-prepay-decline] code=${codeRow.code} reason=${dr.reason}`);
        codeRow = null;
      }
    }
  }
  const refundCode = async (): Promise<void> => {
    if (codeRow && codePrepaid > 0) await refundQuota(env, codeRow.id, codePrepaid);
  };

  // 月度流量限额：预览同样消耗带宽，超限时必须停止，否则持有有效令牌可持续刷流量
  {
    const settings = await getSettings(env);
    const whitelisted = isAdminWhitelisted(clientIp(req), settings.adminIps);
    const usingCode = !!codeRow;
    if (!whitelisted && !usingCode && settings.trafficLimitBytes > 0 && settings.trafficUsedBytes >= settings.trafficLimitBytes) {
      await refundCode();
      return json({ error: "traffic_exceeded" }, { status: 503 });
    }
  }

  let obj;
  try {
    const st = await storage(env);
    obj = await st.get(row.key, range ? { offset: range.offset, length: range.length } : undefined);
  } catch (err: any) {
    console.error("[preview] storage error:", err);
    await refundCode();
    return json({ error: "storage_error" }, { status: 502 });
  }
  if (!obj) {
    await refundCode();
    return json({ error: "not_found" }, { status: 404 });
  }

  const headers = new Headers();
  headers.set("content-type", row.mime || obj.contentType || "application/octet-stream");
  const displayName = row.download_name || row.name;
  headers.set("content-disposition", `inline; filename*=UTF-8''${encodeURIComponent(displayName)}`);
  headers.set("etag", obj.etag);
  headers.set("accept-ranges", "bytes");
  headers.set("cache-control", "private, max-age=60");
  const { addSecurityHeaders } = await import("./pages");
  addSecurityHeaders(headers, { isDownload: true });
  const servedLen = range ? range.length : obj.size;
  headers.set("content-length", String(servedLen));
  if (range) headers.set("content-range", `bytes ${range.offset}-${range.offset + servedLen - 1}/${row.size}`);

  // 预览同样消耗带宽 → 计入月度流量；激活码额度已在响应发出前同步预扣。
  // 客户端中途断开时，把「预扣但没发出去」的额度退回（否则额度会被空气流量吃掉）。
  ctx.waitUntil(addTraffic(env, servedLen));
  let stream = obj.body;
  if (codeRow && codePrepaid > 0) {
    stream = trackSentBytes(obj.body, (sent, complete) => {
      const unsent = codePrepaid - sent;
      if (!complete && unsent > 0) ctx.waitUntil(refundQuota(env, codeRow!.id, unsent));
    });
  }

  return new Response(stream, { status: range ? 206 : 200, headers });
}

/** GET /s/:token/preview/zip —— 返回 ZIP 内部文件结构 */
export async function handlePreviewZip(req: Request, env: Env, token: string): Promise<Response> {
  const row = await getShare(env, token);
  if (!row) return json({ error: "not_found" }, { status: 404 });
  if (row.revoked) return json({ error: "gone" }, { status: 410 });
  if (row.expires_at && row.expires_at < Date.now()) return json({ error: "expired" }, { status: 410 });
  if (previewKind(row.mime, row.name) !== "zip") return json({ ok: false, error: "not_zip" }, { status: 415 });
  if (!(await verifyPreviewToken(env, token, new URL(req.url).search))) {
    return json({ error: "unauthorized" }, { status: 403 });
  }
  const res = await parseZipEntries(env, row.key, row.size);
  if ("error" in res) return json({ ok: false, error: res.error }, { status: 400 });
  return json({ ok: true, entries: res.entries, truncated: res.truncated });
}
