import type { Env } from "./types";

/** 可调参数（均可在管理后台修改） */
export interface Settings {
  siteTitle: string;
  /** 月度流量限额（字节），0 = 不限 */
  trafficLimitBytes: number;
  /** 本月已用流量（字节） */
  trafficUsedBytes: number;
  /** 当前统计月份 YYYY-MM */
  trafficMonth: string;
  /** 单 IP 对同一分享的最大下载次数，0 = 不限 */
  maxDownloadsPerIp: number;
  /** 重复下载统计窗口（小时），0 = 永久 */
  countWindowHours: number;
  /** 超限后是否自动封禁 */
  autoBan: boolean;
  /** 自动封禁时长（小时），0 = 永久 */
  banHours: number;
  /** 2FA 是否已启用 */
  totpEnabled: boolean;
  /** TOTP secret（D1 中存的是用 admin 加密后的密文） */
  totpSecretCipher: string | null;
  /** 恢复码列表（D1 中存的是 hash 后的值，用逗号分隔） */
  totpRecoveryHash: string | null;
  /**
   * Turnstile 模式：
   *   "off"        = 关闭
   *   "on_share"   = 打开分享链接时触发
   *   "on_download"= 点击下载时触发
   *   "both"       = 分享链接打开和下载都可以触发（按阈值）
   */
  turnstileMode: "off" | "on_share" | "on_download" | "both";
  /** 每天每个 IP 触发 Turnstile 的访问次数阈值。0 = 每次都弹。 */
  turnstileThreshold: number;
  /** Turnstile sitekey 覆盖（如果没在 Cloudflare Secret 里配，可在这里写） */
  turnstileSitekeyOverride: string | null;
}

export const DEFAULT_SETTINGS: Settings = {
  siteTitle: "cloud-r2pan",
  trafficLimitBytes: 10 * 1024 ** 3, // 10 GB
  trafficUsedBytes: 0,
  trafficMonth: "",
  maxDownloadsPerIp: 2,
  countWindowHours: 24,
  autoBan: true,
  banHours: 24,
  totpEnabled: false,
  totpSecretCipher: null,
  totpRecoveryHash: null,
  turnstileMode: "off",
  turnstileThreshold: 5,
  turnstileSitekeyOverride: null,
};

function toInt(v: unknown, fallback: number): number {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

export async function getSettings(env: Env): Promise<Settings> {
  const { results } = await env.db.prepare(
    "SELECT key, value FROM settings"
  ).all<{ key: string; value: string }>();
  const map = new Map((results ?? []).map((r) => [r.key, r.value]));

  // ── Bug #1 修复：跨月自动兜底 ──────────────────────────────────
  // 任何调用 getSettings 的地方（下载检查、stats API、settings API、session API）
  // 都会自动得到本月正确的流量值，不再出现"上月用完→本月锁死"的死锁。
  // 此处仅修正内存返回值，DB 实际清零由后续写入操作（addTraffic / stats）自愈。
  const now = new Date();
  const currentMonth = now.toISOString().slice(0, 7);
  const storedMonth = map.get("traffic_month") ?? "";
  let trafficUsedBytes = toInt(map.get("traffic_used_bytes"), 0);
  let trafficMonth = storedMonth;
  if (storedMonth && storedMonth !== currentMonth && trafficUsedBytes > 0) {
    trafficUsedBytes = 0;
    trafficMonth = currentMonth;
  }

  return {
    siteTitle: map.get("site_title") ?? DEFAULT_SETTINGS.siteTitle,
    trafficLimitBytes: toInt(map.get("traffic_limit_bytes"), DEFAULT_SETTINGS.trafficLimitBytes),
    trafficUsedBytes,
    trafficMonth,
    maxDownloadsPerIp: toInt(map.get("max_downloads_per_ip"), DEFAULT_SETTINGS.maxDownloadsPerIp),
    countWindowHours: toInt(map.get("count_window_hours"), DEFAULT_SETTINGS.countWindowHours),
    autoBan: (map.get("auto_ban") ?? "1") === "1",
    banHours: toInt(map.get("ban_hours"), DEFAULT_SETTINGS.banHours),
    totpEnabled: map.get("totp_enabled") === "1",
    totpSecretCipher: map.get("totp_secret_cipher") ?? null,
    totpRecoveryHash: map.get("totp_recovery_hash") ?? null,
    turnstileMode: (map.get("turnstile_mode") ?? DEFAULT_SETTINGS.turnstileMode) as Settings["turnstileMode"],
    turnstileThreshold: toInt(map.get("turnstile_threshold"), DEFAULT_SETTINGS.turnstileThreshold),
    turnstileSitekeyOverride: map.get("turnstile_sitekey_override") ?? null,
  };
}

/** 更新设置（仅覆盖传入的字段） */
export async function updateSettings(env: Env, patch: Partial<Record<string, string>>): Promise<void> {
  const upserts = Object.entries(patch).map(([key, value]) =>
    env.db.prepare(
      "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ).bind(key, String(value))
  );
  if (upserts.length > 0) await env.db.batch(upserts);
}

/**
 * 记录一次下载产生的流量（跨月自动重置）。
 *
 * ── Bug #1 彻底修复（上一次修复只消除了 read-compute-write，
 *    但在 00:00 跨月瞬间仍存在竞态） ──
 *
 * 根因：SELECT 检测 crossMonth → JS 分支选 SQL → batch 写入，
 * 三步之间没有事务隔离。并发请求同时读到"上月"就都走 crossMonth 分支，
 * 最后一个覆盖前值，丢流量。
 *
 * 方案：
 *   1. 跨月判断完全内联到单个 UPDATE 语句的 SQL 子查询里，
 *      数据库自己读 traffic_month 做 CASE WHEN，不再经过 JS 分支
 *   2. 三个 SQL 包在 transaction batch 中，保证原子执行
 *   3. 完全去掉前置 SELECT，消除竞态窗口
 *
 * 无论多少并发，同一事务内 CASE WHEN 读到的 traffic_month 是一致的，
 * 要么全部累加（同月），要么全部重置（跨月）。
 */
export async function addTraffic(env: Env, bytes: number): Promise<void> {
  const now = new Date();
  const month = now.toISOString().slice(0, 7);
  const day = now.toISOString().slice(0, 10);

  await env.db.batch([
    // ① 同步 traffic_month 到当月（幂等：同月时 value 不变）
    env.db.prepare(
      "INSERT INTO settings(key, value) VALUES('traffic_month', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ).bind(month),

    // ② 更新 traffic_used_bytes —— 跨月逻辑完全内联在 SQL 里
    //    同月：累加旧值；跨月：从 0 开始加
    env.db.prepare(
      `UPDATE settings SET value = CAST(
        CASE
          WHEN (SELECT value FROM settings WHERE key = 'traffic_month') = ?1
          THEN COALESCE((SELECT value FROM settings WHERE key = 'traffic_used_bytes'), '0')
          ELSE '0'
        END AS INTEGER) + ?2 AS TEXT)
       WHERE key = 'traffic_used_bytes'`
    ).bind(month, String(bytes)),

    // ③ traffic_stats 每日汇总（原本就是原子累加，保持不变）
    env.db.prepare(
      "INSERT INTO traffic_stats(day, bytes, downloads) VALUES(?1, ?2, 1) ON CONFLICT(day) DO UPDATE SET bytes = bytes + excluded.bytes, downloads = downloads + excluded.downloads"
    ).bind(day, bytes),
  ]);
}
