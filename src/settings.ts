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
 * ── Bug #2 修复：消除 read-compute-write 竞态 ──
 * 旧实现先读 traffic_used_bytes，在 JS 里加 bytes，再写回；并发下载时多个请求读到相同值，
 * 最终只累加到最大值 + 1，造成严重漏记。
 *
 * 新实现：
 *   1. 单次 SELECT 检测 traffic_month 是否匹配当月
 *   2. 同月 → UPDATE ... SET value = CAST(CAST(value AS INTEGER) + ? AS TEXT)  （数据库原子累加）
 *      跨月 → INSERT ... ON CONFLICT DO UPDATE SET value = excluded.value       （重置为 bytes）
 *   3. traffic_stats 原本就是原子累加，保持不变
 *
 * 整个写路径不再依赖任何预先读到的 Settings 对象，并发安全。
 */
export async function addTraffic(env: Env, bytes: number): Promise<void> {
  const now = new Date();
  const month = now.toISOString().slice(0, 7);
  const day = now.toISOString().slice(0, 10);

  // 单次查询检测是否跨月
  const row = await env.db.prepare(
    "SELECT value FROM settings WHERE key = 'traffic_month'"
  ).first<{ value: string }>();
  const crossMonth = !row || row.value !== month;

  // 根据检测结果选择原子写入策略
  const trafficUsedStmt = crossMonth
    ? env.db.prepare(
        "INSERT INTO settings(key, value) VALUES('traffic_used_bytes', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
      ).bind(String(bytes))
    : env.db.prepare(
        "UPDATE settings SET value = CAST(CAST(value AS INTEGER) + ?1 AS TEXT) WHERE key = 'traffic_used_bytes'"
      ).bind(String(bytes));

  await env.db.batch([
    env.db.prepare(
      "INSERT INTO settings(key, value) VALUES('traffic_month', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ).bind(month),
    trafficUsedStmt,
    env.db.prepare(
      "INSERT INTO traffic_stats(day, bytes, downloads) VALUES(?1, ?2, 1) ON CONFLICT(day) DO UPDATE SET bytes = bytes + excluded.bytes, downloads = downloads + excluded.downloads"
    ).bind(day, bytes),
  ]);
}
