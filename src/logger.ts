import type { Env } from "./types";

export interface LogEntry {
  id?: number;
  level: "error" | "warn" | "info";
  source: "server" | "client";
  tag: string;
  message: string;
  stack?: string;
  url?: string;
  method?: string;
  ip?: string;
  ua?: string;
  extra?: string;
  created_at?: number;
}

/**
 * 写一条错误日志到 D1（返回 Promise）。
 *
 * 调用方负责决定是否 await / ctx.waitUntil：
 *   - 在 catch 块里：`await logError(env, {...})` —— 同步写入，保证不会丢
 *   - 在主流程里不想阻塞：`ctx.waitUntil(logError(env, {...}))`
 *   - 绝对不能 fire-and-forget（裸 Promise 不执行）
 */
export async function logError(
  env: Env,
  entry: Omit<LogEntry, "level" | "source" | "created_at"> & Partial<Pick<LogEntry, "level" | "source">>
): Promise<void> {
  try {
    if (!env.db) return;

    const enabled = await isLoggingEnabled(env);
    if (!enabled) return;

    const log: LogEntry = {
      level: entry.level ?? "error",
      source: entry.source ?? "server",
      tag: entry.tag,
      message: entry.message.slice(0, 500),
      stack: entry.stack?.slice(0, 2000),
      url: entry.url?.slice(0, 300),
      method: entry.method,
      ip: entry.ip,
      ua: entry.ua?.slice(0, 500),
      extra: entry.extra?.slice(0, 2000),
      created_at: Date.now(),
    };

    await env.db.prepare(
      `INSERT INTO error_logs (level, source, tag, message, stack, url, method, ip, ua, extra, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
    ).bind(
      log.level, log.source, log.tag, log.message, log.stack ?? null,
      log.url ?? null, log.method ?? null, log.ip ?? null, log.ua ?? null,
      log.extra ?? null, log.created_at
    ).run();

    // 裁剪保护（异步，不阻塞主写入）
    trimOldLogs(env).catch(() => {});
  } catch {
    // 日志自己不能抛
  }
}

let loggingEnabledCache: boolean | null = null;
let loggingCacheTs = 0;
const LOG_CACHE_TTL_MS = 15_000;

async function isLoggingEnabled(env: Env): Promise<boolean> {
  const now = Date.now();
  if (loggingEnabledCache !== null && now - loggingCacheTs < LOG_CACHE_TTL_MS) {
    return loggingEnabledCache;
  }
  try {
    const row: any = await env.db.prepare(
      "SELECT value FROM settings WHERE key = 'error_logging_enabled'"
    ).first();
    loggingEnabledCache = !row || row.value === "1";
    loggingCacheTs = now;
    return loggingEnabledCache;
  } catch {
    loggingEnabledCache = true;
    loggingCacheTs = now;
    return true;
  }
}

const MAX_LOG_ROWS = 10_000;
let lastTrimTs = 0;
const TRIM_INTERVAL_MS = 60_000;

async function trimOldLogs(env: Env): Promise<void> {
  const now = Date.now();
  if (now - lastTrimTs < TRIM_INTERVAL_MS) return;
  lastTrimTs = now;
  try {
    const row: any = await env.db.prepare("SELECT COUNT(*) AS c FROM error_logs").first();
    if (row && row.c > MAX_LOG_ROWS) {
      await env.db.prepare(
        `DELETE FROM error_logs WHERE id IN (
          SELECT id FROM error_logs ORDER BY id ASC LIMIT ?1
        )`
      ).bind(row.c - MAX_LOG_ROWS).run();
    }
  } catch { /* ignore */ }
}

export function invalidateLogCache(): void {
  loggingEnabledCache = null;
}

export function extractError(e: unknown): { message: string; stack?: string } {
  if (e instanceof Error) return { message: e.message || String(e), stack: e.stack };
  return { message: String(e) };
}
