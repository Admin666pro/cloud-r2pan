import type { Env } from "./types";

/**
 * 数据库初始化 —— 首次请求时自动建表, 无需手动迁移。
 * 表结构:
 *   files              上传到 R2 的文件元数据
 *   shares             分享链接 (token 即主键)
 *   download_logs      下载记录 (IP / 浏览器 / 系统 / 流量)
 *   login_logs         管理员登录记录 (成功/失败/登出, 防盗号审计)
 *   turnstile_visits   IP 每日访问计数 (超过阈值触发 Turnstile)
 *   banned_ips         封禁名单 (支持到期自动解封)
 *   settings           可调参数 + 流量用量统计
 *   traffic_stats      每日流量/下载汇总 (用于图表)
 */
const SCHEMA_STATEMENTS: string[] = [
  `CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    mime TEXT NOT NULL DEFAULT 'application/octet-stream',
    uploaded_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS shares (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    max_downloads INTEGER,
    download_count INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    password_hash TEXT,
    password_cipher TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_shares_file ON shares(file_id)`,
  `CREATE TABLE IF NOT EXISTS download_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL,
    file_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    ip TEXT NOT NULL,
    ua TEXT,
    browser TEXT,
    os TEXT,
    country TEXT,
    bytes INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_logs_share_ip ON download_logs(share_id, ip, created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_logs_created ON download_logs(created_at)`,
  `CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    ip TEXT NOT NULL,
    ua TEXT,
    browser TEXT,
    os TEXT,
    country TEXT,
    result TEXT NOT NULL,
    reason TEXT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_login_logs_created ON login_logs(created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_login_logs_ip ON login_logs(ip)`,
  `CREATE TABLE IF NOT EXISTS turnstile_visits (
    ip TEXT NOT NULL,
    day TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(ip, day)
  )`,
  `CREATE INDEX IF NOT EXISTS idx_turnstile_day ON turnstile_visits(day)`,
  `CREATE TABLE IF NOT EXISTS banned_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    banned_at INTEGER NOT NULL,
    expires_at INTEGER
  )`,
  `CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS traffic_stats (
    day TEXT PRIMARY KEY,
    bytes INTEGER NOT NULL DEFAULT 0,
    downloads INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_oauth_states_expires ON oauth_states(expires_at)`,
  `CREATE TABLE IF NOT EXISTS oauth_providers (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    client_id TEXT NOT NULL DEFAULT '',
    client_secret_cipher TEXT,
    scope TEXT NOT NULL DEFAULT 'openid email profile',
    custom_authorize_url TEXT NOT NULL DEFAULT '',
    custom_token_url TEXT NOT NULL DEFAULT '',
    custom_userinfo_url TEXT NOT NULL DEFAULT '',
    custom_token_field TEXT NOT NULL DEFAULT 'access_token',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_oauth_providers_enabled ON oauth_providers(enabled)`,
];

let schemaReady = false;

/**
 * 确保数据库表结构存在 —— 首次请求时自动建表，无需手动迁移。
 *
 * ── Bug #5 修复：并发 DDL 风险 ──────────────────────────────────
 * 原实现每个 Isolate 都有独立的 schemaReady 布尔，冷启动时多 Isolate 会并发跑 DDL batch，
 * 虽然 CREATE TABLE IF NOT EXISTS 本身幂等，但每次都跑完整 DDL 很重。
 *
 * 新实现分层短路：
 *   1. schemaReady（内存）—— 本 Isolate 内的快速短路，零成本
 *   2. 轻量 SELECT settings —— 跨 Isolate 安全检测，schema 已就绪时极快（D1 命中索引）
 *   3. 只有表真的不存在时才执行 DDL batch —— 且用 try/catch 兜底竞态
 *
 * 绝大多数请求命中 ① 或 ②，不会触发 DDL。
 */
export async function ensureSchema(env: Env): Promise<void> {
  if (schemaReady) return;

  // ② 跨 Isolate 安全检测：settings 表是 schema 中最后创建的一张，
  // 它存在意味着整个 schema 已就绪
  try {
    const row = await env.db.prepare("SELECT 1 FROM settings LIMIT 1").first();
    if (row) {
      schemaReady = true;
      return;
    }
  } catch {
    // 表不存在或查询失败，继续走 DDL 路径
  }

  // ③ 真正的建表路径（首次部署 / 库被清空时触发）
  // 用 try/catch 处理极端竞态：另一个 Isolate 刚好也在执行 DDL
  try {
    await env.db.batch(SCHEMA_STATEMENTS.map((sql) => env.db.prepare(sql)));
    // 迁移：旧库补 password_hash 列（若已存在则静默跳过）
    try {
      await env.db.prepare("ALTER TABLE shares ADD COLUMN password_hash TEXT").run();
    } catch {
      /* 列已存在，忽略 */
    }
    // 迁移：旧库补 password_cipher 列（加密后的密码明文）
    try {
      await env.db.prepare("ALTER TABLE shares ADD COLUMN password_cipher TEXT").run();
    } catch {
      /* 列已存在，忽略 */
    }
  } catch {
    // 竞态兜底：可能另一个 Isolate 刚建完表。
    // 再检测一次，确认表存在就算成功
    try {
      const row = await env.db.prepare("SELECT 1 FROM settings LIMIT 1").first();
      if (!row) throw new Error("schema still missing after DDL attempt");
    } catch (e) {
      // 表确实没建起来，重新抛出让上层决定
      throw e;
    }
  }

  schemaReady = true;
}

/** 生成 URL 安全的随机 ID */
export function randomId(len = 12): string {
  const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}
