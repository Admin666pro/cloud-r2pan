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
    max_previews INTEGER,
    preview_count INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    password_hash TEXT,
    password_cipher TEXT,
    download_name TEXT,
    is_market INTEGER NOT NULL DEFAULT 0,
    market_views INTEGER NOT NULL DEFAULT 0,
    market_title TEXT,
    market_desc TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_shares_file ON shares(file_id)`,
  `CREATE INDEX IF NOT EXISTS idx_shares_market ON shares(is_market, revoked)`,
  `CREATE TABLE IF NOT EXISTS direct_links (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    max_downloads INTEGER,
    download_count INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    download_name TEXT,
    notes TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_direct_links_file ON direct_links(file_id)`,
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
  // 下载会话：把"同一次下载"的并发分片/断点续传归并成一次计次，
  // 防止多线程下载器瞬间刷爆 max_downloads / 每 IP 限次并触发自动封禁。
  `CREATE TABLE IF NOT EXISTS download_sessions (
    share_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    counted INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(share_id, ip)
  )`,
  `CREATE INDEX IF NOT EXISTS idx_download_sessions_created ON download_sessions(created_at)`,
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
  // ═══════════ 激活码 ═══════════
  // 每个激活码独立额度，和全局 traffic_limit_bytes 互不影响
  `CREATE TABLE IF NOT EXISTS activation_plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    traffic_bytes INTEGER NOT NULL DEFAULT 0,
    days_valid INTEGER NOT NULL DEFAULT 0,
    quota_message TEXT,
    batch_id TEXT,
    notes TEXT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS activation_codes (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    plan_id TEXT,
    traffic_bytes INTEGER NOT NULL DEFAULT 0,
    used_bytes INTEGER NOT NULL DEFAULT 0,
    days_valid INTEGER NOT NULL DEFAULT 0,
    quota_message TEXT,
    status TEXT NOT NULL DEFAULT 'unused',
    batch_id TEXT,
    notes TEXT,
    created_at INTEGER NOT NULL,
    activated_at INTEGER,
    expires_at INTEGER
  )`,
  `CREATE INDEX IF NOT EXISTS idx_codes_status ON activation_codes(status)`,
  `CREATE INDEX IF NOT EXISTS idx_codes_batch ON activation_codes(batch_id)`,
  `CREATE INDEX IF NOT EXISTS idx_codes_code ON activation_codes(code)`,
  // ═══════════ WebDAV 虚拟目录 ═══════════
  `CREATE TABLE IF NOT EXISTS directories (
    path TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
  )`,
  // ═══════════ 错误日志 ═══════════
  // 前端（含登录页）与后端捕获到的异常自动落库，方便在管理后台查看 / 反馈给开发者
  `CREATE TABLE IF NOT EXISTS error_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    message TEXT NOT NULL,
    stack TEXT,
    path TEXT,
    url TEXT,
    line INTEGER,
    col INTEGER,
    ua TEXT,
    browser TEXT,
    os TEXT,
    country TEXT,
    ip TEXT,
    context TEXT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_error_logs_created ON error_logs(created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_error_logs_source ON error_logs(source)`,
];

/** 所有预期的业务表 —— 自动建表 & 升级时都要检查 */
export const EXPECTED_TABLES = [
  "files", "shares", "direct_links", "download_logs", "login_logs",
  "turnstile_visits", "banned_ips", "settings", "traffic_stats",
  "oauth_states", "oauth_providers", "activation_plans", "activation_codes",
  "directories", "error_logs", "download_sessions",
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
 *
 * ⚠️ 注意：ALTER TABLE 迁移语句不参与 schemaReady 短路，每次 ensureSchema 都执行一遍
 * （用 try/catch 保护，列已存在时静默忽略），保证老用户库升级后列补齐。
 */

/** 所有增量迁移语句 —— 用 migration_version 追踪已执行版本，只跑未执行的 */
const MIGRATION_STATEMENTS: string[] = [
  "ALTER TABLE shares ADD COLUMN password_hash TEXT",
  "ALTER TABLE shares ADD COLUMN password_cipher TEXT",
  "ALTER TABLE shares ADD COLUMN download_name TEXT",
  "ALTER TABLE download_logs ADD COLUMN activation_code TEXT",
  "ALTER TABLE shares ADD COLUMN is_market INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE shares ADD COLUMN market_views INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE shares ADD COLUMN market_title TEXT",
  "ALTER TABLE shares ADD COLUMN market_desc TEXT",
  "CREATE INDEX IF NOT EXISTS idx_shares_market ON shares(is_market, revoked)",
  // ═══════════ WebDAV 虚拟目录 ═══════════
  "ALTER TABLE files ADD COLUMN path TEXT NOT NULL DEFAULT '/'",
  "CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)",
  // ═══════════ 在线预览次数限制（独立于下载次数） ═══════════
  "ALTER TABLE shares ADD COLUMN max_previews INTEGER",
  "ALTER TABLE shares ADD COLUMN preview_count INTEGER NOT NULL DEFAULT 0",
  // ═══════════ 下载会话准入标记（修复"满额后并发白嫖"绕过） ═══════════
  "ALTER TABLE download_sessions ADD COLUMN counted INTEGER NOT NULL DEFAULT 0",
  // ═══════════ 文件系统：修正历史遗留的 files.path = '/' ═══════════
  // 约定 files.path 存**含文件名的全路径**（如 "/a.txt"、"/docs/a.txt"），
  // 但早期 admin 上传漏写 path → 留成默认值 "/"，导致文件在目录树里"消失"（listDir 跳过）。
  // 这里把历史行补成 "/" + name，一次性修正。
  "UPDATE files SET path = '/' || name WHERE path IS NULL OR path = '/'",
  // ═══════════ 下载会话字节预算（修复"TTL 内无限续传"绕过） ═══════════
  // 会话累计已发送字节，累计满一整份文件后立即结束会话；否则同一 IP 在 10 分钟窗口内
  // 可以无限次"续传"把整个文件反复拉走，max_downloads 形同虚设。
  // ⚠️ 新增迁移必须**追加在数组末尾**：迁移按 version 顺序只跑一次，
  //    插在中间会被已有库的 migration_version 跳过。
  "ALTER TABLE download_sessions ADD COLUMN bytes INTEGER NOT NULL DEFAULT 0",
];

/**
 * 幂等迁移：读 settings.migration_version，只跑 index >= version 的迁移语句。
 * 这样每个迁移只执行一次，避免每次请求都白跑 9 条 ALTER。
 * migration_version 存的是"已执行到的最高下标"，默认 -1（一个都没跑过）。
 */
async function runMigrations(env: Env): Promise<void> {
  let version = -1;
  try {
    const row: any = await env.db.prepare(
      "SELECT value FROM settings WHERE key = 'migration_version'"
    ).first();
    if (row?.value) version = Number(row.value) - 1; // 存的是 len（已执行数量），转成下标
  } catch {
    // settings 表可能还不存在（首次部署），这时候全跑一遍
  }

  if (version >= MIGRATION_STATEMENTS.length - 1) return; // 最新

  // 只跑 version+1 之后的迁移
  for (let i = version + 1; i < MIGRATION_STATEMENTS.length; i++) {
    try {
      await env.db.prepare(MIGRATION_STATEMENTS[i]).run();
    } catch {
      /* 列/索引已存在，忽略（保持幂等兜底） */
    }
  }

  // 写入新版本（存数量，不是下标）
  try {
    await env.db.prepare(
      "INSERT INTO settings(key, value) VALUES('migration_version', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ).bind(String(MIGRATION_STATEMENTS.length)).run();
  } catch {
    /* settings 表不存在时忽略 */
  }
}

export async function ensureSchema(env: Env): Promise<void> {
  // ① 防御性检查：如果数据库绑定不存在，直接报错
  if (!env.db) {
    throw new Error("Database binding 'db' is not configured. " +
      "在 Cloudflare 控制台 → Worker Settings → Bindings 添加 D1 绑定，" +
      "或在 wrangler.jsonc 的 d1_databases 中声明。");
  }

  // ② 内存短路 —— 本 isolate 已确认过 schema + 迁移都就绪，直接返回，零成本
  //    Worker 冷启动 / isolate 重启时 schemaReady=false，会重新跑一遍
  if (schemaReady) return;

  // ③ 跨 Isolate 安全检测：用 sqlite_master 检查所有预期的表是否都存在
  let needCreate = false;
  try {
    const { results }: any = await env.db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table'"
    ).all();
    const existing = new Set((results ?? []).map((r: any) => r.name));
    needCreate = !EXPECTED_TABLES.every((t) => existing.has(t));
  } catch {
    // 查询失败（如数据库完全损坏），继续尝试建表
    needCreate = true;
  }

  if (needCreate) {
    // ④ 真正的建表路径（首次部署 / 升级后新增表 / 库被清空时触发）
    // 用 try/catch 处理极端竞态：另一个 Isolate 刚好也在执行 DDL
    try {
      await env.db.batch(SCHEMA_STATEMENTS.map((sql) => env.db.prepare(sql)));
    } catch {
      // 竞态兜底：可能另一个 Isolate 刚建完表。
      // 再检测一次，确认表都存在就算成功
      try {
        const { results }: any = await env.db.prepare(
          "SELECT name FROM sqlite_master WHERE type='table'"
        ).all();
        const existing = new Set((results ?? []).map((r: any) => r.name));
        const stillMissing = EXPECTED_TABLES.filter((t) => !existing.has(t));
        if (stillMissing.length > 0)
          throw new Error("schema still missing tables after DDL: " + stillMissing.join(", "));
      } catch (e) {
        // 表确实没建起来，重新抛出让上层决定
        throw e;
      }
    }
  }

  // ⑤ 跑增量迁移（幂等，只跑未执行过的）
  await runMigrations(env);

  schemaReady = true;
}

export interface ErrorLogInput {
  /** frontend | backend | api */
  source: string;
  message: string;
  stack?: string | null;
  /** 页面路径或接口路径 */
  path?: string | null;
  /** 完整 URL 或触发脚本地址 */
  url?: string | null;
  line?: number | null;
  col?: number | null;
  ua?: string | null;
  browser?: string | null;
  os?: string | null;
  country?: string | null;
  ip?: string | null;
  /** 额外上下文（如 'unhandledrejection' / 'echarts-gl'） */
  context?: string | null;
}

/** 单字段最大长度，防止超长堆栈撑爆行记录 */
function clampField(s: string | null | undefined, max: number): string | null {
  if (s == null) return null;
  const v = String(s);
  if (!v) return null;
  return v.length > max ? v.slice(0, max) : v;
}

/**
 * 写入一条错误日志 —— 永不抛出（日志失败不影响主流程）。
 * 表不存在时先自动建表（ensureSchema 有内存短路，成本极低）。
 */
export async function writeErrorLog(env: Env, e: ErrorLogInput): Promise<void> {
  if (!env.db) return;
  try {
    await ensureSchema(env);
    await env.db
      .prepare(
        `INSERT INTO error_logs(source, message, stack, path, url, line, col, ua, browser, os, country, ip, context, created_at)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)`
      )
      .bind(
        clampField(e.source, 20) ?? "unknown",
        clampField(e.message, 2000) ?? "(no message)",
        clampField(e.stack, 8000),
        clampField(e.path, 500),
        clampField(e.url, 1000),
        e.line ?? null,
        e.col ?? null,
        clampField(e.ua, 1000),
        clampField(e.browser, 60),
        clampField(e.os, 60),
        clampField(e.country, 10),
        clampField(e.ip, 64),
        clampField(e.context, 1000),
        Date.now()
      )
      .run();
  } catch {
    /* 静默：错误日志写入失败不能影响正常流程 */
  }
}

/** 生成 URL 安全的随机 ID */
export function randomId(len = 12): string {
  const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}

/**
 * 预期的列（旧版升级数据库可能缺失）—— 用于 getSchemaStatus 检测。
 * 只列出通过 MIGRATION_STATEMENTS 增量添加的列，CREATE TABLE IF NOT EXISTS 里本来就有的不算。
 */
const EXPECTED_COLUMNS: { table: string; column: string }[] = [
  { table: "shares", column: "password_hash" },
  { table: "shares", column: "password_cipher" },
  { table: "shares", column: "download_name" },
  { table: "shares", column: "is_market" },
  { table: "shares", column: "market_views" },
  { table: "shares", column: "market_title" },
  { table: "shares", column: "market_desc" },
  { table: "download_logs", column: "activation_code" },
  { table: "files", column: "path" },
  { table: "shares", column: "max_previews" },
  { table: "shares", column: "preview_count" },
  { table: "download_sessions", column: "counted" },
  { table: "download_sessions", column: "bytes" },
];

/** 预期的索引（同样是可能缺失的） */
const EXPECTED_INDEXES: string[] = [
  "idx_shares_market",
  "idx_files_path",
  "idx_download_sessions_created",
];

export interface SchemaStatus {
  healthy: boolean;
  tables: { expected: string[]; existing: string[]; missing: string[] };
  columns: { table: string; column: string }[]; // 缺失的列
  indexes: string[]; // 缺失的索引名
  migration: { current: number; total: number; latest: boolean }; // current 是已执行数量
  tableCounts: Record<string, number>; // 各表行数（用于诊断）
}

/**
 * 查询数据库当前 schema 状态，用于设置页面展示健康状况。
 */
export async function getSchemaStatus(env: Env): Promise<SchemaStatus> {
  if (!env.db) {
    throw new Error("Database binding 'db' is not configured");
  }

  // 1+2. 现有表名 + 关心的索引名 —— 合并为一次 batch（1 个 D1 往返，原为 2 次串行）
  const meta: any[] = await env.db.batch<any>([
    env.db.prepare("SELECT name FROM sqlite_master WHERE type='table'"),
    env.db.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"),
  ]);
  const existingTables = new Set((meta[0]?.results ?? []).map((r: any) => r.name));
  const missingTables = EXPECTED_TABLES.filter((t) => !existingTables.has(t));

  const existingIndexes = new Set((meta[1]?.results ?? []).map((r: any) => r.name));
  const missingIndexes = EXPECTED_INDEXES.filter((i) => !existingIndexes.has(i));

  // 3. 迁移版本（settings 表可能不存在，单独容错）
  let migrationCurrent = 0;
  try {
    const row: any = await env.db.prepare(
      "SELECT value FROM settings WHERE key = 'migration_version'"
    ).first();
    if (row?.value) migrationCurrent = Number(row.value);
  } catch { /* settings 表可能不存在 */ }
  const migrationTotal = MIGRATION_STATEMENTS.length;

  // 4+5. 列检查 + 各表行数 —— 合并为一次 batch（1 个 D1 往返，原为 ~23 次串行）
  //      列检查按“去重后的表”执行 PRAGMA，避免同一张表查多次。
  const colTables = [...new Set(EXPECTED_COLUMNS.map((c) => c.table))].filter((t) => existingTables.has(t));
  const countTables = EXPECTED_TABLES.filter((t) => existingTables.has(t));
  const missingColumns: { table: string; column: string }[] = [];
  const tableCounts: Record<string, number> = {};

  try {
    const stmts = [
      ...colTables.map((t) => env.db.prepare(`PRAGMA table_info(${t})`)),
      ...countTables.map((t) => env.db.prepare(`SELECT COUNT(*) AS c FROM ${t}`)),
    ];
    const res: any[] = stmts.length ? await env.db.batch<any>(stmts) : [];

    const colsByTable = new Map<string, Set<string>>();
    colTables.forEach((t, i) => {
      colsByTable.set(t, new Set((res[i]?.results ?? []).map((c: any) => c.name)));
    });
    for (const { table, column } of EXPECTED_COLUMNS) {
      if (!existingTables.has(table)) continue; // 表都没有了就不用查列了
      if (!colsByTable.get(table)?.has(column)) missingColumns.push({ table, column });
    }
    countTables.forEach((t, i) => {
      tableCounts[t] = res[colTables.length + i]?.results?.[0]?.c ?? 0;
    });
  } catch {
    // 极端情况下 batch 失败 —— 回退到逐条查询，保证诊断功能仍可用
    for (const { table, column } of EXPECTED_COLUMNS) {
      if (!existingTables.has(table)) continue;
      try {
        const colRes: any = await env.db.prepare(`PRAGMA table_info(${table})`).all();
        if (!(colRes.results ?? []).some((c: any) => c.name === column)) missingColumns.push({ table, column });
      } catch { /* 忽略 */ }
    }
    for (const t of countTables) {
      try {
        const r: any = await env.db.prepare(`SELECT COUNT(*) AS c FROM ${t}`).first();
        tableCounts[t] = r?.c ?? 0;
      } catch {
        tableCounts[t] = -1; // 查询失败
      }
    }
  }

  const healthy =
    missingTables.length === 0 &&
    missingColumns.length === 0 &&
    missingIndexes.length === 0 &&
    migrationCurrent >= migrationTotal;

  return {
    healthy,
    tables: {
      expected: EXPECTED_TABLES.slice(),
      existing: EXPECTED_TABLES.filter((t) => existingTables.has(t)),
      missing: missingTables,
    },
    columns: missingColumns,
    indexes: missingIndexes,
    migration: {
      current: migrationCurrent,
      total: migrationTotal,
      latest: migrationCurrent >= migrationTotal,
    },
    tableCounts,
  };
}

export interface RepairResult {
  ok: boolean;
  tablesCreated: string[];
  columnsAdded: string[];
  indexesCreated: string[];
  migrationsRun: number;
  durationMs: number;
  finalStatus: SchemaStatus;
  error?: string;
}

/**
 * 强制修复数据库 —— 重置 schemaReady 短路，重新跑完整 ensureSchema。
 * 即使之前已经 "schemaReady"，也会重新执行建表 + 增量迁移。
 *
 * 返回详细的修复摘要，便于前端展示。
 */
export async function repairDatabase(env: Env): Promise<RepairResult> {
  const start = Date.now();
  const tablesCreated: string[] = [];
  const columnsAdded: string[] = [];
  const indexesCreated: string[] = [];

  try {
    if (!env.db) throw new Error("Database binding 'db' is not configured");

    // 强制让 ensureSchema 重新跑一遍 —— 先把内存短路清掉
    schemaReady = false;

    // ── Step 1: 先记录修复前缺什么 —— 修复后对比就能知道 "新增了什么" ──
    const before = await getSchemaStatus(env);

    // ── Step 2: 跑完整 ensureSchema ──
    await ensureSchema(env);

    // ── Step 3: 再跑一次迁移，确保 migration_version 对齐 ──
    // （ensureSchema 内部已经跑过 runMigrations，但这里再次调用也幂等）
    await runMigrations(env);

    // ── Step 4: 记录修复后状态 ──
    const after = await getSchemaStatus(env);

    // 对比 before / after，算出修复动作
    tablesCreated.push(...before.tables.missing);
    for (const c of before.columns) {
      if (!after.columns.some((x) => x.table === c.table && x.column === c.column)) {
        columnsAdded.push(`${c.table}.${c.column}`);
      }
    }
    for (const idx of before.indexes) {
      if (!after.indexes.includes(idx)) indexesCreated.push(idx);
    }

    const migrationsRun =
      after.migration.current > before.migration.current
        ? after.migration.current - before.migration.current
        : 0;

    return {
      ok: true,
      tablesCreated,
      columnsAdded,
      indexesCreated,
      migrationsRun,
      durationMs: Date.now() - start,
      finalStatus: after,
    };
  } catch (e: any) {
    // 就算失败也尽量返回最终状态，方便用户排查
    let finalStatus: SchemaStatus | null = null;
    try {
      finalStatus = await getSchemaStatus(env);
    } catch { /* 数据库可能已经完全挂了 */ }
    return {
      ok: false,
      tablesCreated,
      columnsAdded,
      indexesCreated,
      migrationsRun: 0,
      durationMs: Date.now() - start,
      finalStatus: finalStatus ?? ({
        healthy: false,
        tables: { expected: EXPECTED_TABLES.slice(), existing: [], missing: EXPECTED_TABLES.slice() },
        columns: [],
        indexes: [],
        migration: { current: 0, total: 0, latest: false },
        tableCounts: {},
      }),
      error: String(e?.message ?? e),
    };
  }
}
