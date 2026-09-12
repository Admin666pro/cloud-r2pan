import type { Env } from "./types";
import { randomId } from "./db";

/** 激活码前缀 */
const PREFIX = "R2PAN-";
/** 易混字符：去掉 0 O 1 I */
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/** 生成一个随机激活码，格式 R2PAN-XXXX-XXXX-XXXX */
export function generateOneCode(): string {
  let out = PREFIX;
  for (let g = 0; g < 3; g++) {
    if (g > 0) out += "-";
    const bytes = crypto.getRandomValues(new Uint8Array(4));
    for (let i = 0; i < 4; i++) out += ALPHABET[bytes[i] % ALPHABET.length];
  }
  return out;
}

/** 批量生成 N 个**唯一**的激活码 */
export function generateCodes(count: number): string[] {
  const seen = new Set<string>();
  const list: string[] = [];
  const maxAttempts = count * 50;
  let tries = 0;
  while (list.length < count && tries < maxAttempts) {
    tries++;
    const c = generateOneCode();
    if (!seen.has(c)) {
      seen.add(c);
      list.push(c);
    }
  }
  return list;
}

export interface ActivationCodeRow {
  id: string;
  code: string;
  plan_id: string | null;
  traffic_bytes: number;
  used_bytes: number;
  days_valid: number;
  quota_message: string | null;
  status: "unused" | "active" | "expired" | "exhausted" | "revoked";
  batch_id: string | null;
  notes: string | null;
  created_at: number;
  activated_at: number | null;
  expires_at: number | null;
}

/** 通过 code 字符串查一条激活码（返回 null = 码不存在） */
export async function findCodeByString(
  env: Env,
  codeStr: string
): Promise<ActivationCodeRow | null> {
  return (await env.db
    .prepare("SELECT * FROM activation_codes WHERE code = ?1")
    .bind(codeStr.trim().toUpperCase())
    .first()) as ActivationCodeRow | null;
}

/**
 * 验证激活码能否用于下载：
 *   返回 { ok: true }  码可用，后续调用 deductQuota 扣额度
 *   返回 { ok: false, reason, message }  码不可用
 *
 * reason:
 *   "not_found"    码不存在
 *   "revoked"      已作废
 *   "expired"      时效型码已过期
 *   "exhausted"    流量已耗尽（带 quota_message 自定义文案）
 */
export function checkCodeUsable(row: ActivationCodeRow): {
  ok: boolean;
  reason?: string;
  message?: string;
} {
  if (!row) return { ok: false, reason: "not_found", message: "码不存在" };
  if (row.status === "revoked") return { ok: false, reason: "revoked", message: "该激活码已被作废" };
  if (row.expires_at && row.expires_at < Date.now())
    return { ok: false, reason: "expired", message: "该激活码已过期" };

  // 流量型耗尽判断：total > 0 且 used >= total（total=0 表示无限流量纯时效码）
  const exhausted =
    row.traffic_bytes > 0 && row.used_bytes >= row.traffic_bytes;
  if (exhausted) {
    return {
      ok: false,
      reason: "exhausted",
      // 管理员填了自定义文案就用自定义，否则给默认
      message:
        row.quota_message ||
        "激活码流量已耗尽。免费下载不受影响，如需继续使用激活码请购买新码。",
    };
  }

  return { ok: true };
}

/**
 * 扣减激活码额度（原子操作）。
 * 返回 { ok, remaining, exhausted }：
 *   ok: true  扣减成功
 *   ok: false 码不存在 / 已作废 / 已耗尽 / 已过期
 */
export async function deductQuota(
  env: Env,
  row: ActivationCodeRow,
  bytes: number
): Promise<{ ok: boolean; remaining: number; exhausted: boolean; reason?: string; message?: string }> {
  const now = Date.now();

  // 先查最新状态（避免 stale cache）
  const fresh = (await env.db
    .prepare("SELECT * FROM activation_codes WHERE id = ?1")
    .bind(row.id)
    .first()) as ActivationCodeRow | null;
  if (!fresh) return { ok: false, remaining: 0, exhausted: true, reason: "not_found", message: "码不存在" };
  if (fresh.status === "revoked") return { ok: false, remaining: 0, exhausted: true, reason: "revoked", message: "该激活码已被作废" };
  if (fresh.expires_at && fresh.expires_at < now) return { ok: false, remaining: 0, exhausted: true, reason: "expired", message: "该激活码已过期" };

  // 流量无限 → 直接加 used_bytes 都行，不做耗尽判断
  const unlimited = fresh.traffic_bytes === 0;
  const newUsed = fresh.used_bytes + bytes;

  let sql: string;
  let bind: any[];

  if (unlimited) {
    sql = "UPDATE activation_codes SET used_bytes = ?1 WHERE id = ?2";
    bind = [newUsed, fresh.id];
  } else {
    // 原子 check-and-update：只有 used + bytes <= total 才更新，防止并发超扣
    sql =
      "UPDATE activation_codes SET used_bytes = ?1 WHERE id = ?2 AND used_bytes + ?3 <= traffic_bytes AND status != 'revoked'";
    bind = [newUsed, fresh.id, bytes];
  }

  const result = await env.db.prepare(sql).bind(...bind).run();
  const changed = (result.meta.changes ?? 0) as number;
  if (changed === 0) {
    // 更新失败 → 再次读状态判断具体原因
    const again = (await env.db.prepare("SELECT * FROM activation_codes WHERE id = ?1").bind(fresh.id).first()) as ActivationCodeRow;
    if (!again) return { ok: false, remaining: 0, exhausted: true, reason: "not_found", message: "码不存在" };
    if (again.status === "revoked") return { ok: false, remaining: 0, exhausted: true, reason: "revoked", message: "该激活码已被作废" };
    if (again.traffic_bytes > 0 && again.used_bytes >= again.traffic_bytes) {
      return {
        ok: false,
        remaining: 0,
        exhausted: true,
        reason: "exhausted",
        message: again.quota_message || "激活码流量已耗尽。",
      };
    }
    return { ok: false, remaining: Math.max(0, again.traffic_bytes - again.used_bytes), exhausted: true, reason: "unknown", message: "扣减失败" };
  }

  const remaining = unlimited ? -1 : Math.max(0, fresh.traffic_bytes - newUsed);
  const exhausted = !unlimited && newUsed >= fresh.traffic_bytes;
  return { ok: true, remaining, exhausted };
}

/** 激活：首次使用时把码置为 active 并计算 expires_at */
export async function activateCodeIfNeeded(env: Env, row: ActivationCodeRow): Promise<void> {
  if (row.status !== "unused") return;
  const now = Date.now();
  const expiresAt =
    row.days_valid > 0 && !row.expires_at ? now + row.days_valid * 86400_000 : row.expires_at;
  await env.db
    .prepare(
      "UPDATE activation_codes SET status = 'active', activated_at = ?1, expires_at = COALESCE(?2, expires_at) WHERE id = ?3 AND status = 'unused'"
    )
    .bind(now, expiresAt, row.id)
    .run();
}

/** 查询某个码的剩余额度（公开调用，不需要 admin） */
export function formatCodeStatus(row: ActivationCodeRow) {
  if (!row) return null;
  const remaining = row.traffic_bytes === 0 ? -1 : Math.max(0, row.traffic_bytes - row.used_bytes);
  const total = row.traffic_bytes;
  const pct = total > 0 ? Math.min(100, Math.round((row.used_bytes / total) * 100)) : 0;
  const now = Date.now();
  const isExpired = row.expires_at ? row.expires_at < now : false;
  return {
    code: row.code,
    status: row.status,
    remaining, // -1 表示无限
    total,
    used: row.used_bytes,
    pct,
    days_valid: row.days_valid,
    expired: isExpired,
    expires_at: row.expires_at,
    quota_message: row.quota_message,
    activated_at: row.activated_at,
    created_at: row.created_at,
  };
}

/** 为一批码生成唯一 batch_id（方便按批次查询/作废/导出） */
export function makeBatchId(): string {
  const t = new Date();
  const tag = `${t.getFullYear()}${String(t.getMonth() + 1).padStart(2, "0")}${String(t.getDate()).padStart(2, "0")}`;
  const rand = randomId(4).toUpperCase();
  return `B${tag}-${rand}`;
}
