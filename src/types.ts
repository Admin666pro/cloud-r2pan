export interface Env {
  r2: R2Bucket;
  db: D1Database;
  admin: string;
  /** 可选：2FA 恢复密钥（Cloudflare 后台配置）。优先级高于 D1 里的恢复码。 */
  totp_recovery?: string;
  /** 可选：Turnstile sitekey（前端渲染 widget 用）。优先级高于 settings 里的 sitekey_override。 */
  turnstile_sitekey?: string;
  /** 可选：Turnstile secret（后端验证 token 用）。没配则 Turnstile 整体禁用。 */
  turnstile_secret?: string;
}

export interface ShareRow {
  id: string;
  file_id: string;
  created_at: number;
  expires_at: number | null;
  max_downloads: number | null;
  download_count: number;
  revoked: number;
  /** 分享访问密码哈希（salt:sha256hex），未设置则为 null */
  password_hash: string | null;
}

export interface FileRow {
  id: string;
  key: string;
  name: string;
  size: number;
  mime: string;
  uploaded_at: number;
}

export interface ShareWithFile extends ShareRow {
  key: string;
  name: string;
  size: number;
  mime: string;
}

export interface BanRow {
  ip: string;
  reason: string;
  banned_at: number;
  expires_at: number | null;
}

export interface LogRow {
  id: number;
  share_id: string;
  file_id: string;
  file_name: string;
  ip: string;
  browser: string;
  os: string;
  country: string;
  bytes: number;
  created_at: number;
}

export interface LoginLogRow {
  id: number;
  /** login | logout | verify_fail | rate_limited */
  action: string;
  ip: string;
  ua: string | null;
  browser: string;
  os: string;
  country: string | null;
  /** success | fail */
  result: string;
  reason: string | null;
  created_at: number;
}
