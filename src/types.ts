export interface Env {
  BUCKET: R2Bucket;
  DB: D1Database;
  ADMIN_KEY: string;
}

export interface ShareRow {
  id: string;
  file_id: string;
  created_at: number;
  expires_at: number | null;
  max_downloads: number | null;
  download_count: number;
  revoked: number;
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
