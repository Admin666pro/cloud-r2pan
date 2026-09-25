/**
 * Storage 抽象层 —— 零依赖对象存储访问
 *
 * 支持两种后端：
 *   1. R2StorageProvider  —— 直接用 Cloudflare Workers 的 R2Bucket binding（原有方式）
 *   2. S3StorageProvider  —— 通用 S3 兼容存储（AWS S3 / Backblaze B2 / MinIO / 阿里云 OSS / 腾讯云 COS 等）
 *
 * S3 客户端用纯 fetch + crypto.subtle 手写 AWS Signature V4，
 * 零 npm 依赖，完全符合本项目"零运行时依赖"原则。
 */

import type { Env } from "./types";
import { decryptSecret } from "./crypto";

/* ═══════════════════════════════════════════════════════
 * 存储提供者接口 —— 替换原有 env.r2 的硬编码
 * ═══════════════════════════════════════════════════════ */

export interface StorageObject {
  body: ReadableStream<Uint8Array>;
  size: number;
  contentType: string;
  etag: string;
}

export interface StoragePutResult {
  size: number;
  etag?: string;
}

/** list 返回的条目，与 S3 ListObjectsV2 / R2 list() 对齐 */
export interface StorageListEntry {
  key: string;           // 完整对象 key（如 "photos/vacation.jpg"）
  name: string;          // 显示名（prefix 之后的部分；顶层就是 key）
  size: number;          // 字节数
  lastModified: number;  // Unix 毫秒时间戳
  /** true = "目录"（R2/S3 中是 CommonPrefix，key 以 / 结尾），false = 实际文件 */
  isDir: boolean;
}

export interface StorageListResult {
  entries: StorageListEntry[];
  /** 是否还有下一页，用于继续翻页 */
  truncated: boolean;
  /** 下一页 marker，直接透传给下一次 list() */
  nextMarker?: string;
}

export interface StorageProvider {
  kind: "r2" | "s3" | "webdav";
  /** 上传对象（body 可以是 ReadableStream 或 ArrayBuffer） */
  put(
    key: string,
    body: ReadableStream<Uint8Array> | ArrayBuffer | Uint8Array,
    opts: { contentType?: string; contentDisposition?: string }
  ): Promise<StoragePutResult>;
  /** 读取对象（支持 Range） */
  get(key: string, range?: { offset: number; length?: number }): Promise<StorageObject | null>;
  /** 删除对象 */
  delete(key: string): Promise<void>;
  /** 获取对象元数据（不含 body） */
  head(key: string): Promise<{ size: number; contentType: string } | null>;
  /** 列出对象（模拟目录浏览；prefix 为 "" 时列根目录） */
  list(opts: { prefix?: string; marker?: string; limit?: number }): Promise<StorageListResult>;
}

/* ═══════════════════════════════════════════════════════
 * Provider 1: Cloudflare R2 —— 原有 binding 直接包装
 * ═══════════════════════════════════════════════════════ */

export function createR2Provider(r2: R2Bucket): StorageProvider {
  return {
    kind: "r2",
    async put(key, body, opts) {
      const r2Body = body instanceof Uint8Array ? body.buffer : body;
      const httpMetadata: Record<string, string> = {};
      if (opts.contentType) httpMetadata.contentType = opts.contentType;
      if (opts.contentDisposition) httpMetadata.contentDisposition = opts.contentDisposition;
      const obj = await r2.put(key, r2Body as any, { httpMetadata });
      return { size: obj.size, etag: obj.httpEtag };
    },
    async get(key, range) {
      const r2Range = range
        ? range.length !== undefined
          ? { offset: range.offset, length: range.length }
          : { offset: range.offset }
        : undefined;
      const obj = (await r2.get(key, r2Range as any)) as any;
      if (!obj) return null;
      return {
        body: obj.body as ReadableStream<Uint8Array>,
        size: obj.size,
        contentType: obj.httpMetadata?.contentType ?? "application/octet-stream",
        etag: obj.httpEtag,
      };
    },
    async delete(key) {
      await r2.delete(key);
    },
    async head(key) {
      const obj = await r2.head(key);
      if (!obj) return null;
      return { size: obj.size, contentType: obj.httpMetadata?.contentType ?? "application/octet-stream" };
    },
    async list(opts) {
      const prefix = opts.prefix ?? "";
      const limit = opts.limit ?? 100;
      const params: any = { prefix, limit, delimiter: "/" };
      if (opts.marker) params.cursor = opts.marker;
      const result: any = await r2.list(params);
      const entries: StorageListEntry[] = [];
      for (const dir of result.delimitedPrefixes ?? []) {
        // dir 形如 "photos/"
        const name = prefix ? dir.slice(prefix.length) : dir;
        entries.push({ key: dir, name, size: 0, lastModified: 0, isDir: true });
      }
      for (const obj of result.objects ?? []) {
        const name = prefix && obj.key.startsWith(prefix) ? obj.key.slice(prefix.length) : obj.key;
        entries.push({
          key: obj.key,
          name,
          size: obj.size,
          lastModified: obj.uploaded ? new Date(obj.uploaded).getTime() : 0,
          isDir: false,
        });
      }
      return { entries, truncated: !!result.truncated, nextMarker: result.truncated ? result.cursor : undefined };
    },
  };
}

/* ═══════════════════════════════════════════════════════
 * Provider 2: S3 兼容存储 —— 纯 fetch + AWS Signature V4
 * ═══════════════════════════════════════════════════════ */

export interface S3Config {
  endpoint: string; // 如 https://s3.amazonaws.com 或 https://s3.us-west-002.backblazeb2.com
  region: string; // 如 us-east-1、ap-southeast-1、auto（R2 用 auto）
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** "path" = bucket 在 URL path 中；"virtual" = bucket 作为 hostname 前缀 */
  addressingStyle?: "path" | "virtual";
  /** 可选的自定义路径前缀（如 MinIO 的子路径） */
  pathPrefix?: string;
}

/** URL 编码（RFC 3986），AWS S3 签名要求严格的百分号编码 */
function encodeURIComponentStrict(s: string): string {
  return encodeURIComponent(s)
    .replace(/'/g, "%27")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29")
    .replace(/\*/g, "%2A");
}

/** 生成规范化请求（Canonical Request）—— AWS Signature V4 的核心 */
function buildCanonicalRequest(
  method: string,
  path: string,
  query: URLSearchParams | undefined,
  headers: Record<string, string>,
  bodyHash: string
): { canonical: string; signedHeaders: string } {
  const sortedHeaderNames = Object.keys(headers)
    .map((k) => k.toLowerCase())
    .sort();
  const signedHeaders = sortedHeaderNames.join(";");

  const headerLines = sortedHeaderNames.map((name) => `${name}:${headers[name.trim()]!.trim()}\n`).join("");

  // 规范化 query string
  let canonicalQuery = "";
  if (query) {
    const pairs: [string, string][] = [];
    query.forEach((v, k) => pairs.push([k, v]));
    pairs.sort((a, b) =>
      a[0] === b[0] ? encodeURIComponentStrict(a[1]).localeCompare(encodeURIComponentStrict(b[1]))
        : encodeURIComponentStrict(a[0]).localeCompare(encodeURIComponentStrict(b[0]))
    );
    canonicalQuery = pairs.map(([k, v]) => `${encodeURIComponentStrict(k)}=${encodeURIComponentStrict(v)}`).join("&");
  }

  const canonical = [
    method,
    path,
    canonicalQuery,
    headerLines,
    signedHeaders,
    bodyHash,
  ].join("\n");

  return { canonical, signedHeaders };
}

/** HMAC-SHA256 */
async function hmacSha256(key: ArrayBuffer | Uint8Array, data: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key instanceof Uint8Array ? key.buffer : key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
}

async function sha256Hex(data: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * 极简 XML 解析器 —— 专用于 S3 ListObjectsV2 返回
 * 不做通用解析，只提取 ListBucketResult 下的 Contents + CommonPrefixes + IsTruncated + NextContinuationToken
 */
function parseS3ListXml(xml: string, prefix: string): StorageListResult {
  const entries: StorageListEntry[] = [];

  // 提取 CommonPrefixes（目录）
  const cpRe = /<CommonPrefixes>[\s\S]*?<Prefix>([^<]*?)<\/Prefix>[\s\S]*?<\/CommonPrefixes>/g;
  let m: RegExpExecArray | null;
  while ((m = cpRe.exec(xml)) !== null) {
    const dirKey = m[1]; // 形如 "photos/"
    const name = prefix && dirKey.startsWith(prefix) ? dirKey.slice(prefix.length) : dirKey;
    entries.push({ key: dirKey, name, size: 0, lastModified: 0, isDir: true });
  }

  // 提取 Contents（文件）
  const ctRe = /<Contents>([\s\S]*?)<\/Contents>/g;
  while ((m = ctRe.exec(xml)) !== null) {
    const block = m[1];
    const keyMatch = block.match(/<Key>([^<]*?)<\/Key>/);
    const sizeMatch = block.match(/<Size>(\d+)<\/Size>/);
    const lmMatch = block.match(/<LastModified>([^<]*?)<\/LastModified>/);
    if (!keyMatch) continue;
    const key = keyMatch[1];
    const name = prefix && key.startsWith(prefix) ? key.slice(prefix.length) : key;
    const size = sizeMatch ? parseInt(sizeMatch[1]!, 10) : 0;
    let lastModified = 0;
    if (lmMatch) {
      const t = Date.parse(lmMatch[1]);
      if (!Number.isNaN(t)) lastModified = t;
    }
    entries.push({ key, name, size, lastModified, isDir: false });
  }

  // IsTruncated
  const truncMatch = xml.match(/<IsTruncated>(true|false)<\/IsTruncated>/);
  const truncated = truncMatch?.[1] === "true";
  // NextContinuationToken（ListObjectsV2 分页 marker）
  const nctMatch = xml.match(/<NextContinuationToken>([^<]*?)<\/NextContinuationToken>/);

  return {
    entries,
    truncated,
    nextMarker: truncated && nctMatch ? nctMatch[1] : undefined,
  };
}

/** AWS Signature V4 签名派生 */
async function deriveSigningKey(secret: string, date: string, region: string): Promise<ArrayBuffer> {
  const kDate = await hmacSha256(new TextEncoder().encode("AWS4" + secret), date);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, "s3");
  return await hmacSha256(kService, "aws4_request");
}

/** 构造完整 S3 URL + 签名 */
async function signS3Request(
  cfg: S3Config,
  method: string,
  s3Key: string,
  query: URLSearchParams | undefined,
  headers: Record<string, string>,
  bodyHash: string,
  now: Date
): Promise<{ url: string; headers: Record<string, string> }> {
  const host = new URL(cfg.endpoint).hostname;
  const dateStamp = now.toISOString().slice(0, 10);
  const amzDate = now.toISOString().replace(/[-:]/g, "").slice(0, 19) + "Z"; // 20260914T120000Z

  // 构造 URL
  const baseUrl = cfg.endpoint.replace(/\/$/, "");
  const prefix = cfg.pathPrefix ? `/${cfg.pathPrefix.replace(/^\//, "").replace(/\/$/, "")}` : "";
  const encodedKey = s3Key.split("/").map(encodeURIComponentStrict).join("/");

  let path: string;
  let url: string;
  if (cfg.addressingStyle === "virtual") {
    // bucket 作为 hostname 前缀（https://bucket.endpoint/key）
    path = `${prefix}/${encodedKey}`;
    url = `${baseUrl.replace(`https://`, `https://${cfg.bucket}.`)}${path}`;
  } else {
    // path style（默认）: https://endpoint/bucket/key
    path = `${prefix}/${cfg.bucket}/${encodedKey}`;
    url = `${baseUrl}${path}`;
  }

  // 添加签名头
  headers["Host"] = host;
  headers["x-amz-date"] = amzDate;
  headers["x-amz-content-sha256"] = bodyHash;

  const { canonical, signedHeaders } = buildCanonicalRequest(method, path, query, headers, bodyHash);
  const canonicalHash = await sha256Hex(canonical);
  const credentialScope = `${dateStamp}/${cfg.region}/s3/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${canonicalHash}`;
  const signingKey = await deriveSigningKey(cfg.secretAccessKey, dateStamp, cfg.region);
  const signature = bufToHex(await hmacSha256(signingKey, stringToSign));

  headers["Authorization"] =
    `AWS4-HMAC-SHA256 Credential=${cfg.accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  // 把 query 也拼进 url
  if (query) url += `?${query.toString()}`;

  return { url, headers };
}

/** 构造 S3 Provider —— 通用 S3 兼容存储 */
export function createS3Provider(cfg: S3Config): StorageProvider {
  const endpoint = cfg.endpoint.replace(/\/+$/, "");
  const region = cfg.region || "us-east-1";
  const addressing = cfg.addressingStyle || "path";

  async function doFetch(
    method: string,
    key: string,
    opts: {
      query?: URLSearchParams;
      headers?: Record<string, string>;
      body?: ReadableStream<Uint8Array> | ArrayBuffer | Uint8Array | string;
      expectNoBody?: boolean;
    }
  ): Promise<Response> {
    const amzHeaders: Record<string, string> = opts.headers ? { ...opts.headers } : {};
    const now = new Date();

    // 计算 body SHA256（S3 签名需要）
    let bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // 空字符串 hash
    let fetchBody: any = undefined;
    if (opts.body !== undefined) {
      if (typeof opts.body === "string") {
        bodyHash = await sha256Hex(opts.body);
        fetchBody = opts.body;
      } else if (opts.body instanceof ReadableStream) {
        // ReadableStream 不适合 hash（消费后不能重放），使用 UNSIGNED-PAYLOAD
        bodyHash = "UNSIGNED-PAYLOAD";
        fetchBody = opts.body;
      } else if (opts.body instanceof Uint8Array || opts.body instanceof ArrayBuffer) {
        const buf = opts.body instanceof ArrayBuffer ? opts.body : opts.body.buffer;
        bodyHash = await sha256Hex(new TextDecoder().decode(buf));
        fetchBody = buf;
      }
    }

    const { url, headers } = await signS3Request(
      { ...cfg, endpoint, region, addressingStyle: addressing },
      method,
      key,
      opts.query,
      amzHeaders,
      bodyHash,
      now
    );

    const resp = await fetch(url, {
      method,
      headers,
      body: fetchBody,
    });
    return resp;
  }

  return {
    kind: "s3",

    async put(key, body, opts) {
      const headers: Record<string, string> = {};
      if (opts.contentType) headers["Content-Type"] = opts.contentType;
      if (opts.contentDisposition) headers["Content-Disposition"] = opts.contentDisposition;

      const resp = await doFetch("PUT", key, { body, headers });
      if (!resp.ok) {
        const text = await resp.text().catch(() => resp.statusText);
        throw new Error(`S3 PUT failed: ${resp.status} ${text}`);
      }
      const size = body instanceof Uint8Array ? body.byteLength
        : body instanceof ArrayBuffer ? body.byteLength
        : body instanceof ReadableStream ? -1 : 0;
      return { size: size >= 0 ? size : 0, etag: resp.headers.get("etag")?.replace(/"/g, "") || undefined };
    },

    async get(key, range) {
      const headers: Record<string, string> = {};
      if (range) {
        let rangeHeader: string;
        if (range.length !== undefined) {
          rangeHeader = `bytes=${range.offset}-${range.offset + range.length - 1}`;
        } else {
          rangeHeader = `bytes=${range.offset}-`;
        }
        headers["Range"] = rangeHeader;
      }
      const resp = await doFetch("GET", key, { headers });
      if (resp.status === 404 || resp.status === 403) return null;
      if (!resp.ok) {
        const text = await resp.text().catch(() => resp.statusText);
        throw new Error(`S3 GET failed: ${resp.status} ${text}`);
      }
      const sizeStr = resp.headers.get("Content-Length") || resp.headers.get("x-amz-meta-size") || "0";
      const size = parseInt(sizeStr, 10) || 0;
      return {
        body: resp.body!,
        size,
        contentType: resp.headers.get("Content-Type") || "application/octet-stream",
        etag: resp.headers.get("ETag") || "",
      };
    },

    async delete(key) {
      const resp = await doFetch("DELETE", key, { expectNoBody: true });
      if (!resp.ok && resp.status !== 404) {
        // S3 的 404 不算错误
        const text = await resp.text().catch(() => resp.statusText);
        throw new Error(`S3 DELETE failed: ${resp.status} ${text}`);
      }
    },

    async head(key) {
      const resp = await doFetch("HEAD", key, {});
      if (resp.status === 404 || resp.status === 403) return null;
      if (!resp.ok) return null;
      const size = parseInt(resp.headers.get("Content-Length") || "0", 10) || 0;
      return {
        size,
        contentType: resp.headers.get("Content-Type") || "application/octet-stream",
      };
    },
    async list(opts) {
      const prefix = opts.prefix ?? "";
      const limit = opts.limit ?? 100;
      const query = new URLSearchParams();
      query.set("list-type", "2");
      query.set("delimiter", "/");
      query.set("max-keys", String(limit));
      if (prefix) query.set("prefix", prefix);
      if (opts.marker) query.set("start-after", opts.marker);

      // ListObjectsV2 是对 bucket 本身发 GET，key 为空串
      const resp = await doFetch("GET", "", { query });
      if (!resp.ok) {
        const text = await resp.text().catch(() => resp.statusText);
        throw new Error(`S3 LIST failed: ${resp.status} ${text}`);
      }
      const xmlText = await resp.text();
      return parseS3ListXml(xmlText, prefix);
    },
  };
}


/* ═══════════════════════════════════════════════════════
 * Provider 3: 远程 WebDAV —— 纯 fetch + Basic Auth
 * 坚果云 / 阿里云盘 / OneDrive / Nextcloud 等都支持
 * ═══════════════════════════════════════════════════════ */

export interface WebDAVConfig {
  /** 服务器 URL，如 https://dav.jianguoyun.com/dav/ */
  url: string;
  /** Basic Auth 用户名 */
  username: string;
  /** Basic Auth 密码（明文，调用方负责解密） */
  password: string;
}

/** 极简 XML 解析器 —— 专用于 WebDAV PROPFIND 响应（Worker runtime 无 DOMParser） */
function parseWebdavPropfind(xml: string, baseUrlPath: string): StorageListResult {
  const entries: StorageListEntry[] = [];
  const basePath = baseUrlPath.replace(/\/+$/, ""); // e.g. "/dav/files/user"

  // 辅助：从 xml 中提取第一个 <tag>...</tag> 内容（忽略命名空间前缀如 D:）
  function extractTag(src: string, tag: string): string | null {
    const openRe = new RegExp(`<(?:\\w+:)?${tag}(?:\\s[^>]*)?>`, "i");
    const closeRe = new RegExp(`</(?:\\w+:)?${tag}>`, "i");
    const open = openRe.exec(src);
    if (!open) return null;
    const close = closeRe.exec(src.slice(open.index + open[0].length));
    if (!close) return null;
    return src.slice(open.index + open[0].length, open.index + open[0].length + close.index).trim();
  }

  // 辅助：检查是否有自闭合标签 <tag/> 或 <tag></tag>
  function hasEmptyTag(src: string, tag: string): boolean {
    const selfCloseRe = new RegExp(`<(?:\\w+:)?${tag}(?:\\s[^>]*)?/>`, "i");
    if (selfCloseRe.test(src)) return true;
    const openRe = new RegExp(`<(?:\\w+:)?${tag}(?:\\s[^>]*)?>`, "i");
    const closeRe = new RegExp(`</(?:\\w+:)?${tag}>`, "i");
    const open = openRe.exec(src);
    if (!open) return false;
    const close = closeRe.exec(src.slice(open.index + open[0].length));
    if (!close) return false;
    // 中间有没有别的东西（除了空白和子标签）
    const mid = src.slice(open.index + open[0].length, open.index + open[0].length + close.index).trim();
    return mid === "";
  }

  // 按 </response> 切割成块
  const responseCloseRe = /<\/(?:\w+:)?response>/gi;
  let lastIdx = 0;
  let m: RegExpExecArray | null;
  const responseBlocks: string[] = [];
  while ((m = responseCloseRe.exec(xml)) !== null) {
    // 找最近的 <response 开始
    const before = xml.slice(lastIdx, m.index);
    const openMatch = before.match(/<(?:\w+:)?response(?:\s[^>]*)?>/i);
    if (openMatch) {
      const start = lastIdx + openMatch.index!;
      responseBlocks.push(xml.slice(start, m.index + m[0].length));
    }
    lastIdx = m.index + m[0].length;
  }

  for (const block of responseBlocks) {
    const href = extractTag(block, "href");
    if (!href) continue;

    // 跳过 "." 或空 href
    if (!href || href === "." || href === basePath + "/" || href === basePath) continue;

    // href 是 URL 或绝对路径；提取 pathname
    let key = href;
    try {
      const u = new URL(href);
      key = u.pathname;
    } catch {
      // 已经是绝对路径
    }
    // 去掉 basePath 前缀
    if (key.startsWith(basePath)) {
      key = key.slice(basePath.length);
    }
    key = key.replace(/^\//, "");
    if (!key) continue;

    // 检查 resourcetype 是否包含 <collection/>
    const resTypeRaw = extractTag(block, "resourcetype") || "";
    const hasCollection = /<(?:\w+:)?collection(?:\s[^>]*)?\/?>/i.test(resTypeRaw);
    const isDirByHref = href.endsWith("/");
    const isDir = hasCollection || isDirByHref;

    const name = key.split("/").filter(Boolean).pop() || (isDir ? key.replace(/\/$/, "") : key);

    // size —— 如果目录且没有 getcontentlength，默认为 0
    let size = 0;
    const sizeStr = extractTag(block, "getcontentlength");
    if (sizeStr) size = parseInt(sizeStr, 10) || 0;

    let contentType = "application/octet-stream";
    const ctStr = extractTag(block, "getcontenttype");
    if (ctStr) contentType = ctStr;

    let lastModified = 0;
    const lmStr = extractTag(block, "getlastmodified");
    if (lmStr) {
      const t = Date.parse(lmStr);
      if (!Number.isNaN(t)) lastModified = t;
    }

    entries.push({ key, name, size, lastModified, isDir });
  }

  // hasEmptyTag 防止未使用警告
  void hasEmptyTag;

  return { entries, truncated: false };
}

/** 构造完整远程 URL */
function buildWebdavUrl(baseUrl: string, key: string): string {
  const base = baseUrl.replace(/\/+$/, "");
  const safeKey = key.replace(/^\//, "");
  // 手动编码 key 里的路径段（保留 /）
  const encoded = safeKey.split("/").map(encodeURIComponent).join("/");
  if (!safeKey) return base + "/";
  return base + "/" + encoded;
}

/** 构造 Basic Auth header */
function webdavAuth(username: string, password: string): string {
  const token = btoa(username + ":" + password);
  return "Basic " + token;
}

/** WebDAV Storage Provider —— 远程挂载外部网盘 */
export function createWebDAVProvider(cfg: WebDAVConfig): StorageProvider {
  const baseUrl = cfg.url.replace(/\/+$/, "");
  // base URL 解析出来的 pathname，PROPFIND 里 href 会包含这个前缀
  let baseUrlPath = "/";
  try {
    baseUrlPath = new URL(baseUrl).pathname || "/";
  } catch {}
  baseUrlPath = baseUrlPath.replace(/\/+$/, "");

  async function doFetch(method: string, key: string, opts: {
    headers?: Record<string, string>;
    body?: BodyInit;
    expected?: number[];
    noThrow?: boolean;
  } = {}): Promise<Response> {
    const hdrs: Record<string, string> = {
      Authorization: webdavAuth(cfg.username, cfg.password),
      ...(opts.headers || {}),
    };
    const url = buildWebdavUrl(baseUrl, key);
    const resp = await fetch(url, { method, headers: hdrs, body: opts.body });
    const ok = opts.expected ? opts.expected.includes(resp.status) : resp.ok;
    if (!ok && !opts.noThrow) {
      const text = await resp.text().catch(() => resp.statusText);
      throw new Error(`WebDAV ${method} failed: ${resp.status} ${text}`);
    }
    return resp;
  }

  return {
    kind: "webdav",

    async put(key, body, opts) {
      const hdrs: Record<string, string> = {};
      if (opts.contentType) hdrs["Content-Type"] = opts.contentType;
      if (opts.contentDisposition) hdrs["Content-Disposition"] = opts.contentDisposition;

      // WebDAV PUT 需要父目录存在，尝试自动创建
      const parts = key.split("/");
      if (parts.length > 1) {
        let acc = "";
        for (let i = 0; i < parts.length - 1; i++) {
          acc += parts[i] + "/";
          try {
            await doFetch("MKCOL", acc, { noThrow: true });
          } catch {} // 目录已存在会报 405/409，忽略
        }
      }

      const resp = await doFetch("PUT", key, { headers: hdrs, body: body as any });
      const size = body instanceof Uint8Array ? body.byteLength
        : body instanceof ArrayBuffer ? body.byteLength
        : 0;
      return { size, etag: resp.headers.get("etag") || undefined };
    },

    async get(key, range) {
      const hdrs: Record<string, string> = {};
      if (range) {
        let rangeHeader: string;
        if (range.length !== undefined) {
          rangeHeader = `bytes=${range.offset}-${range.offset + range.length - 1}`;
        } else {
          rangeHeader = `bytes=${range.offset}-`;
        }
        hdrs["Range"] = rangeHeader;
      }
      const resp = await doFetch("GET", key, { headers: hdrs, expected: [200, 206, 404, 403], noThrow: true });
      if (resp.status === 404 || resp.status === 403) return null;
      if (!resp.ok) throw new Error(`WebDAV GET failed: ${resp.status}`);

      const sizeStr = resp.headers.get("Content-Length") || "0";
      return {
        body: resp.body!,
        size: parseInt(sizeStr, 10) || 0,
        contentType: resp.headers.get("Content-Type") || "application/octet-stream",
        etag: resp.headers.get("ETag") || "",
      };
    },

    async delete(key) {
      await doFetch("DELETE", key, { expected: [200, 204, 207, 404], noThrow: true });
    },

    async head(key) {
      const resp = await doFetch("HEAD", key, { expected: [200, 207, 404, 403], noThrow: true });
      if (resp.status === 404 || resp.status === 403) return null;
      if (!resp.ok) return null;
      const size = parseInt(resp.headers.get("Content-Length") || "0", 10) || 0;
      return { size, contentType: resp.headers.get("Content-Type") || "application/octet-stream" };
    },

    async list(opts) {
      const prefix = opts.prefix ?? "";
      const limit = opts.limit ?? 100;

      // PROPFIND 请求体：Depth: 1 只列直接子项
      const propfindBody = `<?xml version="1.0" encoding="utf-8"?>\n<D:propfind xmlns:D="DAV:">\n  <D:prop>\n    <D:resourcetype/>\n    <D:getcontentlength/>\n    <D:getcontenttype/>\n    <D:getlastmodified/>\n  </D:prop>\n</D:propfind>`;

      const resp = await doFetch("PROPFIND", prefix || "", {
        headers: {
          "Depth": "1",
          "Content-Type": "application/xml",
        },
        body: propfindBody,
        expected: [200, 207],
        noThrow: false,
      });
      const xmlText = await resp.text();
      const result = parseWebdavPropfind(xmlText, baseUrlPath);

      // PROPFIND 会返回当前目录自身（href = base），过滤掉
      result.entries = result.entries.filter(e => e.key !== prefix.replace(/\/$/, ""));

      // limit 截断
      if (result.entries.length > limit) {
        result.entries = result.entries.slice(0, limit);
        result.truncated = true;
      }

      return result;
    },
  };
}

/* ═══════════════════════════════════════════════════════
 * Storage Provider 工厂 —— 根据 settings 自动选择后端
 *
 * 优先级：
 *   1. storage_provider === "webdav" 且配置了远程 URL → 用 WebDAV
 *   2. storage_provider === "s3" 且配置了 S3 → 用 S3
 *   3. 否则默认用 env.r2（需要 env.r2 binding 存在）
 * ═══════════════════════════════════════════════════════ */

export async function createStorageProvider(
  env: Env,
  settings: {
    storageProvider: string | null;
    s3Endpoint: string | null;
    s3Region: string | null;
    s3Bucket: string | null;
    s3AccessKeyId: string | null;
    s3SecretKeyCipher: string | null;
    s3AddressingStyle: string | null;
    storageWebdavUrl: string | null;
    storageWebdavUsername: string | null;
    storageWebdavPasswordCipher: string | null;
  }
): Promise<StorageProvider> {
  // ① WebDAV
  const useWebdav = settings.storageProvider === "webdav" && settings.storageWebdavUrl && settings.storageWebdavUsername;
  if (useWebdav) {
    const password = settings.storageWebdavPasswordCipher
      ? await decryptSecret(settings.storageWebdavPasswordCipher, env.admin)
      : null;
    if (!password) throw new Error("Storage: WebDAV password not configured");
    return createWebDAVProvider({
      url: settings.storageWebdavUrl!,
      username: settings.storageWebdavUsername!,
      password,
    });
  }
  // ② S3
  const useS3 = settings.storageProvider === "s3" && settings.s3Endpoint && settings.s3Bucket;
  if (useS3) {
    const secretAccessKey = settings.s3SecretKeyCipher
      ? await decryptSecret(settings.s3SecretKeyCipher, env.admin)
      : null;
    if (!secretAccessKey || !settings.s3AccessKeyId) {
      // S3 配置不完整，回退到 R2
      if (!env.r2) throw new Error("Storage: S3 config incomplete and no R2 binding available");
      return createR2Provider(env.r2);
    }
    return createS3Provider({
      endpoint: settings.s3Endpoint!,
      region: settings.s3Region || "us-east-1",
      bucket: settings.s3Bucket!,
      accessKeyId: settings.s3AccessKeyId,
      secretAccessKey,
      addressingStyle: (settings.s3AddressingStyle as "path" | "virtual") || "path",
    });
  }
  // ③ 默认 R2
  if (!env.r2) throw new Error("Storage: no R2 binding and S3/WebDAV not configured");
  return createR2Provider(env.r2);
}
