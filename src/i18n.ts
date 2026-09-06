/** 服务端国际化：根据 Accept-Language（首选）+ Cloudflare 时区（兜底）判断语言 */
export type Lang = "zh" | "en";
export type L10n = { zh: string; en: string };

/** 中国大陆/港澳台时区 */
const CN_TIMEZONES =
  /^Asia\/(Shanghai|Chongqing|Harbin|Urumqi|Kashgar|Hong_Kong|Macau|Taipei)$/;

export function pickLang(req: Request): Lang {
  // 1. Accept-Language 首选语言（浏览器自动携带，前端 fetch 也会带上）
  const al = req.headers.get("accept-language");
  if (al) {
    const first = al.split(",")[0]?.trim().toLowerCase() ?? "";
    if (first.startsWith("zh")) return "zh";
    if (first.startsWith("en")) return "en";
  }
  // 2. Cloudflare 注入的访客时区
  const tz = (req as Request & { cf?: { timeZone?: string } }).cf?.timeZone;
  if (tz && CN_TIMEZONES.test(tz)) return "zh";
  // 3. 默认英文
  return "en";
}
