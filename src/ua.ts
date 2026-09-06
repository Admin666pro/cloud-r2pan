/** 轻量 User-Agent 解析（浏览器 + 操作系统） */
export function parseUA(ua: string): { browser: string; os: string } {
  let browser = "未知";
  let os = "未知";

  if (/Edg(e|A|iOS)?\//.test(ua)) browser = "Edge";
  else if (/OPR\/|Opera/.test(ua)) browser = "Opera";
  else if (/SamsungBrowser\//.test(ua)) browser = "三星浏览器";
  else if (/MiuiBrowser\//.test(ua)) browser = "小米浏览器";
  else if (/QQBrowser\//.test(ua)) browser = "QQ 浏览器";
  else if (/MicroMessenger\//.test(ua)) browser = "微信";
  else if (/Firefox\//.test(ua)) browser = "Firefox";
  else if (/CriOS\//.test(ua)) browser = "Chrome";
  else if (/Chrome\//.test(ua)) browser = "Chrome";
  else if (/FxiOS\//.test(ua)) browser = "Firefox";
  else if (/Safari\//.test(ua) && /Version\//.test(ua)) browser = "Safari";
  else if (/curl\//i.test(ua)) browser = "curl";
  else if (/Wget\//i.test(ua)) browser = "Wget";
  else if (/python-requests/i.test(ua)) browser = "Python";
  else if (/axios\//i.test(ua)) browser = "axios";

  if (/iPhone/.test(ua)) os = "iOS";
  else if (/iPad/.test(ua)) os = "iPadOS";
  else if (/Android/.test(ua)) os = "Android";
  else if (/Windows NT 11/.test(ua)) os = "Windows 11";
  else if (/Windows NT 10/.test(ua)) os = "Windows";
  else if (/Windows/.test(ua)) os = "Windows";
  else if (/Mac OS X|Macintosh/.test(ua)) os = "macOS";
  else if (/CrOS/.test(ua)) os = "ChromeOS";
  else if (/Linux/.test(ua)) os = "Linux";

  return { browser, os };
}
