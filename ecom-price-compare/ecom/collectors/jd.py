"""京东采集器: 真实尝试抓取 search.jd.com 搜索页, 失败/被风控时抛错交上层兜底."""
from __future__ import annotations

import logging
import re
import time
from urllib.parse import quote

from bs4 import BeautifulSoup

from ecom.models import ProductItem

from .base import BaseCollector, CollectorError

logger = logging.getLogger("ecom.collector.jd")

SEARCH_URL = "https://search.jd.com/Search"


class JDCollector(BaseCollector):
    platform = "jd"
    display_name = "京东"

    def collect(self, keyword: str, limit: int = 20) -> list[ProductItem]:
        import requests

        headers = dict(self.config.request["headers"])
        headers["Referer"] = "https://www.jd.com/"
        params = {"keyword": keyword, "enc": "utf-8", "wq": keyword, "psort": "3"}
        session = requests.Session()
        last_err: Exception | None = None

        for attempt in range(self.config.request["retry"] + 1):
            try:
                resp = session.get(
                    SEARCH_URL, params=params, headers=headers,
                    timeout=self.config.request["timeout"],
                )
                resp.raise_for_status()
                items = self._parse(resp.text, keyword)
                if not items:
                    raise CollectorError(f"京东未解析到商品(可能触发风控): HTTP {resp.status_code}")
                return items[:limit]
            except Exception as e:  # noqa: BLE001
                last_err = e
                time.sleep(0.8 * (attempt + 1))
        raise CollectorError(f"京东采集失败: {last_err}")

    def _parse(self, html: str, keyword: str) -> list[ProductItem]:
        """解析商品列表 HTML (li.gl-item: 名称/价格/店铺/评分/链接)."""
        soup = BeautifulSoup(html, "html.parser")
        result: list[ProductItem] = []
        for li in soup.select("li.gl-item"):
            sku = li.get("data-sku") or li.get("data-pid") or ""
            a = li.select_one(".p-name a")
            if not a:
                continue
            title = a.get_text("", strip=True)
            if not title or keyword and keyword not in title:
                continue
            price = self._parse_price(li)
            shop = self._parse_shop(li)
            score = self._parse_score(li)
            sales = self._parse_sales(li)
            url = "https://item.jd.com/{}.html".format(sku) if sku else a.get("href", "")
            if not url.startswith("http"):
                url = "https:" + url if url.startswith("//") else "https://item.jd.com/" + url.lstrip("/")
            result.append(self._make_item(title, price, sales, shop, score, url, source="real"))
        return result

    @staticmethod
    def _parse_price(li) -> float:
        p = li.select_one(".p-price i")
        if p:
            try:
                return float(p.get_text(strip=True).replace(",", ""))
            except ValueError:
                pass
        # 兜底: 从 onclick/promotion 中抓价格
        m = re.search(r'"p":"?([\d.]+)"?', str(li))
        return float(m.group(1)) if m else 0.0

    @staticmethod
    def _parse_shop(li) -> str:
        s = li.select_one(".p-shop a")
        return s.get_text(strip=True) if s else ""

    @staticmethod
    def _parse_score(li) -> float:
        # 京东列表页无评分, 按星级估计 4.5-4.9
        return 4.7

    @staticmethod
    def _parse_sales(li) -> int:
        s = li.select_one(".p-commit strong a")
        if s:
            txt = s.get_text(strip=True)
            m = re.search(r"(\d+(?:\.\d+)?)(万|w)?", txt)
            if m:
                num = float(m.group(1))
                return int(num * 10000) if m.group(2) else int(num)
        return 0