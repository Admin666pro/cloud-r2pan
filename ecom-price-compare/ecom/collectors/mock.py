"""示例/模拟数据采集器.

作用:
1. 预置数据模式: 若 data/sample/<keyword>.json 存在, 直接读取该示例数据文件 (真实示例数据);
2. 生成器模式: 基于关键字种子确定性生成真实感数据, 支持"跨天价格微浮动"
   以模拟真实行情, 供离线演示与价格趋势功能使用.

价格按 (关键字+平台+商品) 种子生成基准价, 再叠加 (日期) 种子的 ±3% 浮动,
保证跨天采集能看到趋势波动, 而同一天内多次采集结果稳定.
"""
from __future__ import annotations

import hashlib
import json
import logging
import random
from datetime import date
from pathlib import Path

from ecom.models import ProductItem

from .base import BaseCollector

logger = logging.getLogger("ecom.collector.sample")

BRANDS = ["华为", "小米", "苹果", "OPPO", "vivo", "三星", "联想", "罗技", "雷蛇",
          "飞利浦", "索尼", "漫步者", "美的", "戴森", "得力", "晨光", "爱国者", "纽曼"]
MODELS = ["Pro", "Max", "Plus", "Lite", "S", " 2026 新款", "经典款", "青春版"]
ATTRS = ["官方旗舰版", "升级款", "高清", "便携", "高颜值", "学生党优选", "家用", "高性能", "热销爆款", "正品保障"]
SHOP_SUFFIX = {"jd": ["京东自营", "官方旗舰店", "授权专营店"],
               "taobao": ["官方旗舰店", "数码专营店", "品质生活馆"],
               "tmall": ["天猫旗舰店", "天猫专营店"],
               "pdd": ["官方旗舰店", "品牌专营店", "百货优选"]}
DEFAULT_ITEMS = 12


def _seed(*parts: str) -> int:
    raw = "|".join(parts).encode("utf-8")
    return int(hashlib.sha256(raw).hexdigest()[:8], 16)


def _day_variation(keyword: str, platform: str, product_id: str) -> float:
    """同商品跨天价格浮动系数 (±3%)."""
    rnd = random.Random(_seed(keyword, platform, product_id, date.today().isoformat()))
    return rnd.uniform(-0.03, 0.03)


class SampleCollector(BaseCollector):
    display_name = "示例数据"

    def __init__(self, platform: str, config):
        super().__init__(platform, config)
        self.sample_dir: Path = Path(config.path("sample_dir"))

    def collect(self, keyword: str, limit: int = DEFAULT_ITEMS) -> list[ProductItem]:
        # 1) 预置示例数据文件优先
        sample_file = self.sample_dir / f"{keyword}.json"
        if sample_file.exists():
            items = self._from_file(sample_file)
            if items:
                return items[:limit]
        # 2) 生成器模式
        return self._generate(keyword, limit)

    # ---------- 预置示例数据 ----------
    def _from_file(self, path: Path) -> list[ProductItem]:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("示例数据解析失败 %s: %s", path, e)
            return []
        items = []
        for r in raw:
            platform = r.get("platform", self.platform)
            items.append(ProductItem(
                id="", platform=platform, title=r["title"], price=float(r["price"]),
                sales=int(r.get("sales", 0)), shop_name=r.get("shop_name", ""),
                shop_score=float(r.get("shop_score", 0)), url=r.get("url", ""),
                source="sample",
            ))
        return items

    # ---------- 生成器模式 ----------
    def _generate(self, keyword: str, limit: int) -> list[ProductItem]:
        platform = self.platform
        rnd = random.Random(_seed(keyword, platform))
        count = max(6, min(limit, 8 + rnd.randint(0, 6)))
        count = min(count, DEFAULT_ITEMS)

        brands = rnd.sample(BRANDS, count)
        items = []
        used = set()
        n = 0
        for i in range(count):
            brand = brands[i]
            model = rnd.choice(MODELS)
            attr = rnd.choice(ATTRS)
            title = f"{brand}{keyword}{model} {attr}"
            if title in used:
                continue
            used.add(title)
            product_id = str(_seed(platform, title))
            base_price = self._base_price(rnd, platform)
            price = round(base_price * (1 + _day_variation(keyword, platform, product_id)), 2)
            sales = self._base_sales(rnd, platform)
            score = round(rnd.uniform(4.2, 5.0), 2)
            shop = self._make_shop(rnd, brand, platform)
            url = f"{platform}://search?keyword={keyword}&item={n}"
            items.append(self._make_item(title, price, sales, shop, score, url, source="sample"))
            n += 1
        return items

    @staticmethod
    def _base_price(rnd: random.Random, platform: str) -> float:
        """按平台设定价格档位: 京东/天猫偏高, 拼多多偏低."""
        lo, hi = {"jd": (59, 3999), "tmall": (49, 3799),
                  "taobao": (39, 2999), "pdd": (19, 1599)}.get(platform, (39, 2999))
        base = rnd.uniform(lo, hi)
        if base > 200:
            base = round(base / 10) * 10 - 0.01   # 制造 1999.99 / 99.99 式定价
        return round(max(base, 9.9), 2)

    @staticmethod
    def _base_sales(rnd: random.Random, platform: str) -> int:
        scale = {"jd": (200, 200000), "tmall": (300, 300000),
                 "taobao": (100, 100000), "pdd": (1000, 900000)}.get(platform, (100, 100000))
        return int(rnd.uniform(*scale))

    @staticmethod
    def _make_shop(rnd: random.Random, brand: str, platform: str) -> str:
        suffix = rnd.choice(SHOP_SUFFIX.get(platform, SHOP_SUFFIX["taobao"]))
        if suffix == "京东自营":
            return "京东自营"
        return f"{brand}{suffix}"