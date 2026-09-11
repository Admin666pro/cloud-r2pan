"""数据模型定义."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ProductItem:
    """一条商品采集记录."""

    id: str                            # 商品唯一ID(由平台+来源生成)
    platform: str                      # 平台: jd / taobao / pdd / tmall
    title: str                         # 商品名称
    price: float                       # 当前价格(元)
    sales: int                         # 销量(件)
    shop_name: str = ""                # 店铺名称
    shop_score: float = 0.0            # 店铺评分(0-5)
    url: str = ""                      # 商品链接
    source: str = "sample"             # 数据来源: real(真实抓取) / sample(示例/模拟)
    fetched_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    @property
    def product_key(self) -> str:
        """商品去重键: 平台 + 规范化标题. 用于跨次运行识别同一商品, 跟踪价格趋势."""
        norm = "".join(ch for ch in self.title.lower() if ch.isalnum())
        return f"{self.platform}:{norm}"

    @property
    def price_text(self) -> str:
        return f"¥{self.price:,.2f}"

    def to_record(self) -> dict:
        d = asdict(self)
        d["product_key"] = self.product_key
        return d


@dataclass
class PricePoint:
    """价格趋势中的一个采样点."""

    date: str        # YYYY-MM-DD
    price: float


@dataclass
class CollectResult:
    """一次采集任务的完整结果(采集 + 处理 + 分析)."""

    keyword: str
    items: list[ProductItem]                       # 清洗去重并按价格升序后的商品
    total_collected: int = 0                       # 采集原始条数
    deduped: int = 0                               # 去重删除条数
    platforms: list[str] = field(default_factory=list)
    analysis: dict = field(default_factory=dict)   # 性价比推荐等分析结果
    trend: dict = field(default_factory=dict)      # 价格趋势
    fetched_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def to_dict(self) -> dict:
        return {
            "keyword": self.keyword,
            "total_collected": self.total_collected,
            "deduped": self.deduped,
            "platforms": self.platforms,
            "fetched_at": self.fetched_at,
            "items": [i.to_record() for i in self.items],
            "analysis": self.analysis,
            "trend": self.trend,
        }


def make_id(platform: str, *parts: str) -> str:
    raw = f"{platform}|" + "|".join(parts)
    return hashlib.md5(raw.encode("utf-8")).hexdigest()[:16]