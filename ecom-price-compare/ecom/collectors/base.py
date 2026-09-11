"""采集器基类."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from ecom.models import ProductItem

logger = logging.getLogger("ecom.collector")


class CollectorError(Exception):
    """采集失败."""


class BaseCollector(ABC):
    """平台采集器抽象.

    每个平台实现一个 collect(), 返回原始商品列表(可能重复/脏数据),
    清洗与去重由上层 processor 统一处理.
    """

    platform: str = ""
    display_name: str = ""

    def __init__(self, platform: str, config):
        self.platform = platform
        self.config = config

    @abstractmethod
    def collect(self, keyword: str, limit: int = 20) -> list[ProductItem]:
        """按关键词抓取指定数量的商品."""

    def _make_item(self, title: str, price: float, sales: int, shop: str,
                   score: float, url: str, source: str = "real") -> ProductItem:
        return ProductItem(
            id="",
            platform=self.platform,
            title=title,
            price=round(float(price), 2),
            sales=int(sales or 0),
            shop_name=shop,
            shop_score=round(float(score or 0), 2),
            url=url,
            source=source,
        )