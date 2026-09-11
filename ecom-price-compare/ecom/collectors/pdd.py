"""拼多多采集器: 反爬极强, 需签名参数与登录态, 默认直接抛错(由上层回退示例数据)."""
from __future__ import annotations

import logging

from .base import BaseCollector, CollectorError

logger = logging.getLogger("ecom.collector.pdd")


class PDDCollector(BaseCollector):
    platform = "pdd"
    display_name = "拼多多"

    def collect(self, keyword: str, limit: int = 20):
        raise CollectorError(
            "拼多多接口需签名与登录态, 无法匿名抓取; 已自动回退示例数据"
        )