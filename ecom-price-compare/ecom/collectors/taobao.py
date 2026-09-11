"""淘宝/天猫采集器: 真实抓取需要登录态, 默认直接抛错(由上层回退示例数据).

保留真实抓取通道占位: 若配置提供 cookies, 可尝试 s.taobao.com 搜索页解析
写在 window.__INITIAL_DATA__ 中的商品 JSON.
"""
from __future__ import annotations

import logging

from .base import BaseCollector, CollectorError

logger = logging.getLogger("ecom.collector.taobao")


class TaobaoCollector(BaseCollector):
    platform = "taobao"
    display_name = "淘宝/天猫"

    def collect(self, keyword: str, limit: int = 20):
        # 淘宝搜索需要登录与滑块验证, 未配置 cookies 时直接抛出, 交由上层示例兜底
        raise CollectorError(
            "淘宝/天猫搜索需要登录态(cookies), 未提供有效凭证; 已自动回退示例数据"
        )