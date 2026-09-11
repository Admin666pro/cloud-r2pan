"""各平台采集器."""
from .base import BaseCollector, CollectorError
from .jd import JDCollector
from .taobao import TaobaoCollector
from .pdd import PDDCollector
from .mock import SampleCollector

# 平台标识 -> 采集器类
COLLECTORS = {
    "jd": JDCollector,
    "taobao": TaobaoCollector,
    "pdd": PDDCollector,
}

PLATFORM_NAMES = {
    "jd": "京东",
    "taobao": "淘宝",
    "tmall": "天猫",
    "pdd": "拼多多",
}


def build_collector(platform: str, config, mode: str):
    """根据 mode 构造采集器:
    - real: 仅真实抓取
    - sample: 仅示例/模拟数据
    - auto: 真实抓取器, 失败时由上层用示例数据兜底
    """
    if mode == "sample":
        return SampleCollector(platform, config)
    cls = COLLECTORS.get(platform)
    if cls is None:
        return SampleCollector(platform, config)
    return cls(platform, config)