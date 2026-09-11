"""配置加载: 读取 config.yaml, 提供默认值."""
from __future__ import annotations

import os
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FLOW = 60  # 每次采集温度调整系数, 仅供演示

DEFAULTS = {
    "request": {
        "timeout": 8,          # 单次 HTTP 请求超时(秒)
        "retry": 2,            # 失败重试次数
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept-Language": "zh-CN,zh;q=0.9",
        },
    },
    "pipeline": {
        "mode": "auto",        # auto=真实抓取优先,失败回退示例 / real=仅真实 / sample=仅示例
        "fallback_sample": True,
        "max_items_per_platform": 20,
        "dedup_similarity": 0.82,   # 标题相似度阈值, 超过则视为同一商品
    },
    "analysis": {
        "w_price": 0.5,        # 性价比评分权重: 价格
        "w_sales": 0.3,        # 销量
        "w_score": 0.2,        # 店铺评分
        "top_n": 3,            # 推荐数量
    },
    "paths": {
        "data_dir": "data",
        "history_dir": "data/history",
        "sample_dir": "data/sample",
        "output_dir": "output",
    },
    "web": {"host": "127.0.0.1", "port": 8000},
}


class Config:
    def __init__(self, base_dir: Path = _ROOT):
        self.base_dir = base_dir
        self.data = self._load(base_dir / "config.yaml")

    def _load(self, path: Path) -> dict:
        cfg = self._deep_copy(DEFAULTS)
        if path.exists():
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            self._merge(cfg, loaded)
        return cfg

    @staticmethod
    def _merge(base: dict, extra: dict) -> None:
        for k, v in extra.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                Config._merge(base[k], v)
            else:
                base[k] = v

    @staticmethod
    def _deep_copy(d: dict) -> dict:
        import copy
        return copy.deepcopy(d)

    def get(self, *keys, default=None):
        node: dict = self.data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    @property
    def request(self) -> dict:
        return self.data["request"]

    @property
    def pipeline(self) -> dict:
        return self.data["pipeline"]

    @property
    def analysis(self) -> dict:
        return self.data["analysis"]

    @property
    def web(self) -> dict:
        return self.data["web"]

    def path(self, key: str, *subs: str) -> Path:
        rel = os.path.join(self.get("paths", "data_dir"), *subs)
        p = Path(rel)
        if not p.is_absolute():
            p = self.base_dir / p
        p.mkdir(parents=True, exist_ok=True)
        return p


_default_config: Config | None = None


def get_config() -> Config:
    global _default_config
    if _default_config is None:
        _default_config = Config()
    return _default_config