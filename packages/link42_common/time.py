from __future__ import annotations

from datetime import datetime, timezone


def utcnow_naive() -> datetime:
    """返回 UTC 的无时区时间，兼容项目现有数据库 DateTime 字段。"""

    return datetime.now(timezone.utc).replace(tzinfo=None)
