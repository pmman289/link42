from __future__ import annotations

import re


AGENT_VERSION = "0.6.23"
AGENT_PROTOCOL_VERSION = 1
CONTROLLER_VERSION = "0.6.28"


def parse_version(value: str | None) -> tuple[int, int, int]:
    """解析兼容 Agent/主控版本比较的前三段数字。"""

    if not value:
        return (0, 0, 0)
    match = re.match(r"^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(value))
    if not match:
        return (0, 0, 0)
    return tuple(int(group or 0) for group in match.groups())  # type: ignore[return-value]
