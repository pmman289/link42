from __future__ import annotations

import re
import shutil
import unicodedata
from datetime import datetime
from typing import Any

from .system import run_command


PING_TIME_RE = re.compile(r"time[=<]([0-9.]+)\s*ms")


def sanitize_error(value: object, max_bytes: int = 500) -> str:
    """Convert command output into one-line text accepted by the controller."""

    text = str(value or "")
    text = " ".join(text.split())
    text = "".join(char for char in text if ord(char) >= 0x20 and ord(char) != 0x7F and not unicodedata.category(char).startswith("C"))
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    marker = " ...[truncated]"
    head = encoded[: max_bytes - len(marker.encode("utf-8"))].decode("utf-8", errors="ignore")
    return head + marker


def probe_latency(target_host: str, timeout_seconds: float) -> dict[str, Any]:
    """对目标地址执行一次 ping，并返回链路监测结果。"""

    ping_bin = ping_command_for_target(target_host)
    if ping_bin is None:
        return result(False, None, "ping command not found")
    timeout = max(1, int(round(timeout_seconds)))
    command = [ping_bin, "-n", "-c", "1", "-W", str(timeout), target_host]
    # ping 自身的 -W 只限制探测等待；再给进程一个小的外层上限，避免
    # 异常实现或解析器把整轮 Agent 轮询拖到通用命令超时。
    completed = run_command(command, allow_failure=True, timeout=float(timeout) + 1.0)
    output = f"{completed.get('stdout', '')}\n{completed.get('stderr', '')}"
    if completed["returncode"] != 0:
        return result(False, None, sanitize_error(output) or "timeout")
    match = PING_TIME_RE.search(output)
    if not match:
        return result(False, None, "ping output did not include latency")
    return result(True, float(match.group(1)), None)


def ping_command_for_target(target_host: str) -> str | None:
    """按目标地址类型选择常见 Linux/OpenWrt 可用的 ping 命令。"""

    if ":" in target_host:
        return shutil.which("ping6") or shutil.which("ping")
    return shutil.which("ping")


def result(success: bool, latency_ms: float | None, error: str | None) -> dict[str, Any]:
    """组装 Agent 上报链路监测结果时使用的统一结构。"""

    return {
        "checked_at": datetime.utcnow().isoformat(),
        "success": success,
        "latency_ms": latency_ms,
        "error": error,
    }
