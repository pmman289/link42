from __future__ import annotations

import ipaddress
import shutil
import subprocess
import time
from typing import Any


DEFAULT_BIRD_COMMAND_TIMEOUT_SECONDS = 8.0
DEFAULT_OUTPUT_LIMIT_BYTES = 256 * 1024


def normalized_ip(value: object) -> str:
    """校验并规范化 Looking Glass 查询目标 IP。"""

    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError as exc:
        raise ValueError("ip must be a valid IPv4 or IPv6 address") from exc


def positive_float(value: object, default: float) -> float:
    """读取正数配置项，非法或空值时返回默认值。"""

    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def positive_int(value: object, default: int) -> int:
    """读取正整数配置项，非法或空值时返回默认值。"""

    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def truncate_text(value: str, limit_bytes: int) -> tuple[str, bool]:
    """按 UTF-8 字节数截断命令输出，并返回是否发生截断。"""

    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit_bytes:
        return value, False
    truncated = encoded[:limit_bytes].decode("utf-8", errors="replace")
    return truncated, True


def coerce_text(value: object) -> str:
    """把 subprocess 返回的文本或字节输出统一转成字符串。"""

    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def birdc_binary() -> str:
    """查找 birdc 可执行文件。"""

    path = shutil.which("birdc")
    if not path:
        raise RuntimeError("birdc was not found")
    return path


def execute_bird_route_lookup(payload: dict[str, Any]) -> dict[str, Any]:
    """执行受限的 birdc show route for <ip> all 查询并返回原始输出。"""

    target_ip = normalized_ip(payload.get("ip"))
    timeout = positive_float(payload.get("command_timeout_seconds"), DEFAULT_BIRD_COMMAND_TIMEOUT_SECONDS)
    output_limit = positive_int(payload.get("output_limit_bytes"), DEFAULT_OUTPUT_LIMIT_BYTES)
    command = [birdc_binary(), "show", "route", "for", target_ip, "all"]
    started_at = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout, stdout_truncated = truncate_text(coerce_text(exc.stdout), output_limit)
        stderr, stderr_truncated = truncate_text(coerce_text(exc.stderr), output_limit)
        return {
            "command": f"birdc show route for {target_ip} all",
            "exit_code": None,
            "stdout": stdout,
            "stderr": stderr or f"command timed out after {timeout:g}s",
            "truncated": stdout_truncated or stderr_truncated,
            "duration_ms": int((time.monotonic() - started_at) * 1000),
            "error_code": "timeout",
            "error": f"BIRD 查询超过 {timeout:g} 秒未返回",
        }
    stdout, stdout_truncated = truncate_text(completed.stdout or "", output_limit)
    stderr, stderr_truncated = truncate_text(completed.stderr or "", output_limit)
    result = {
        "command": f"birdc show route for {target_ip} all",
        "exit_code": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "truncated": stdout_truncated or stderr_truncated,
        "duration_ms": int((time.monotonic() - started_at) * 1000),
    }
    if completed.returncode != 0:
        result["error_code"] = "command_failed"
        result["error"] = "BIRD 查询执行失败"
    return result
