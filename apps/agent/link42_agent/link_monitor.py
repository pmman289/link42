from __future__ import annotations

import re
import shutil
from datetime import datetime
from typing import Any

from .system import run_command


PING_TIME_RE = re.compile(r"time[=<]([0-9.]+)\s*ms")


def probe_latency(target_host: str, timeout_seconds: float) -> dict[str, Any]:
    """Ping a target once and return a Link42 monitor result payload."""

    ping_bin = ping_command_for_target(target_host)
    if ping_bin is None:
        return result(False, None, "ping command not found")
    timeout = max(1, int(round(timeout_seconds)))
    command = [ping_bin, "-n", "-c", "1", "-W", str(timeout), target_host]
    completed = run_command(command, allow_failure=True)
    output = f"{completed.get('stdout', '')}\n{completed.get('stderr', '')}"
    if completed["returncode"] != 0:
        return result(False, None, output.strip() or "timeout")
    match = PING_TIME_RE.search(output)
    if not match:
        return result(False, None, "ping output did not include latency")
    return result(True, float(match.group(1)), None)


def ping_command_for_target(target_host: str) -> str | None:
    """Pick an IPv4/IPv6 ping binary that works on common Linux and OpenWrt systems."""

    if ":" in target_host:
        return shutil.which("ping6") or shutil.which("ping")
    return shutil.which("ping")


def result(success: bool, latency_ms: float | None, error: str | None) -> dict[str, Any]:
    return {
        "checked_at": datetime.utcnow().isoformat(),
        "success": success,
        "latency_ms": latency_ms,
        "error": error,
    }
