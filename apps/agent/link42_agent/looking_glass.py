from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import time
from typing import Any


DEFAULT_BIRD_COMMAND_TIMEOUT_SECONDS = 8.0
DEFAULT_PING_COMMAND_TIMEOUT_SECONDS = 12.0
DEFAULT_TRACEROUTE_COMMAND_TIMEOUT_SECONDS = 20.0
DEFAULT_OUTPUT_LIMIT_BYTES = 256 * 1024
TARGET_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
PROTOCOL_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}$")
MIN_BGP_ASN = 1
MAX_BGP_ASN = 4294967295


def normalized_ip(value: object) -> str:
    """校验并规范化 Looking Glass 查询目标 IP。"""

    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError as exc:
        raise ValueError("ip must be a valid IPv4 or IPv6 address") from exc


def normalized_target(value: object) -> str:
    """校验并规范化 ping/traceroute 目标，允许 IP 或普通域名。"""

    text = str(value or "").strip()
    if not text:
        raise ValueError("target is required")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if TARGET_HOSTNAME_RE.fullmatch(text) and ".." not in text:
        return text.rstrip(".").lower()
    raise ValueError("target must be a valid IP address or hostname")


def normalized_protocol_name(value: object) -> str:
    """校验 BIRD 协议名称，避免空白和命令控制字符进入 birdc 参数。"""

    name = str(value or "").strip()
    if PROTOCOL_NAME_RE.fullmatch(name):
        return name
    raise ValueError("protocol_name must use 1-64 characters: letters, numbers, _, ., :, -")


def normalized_bgp_asn(value: object) -> int:
    """校验并规范化 BGP ASN，只允许 1 到 4294967295 的整数。"""

    text = str(value or "").strip()
    if not re.fullmatch(r"\d+", text):
        raise ValueError("asn must be an integer between 1 and 4294967295")
    parsed = int(text)
    if MIN_BGP_ASN <= parsed <= MAX_BGP_ASN:
        return parsed
    raise ValueError("asn must be an integer between 1 and 4294967295")


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


def required_binary(name: str) -> str:
    """查找必须存在的系统命令。"""

    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"{name} was not found")
    return path


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    """读取带上下限的整数参数，非法或空值时返回默认值。"""

    parsed = positive_int(value, default)
    return max(minimum, min(maximum, parsed))


def run_fixed_command(command: list[str], timeout: float, output_limit: int, timeout_message: str) -> dict[str, Any]:
    """执行固定参数命令，统一裁剪输出并返回原始 stdout/stderr。"""

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
            "command": " ".join(command[1:]),
            "exit_code": None,
            "stdout": stdout,
            "stderr": stderr or f"command timed out after {timeout:g}s",
            "truncated": stdout_truncated or stderr_truncated,
            "duration_ms": int((time.monotonic() - started_at) * 1000),
            "error_code": "timeout",
            "error": timeout_message,
        }
    stdout, stdout_truncated = truncate_text(completed.stdout or "", output_limit)
    stderr, stderr_truncated = truncate_text(completed.stderr or "", output_limit)
    result = {
        "command": " ".join(command[1:]),
        "exit_code": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "truncated": stdout_truncated or stderr_truncated,
        "duration_ms": int((time.monotonic() - started_at) * 1000),
    }
    if completed.returncode != 0:
        result["error_code"] = "command_failed"
        result["error"] = "命令执行失败"
    return result


def execute_bird_route_lookup(payload: dict[str, Any]) -> dict[str, Any]:
    """执行受限的 birdc show route for <ip> all 查询并返回原始输出。"""

    target_ip = normalized_ip(payload.get("ip"))
    timeout = positive_float(payload.get("command_timeout_seconds"), DEFAULT_BIRD_COMMAND_TIMEOUT_SECONDS)
    output_limit = positive_int(payload.get("output_limit_bytes"), DEFAULT_OUTPUT_LIMIT_BYTES)
    command = [birdc_binary(), "show", "route", "for", target_ip, "all"]
    result = run_fixed_command(command, timeout, output_limit, f"BIRD 查询超过 {timeout:g} 秒未返回")
    result["command"] = f"birdc show route for {target_ip} all"
    if result.get("error_code") == "command_failed":
        result["error"] = "BIRD 查询执行失败"
    return result


def execute_bird_routes_by_origin_as(payload: dict[str, Any]) -> dict[str, Any]:
    """执行受限的 birdc show route where bgp_path.last = <asn> all primary 查询并返回原始输出。"""

    asn = normalized_bgp_asn(payload.get("asn"))
    timeout = positive_float(payload.get("command_timeout_seconds"), DEFAULT_BIRD_COMMAND_TIMEOUT_SECONDS)
    output_limit = positive_int(payload.get("output_limit_bytes"), DEFAULT_OUTPUT_LIMIT_BYTES)
    command = [
        birdc_binary(),
        "show",
        "route",
        "where",
        "bgp_path.last",
        "=",
        str(asn),
        "all",
        "primary",
    ]
    result = run_fixed_command(command, timeout, output_limit, f"BIRD ASN 路由查询超过 {timeout:g} 秒未返回")
    result["command"] = f"birdc show route where bgp_path.last = {asn} all primary"
    if result.get("error_code") == "command_failed":
        result["error"] = "BIRD ASN 路由查询执行失败"
    return result


def execute_bird_protocols(payload: dict[str, Any]) -> dict[str, Any]:
    """执行受限的 birdc show protocols 查询并返回原始输出。"""

    timeout = positive_float(payload.get("command_timeout_seconds"), DEFAULT_BIRD_COMMAND_TIMEOUT_SECONDS)
    output_limit = positive_int(payload.get("output_limit_bytes"), DEFAULT_OUTPUT_LIMIT_BYTES)
    command = [birdc_binary(), "show", "protocols"]
    result = run_fixed_command(command, timeout, output_limit, f"BIRD 协议状态查询超过 {timeout:g} 秒未返回")
    result["command"] = "birdc show protocols"
    if result.get("error_code") == "command_failed":
        result["error"] = "BIRD 协议状态查询执行失败"
    return result


def execute_bird_protocol_detail(payload: dict[str, Any]) -> dict[str, Any]:
    """执行受限的 birdc show protocols all <protocol_name> 查询并返回原始输出。"""

    protocol_name = normalized_protocol_name(payload.get("protocol_name"))
    timeout = positive_float(payload.get("command_timeout_seconds"), DEFAULT_BIRD_COMMAND_TIMEOUT_SECONDS)
    output_limit = positive_int(payload.get("output_limit_bytes"), DEFAULT_OUTPUT_LIMIT_BYTES)
    command = [birdc_binary(), "show", "protocols", "all", protocol_name]
    result = run_fixed_command(command, timeout, output_limit, f"BIRD 协议详情查询超过 {timeout:g} 秒未返回")
    result["command"] = f"birdc show protocols all {protocol_name}"
    if result.get("error_code") == "command_failed":
        result["error"] = "BIRD 协议详情查询执行失败"
    return result


def execute_ping(payload: dict[str, Any]) -> dict[str, Any]:
    """执行受限 ping 查询并返回原始输出。"""

    target = normalized_target(payload.get("target"))
    count = bounded_int(payload.get("count"), 4, 1, 10)
    per_probe_timeout = bounded_int(payload.get("per_probe_timeout_seconds"), 2, 1, 10)
    timeout = positive_float(payload.get("command_timeout_seconds"), DEFAULT_PING_COMMAND_TIMEOUT_SECONDS)
    output_limit = positive_int(payload.get("output_limit_bytes"), DEFAULT_OUTPUT_LIMIT_BYTES)
    command = [required_binary("ping"), "-c", str(count), "-W", str(per_probe_timeout), target]
    result = run_fixed_command(command, timeout, output_limit, f"ping 超过 {timeout:g} 秒未返回")
    result["command"] = f"ping -c {count} -W {per_probe_timeout} {target}"
    if result.get("error_code") == "command_failed":
        result["error"] = "ping 执行失败"
    return result


def execute_traceroute(payload: dict[str, Any]) -> dict[str, Any]:
    """执行受限 traceroute 查询并返回原始输出。"""

    target = normalized_target(payload.get("target"))
    max_hops = bounded_int(payload.get("max_hops"), 30, 1, 64)
    wait_seconds = bounded_int(payload.get("wait_seconds"), 3, 1, 10)
    queries = bounded_int(payload.get("queries"), 3, 1, 5)
    timeout = positive_float(payload.get("command_timeout_seconds"), DEFAULT_TRACEROUTE_COMMAND_TIMEOUT_SECONDS)
    output_limit = positive_int(payload.get("output_limit_bytes"), DEFAULT_OUTPUT_LIMIT_BYTES)
    command = [required_binary("traceroute"), "-n", "-m", str(max_hops), "-w", str(wait_seconds), "-q", str(queries), target]
    result = run_fixed_command(command, timeout, output_limit, f"traceroute 超过 {timeout:g} 秒未返回")
    result["command"] = f"traceroute -n -m {max_hops} -w {wait_seconds} -q {queries} {target}"
    if result.get("error_code") == "command_failed":
        result["error"] = "traceroute 执行失败"
    return result
