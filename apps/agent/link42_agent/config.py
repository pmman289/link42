from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
from urllib.parse import urlsplit


_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}


def _required_server_url(value: str) -> str:
    """在进程启动前拒绝无法交给 AgentClient 的主控地址。"""

    cleaned = value.strip().rstrip("/")
    try:
        parsed = urlsplit(cleaned)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("LINK42_SERVER_URL must be a valid http(s) URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(ord(char) < 0x21 or ord(char) == 0x7F for char in cleaned)
    ):
        raise ValueError("LINK42_SERVER_URL must be a valid http(s) URL without path or credentials")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("LINK42_SERVER_URL port must be between 1 and 65535")
    return cleaned


def _required_node_id(value: str) -> int:
    """节点 ID 必须是正整数，避免 Agent 永久使用无效路径轮询。"""

    try:
        node_id = int(value.strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("LINK42_NODE_ID must be a positive integer") from exc
    if node_id <= 0:
        raise ValueError("LINK42_NODE_ID must be a positive integer")
    return node_id


def _required_token(value: str) -> str:
    """Token 不得为空或包含会破坏 HTTP/日志边界的控制字符。"""

    cleaned = value.strip()
    if not cleaned or any(ord(char) < 0x21 or ord(char) == 0x7F for char in cleaned):
        raise ValueError("LINK42_AGENT_TOKEN must be a non-empty token without control characters")
    return cleaned


def _managed_directory(value: str, label: str) -> str:
    """受管目录必须是绝对且非根目录路径，避免误配置后写入系统根目录。"""

    cleaned = value.strip()
    path = Path(cleaned)
    if (
        not cleaned
        or not path.is_absolute()
        or path.resolve(strict=False) == Path("/")
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in cleaned)
    ):
        raise ValueError(f"{label} must be an absolute non-root path")
    return cleaned


@dataclass
class AgentConfig:
    """Agent 运行配置。"""

    server_url: str
    node_id: int
    token: str
    poll_interval: int = 5
    wireguard_dir: str = "/etc/wireguard"
    gre_dir: str = "/etc/link42/gre"
    dry_run: bool = False
    log_level: str = "INFO"
    http_timeout: float = 10.0
    heartbeat_timeout: float = 5.0
    poll_jitter: float = 0.2


def load_config_from_env() -> AgentConfig:
    """从环境变量读取 Agent 配置，便于 systemd 和容器复用同一入口。"""

    try:
        poll_interval = int(os.environ.get("LINK42_POLL_INTERVAL", "5"))
    except ValueError as exc:
        raise ValueError("LINK42_POLL_INTERVAL must be an integer") from exc
    if not 1 <= poll_interval <= 3600:
        raise ValueError("LINK42_POLL_INTERVAL must be between 1 and 3600 seconds")

    http_timeout = _positive_float_from_env("LINK42_HTTP_TIMEOUT", 10.0)
    heartbeat_timeout = _positive_float_from_env("LINK42_HEARTBEAT_TIMEOUT", 5.0)
    if heartbeat_timeout > http_timeout:
        raise ValueError("LINK42_HEARTBEAT_TIMEOUT must not exceed LINK42_HTTP_TIMEOUT")
    try:
        poll_jitter = float(os.environ.get("LINK42_POLL_JITTER", "0.2"))
    except ValueError as exc:
        raise ValueError("LINK42_POLL_JITTER must be a number between 0 and 1") from exc
    if not math.isfinite(poll_jitter) or not 0 <= poll_jitter <= 1:
        raise ValueError("LINK42_POLL_JITTER must be a number between 0 and 1")

    return AgentConfig(
        server_url=_required_server_url(os.environ["LINK42_SERVER_URL"]),
        node_id=_required_node_id(os.environ["LINK42_NODE_ID"]),
        token=_required_token(os.environ["LINK42_AGENT_TOKEN"]),
        poll_interval=poll_interval,
        wireguard_dir=_managed_directory(os.environ.get("LINK42_WIREGUARD_DIR", "/etc/wireguard"), "LINK42_WIREGUARD_DIR"),
        gre_dir=_managed_directory(os.environ.get("LINK42_GRE_DIR", "/etc/link42/gre"), "LINK42_GRE_DIR"),
        dry_run=os.environ.get("LINK42_AGENT_DRY_RUN", "0") == "1",
        log_level=_validated_log_level(os.environ.get("LINK42_LOG_LEVEL", "INFO")),
        http_timeout=http_timeout,
        heartbeat_timeout=heartbeat_timeout,
        poll_jitter=poll_jitter,
    )


def _positive_float_from_env(name: str, default: float) -> float:
    """读取有限的正浮点配置，避免网络请求被配置成无限等待。"""

    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive number")
    return value


def _validated_log_level(value: str) -> str:
    """日志等级使用 logging 支持的固定名称，错误配置应立即暴露。"""

    level = value.strip().upper()
    if level not in _LOG_LEVELS:
        raise ValueError("LINK42_LOG_LEVEL must be one of CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET")
    return level
