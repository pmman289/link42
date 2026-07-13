from __future__ import annotations

import json
import logging
import socket
import ssl
import time
from typing import Any, Optional
from urllib import error, request
from urllib.parse import urlsplit

from link42_common.version import AGENT_PROTOCOL_VERSION, AGENT_VERSION

from .config import AgentConfig


logger = logging.getLogger("link42.agent.client")
AGENT_USER_AGENT = f"Link42-Agent/{AGENT_VERSION}"
QUIET_SUCCESS_PATHS = {
    "/api/agent/register",
    "/api/agent/heartbeat",
    "/api/agent/tasks/poll",
    "/api/agent/link-monitors/poll",
}


class AgentHttpError(RuntimeError):
    """Agent API 请求失败。"""

    def __init__(self, status_code: int, path: str, body: str) -> None:
        """保存 HTTP 状态、路径和响应体，便于上层记录失败原因。"""

        self.status_code = status_code
        self.path = path
        self.body = body
        super().__init__(f"HTTP {status_code} for {path}: {body}")


class AgentConnectionError(RuntimeError):
    """Agent 无法连接主控。"""

    def __init__(self, server_url: str, path: str, reason: str) -> None:
        """保存主控地址、请求路径和便于用户理解的失败原因。"""

        self.server_url = server_url
        self.path = path
        self.reason = reason
        super().__init__(f"无法连接主控 {server_url}：{reason}")


def validate_server_url(server_url: str) -> None:
    """校验主控地址是否为包含主机名的 HTTP 或 HTTPS URL。"""

    try:
        parsed = urlsplit(server_url)
        port = parsed.port
    except ValueError as exc:
        raise AgentConnectionError(server_url, "", "主控地址格式无效") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AgentConnectionError(server_url, "", "主控地址格式无效，请以 http:// 或 https:// 开头")
    if port is not None and not 1 <= port <= 65535:
        raise AgentConnectionError(server_url, "", "主控地址端口必须在 1 到 65535 之间")


def describe_url_error(exc: error.URLError) -> str:
    """把 urllib 的底层网络异常转换成面向用户的中文原因。"""

    reason = exc.reason
    if isinstance(reason, socket.gaierror):
        return "主控域名无法解析"
    if isinstance(reason, ConnectionRefusedError):
        return "主控拒绝连接"
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "连接主控超时"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "主控 HTTPS 证书校验失败"
    detail = str(reason).strip()
    return f"网络连接失败（{detail}）" if detail else "网络连接失败"


class AgentClient:
    """Agent 访问中心 API 的 HTTP 客户端。"""

    def __init__(self, config: AgentConfig) -> None:
        """保存配置并创建 HTTP client。"""

        validate_server_url(config.server_url)
        self.config = config

    def auth_payload(self) -> dict[str, Any]:
        """生成每个 Agent 请求都需要携带的认证字段。"""

        return {"node_id": self.config.node_id, "token": self.config.token}

    def agent_payload(self, capabilities: Optional[list[str]] = None, platform: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """生成 Agent 版本、协议和能力描述。"""

        return {
            "agent_version": AGENT_VERSION,
            "protocol_version": AGENT_PROTOCOL_VERSION,
            "capabilities": capabilities or ["wireguard", "wg_quick_import"],
            "platform": platform or {},
        }

    def register(self, hostname: str, capabilities: Optional[list[str]] = None, platform: Optional[dict[str, Any]] = None) -> None:
        """向中心 API 注册当前节点。"""

        payload = {**self.auth_payload(), **self.agent_payload(capabilities, platform), "hostname": hostname}
        self._post_json("/api/agent/register", payload)

    def heartbeat(self, capabilities: Optional[list[str]] = None, platform: Optional[dict[str, Any]] = None) -> None:
        """发送心跳，维持节点在线状态。"""

        self._post_json(
            "/api/agent/heartbeat",
            {**self.auth_payload(), **self.agent_payload(capabilities, platform)},
        )

    def poll_tasks(self, capabilities: Optional[list[str]] = None, platform: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
        """拉取待执行任务。"""

        payload = {
            **self.auth_payload(),
            **self.agent_payload(capabilities, platform),
        }
        return self._post_json("/api/agent/tasks/poll", payload)["tasks"]

    def report_task(self, task_id: int, status: str, result: dict[str, Any]) -> None:
        """上报任务执行结果。"""

        payload = {**self.auth_payload(), "status": status, "result": result}
        self._post_json(f"/api/agent/tasks/{task_id}/result", payload)

    def poll_link_monitors(self, capabilities: Optional[list[str]] = None, platform: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
        """拉取到期的链路监测目标。"""

        payload = {**self.auth_payload(), **self.agent_payload(capabilities, platform)}
        return self._post_json("/api/agent/link-monitors/poll", payload)["monitors"]

    def report_link_monitor_results(self, results: list[dict[str, Any]]) -> None:
        """上报链路监测结果。"""

        self._post_json("/api/agent/link-monitors/result", {**self.auth_payload(), "results": results})

    def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """向中心 API 发送 JSON 请求并解析 JSON 响应。"""

        data = json.dumps(payload).encode("utf-8")
        started_at = time.monotonic()
        http_request = request.Request(
            f"{self.config.server_url}{path}",
            data=data,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": AGENT_USER_AGENT,
            },
        )
        try:
            with request.urlopen(http_request, timeout=30) as response:
                body = response.read().decode("utf-8")
                if path not in QUIET_SUCCESS_PATHS:
                    logger.debug(
                        "Agent API 请求完成 path=%s status=%s duration=%.2fs",
                        path,
                        response.getcode(),
                        time.monotonic() - started_at,
                    )
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            logger.debug(
                "Agent API 返回错误 path=%s status=%s duration=%.2fs body=%s",
                path,
                exc.code,
                time.monotonic() - started_at,
                body[:500],
            )
            raise AgentHttpError(exc.code, path, body) from exc
        except error.URLError as exc:
            logger.debug(
                "Agent API 连接失败 path=%s duration=%.2fs error=%s",
                path,
                time.monotonic() - started_at,
                exc,
            )
            raise AgentConnectionError(self.config.server_url, path, describe_url_error(exc)) from exc
        if not body:
            return {}
        return json.loads(body)
