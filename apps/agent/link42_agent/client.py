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
# The controller may return up to five tasks per poll and each task payload is
# capped at 2 MiB.  Keep enough headroom for JSON framing and task metadata;
# the limit still bounds an untrusted response before it reaches json.loads.
MAX_AGENT_RESPONSE_BYTES = 16 * 1024 * 1024
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
    # API 路径会直接拼接到该地址；用户信息、路径、查询串和片段既没有
    # 配置意义，也会导致请求发往与界面显示不同的 URL。禁止它们同时
    # 避免把凭据意外交给 URL 中的第三方主机。
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(ord(char) < 0x21 or ord(char) == 0x7F for char in server_url)
    ):
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
        config.server_url = config.server_url.rstrip("/")
        self.config = config
        # 暂时断网时保留未确认结果；后续循环只重传结果，不重复执行本机任务。
        self.pending_task_reports: dict[int, dict[str, Any]] = {}

    def auth_payload(self) -> dict[str, Any]:
        """生成每个 Agent 请求都需要携带的认证字段。"""

        return {"node_id": self.config.node_id, "token": self.config.token}

    def agent_payload(self, capabilities: Optional[list[str]] = None, platform: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """生成 Agent 版本、协议和能力描述。"""

        return {
            "agent_version": AGENT_VERSION,
            "protocol_version": AGENT_PROTOCOL_VERSION,
            # 空列表/空对象也是有效的完整快照；只有旧调用方没有传参时
            # 才使用兼容默认值，不能用 truthiness 把能力卸载覆盖掉。
            "capabilities": capabilities if capabilities is not None else ["wireguard", "wg_quick_import"],
            "platform": platform if platform is not None else {},
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
        self.pending_task_reports[task_id] = payload
        self._send_task_report(task_id, payload)

    def _send_task_report(self, task_id: int, payload: dict[str, Any]) -> None:
        """发送待确认结果；终态冲突或任务已删除时停止重传。"""

        try:
            self._post_json(f"/api/agent/tasks/{task_id}/result", payload)
        except AgentHttpError as exc:
            if 400 <= exc.status_code < 500 and exc.status_code not in {401, 403, 408, 429}:
                self.pending_task_reports.pop(task_id, None)
            raise
        else:
            self.pending_task_reports.pop(task_id, None)

    def retry_task_reports(self) -> None:
        """在每轮恢复通信后重传未确认任务结果，保持原始执行状态。"""

        for task_id, payload in list(self.pending_task_reports.items()):
            try:
                self._send_task_report(task_id, payload)
            except (AgentConnectionError, AgentHttpError) as exc:
                logger.warning("任务结果重传失败 task_id=%s error=%s", task_id, exc)

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
                body = self._read_response_body(response, path)
                if path not in QUIET_SUCCESS_PATHS:
                    logger.debug(
                        "Agent API 请求完成 path=%s status=%s duration=%.2fs",
                        path,
                        response.getcode(),
                        time.monotonic() - started_at,
                    )
        except error.HTTPError as exc:
            body = self._read_response_body(exc, path, errors="replace")
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

    def _read_response_body(self, response: Any, path: str, *, errors: str = "strict") -> str:
        """有界读取主控响应，避免异常代理响应耗尽 Agent 内存。"""

        chunks: list[bytes] = []
        total = 0
        single_read = False
        while True:
            try:
                chunk = response.read(min(64 * 1024, MAX_AGENT_RESPONSE_BYTES - total + 1))
            except TypeError:
                # 兼容最小 HTTP 测试替身；标准 urllib 响应支持 size 参数。
                chunk = response.read()
                single_read = True
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_AGENT_RESPONSE_BYTES:
                raise AgentConnectionError(self.config.server_url, path, "主控响应过大")
            chunks.append(chunk)
            if single_read:
                break
        return b"".join(chunks).decode("utf-8", errors=errors)
