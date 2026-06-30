from __future__ import annotations

import json
from typing import Any, Optional
from urllib import error, request

from link42_common.version import AGENT_PROTOCOL_VERSION, AGENT_VERSION

from .config import AgentConfig


class AgentHttpError(RuntimeError):
    """Agent API 请求失败。"""

    def __init__(self, status_code: int, path: str, body: str) -> None:
        self.status_code = status_code
        self.path = path
        self.body = body
        super().__init__(f"HTTP {status_code} for {path}: {body}")


class AgentClient:
    """Agent 访问中心 API 的 HTTP 客户端。"""

    def __init__(self, config: AgentConfig) -> None:
        """保存配置并创建 HTTP client。"""

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
        data = json.dumps(payload).encode("utf-8")
        http_request = request.Request(
            f"{self.config.server_url}{path}",
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with request.urlopen(http_request, timeout=30) as response:
                body = response.read().decode("utf-8")
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise AgentHttpError(exc.code, path, body) from exc
        if not body:
            return {}
        return json.loads(body)
