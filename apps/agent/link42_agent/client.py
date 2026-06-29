from __future__ import annotations

from typing import Any

import httpx
from link42_common.version import AGENT_PROTOCOL_VERSION, AGENT_VERSION

from .config import AgentConfig


class AgentClient:
    """Agent 访问中心 API 的 HTTP 客户端。"""

    def __init__(self, config: AgentConfig) -> None:
        """保存配置并创建 HTTP client。"""

        self.config = config
        self.client = httpx.Client(base_url=config.server_url, timeout=30)

    def auth_payload(self) -> dict[str, Any]:
        """生成每个 Agent 请求都需要携带的认证字段。"""

        return {"node_id": self.config.node_id, "token": self.config.token}

    def agent_payload(self, capabilities: list[str] | None = None, platform: dict[str, Any] | None = None) -> dict[str, Any]:
        """生成 Agent 版本、协议和能力描述。"""

        return {
            "agent_version": AGENT_VERSION,
            "protocol_version": AGENT_PROTOCOL_VERSION,
            "capabilities": capabilities or ["wireguard", "wg_quick_import"],
            "platform": platform or {},
        }

    def register(self, hostname: str, capabilities: list[str] | None = None, platform: dict[str, Any] | None = None) -> None:
        """向中心 API 注册当前节点。"""

        payload = {**self.auth_payload(), **self.agent_payload(capabilities, platform), "hostname": hostname}
        self.client.post("/api/agent/register", json=payload).raise_for_status()

    def heartbeat(self, capabilities: list[str] | None = None, platform: dict[str, Any] | None = None) -> None:
        """发送心跳，维持节点在线状态。"""

        self.client.post(
            "/api/agent/heartbeat",
            json={**self.auth_payload(), **self.agent_payload(capabilities, platform)},
        ).raise_for_status()

    def poll_tasks(self, capabilities: list[str] | None = None, platform: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """拉取待执行任务。"""

        payload = {
            **self.auth_payload(),
            **self.agent_payload(capabilities, platform),
        }
        response = self.client.post("/api/agent/tasks/poll", json=payload)
        response.raise_for_status()
        return response.json()["tasks"]

    def report_task(self, task_id: int, status: str, result: dict[str, Any]) -> None:
        """上报任务执行结果。"""

        payload = {**self.auth_payload(), "status": status, "result": result}
        self.client.post(f"/api/agent/tasks/{task_id}/result", json=payload).raise_for_status()
