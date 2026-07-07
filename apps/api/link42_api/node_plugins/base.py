from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from link42_common.connection_types import TASK_REQUIREMENTS
from sqlalchemy.orm import Session

from .. import models


@dataclass(frozen=True)
class NodePluginAction:
    """主控暴露给前端、最终由 Agent 执行的节点插件动作。"""

    name: str
    task_type: str
    risk: str = "read"
    requires_confirm: bool = False


@dataclass(frozen=True)
class AgentTaskSpec:
    """节点插件动作生成的 Agent 任务描述。"""

    task_type: str
    payload: dict[str, Any]


@dataclass
class NodePluginContext:
    """传给主控侧节点插件的上下文。"""

    node: models.Node
    db: Session
    actor: str = "admin"


class NodePlugin:
    """主控侧节点插件基类。"""

    type: str
    display_name: str
    description: str
    min_agent_version: str
    capabilities: list[str]
    actions: dict[str, NodePluginAction]

    def describe(self) -> dict[str, Any]:
        """返回插件元数据和可执行 action 列表。"""

        return {
            "type": self.type,
            "display_name": self.display_name,
            "description": self.description,
            "min_agent_version": self.min_agent_version,
            "capabilities": self.capabilities,
            "actions": [
                {
                    "name": action.name,
                    "task_type": action.task_type,
                    "risk": action.risk,
                    "requires_confirm": action.requires_confirm,
                }
                for action in self.actions.values()
            ],
        }

    def status_for_node(self, context: NodePluginContext) -> dict[str, Any]:
        """根据节点能力和版本判断插件在该节点上是否可用。"""

        capabilities = set(context.node.agent_capabilities or [])
        missing = [capability for capability in self.capabilities if capability not in capabilities]
        task_requirements = [
            TASK_REQUIREMENTS[action.task_type]
            for action in self.actions.values()
            if action.task_type in TASK_REQUIREMENTS
        ]
        min_versions = [str(requirement.get("min_agent_version") or "0.0.0") for requirement in task_requirements]
        required_min_version = max([self.min_agent_version, *min_versions], key=parse_semver)
        version_supported = parse_semver(context.node.agent_version) >= parse_semver(required_min_version)
        return {
            **self.describe(),
            "available": not missing and version_supported,
            "missing_capabilities": missing,
            "agent_version": context.node.agent_version,
            "version_supported": version_supported,
            "node_status": context.node.status,
        }

    def validate_payload(self, action: str, payload: dict[str, Any], context: NodePluginContext) -> dict[str, Any]:
        """校验并清洗插件 action 的前端 payload。"""

        if action not in self.actions:
            raise ValueError("plugin action not found")
        return dict(payload)

    def build_task(self, action: str, payload: dict[str, Any], context: NodePluginContext) -> AgentTaskSpec:
        """把已校验 payload 转换为 Agent 可执行任务。"""

        action_spec = self.actions[action]
        return AgentTaskSpec(task_type=action_spec.task_type, payload=payload)


def parse_semver(value: str | None) -> tuple[int, int, int]:
    """解析三段式版本号，缺失或非法段按 0 处理。"""

    if not value:
        return (0, 0, 0)
    parts = value.split("-", 1)[0].split(".")
    parsed: list[int] = []
    for part in parts[:3]:
        try:
            parsed.append(int(part))
        except ValueError:
            parsed.append(0)
    while len(parsed) < 3:
        parsed.append(0)
    return tuple(parsed)  # type: ignore[return-value]
