from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import AgentConfig


@dataclass
class AgentPluginContext:
    """传给 Agent 侧节点插件的运行上下文。"""

    config: AgentConfig
    platform: dict[str, Any]


class AgentNodePlugin:
    """Agent 侧节点插件基类。"""

    type: str
    capabilities: list[str]
    actions: set[str]

    def detect(self, context: AgentPluginContext) -> dict[str, Any]:
        """检测当前节点是否具备插件运行能力。"""

        return {}

    def execute(self, action: str, payload: dict[str, Any], context: AgentPluginContext) -> dict[str, Any]:
        """执行插件 action，子类需要按自身能力覆盖。"""

        raise ValueError(f"unsupported action: {action}")
