from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import AgentConfig


@dataclass
class AgentPluginContext:
    """Runtime context passed to agent-side node plugins."""

    config: AgentConfig
    platform: dict[str, Any]


class AgentNodePlugin:
    """Base class for agent-side node plugins."""

    type: str
    capabilities: list[str]
    actions: set[str]

    def detect(self, context: AgentPluginContext) -> dict[str, Any]:
        return {}

    def execute(self, action: str, payload: dict[str, Any], context: AgentPluginContext) -> dict[str, Any]:
        raise ValueError(f"unsupported action: {action}")
