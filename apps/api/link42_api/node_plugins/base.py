from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from link42_common.connection_types import TASK_REQUIREMENTS
from sqlalchemy.orm import Session

from .. import models


@dataclass(frozen=True)
class NodePluginAction:
    """A node plugin action exposed by the controller and executed by the agent."""

    name: str
    task_type: str
    risk: str = "read"
    requires_confirm: bool = False


@dataclass(frozen=True)
class AgentTaskSpec:
    """Task descriptor produced by a node plugin action."""

    task_type: str
    payload: dict[str, Any]


@dataclass
class NodePluginContext:
    """Controller-side context passed to node plugins."""

    node: models.Node
    db: Session
    actor: str = "admin"


class NodePlugin:
    """Base class for controller-side node plugins."""

    type: str
    display_name: str
    description: str
    min_agent_version: str
    capabilities: list[str]
    actions: dict[str, NodePluginAction]

    def describe(self) -> dict[str, Any]:
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
        if action not in self.actions:
            raise ValueError("plugin action not found")
        return dict(payload)

    def build_task(self, action: str, payload: dict[str, Any], context: NodePluginContext) -> AgentTaskSpec:
        action_spec = self.actions[action]
        return AgentTaskSpec(task_type=action_spec.task_type, payload=payload)


def parse_semver(value: str | None) -> tuple[int, int, int]:
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
