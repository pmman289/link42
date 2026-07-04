from __future__ import annotations

from typing import Any

from .base import AgentTaskSpec, NodePlugin, NodePluginAction, NodePluginContext


class PortInventoryNodePlugin(NodePlugin):
    """Controller-side port inventory helper plugin."""

    type = "port-inventory"
    display_name = "端口台账"
    description = "记录节点对外入口端口用途，并扫描指定范围内正在占用的 TCP/UDP/WireGuard 端口。"
    min_agent_version = "0.5.10"
    capabilities = ["node_plugin.port_inventory"]
    actions = {
        "scan": NodePluginAction("scan", "node_plugin.port_inventory.scan", "read"),
    }

    def validate_payload(self, action: str, payload: dict[str, Any], context: NodePluginContext) -> dict[str, Any]:
        super().validate_payload(action, payload, context)
        if action != "scan":
            raise ValueError("plugin action not found")
        range_start = int(payload.get("range_start") or 0)
        range_end = int(payload.get("range_end") or 0)
        if not 1 <= range_start <= 65535 or not 1 <= range_end <= 65535:
            raise ValueError("port range must be between 1 and 65535")
        if range_start > range_end:
            raise ValueError("range_start must be less than or equal to range_end")
        return {"range_start": range_start, "range_end": range_end}

    def build_task(self, action: str, payload: dict[str, Any], context: NodePluginContext) -> AgentTaskSpec:
        task = super().build_task(action, payload, context)
        return AgentTaskSpec(
            task_type=task.task_type,
            payload={
                **task.payload,
                "plugin_type": self.type,
                "action": action,
                "node_id": context.node.id,
            },
        )
