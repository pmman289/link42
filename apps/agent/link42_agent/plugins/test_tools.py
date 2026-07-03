from __future__ import annotations

from typing import Any

from .base import AgentNodePlugin, AgentPluginContext


class TestToolsAgentPlugin(AgentNodePlugin):
    """Safe test plugin proving the node plugin host pipeline works."""

    type = "test-tools"
    capabilities = [
        "node_plugin",
        "node_plugin.test_tools",
        "node_plugin.test_tools.echo",
        "node_plugin.test_tools.inspect",
    ]
    actions = {"echo", "inspect"}

    def detect(self, context: AgentPluginContext) -> dict[str, Any]:
        return {
            "plugin_type": self.type,
            "available": True,
            "dry_run": context.config.dry_run,
        }

    def execute(self, action: str, payload: dict[str, Any], context: AgentPluginContext) -> dict[str, Any]:
        if action == "echo":
            message = str(payload.get("message") or "")[:500]
            return {
                "plugin_type": self.type,
                "action": action,
                "message": message,
                "dry_run": context.config.dry_run,
            }
        if action == "inspect":
            platform = dict(context.platform)
            return {
                "plugin_type": self.type,
                "action": action,
                "platform": platform,
                "dry_run": context.config.dry_run,
            }
        raise ValueError(f"unsupported test-tools action: {action}")
