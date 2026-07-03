from __future__ import annotations

from typing import Any

from .base import AgentTaskSpec, NodePlugin, NodePluginAction, NodePluginContext


class TestToolsNodePlugin(NodePlugin):
    """Safe built-in plugin used to verify the node plugin host pipeline."""

    type = "test-tools"
    display_name = "测试插件"
    description = "验证节点插件能力的安全测试插件，可回显文本并读取 Agent 平台摘要。"
    min_agent_version = "0.5.8"
    capabilities = ["node_plugin.test_tools"]
    actions = {
        "echo": NodePluginAction(
            name="echo",
            task_type="node_plugin.test_tools.echo",
            risk="read",
        ),
        "inspect": NodePluginAction(
            name="inspect",
            task_type="node_plugin.test_tools.inspect",
            risk="read",
        ),
    }

    def validate_payload(self, action: str, payload: dict[str, Any], context: NodePluginContext) -> dict[str, Any]:
        super().validate_payload(action, payload, context)
        if action == "echo":
            message = str(payload.get("message") or "").strip()
            if not message:
                message = "hello from Link42 node plugin"
            return {"message": message[:500]}
        if action == "inspect":
            return {}
        raise ValueError("plugin action not found")

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
