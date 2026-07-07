from __future__ import annotations

from typing import Any

from .base import AgentTaskSpec, NodePlugin, NodePluginAction, NodePluginContext


class BirdNodePlugin(NodePlugin):
    """主控侧 BIRD 配置编辑插件。"""

    type = "bird"
    display_name = "BIRD 配置"
    description = "递归读取、校验并编辑节点上的 /etc/bird.conf 和 /etc/bird 配置文件。"
    min_agent_version = "0.5.8"
    capabilities = ["node_plugin.bird"]
    actions = {
        "list": NodePluginAction("list", "node_plugin.bird.list", "read"),
        "read": NodePluginAction("read", "node_plugin.bird.read", "read"),
        "validate": NodePluginAction("validate", "node_plugin.bird.validate", "validate"),
        "apply": NodePluginAction("apply", "node_plugin.bird.apply", "write", True),
        "apply_many": NodePluginAction("apply_many", "node_plugin.bird.apply_many", "write", True),
        "status": NodePluginAction("status", "node_plugin.bird.status", "read"),
    }

    def validate_payload(self, action: str, payload: dict[str, Any], context: NodePluginContext) -> dict[str, Any]:
        """按 BIRD action 校验资源路径、配置内容和批量文件列表。"""

        super().validate_payload(action, payload, context)
        if action in {"list", "status"}:
            return {}
        if action == "read":
            return {"resource_key": required_string(payload, "resource_key")[:500]}
        if action == "validate":
            return {
                "resource_key": required_string(payload, "resource_key")[:500],
                "content": required_raw_string(payload, "content"),
            }
        if action == "apply":
            return {
                "resource_key": required_string(payload, "resource_key")[:500],
                "content": required_raw_string(payload, "content"),
                "base_sha256": optional_string(payload, "base_sha256"),
                "reload": bool(payload.get("reload", True)),
            }
        if action == "apply_many":
            return {
                "files": required_resource_changes(payload),
                "reload": bool(payload.get("reload", True)),
            }
        raise ValueError("plugin action not found")

    def build_task(self, action: str, payload: dict[str, Any], context: NodePluginContext) -> AgentTaskSpec:
        """为 BIRD action 附加插件类型、动作和节点 ID 后生成任务。"""

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


def required_string(payload: dict[str, Any], key: str) -> str:
    """读取必填字符串字段并去除首尾空白。"""

    value = str(payload.get(key) or "").strip()
    if not value:
        raise ValueError(f"{key} is required")
    return value


def required_raw_string(payload: dict[str, Any], key: str) -> str:
    """读取必须保持原样的字符串字段，不做 trim。"""

    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def optional_string(payload: dict[str, Any], key: str) -> str | None:
    """读取可选字符串字段，空值归一为空。"""

    value = str(payload.get(key) or "").strip()
    return value or None


def required_resource_changes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """校验批量 BIRD 配置变更列表。"""

    files = payload.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("files are required")
    cleaned: list[dict[str, Any]] = []
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("file entry must be an object")
        cleaned.append({
            "resource_key": required_string(item, "resource_key")[:500],
            "content": required_raw_string(item, "content"),
            "base_sha256": optional_string(item, "base_sha256"),
        })
    return cleaned
