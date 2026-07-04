from __future__ import annotations

from typing import Any

from ..config import AgentConfig
from ..system import get_agent_platform
from .base import AgentNodePlugin, AgentPluginContext
from .bird import BirdAgentPlugin
from .port_inventory import PortInventoryAgentPlugin


AGENT_NODE_PLUGINS: dict[str, AgentNodePlugin] = {
    "bird": BirdAgentPlugin(),
    "port_inventory": PortInventoryAgentPlugin(),
}


def node_plugin_capabilities(config: AgentConfig | None = None, platform: dict[str, Any] | None = None) -> list[str]:
    """Return capabilities advertised by detected node plugins."""

    if config is None:
        config = AgentConfig(server_url="", node_id=0, token="")
    context = AgentPluginContext(config=config, platform=platform or get_agent_platform())
    capabilities: set[str] = set()
    for plugin in AGENT_NODE_PLUGINS.values():
        detected = plugin.detect(context)
        if detected.get("available", True):
            capabilities.update(plugin.capabilities)
    return sorted(capabilities)


def execute_node_plugin_task(task_type: str, payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """Execute a node_plugin.<plugin>.<action> task."""

    parts = task_type.split(".")
    if len(parts) != 3 or parts[0] != "node_plugin":
        raise ValueError(f"invalid node plugin task type: {task_type}")
    _, plugin_name, action = parts
    plugin = AGENT_NODE_PLUGINS.get(plugin_name)
    if plugin is None:
        raise ValueError(f"unsupported node plugin: {plugin_name}")
    if action not in plugin.actions:
        raise ValueError(f"unsupported node plugin action: {action}")
    context = AgentPluginContext(config=config, platform=get_agent_platform())
    return plugin.execute(action, payload, context)
