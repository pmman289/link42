from __future__ import annotations

from .base import NodePlugin
from .bird import BirdNodePlugin
from .test_tools import TestToolsNodePlugin


NODE_PLUGINS: dict[str, NodePlugin] = {
    "bird": BirdNodePlugin(),
    "test-tools": TestToolsNodePlugin(),
}


def get_node_plugin(plugin_type: str) -> NodePlugin | None:
    return NODE_PLUGINS.get(plugin_type)
