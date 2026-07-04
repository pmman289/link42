from __future__ import annotations

from .base import NodePlugin
from .bird import BirdNodePlugin
from .port_inventory import PortInventoryNodePlugin


NODE_PLUGINS: dict[str, NodePlugin] = {
    "bird": BirdNodePlugin(),
    "port-inventory": PortInventoryNodePlugin(),
}


def get_node_plugin(plugin_type: str) -> NodePlugin | None:
    return NODE_PLUGINS.get(plugin_type)
