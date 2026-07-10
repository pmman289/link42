from __future__ import annotations

from dataclasses import dataclass


CONNECTION_TYPE_WIREGUARD = "wireguard"
CONNECTION_TYPE_GRE = "gre"
LOOKING_GLASS_BIRD_ROUTE_LOOKUP_TASK = "looking_glass.bird.route_lookup"


@dataclass(frozen=True)
class ConnectionTaskSet:
    """连接后端对应的一组标准 Agent 任务名。"""

    import_scan: str | None
    apply_config: str
    read_config: str
    status: str
    start: str
    stop: str
    delete_config: str


WIREGUARD_TASKS = ConnectionTaskSet(
    import_scan="wireguard.import_scan",
    apply_config="wireguard.apply_config",
    read_config="wireguard.read_config",
    status="wireguard.status",
    start="wireguard.start_interface",
    stop="wireguard.stop_interface",
    delete_config="wireguard.delete_config",
)

GRE_TASKS = ConnectionTaskSet(
    import_scan=None,
    apply_config="gre.apply_config",
    read_config="gre.read_config",
    status="gre.status",
    start="gre.start_interface",
    stop="gre.stop_interface",
    delete_config="gre.delete_config",
)


TASK_REQUIREMENTS = {
    WIREGUARD_TASKS.import_scan: {"min_agent_version": "0.1.0", "capabilities": ["wg_quick_import"]},
    WIREGUARD_TASKS.apply_config: {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    WIREGUARD_TASKS.read_config: {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    WIREGUARD_TASKS.status: {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    WIREGUARD_TASKS.start: {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    WIREGUARD_TASKS.stop: {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    WIREGUARD_TASKS.delete_config: {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    GRE_TASKS.apply_config: {"min_agent_version": "0.6.0", "capabilities": ["gre"]},
    GRE_TASKS.read_config: {"min_agent_version": "0.6.0", "capabilities": ["gre"]},
    GRE_TASKS.status: {"min_agent_version": "0.6.0", "capabilities": ["gre"]},
    GRE_TASKS.start: {"min_agent_version": "0.6.0", "capabilities": ["gre"]},
    GRE_TASKS.stop: {"min_agent_version": "0.6.0", "capabilities": ["gre"]},
    GRE_TASKS.delete_config: {"min_agent_version": "0.6.0", "capabilities": ["gre"]},
    "middleware.install": {"min_agent_version": "0.2.0", "capabilities": ["middleware.install"]},
    "middleware.udp2raw.apply": {"min_agent_version": "0.2.0", "capabilities": ["middleware.udp2raw"]},
    "middleware.udp2raw.start": {"min_agent_version": "0.2.0", "capabilities": ["middleware.udp2raw"]},
    "middleware.udp2raw.stop": {"min_agent_version": "0.2.0", "capabilities": ["middleware.udp2raw"]},
    "middleware.udp2raw.delete": {"min_agent_version": "0.2.0", "capabilities": ["middleware.udp2raw"]},
    "middleware.udp2raw.status": {"min_agent_version": "0.2.0", "capabilities": ["middleware.udp2raw"]},
    "middleware.mimic.apply": {"min_agent_version": "0.5.2", "capabilities": ["middleware.mimic"]},
    "middleware.mimic.start": {"min_agent_version": "0.5.2", "capabilities": ["middleware.mimic"]},
    "middleware.mimic.stop": {"min_agent_version": "0.5.2", "capabilities": ["middleware.mimic"]},
    "middleware.mimic.delete": {"min_agent_version": "0.5.2", "capabilities": ["middleware.mimic"]},
    "middleware.mimic.status": {"min_agent_version": "0.5.2", "capabilities": ["middleware.mimic"]},
    "node_plugin.bird.list": {"min_agent_version": "0.5.8", "capabilities": ["node_plugin.bird"]},
    "node_plugin.bird.read": {"min_agent_version": "0.5.8", "capabilities": ["node_plugin.bird"]},
    "node_plugin.bird.validate": {"min_agent_version": "0.5.8", "capabilities": ["node_plugin.bird"]},
    "node_plugin.bird.apply": {"min_agent_version": "0.5.9", "capabilities": ["node_plugin.bird"]},
    "node_plugin.bird.apply_many": {"min_agent_version": "0.5.9", "capabilities": ["node_plugin.bird"]},
    "node_plugin.bird.status": {"min_agent_version": "0.5.8", "capabilities": ["node_plugin.bird"]},
    "node_plugin.port_inventory.scan": {"min_agent_version": "0.5.10", "capabilities": ["node_plugin.port_inventory"]},
    LOOKING_GLASS_BIRD_ROUTE_LOOKUP_TASK: {
        "min_agent_version": "0.6.0",
        "capabilities": ["looking_glass.bird.route_lookup"],
    },
    "agent.self_upgrade": {"min_agent_version": "0.2.0", "capabilities": ["agent.self_upgrade"]},
}


def connection_type_for_task(task_type: str) -> str | None:
    """从任务名中解析连接后端类型，无法识别时返回空。"""

    prefix = task_type.split(".", 1)[0]
    if prefix == CONNECTION_TYPE_WIREGUARD:
        return CONNECTION_TYPE_WIREGUARD
    if prefix == CONNECTION_TYPE_GRE:
        return CONNECTION_TYPE_GRE
    return None
