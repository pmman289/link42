from __future__ import annotations

from dataclasses import dataclass


CONNECTION_TYPE_WIREGUARD = "wireguard"


@dataclass(frozen=True)
class ConnectionTaskSet:
    """A connection backend's standard agent task names."""

    import_scan: str
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


TASK_REQUIREMENTS = {
    WIREGUARD_TASKS.import_scan: {"min_agent_version": "0.1.0", "capabilities": ["wg_quick_import"]},
    WIREGUARD_TASKS.apply_config: {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    WIREGUARD_TASKS.read_config: {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    WIREGUARD_TASKS.status: {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    WIREGUARD_TASKS.start: {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    WIREGUARD_TASKS.stop: {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    WIREGUARD_TASKS.delete_config: {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
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
    "agent.self_upgrade": {"min_agent_version": "0.2.0", "capabilities": ["agent.self_upgrade"]},
}


def connection_type_for_task(task_type: str) -> str | None:
    """Return the connection backend prefix for a task name, when one exists."""

    prefix = task_type.split(".", 1)[0]
    if prefix == CONNECTION_TYPE_WIREGUARD:
        return CONNECTION_TYPE_WIREGUARD
    return None
