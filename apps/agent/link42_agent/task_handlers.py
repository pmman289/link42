from __future__ import annotations

from typing import Any, Callable

from link42_common.connection_types import WIREGUARD_TASKS

from .config import AgentConfig
from .middleware import (
    apply_udp2raw,
    delete_udp2raw,
    install_middleware,
    start_udp2raw,
    status_udp2raw,
    stop_udp2raw,
)
from .system import (
    apply_wireguard_config,
    delete_wireguard_config,
    get_wireguard_status,
    read_wireguard_config,
    scan_wg_quick_configs,
    start_wireguard_interface,
    stop_wireguard_interface,
)
from .upgrade import self_upgrade


TaskHandler = Callable[[dict[str, Any], AgentConfig], dict[str, Any]]


def _dry_run(config: AgentConfig) -> bool:
    return config.dry_run


def wireguard_import_scan(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    return {"candidates": scan_wg_quick_configs(config.wireguard_dir)}


def wireguard_apply_config(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    return apply_wireguard_config(payload, config.wireguard_dir, dry_run=_dry_run(config))


def wireguard_read_config(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    return read_wireguard_config(payload, config.wireguard_dir)


def middleware_install(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    return install_middleware(payload, config, dry_run=_dry_run(config))


TASK_HANDLERS: dict[str, TaskHandler] = {
    WIREGUARD_TASKS.import_scan: wireguard_import_scan,
    WIREGUARD_TASKS.apply_config: wireguard_apply_config,
    WIREGUARD_TASKS.read_config: wireguard_read_config,
    WIREGUARD_TASKS.status: lambda payload, config: get_wireguard_status(payload),
    WIREGUARD_TASKS.start: lambda payload, config: start_wireguard_interface(payload, dry_run=_dry_run(config)),
    WIREGUARD_TASKS.stop: lambda payload, config: stop_wireguard_interface(payload, dry_run=_dry_run(config)),
    WIREGUARD_TASKS.delete_config: lambda payload, config: delete_wireguard_config(
        payload,
        config.wireguard_dir,
        dry_run=_dry_run(config),
    ),
    "middleware.install": middleware_install,
    "middleware.udp2raw.apply": lambda payload, config: apply_udp2raw(payload, dry_run=_dry_run(config)),
    "middleware.udp2raw.start": lambda payload, config: start_udp2raw(payload, dry_run=_dry_run(config)),
    "middleware.udp2raw.stop": lambda payload, config: stop_udp2raw(payload, dry_run=_dry_run(config)),
    "middleware.udp2raw.delete": lambda payload, config: delete_udp2raw(payload, dry_run=_dry_run(config)),
    "middleware.udp2raw.status": lambda payload, config: status_udp2raw(payload),
    "agent.self_upgrade": lambda payload, config: self_upgrade(payload, config, dry_run=_dry_run(config)),
}


def execute_registered_task(task_type: str, payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """Execute an agent task through the registered backend handler."""

    handler = TASK_HANDLERS.get(task_type)
    if handler is None:
        raise ValueError(f"unsupported task type: {task_type}")
    return handler(payload, config)
