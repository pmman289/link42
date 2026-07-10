from __future__ import annotations

from typing import Any, Callable

from link42_common.connection_types import GRE_TASKS, LOOKING_GLASS_BIRD_ROUTE_LOOKUP_TASK, WIREGUARD_TASKS

from .config import AgentConfig
from .gre import (
    apply_gre_config,
    delete_gre_config,
    gre_status,
    read_gre_config,
    start_gre_interface,
    stop_gre_interface,
)
from .looking_glass import execute_bird_route_lookup
from .middleware import (
    apply_udp2raw,
    apply_mimic,
    delete_mimic,
    delete_udp2raw,
    install_middleware,
    start_mimic,
    start_udp2raw,
    status_mimic,
    status_udp2raw,
    stop_mimic,
    stop_udp2raw,
)
from .plugins import execute_node_plugin_task
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
    """读取 Agent 是否处于只演练不落地的 dry-run 模式。"""

    return config.dry_run


def wireguard_import_scan(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """扫描本机可导入的 wg-quick 配置候选项。"""

    return {"candidates": scan_wg_quick_configs(config.wireguard_dir)}


def wireguard_apply_config(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """写入并应用 WireGuard 配置任务。"""

    return apply_wireguard_config(payload, config.wireguard_dir, dry_run=_dry_run(config))


def wireguard_read_config(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """读取本机指定 WireGuard 配置文件。"""

    return read_wireguard_config(payload, config.wireguard_dir)


def middleware_install(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """安装任务中指定的连接中间层组件。"""

    return install_middleware(payload, config, dry_run=_dry_run(config))


def gre_apply_config(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """写入 GRE 配置任务。"""

    return apply_gre_config(payload, config.gre_dir, dry_run=_dry_run(config))


def gre_read_config(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """读取 GRE 配置任务。"""

    return read_gre_config(payload, config.gre_dir)


def gre_start(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """启动 GRE 接口任务。"""

    return start_gre_interface(payload, config.gre_dir, dry_run=_dry_run(config))


def gre_stop(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """停止 GRE 接口任务。"""

    return stop_gre_interface(payload, dry_run=_dry_run(config))


def gre_delete(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """删除 GRE 配置任务。"""

    return delete_gre_config(payload, config.gre_dir, dry_run=_dry_run(config))


def gre_status_task(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """查询 GRE 接口状态任务。"""

    return gre_status(payload)


def looking_glass_bird_route_lookup(payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """执行 Looking Glass 受限 BIRD 路由查询任务。"""

    return execute_bird_route_lookup(payload)


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
    GRE_TASKS.apply_config: gre_apply_config,
    GRE_TASKS.read_config: gre_read_config,
    GRE_TASKS.status: gre_status_task,
    GRE_TASKS.start: gre_start,
    GRE_TASKS.stop: gre_stop,
    GRE_TASKS.delete_config: gre_delete,
    LOOKING_GLASS_BIRD_ROUTE_LOOKUP_TASK: looking_glass_bird_route_lookup,
    "middleware.install": middleware_install,
    "middleware.udp2raw.apply": lambda payload, config: apply_udp2raw(payload, dry_run=_dry_run(config)),
    "middleware.udp2raw.start": lambda payload, config: start_udp2raw(payload, dry_run=_dry_run(config)),
    "middleware.udp2raw.stop": lambda payload, config: stop_udp2raw(payload, dry_run=_dry_run(config)),
    "middleware.udp2raw.delete": lambda payload, config: delete_udp2raw(payload, dry_run=_dry_run(config)),
    "middleware.udp2raw.status": lambda payload, config: status_udp2raw(payload),
    "middleware.mimic.apply": lambda payload, config: apply_mimic(payload, dry_run=_dry_run(config)),
    "middleware.mimic.start": lambda payload, config: start_mimic(payload, dry_run=_dry_run(config)),
    "middleware.mimic.stop": lambda payload, config: stop_mimic(payload, dry_run=_dry_run(config)),
    "middleware.mimic.delete": lambda payload, config: delete_mimic(payload, dry_run=_dry_run(config)),
    "middleware.mimic.status": lambda payload, config: status_mimic(payload),
    "agent.self_upgrade": lambda payload, config: self_upgrade(payload, config, dry_run=_dry_run(config)),
}


def execute_registered_task(task_type: str, payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """按任务类型分派到已注册的 Agent 后端处理器。"""

    if task_type.startswith("node_plugin."):
        return execute_node_plugin_task(task_type, payload, config)
    handler = TASK_HANDLERS.get(task_type)
    if handler is None:
        raise ValueError(f"unsupported task type: {task_type}")
    return handler(payload, config)
