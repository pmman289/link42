from __future__ import annotations

import sys
import time
import traceback
from typing import Any, Union

from link42_common.version import AGENT_VERSION

from .client import AgentClient
from .config import AgentConfig
from .config import load_config_from_env
from .system import (
    get_agent_platform,
    get_hostname,
    get_service_manager_name,
)
from .task_handlers import execute_registered_task


def build_capabilities() -> list[str]:
    """返回当前 Agent 支持的任务能力。"""

    service_manager = get_service_manager_name()
    capabilities = [
        "wireguard",
        f"service:{service_manager}",
    ]
    if service_manager != "openwrt-uci":
        capabilities.append("wg_quick_import")
    if service_manager in ["systemd", "openwrt-uci"]:
        capabilities.extend([
            "middleware",
            "middleware.install",
            "middleware.udp2raw",
        ])
    if service_manager == "systemd":
        capabilities.extend([
            "agent.self_upgrade",
        ])
        capabilities.append("middleware.udp2raw.systemd")
    if service_manager == "openwrt-uci":
        capabilities.append("middleware.udp2raw.openwrt-procd")
    return capabilities


def execute_task(task: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """根据任务类型执行本机操作。"""

    task_type = task["type"]
    payload = task.get("payload", {})
    return execute_registered_task(task_type, payload, config)


def run_once(client: AgentClient, config: Union[AgentConfig, str]) -> None:
    """执行一次心跳、拉取任务和处理任务的循环。"""

    if isinstance(config, str):
        config = AgentConfig(server_url="", node_id=0, token="", wireguard_dir=config)
    capabilities = build_capabilities()
    platform = get_agent_platform()
    try:
        client.heartbeat(capabilities, platform)
    except TypeError:
        client.heartbeat()
    try:
        tasks = client.poll_tasks(capabilities, platform)
    except TypeError:
        tasks = client.poll_tasks(capabilities)
    for task in tasks:
        try:
            result = execute_task(task, config)
            client.report_task(task["id"], "succeeded", result)
        except Exception as exc:  # noqa: BLE001
            # Agent 不能因为单个任务失败而退出；失败信息上报后继续处理后续任务。
            client.report_task(
                task["id"],
                "failed",
                {"error": str(exc), "traceback": traceback.format_exc()},
            )


def main() -> None:
    """Agent 命令行入口，持续轮询中心 API。"""

    if "--version" in sys.argv or "version" in sys.argv[1:]:
        print(AGENT_VERSION)
        return

    config = load_config_from_env()
    client = AgentClient(config)
    while True:
        try:
            client.register(get_hostname(), build_capabilities(), get_agent_platform())
            run_once(client, config)
        except Exception:  # noqa: BLE001
            # 中心 API 重启或网络短暂中断时，Agent 保持运行并在下一轮重试。
            print(traceback.format_exc(), flush=True)
        time.sleep(config.poll_interval)


if __name__ == "__main__":
    main()
