from __future__ import annotations

import time
import traceback
from typing import Any

from .client import AgentClient
from .config import load_config_from_env
from .system import (
    apply_wireguard_config,
    delete_wireguard_config,
    get_hostname,
    get_service_manager_name,
    read_wireguard_config,
    scan_wg_quick_configs,
    get_wireguard_status,
    start_wireguard_interface,
    stop_wireguard_interface,
)


def execute_task(task: dict[str, Any], wireguard_dir: str, dry_run: bool = False) -> dict[str, Any]:
    """根据任务类型执行本机操作。"""

    task_type = task["type"]
    payload = task.get("payload", {})

    if task_type == "wireguard.import_scan":
        return {"candidates": scan_wg_quick_configs(wireguard_dir)}
    if task_type == "wireguard.apply_config":
        return apply_wireguard_config(payload, wireguard_dir, dry_run=dry_run)
    if task_type == "wireguard.read_config":
        return read_wireguard_config(payload, wireguard_dir)
    if task_type == "wireguard.status":
        return get_wireguard_status(payload)
    if task_type == "wireguard.start_interface":
        return start_wireguard_interface(payload, dry_run=dry_run)
    if task_type == "wireguard.stop_interface":
        return stop_wireguard_interface(payload, dry_run=dry_run)
    if task_type == "wireguard.delete_config":
        return delete_wireguard_config(payload, wireguard_dir, dry_run=dry_run)

    raise ValueError(f"unsupported task type: {task_type}")


def run_once(client: AgentClient, wireguard_dir: str, dry_run: bool = False) -> None:
    """执行一次心跳、拉取任务和处理任务的循环。"""

    client.heartbeat()
    capabilities = ["wireguard", "wg_quick_import", f"service:{get_service_manager_name()}"]
    for task in client.poll_tasks(capabilities):
        try:
            result = execute_task(task, wireguard_dir, dry_run=dry_run)
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

    config = load_config_from_env()
    client = AgentClient(config)
    while True:
        try:
            client.register(get_hostname())
            run_once(client, config.wireguard_dir, dry_run=config.dry_run)
        except Exception:  # noqa: BLE001
            # 中心 API 重启或网络短暂中断时，Agent 保持运行并在下一轮重试。
            print(traceback.format_exc(), flush=True)
        time.sleep(config.poll_interval)


if __name__ == "__main__":
    main()
