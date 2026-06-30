from __future__ import annotations

import glob
import os
import platform
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Optional

from link42_wireguard import parse_wg_quick, parsed_interface_to_dict

from .service_manager import DirectWgQuickManager, OpenWrtUciManager, UnsupportedServiceManager, detect_service_manager


# wg-quick 默认配置目录；可通过环境变量覆盖，便于测试和非标准系统布局。
DEFAULT_WIREGUARD_DIR = "/etc/wireguard"
DEFAULT_COMMAND_TIMEOUT_SECONDS = 30


def command_timeout_seconds() -> float:
    """读取系统命令超时时间，避免 systemctl 等命令卡死导致任务无限 running。"""

    value = os.getenv("LINK42_COMMAND_TIMEOUT", str(DEFAULT_COMMAND_TIMEOUT_SECONDS))
    try:
        timeout = float(value)
    except ValueError:
        return DEFAULT_COMMAND_TIMEOUT_SECONDS
    return timeout if timeout > 0 else DEFAULT_COMMAND_TIMEOUT_SECONDS


def get_hostname() -> str:
    """读取当前节点 hostname，用于 Agent 注册时上报。"""

    return socket.gethostname()


def get_service_manager_name() -> str:
    """返回当前主机使用的 wg-quick 服务管理后端名称。"""

    return detect_service_manager(run_command).name


def get_agent_platform() -> dict[str, Any]:
    """返回 Agent 当前运行平台信息，用于主控判断插件和升级资产。"""

    libc_name, libc_version = platform.libc_ver()
    if platform.system().lower() == "linux" and shutil.which("ldd"):
        result = run_command(["ldd", "--version"], allow_failure=True)
        output = f"{result.get('stdout', '')}\n{result.get('stderr', '')}".lower()
        if "musl" in output:
            libc_name = "musl"
            libc_version = libc_version if libc_version and libc_version != "2.0" else None
    return {
        "os": platform.system().lower(),
        "arch": platform.machine(),
        "service_manager": get_service_manager_name(),
        "libc": libc_name or None,
        "libc_version": libc_version or None,
        "glibc": libc_version if libc_name == "glibc" else None,
    }


def scan_wg_quick_configs(wireguard_dir: str = DEFAULT_WIREGUARD_DIR) -> list[dict[str, Any]]:
    """扫描并解析本机 wg-quick 配置文件。

    这里不会修改任何文件，只返回候选配置；是否导入、是否接管管理，都由
    前端和 API 后续流程决定。
    """

    candidates: list[dict[str, Any]] = []
    if not shutil.which("wg-quick"):
        return candidates
    for path_text in sorted(glob.glob(os.path.join(wireguard_dir, "*.conf"))):
        path = Path(path_text)
        content = path.read_text(encoding="utf-8")
        parsed = parse_wg_quick(content, name=path.stem)
        parsed_json = parsed_interface_to_dict(parsed)
        candidates.append(
            {
                "path": str(path),
                "content": content,
                "parsed": parsed_json,
                "warnings": parsed_json.get("warnings", []),
            }
        )
    return candidates


def apply_wireguard_config(
    payload: dict[str, Any],
    wireguard_dir: str = DEFAULT_WIREGUARD_DIR,
    dry_run: bool = False,
) -> dict[str, Any]:
    """写入 WireGuard 配置并调用 wg-quick 应用。

    如果目标配置已存在，先生成带时间戳的备份，避免接管导入配置时误丢原文件。
    本地体验模式下 dry_run=True，只写配置和备份，不调用 wg-quick 改动网络。
    """

    interface_name = payload["interface_name"]
    config_text = payload["config"]
    enable_on_boot = bool(payload.get("enable_on_boot"))
    manager = detect_service_manager(run_command)
    if isinstance(manager, OpenWrtUciManager):
        return manager.apply_config(interface_name, config_text, enable_on_boot=enable_on_boot)
    if isinstance(manager, UnsupportedServiceManager):
        raise RuntimeError(manager.state(interface_name)["message"])

    target = Path(wireguard_dir) / f"{interface_name}.conf"
    target.parent.mkdir(parents=True, exist_ok=True)
    service_state = manager.state(interface_name)

    backup_path: Optional[str] = None
    if target.exists():
        backup = rotate_wireguard_backup(target)
        shutil.copy2(target, backup)
        backup_path = str(backup)

    target.write_text(config_text, encoding="utf-8")

    if dry_run:
        return {
            "changed": True,
            "dry_run": True,
            "config_path": str(target),
            "backup_path": backup_path,
            "message": "dry-run enabled, wg-quick was not executed",
        }

    if service_state["managed"]:
        apply_result = manager.restart(interface_name)
        enable_result = manager.enable(interface_name) if enable_on_boot else None
        return {
            "changed": True,
            "config_path": str(target),
            "backup_path": backup_path,
            "service": service_state,
            "restart": apply_result,
            "enable": enable_result,
        }

    if enable_on_boot:
        enable_result = manager.enable(interface_name)
        restart_result = manager.restart(interface_name)
        return {
            "changed": True,
            "config_path": str(target),
            "backup_path": backup_path,
            "service": service_state,
            "enable": enable_result,
            "restart": restart_result,
        }

    restart_result = DirectWgQuickManager(run_command).restart(interface_name)
    if "down" in restart_result and "up" in restart_result:
        return {
            "changed": True,
            "config_path": str(target),
            "backup_path": backup_path,
            "service": service_state,
            "down": restart_result["down"],
            "up": restart_result["up"],
        }
    return {
        "changed": True,
        "config_path": str(target),
        "backup_path": backup_path,
        "service": service_state,
        "restart": restart_result,
    }


def rotate_wireguard_backup(target: Path) -> Path:
    """返回固定备份路径，并清理同接口历史备份，确保最多保留一个备份文件。"""

    backup = target.with_name(f"{target.name}.link42-backup")
    for old_backup in target.parent.glob(f"{target.name}.link42-backup-*"):
        old_backup.unlink(missing_ok=True)
    backup.unlink(missing_ok=True)
    return backup


def read_wireguard_config(payload: dict[str, Any], wireguard_dir: str = DEFAULT_WIREGUARD_DIR) -> dict[str, Any]:
    """读取本机已写入的 WireGuard 配置，用于生成真实部署 diff。"""

    interface_name = payload["interface_name"]
    target = Path(wireguard_dir) / f"{interface_name}.conf"
    manager = detect_service_manager(run_command)
    if isinstance(manager, OpenWrtUciManager):
        return {
            "exists": False,
            "config": "",
            "config_backend": manager.name,
            "config_path": None,
            "service": manager.state(interface_name),
            "message": "OpenWrt UCI backend does not expose a wg-quick config file",
        }
    if not target.exists():
        return {"exists": False, "config": "", "config_path": str(target)}
    return {"exists": True, "config": target.read_text(encoding="utf-8"), "config_path": str(target)}


def get_wireguard_status(payload: dict[str, Any]) -> dict[str, Any]:
    """查询 WireGuard 接口当前是否存在于内核状态中。"""

    interface_name = payload["interface_name"]
    result = run_command(["wg", "show", interface_name], allow_failure=True)
    runtime_status = "running" if result["returncode"] == 0 else "stopped"
    return {
        "runtime_status": runtime_status,
        "status": result,
        "service": get_wg_quick_service_state(interface_name),
    }


def start_wireguard_interface(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """启动指定 WireGuard 接口。"""

    interface_name = payload["interface_name"]
    if dry_run:
        return {"changed": False, "dry_run": True, "message": "dry-run enabled, wg-quick up was not executed"}
    current = get_wireguard_status(payload)
    if current["runtime_status"] == "running":
        return {"changed": False, "runtime_status": "running", "message": "interface already running"}
    service_state = current["service"]
    manager = detect_service_manager(run_command)
    if service_state["managed"] or isinstance(manager, OpenWrtUciManager):
        return {
            "changed": True,
            "service": service_state,
            "start": manager.start(interface_name),
        }
    return {"changed": True, "up": run_command(["wg-quick", "up", interface_name], allow_failure=False)}


def stop_wireguard_interface(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """关闭指定 WireGuard 接口。"""

    interface_name = payload["interface_name"]
    if dry_run:
        return {"changed": False, "dry_run": True, "message": "dry-run enabled, wg-quick down was not executed"}
    current = get_wireguard_status(payload)
    if current["runtime_status"] == "stopped":
        return {"changed": False, "runtime_status": "stopped", "message": "interface already stopped"}
    service_state = current["service"]
    manager = detect_service_manager(run_command)
    if service_state["managed"] or isinstance(manager, OpenWrtUciManager):
        return {
            "changed": True,
            "service": service_state,
            "stop": manager.stop(interface_name),
        }
    return {"changed": True, "down": run_command(["wg-quick", "down", interface_name], allow_failure=True)}


def delete_wireguard_config(
    payload: dict[str, Any],
    wireguard_dir: str = DEFAULT_WIREGUARD_DIR,
    dry_run: bool = False,
) -> dict[str, Any]:
    """删除指定 WireGuard 配置文件；调用方必须先确认接口已停止。"""

    interface_name = payload["interface_name"]
    target = Path(wireguard_dir) / f"{interface_name}.conf"
    manager = detect_service_manager(run_command)
    if dry_run:
        return {
            "changed": False,
            "dry_run": True,
            "config_path": str(target),
            "message": "dry-run enabled, config file was not deleted",
        }
    if isinstance(manager, OpenWrtUciManager):
        return manager.delete_config(interface_name)
    if isinstance(manager, UnsupportedServiceManager):
        raise RuntimeError(manager.state(interface_name)["message"])
    if target.exists():
        target.unlink()
        return {"changed": True, "config_path": str(target)}
    return {"changed": False, "config_path": str(target), "message": "config file did not exist"}


def get_wg_quick_service_state(interface_name: str) -> dict[str, Any]:
    """识别接口是否已经由主机 init 系统管理。"""

    return detect_service_manager(run_command).state(interface_name)


def run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
    """执行系统命令，并返回可上报给 API 的结构化结果。"""

    timeout = command_timeout_seconds()
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        result = {
            "command": command,
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": f"command timed out after {timeout:g}s",
            "timeout": timeout,
        }
        if not allow_failure:
            raise RuntimeError(f"command timed out after {timeout:g}s: {' '.join(command)}") from exc
        return result
    result = {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if completed.returncode != 0 and not allow_failure:
        raise RuntimeError(f"command failed: {' '.join(command)}\n{completed.stderr}")
    return result
