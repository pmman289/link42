from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
import shutil
import sys
from typing import Any

from .system import run_command


DEFAULT_GRE_DIR = "/etc/link42/gre"
DEFAULT_GRE_SYSTEMD_UNIT_PATH = "/etc/systemd/system/link42-gre@.service"


@lru_cache(maxsize=1)
def gre_runtime_supported() -> bool:
    """判断当前节点是否具备第一版 GRE 运行条件。"""

    ip_binary = shutil.which("ip")
    if not ip_binary:
        return False
    result = run_command([ip_binary, "tunnel", "help"], allow_failure=True)
    output = f"{result.get('stdout', '')}\n{result.get('stderr', '')}".lower()
    return result["returncode"] == 0 or "gre" in output


def gre_config_dir(path: str | None = None) -> Path:
    """返回 GRE 配置目录路径。"""

    return Path(path or DEFAULT_GRE_DIR)


def gre_config_path(interface_name: str, config_dir: str | None = None) -> Path:
    """返回指定 GRE 接口的 Link42 配置文件路径。"""

    return gre_config_dir(config_dir) / f"{interface_name}.json"


def gre_systemd_unit_path() -> Path:
    """返回 Link42 GRE systemd 模板服务文件路径。"""

    return Path(DEFAULT_GRE_SYSTEMD_UNIT_PATH)


def gre_systemd_unit_name(interface_name: str) -> str:
    """返回指定 GRE 接口对应的 systemd unit 名称。"""

    return f"link42-gre@{interface_name}.service"


def systemctl_command() -> str:
    """返回 systemctl 命令路径。"""

    return shutil.which("systemctl") or "systemctl"


def gre_systemd_available() -> bool:
    """判断当前节点是否可以使用 systemd 管理 GRE 持久化。"""

    return bool(shutil.which("systemctl")) and Path("/run/systemd/system").exists()


def agent_binary_path() -> str:
    """返回 systemd unit 调用当前 Agent 的可执行路径。"""

    discovered = shutil.which("link42-agent")
    if discovered:
        return discovered
    return str(Path(sys.argv[0]).resolve())


def render_gre_systemd_unit(config_dir: str | None = None) -> str:
    """渲染 Link42 GRE systemd 模板服务。"""

    return "\n".join(
        [
            "[Unit]",
            "Description=Link42 GRE tunnel %i",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=yes",
            f"Environment=LINK42_GRE_DIR={gre_config_dir(config_dir)}",
            f"ExecStart={agent_binary_path()} gre-start %i",
            f"ExecStop=-{ip_command()} link del %i",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def install_gre_systemd_unit(config_dir: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    """安装或更新 GRE systemd 模板服务文件。"""

    path = gre_systemd_unit_path()
    content = render_gre_systemd_unit(config_dir)
    if dry_run:
        return {"changed": True, "unit_path": str(path), "content": content, "dry_run": True}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return {"changed": True, "unit_path": str(path)}


def normalize_gre_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """清洗 Agent GRE 任务 payload，确保后续渲染字段稳定。"""

    config = {
        "interface_name": str(payload["interface_name"]).strip(),
        "previous_interface_name": str(payload.get("previous_interface_name") or "").strip() or None,
        "outer_local_ip": str(payload["outer_local_ip"]).strip(),
        "outer_remote_ip": str(payload["outer_remote_ip"]).strip(),
        "tunnel_ips": [str(item).strip() for item in payload.get("tunnel_ips") or [] if str(item).strip()],
        "routes": [str(item).strip() for item in payload.get("routes") or [] if str(item).strip()],
        "mtu": int(payload.get("mtu") or 1476),
        "key": str(payload.get("key") or "").strip() or None,
        "ttl": int(payload["ttl"]) if payload.get("ttl") is not None else None,
        "pmtudisc": bool(payload.get("pmtudisc", True)),
    }
    if config["ttl"] is not None and not config["pmtudisc"]:
        raise ValueError("GRE ttl requires PMTU discovery")
    return config


def write_gre_config(config: dict[str, Any], config_dir: str | None = None) -> Path:
    """把 GRE 配置写入 Link42 管理目录。"""

    target = gre_config_path(config["interface_name"], config_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(config, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return target


def delete_gre_config_file(interface_name: str | None, config_dir: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    """删除指定 GRE 接口的 Link42 配置文件，接口名为空时只返回未删除。"""

    cleaned = str(interface_name or "").strip()
    if not cleaned:
        return {"interface_name": None, "config_path": None, "deleted": False}
    path = gre_config_path(cleaned, config_dir)
    deleted = False
    if not dry_run and path.exists():
        path.unlink()
        deleted = True
    return {"interface_name": cleaned, "config_path": str(path), "deleted": deleted, "dry_run": dry_run}


def read_gre_config(payload: dict[str, Any], config_dir: str | None = None) -> dict[str, Any]:
    """读取 Link42 管理的 GRE 配置文件。"""

    interface_name = str(payload["interface_name"]).strip()
    path = gre_config_path(interface_name, config_dir)
    if not path.exists():
        return {"exists": False, "config_path": str(path), "config": None}
    return {"exists": True, "config_path": str(path), "config": json.loads(path.read_text(encoding="utf-8"))}


def ip_command() -> str:
    """返回 iproute2 命令路径。"""

    return shutil.which("ip") or "ip"


def gre_tunnel_add_command(config: dict[str, Any]) -> list[str]:
    """生成创建 GRE tunnel 的 ip 命令。"""

    command = [
        ip_command(),
        "tunnel",
        "add",
        config["interface_name"],
        "mode",
        "gre",
        "local",
        config["outer_local_ip"],
        "remote",
        config["outer_remote_ip"],
    ]
    if config.get("key"):
        command.extend(["key", str(config["key"])])
    if config.get("ttl") is not None:
        command.extend(["ttl", str(config["ttl"])])
    command.append("pmtudisc" if config.get("pmtudisc", True) else "nopmtudisc")
    return command


def gre_start_commands(config: dict[str, Any]) -> list[list[str]]:
    """生成启动 GRE 接口所需的命令序列。"""

    interface_name = config["interface_name"]
    commands = [[ip_command(), "link", "del", interface_name]]
    commands.append(gre_tunnel_add_command(config))
    for tunnel_ip in config["tunnel_ips"]:
        commands.append([ip_command(), "addr", "add", tunnel_ip, "dev", interface_name])
    commands.append([ip_command(), "link", "set", "dev", interface_name, "mtu", str(config["mtu"]), "up"])
    for route in config["routes"]:
        commands.append([ip_command(), "route", "replace", route, "dev", interface_name])
    previous_interface_name = config.get("previous_interface_name")
    if previous_interface_name and previous_interface_name != interface_name:
        commands.append([ip_command(), "link", "del", previous_interface_name])
    return commands


def gre_systemd_start_commands(config: dict[str, Any]) -> list[list[str]]:
    """生成通过 systemd 启动 GRE 接口所需的命令序列。"""

    interface_name = config["interface_name"]
    commands: list[list[str]] = []
    previous_interface_name = config.get("previous_interface_name")
    if previous_interface_name and previous_interface_name != interface_name:
        cleanup_commands = [
            [systemctl_command(), "disable", "--now", gre_systemd_unit_name(previous_interface_name)],
            [ip_command(), "link", "del", previous_interface_name],
        ]
    else:
        cleanup_commands = []
    commands.extend(
        [
            [systemctl_command(), "daemon-reload"],
            [systemctl_command(), "enable", gre_systemd_unit_name(interface_name)],
            [systemctl_command(), "restart", gre_systemd_unit_name(interface_name)],
        ]
    )
    commands.extend(cleanup_commands)
    return commands


def apply_gre_config(payload: dict[str, Any], config_dir: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    """写入 GRE 配置，不直接改动运行中接口。"""

    config = normalize_gre_payload(payload)
    path = write_gre_config(config, config_dir)
    return {"changed": True, "config_path": str(path), "config": config, "dry_run": dry_run}


def start_gre_interface(
    payload: dict[str, Any],
    config_dir: str | None = None,
    dry_run: bool = False,
    use_service: bool = True,
) -> dict[str, Any]:
    """幂等启动 GRE 接口，已存在时先删除再重建。"""

    config = normalize_gre_payload(payload)
    write_gre_config(config, config_dir)
    commands: list[dict[str, Any]] = []
    if use_service and gre_systemd_available():
        service_commands = gre_systemd_start_commands(config)
        if dry_run:
            return {
                "changed": True,
                "dry_run": True,
                "service_backend": "systemd",
                "unit": install_gre_systemd_unit(config_dir, dry_run=True),
                "commands": service_commands,
                "runtime_status": "running",
            }
        unit_result = install_gre_systemd_unit(config_dir)
        for command in service_commands:
            allow_failure = (
                command[:3] == [systemctl_command(), "disable", "--now"]
                or command[:3] == [ip_command(), "link", "del"]
            )
            commands.append(run_command(command, allow_failure=allow_failure))
        previous_cleanup = delete_gre_config_file(config.get("previous_interface_name"), config_dir)
        return {
            "changed": True,
            "service_backend": "systemd",
            "unit": unit_result,
            "commands": commands,
            "previous_config_cleanup": previous_cleanup,
            "runtime_status": "running",
        }
    if dry_run:
        return {"changed": True, "dry_run": True, "commands": gre_start_commands(config), "runtime_status": "running"}
    for command in gre_start_commands(config):
        allow_failure = command[:3] == [ip_command(), "link", "del"]
        commands.append(run_command(command, allow_failure=allow_failure))
    previous_cleanup = delete_gre_config_file(config.get("previous_interface_name"), config_dir)
    return {"changed": True, "commands": commands, "previous_config_cleanup": previous_cleanup, "runtime_status": "running"}


def start_gre_from_config(interface_name: str, config_dir: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    """从 Link42 GRE 配置文件直接启动接口，供 systemd 模板服务调用。"""

    config = read_gre_config({"interface_name": interface_name}, config_dir)
    if not config.get("exists") or not isinstance(config.get("config"), dict):
        raise RuntimeError(f"GRE config not found: {interface_name}")
    return start_gre_interface(config["config"], config_dir, dry_run=dry_run, use_service=False)


def gre_systemd_stop_commands(interface_name: str) -> list[list[str]]:
    """生成通过 systemd 停止 GRE 接口所需的命令序列。"""

    return [
        [systemctl_command(), "disable", "--now", gre_systemd_unit_name(interface_name)],
        [ip_command(), "link", "del", interface_name],
    ]


def stop_gre_interface(payload: dict[str, Any], dry_run: bool = False, use_service: bool = True) -> dict[str, Any]:
    """幂等停止 GRE 接口，接口不存在也视为成功。"""

    interface_name = str(payload["interface_name"]).strip()
    if use_service and gre_systemd_available():
        service_commands = gre_systemd_stop_commands(interface_name)
        if dry_run:
            return {
                "changed": True,
                "dry_run": True,
                "service_backend": "systemd",
                "commands": service_commands,
                "runtime_status": "stopped",
            }
        results = [run_command(command, allow_failure=True) for command in service_commands]
        return {
            "changed": any(result["returncode"] == 0 for result in results),
            "service_backend": "systemd",
            "commands": results,
            "runtime_status": "stopped",
        }
    command = [ip_command(), "link", "del", interface_name]
    if dry_run:
        return {"changed": True, "dry_run": True, "commands": [command], "runtime_status": "stopped"}
    result = run_command(command, allow_failure=True)
    return {"changed": result["returncode"] == 0, "delete": result, "runtime_status": "stopped"}


def delete_gre_config(payload: dict[str, Any], config_dir: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    """停止 GRE 接口并删除 Link42 管理的配置文件。"""

    stop_result = stop_gre_interface(payload, dry_run=dry_run)
    interface_name = str(payload["interface_name"]).strip()
    current_config = delete_gre_config_file(interface_name, config_dir, dry_run=dry_run)
    previous_interface_name = str(payload.get("previous_interface_name") or "").strip() or None
    previous_stop = None
    previous_config = None
    if previous_interface_name and previous_interface_name != interface_name:
        previous_stop = stop_gre_interface({"interface_name": previous_interface_name}, dry_run=dry_run)
        previous_config = delete_gre_config_file(previous_interface_name, config_dir, dry_run=dry_run)
    return {
        "changed": (
            bool(stop_result.get("changed"))
            or bool(current_config.get("deleted"))
            or bool(previous_stop and previous_stop.get("changed"))
            or bool(previous_config and previous_config.get("deleted"))
        ),
        "stop": stop_result,
        "config_path": current_config["config_path"],
        "deleted": current_config["deleted"],
        "previous_stop": previous_stop,
        "previous_config": previous_config,
        "runtime_status": "stopped",
    }


def gre_link_stdout_is_running(stdout: str) -> bool:
    """根据 ip link 输出判断 GRE 接口是否处于可用状态。"""

    if "state UP" in stdout:
        return True
    first_line = stdout.splitlines()[0] if stdout.splitlines() else ""
    match = None
    if "<" in first_line and ">" in first_line:
        match = first_line.split("<", 1)[1].split(">", 1)[0]
    if not match:
        return False
    flags = {flag.strip() for flag in match.split(",")}
    return "UP" in flags


def gre_status(payload: dict[str, Any]) -> dict[str, Any]:
    """读取 GRE 接口运行状态。"""

    interface_name = str(payload["interface_name"]).strip()
    result = run_command([ip_command(), "link", "show", "dev", interface_name], allow_failure=True)
    running = result["returncode"] == 0 and gre_link_stdout_is_running(str(result.get("stdout") or ""))
    return {
        "runtime_status": "running" if running else "stopped",
        "link": result,
    }
