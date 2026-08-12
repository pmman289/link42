from __future__ import annotations

from functools import lru_cache
import ipaddress
import json
from pathlib import Path
import shlex
import shutil
import sys
from typing import Any

from .system import run_command
from .validation import atomic_write_text, managed_child_path, validate_interface_name


DEFAULT_GRE_DIR = "/etc/link42/gre"
DEFAULT_GRE_SYSTEMD_UNIT_PATH = "/etc/systemd/system/link42-gre@.service"
OPENWRT_GRE_PROTO_PATH = "/lib/netifd/proto/gre.sh"


@lru_cache(maxsize=1)
def gre_runtime_supported() -> bool:
    """判断当前节点是否具备 GRE 运行条件。"""

    ip_binary = shutil.which("ip")
    if not ip_binary:
        return False
    result = run_command([ip_binary, "tunnel", "help"], allow_failure=True, log_failure=False)
    output = f"{result.get('stdout', '')}\n{result.get('stderr', '')}".lower()
    return result["returncode"] == 0 or "gre" in output


@lru_cache(maxsize=1)
def gre_ipv6_runtime_supported() -> bool:
    """判断当前节点的 iproute2 是否支持 IP6GRE。"""

    ip_binary = shutil.which("ip")
    if not ip_binary:
        return False
    result = run_command([ip_binary, "-6", "tunnel", "help"], allow_failure=True, log_failure=False)
    output = f"{result.get('stdout', '')}\n{result.get('stderr', '')}".lower()
    return "ip6gre" in output


@lru_cache(maxsize=1)
def openwrt_gre_supported() -> bool:
    """判断当前 OpenWrt 节点是否具备 netifd GRE 管理能力。"""

    return bool(
        shutil.which("uci")
        and shutil.which("ifup")
        and shutil.which("ifdown")
        and Path(OPENWRT_GRE_PROTO_PATH).exists()
    )


@lru_cache(maxsize=1)
def openwrt_gre_ipv6_supported() -> bool:
    """判断 OpenWrt netifd 和内核模块是否支持 GRE over IPv6。"""

    if not openwrt_gre_supported():
        return False
    try:
        script = Path(OPENWRT_GRE_PROTO_PATH).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    module_paths = list(Path("/lib/modules").glob("*/ip6_gre.ko*"))
    module_available = Path("/sys/module/ip6_gre").exists() or bool(module_paths)
    return "proto_grev6_setup" in script and module_available


def openwrt_gre_available() -> bool:
    """判断当前任务是否应走 OpenWrt UCI GRE 后端。"""

    return openwrt_gre_supported()


def gre_outer_ip_version(config: dict[str, Any]) -> int:
    """返回 GRE 外层地址版本，兼容未保存显式版本的旧配置。"""

    if config.get("outer_ip_version"):
        return int(config["outer_ip_version"])
    if config.get("outer_local_ip"):
        return ipaddress.ip_address(config["outer_local_ip"]).version
    return 4


def require_openwrt_gre_family_supported(config: dict[str, Any]) -> None:
    """拒绝当前 OpenWrt 缺少 netifd 或内核支持的 GRE 地址族。"""

    if gre_outer_ip_version(config) == 6 and not openwrt_gre_ipv6_supported():
        raise RuntimeError("OpenWrt does not support GRE over IPv6")


def gre_config_dir(path: str | None = None) -> Path:
    """返回 GRE 配置目录路径。"""

    return Path(path or DEFAULT_GRE_DIR)


def gre_config_path(interface_name: str, config_dir: str | None = None) -> Path:
    """返回指定 GRE 接口的 Link42 配置文件路径。"""

    name = validate_interface_name(interface_name)
    return managed_child_path(gre_config_dir(config_dir), f"{name}.json")


def gre_systemd_unit_path() -> Path:
    """返回 Link42 GRE systemd 模板服务文件路径。"""

    return Path(DEFAULT_GRE_SYSTEMD_UNIT_PATH)


def gre_systemd_unit_name(interface_name: str) -> str:
    """返回指定 GRE 接口对应的 systemd unit 名称。"""

    return f"link42-gre@{validate_interface_name(interface_name)}.service"


def systemctl_command() -> str:
    """返回 systemctl 命令路径。"""

    return shutil.which("systemctl") or "systemctl"


def gre_systemd_available() -> bool:
    """判断当前节点是否可以使用 systemd 管理 GRE 持久化。"""

    return bool(shutil.which("systemctl")) and Path("/run/systemd/system").exists()


def agent_source_pythonpath() -> str | None:
    """返回源码运行时需要注入给 systemd 的 Python 模块搜索路径。"""

    agent_root = Path(__file__).resolve().parents[1]
    repo_root = Path(__file__).resolve().parents[3]
    packages_root = repo_root / "packages"
    paths = [path for path in [agent_root, packages_root] if path.exists()]
    if not paths:
        return None
    return ":".join(str(path) for path in paths)


def agent_binary_path() -> str:
    """返回 systemd unit 调用当前 Agent 的命令行。"""

    discovered = shutil.which("link42-agent")
    if discovered:
        return shlex.quote(discovered)
    return f"{shlex.quote(sys.executable)} -m link42_agent.main"


def render_gre_systemd_unit(config_dir: str | None = None) -> str:
    """渲染 Link42 GRE systemd 模板服务。"""

    service_environment = [f"Environment=LINK42_GRE_DIR={gre_config_dir(config_dir)}"]
    if not shutil.which("link42-agent"):
        source_pythonpath = agent_source_pythonpath()
        if source_pythonpath:
            service_environment.append(f"Environment=PYTHONPATH={source_pythonpath}")

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
            *service_environment,
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

    outer_local_ip = str(payload["outer_local_ip"]).strip()
    outer_remote_ip = str(payload["outer_remote_ip"]).strip()
    try:
        local_address = ipaddress.ip_address(outer_local_ip)
        remote_address = ipaddress.ip_address(outer_remote_ip)
    except ValueError as exc:
        raise ValueError("GRE outer addresses must be IP literals") from exc
    if local_address.version != remote_address.version:
        raise ValueError("GRE outer addresses must use the same IP version")
    config = {
        "interface_name": validate_interface_name(payload["interface_name"]),
        "previous_interface_name": (
            validate_interface_name(payload["previous_interface_name"], "previous interface name")
            if str(payload.get("previous_interface_name") or "").strip()
            else None
        ),
        "outer_local_ip": outer_local_ip,
        "outer_remote_ip": outer_remote_ip,
        "outer_ip_version": local_address.version,
        "tunnel_ips": [str(item).strip() for item in payload.get("tunnel_ips") or [] if str(item).strip()],
        "routes": [str(item).strip() for item in payload.get("routes") or [] if str(item).strip()],
        "mtu": int(payload.get("mtu") or (1456 if local_address.version == 6 else 1476)),
        "key": str(payload.get("key") or "").strip() or None,
        "ttl": int(payload["ttl"]) if payload.get("ttl") is not None else None,
        "pmtudisc": bool(payload.get("pmtudisc", True)),
    }
    if config["outer_ip_version"] == 4 and config["ttl"] is not None and not config["pmtudisc"]:
        raise ValueError("GRE ttl requires PMTU discovery")
    return config


def write_gre_config(config: dict[str, Any], config_dir: str | None = None) -> Path:
    """把 GRE 配置写入 Link42 管理目录。"""

    target = gre_config_path(config["interface_name"], config_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(target, json.dumps(config, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
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

    interface_name = validate_interface_name(payload["interface_name"])
    path = gre_config_path(interface_name, config_dir)
    if not path.exists():
        return {"exists": False, "config_path": str(path), "config": None}
    return {"exists": True, "config_path": str(path), "config": json.loads(path.read_text(encoding="utf-8"))}


def ip_command() -> str:
    """返回 iproute2 命令路径。"""

    return shutil.which("ip") or "ip"


def uci_command() -> str:
    """返回 OpenWrt uci 命令路径。"""

    return shutil.which("uci") or "uci"


def ifup_command() -> str:
    """返回 OpenWrt ifup 命令路径。"""

    return shutil.which("ifup") or "ifup"


def ifdown_command() -> str:
    """返回 OpenWrt ifdown 命令路径。"""

    return shutil.which("ifdown") or "ifdown"


def gre_tunnel_add_command(config: dict[str, Any]) -> list[str]:
    """生成创建 GRE tunnel 的 ip 命令。"""

    outer_ip_version = gre_outer_ip_version(config)
    command = [ip_command()]
    if outer_ip_version == 6:
        command.append("-6")
    command.extend([
        "tunnel",
        "add",
        config["interface_name"],
        "mode",
        "ip6gre" if outer_ip_version == 6 else "gre",
        "local",
        config["outer_local_ip"],
        "remote",
        config["outer_remote_ip"],
    ])
    if config.get("key"):
        command.extend(["key", str(config["key"])])
    if config.get("ttl") is not None:
        command.extend(["hoplimit" if outer_ip_version == 6 else "ttl", str(config["ttl"])])
    if outer_ip_version == 4:
        command.append("pmtudisc" if config.get("pmtudisc", True) else "nopmtudisc")
    return command


def gre_route_replace_command(route: str, interface_name: str) -> list[str]:
    """根据路由网段版本生成 IPv4 或 IPv6 route replace 命令。"""

    network = ipaddress.ip_network(route, strict=False)
    if network.version == 6:
        return [ip_command(), "-6", "route", "replace", route, "dev", interface_name]
    return [ip_command(), "route", "replace", route, "dev", interface_name]


def gre_start_commands(config: dict[str, Any]) -> list[list[str]]:
    """生成启动 GRE 接口所需的命令序列。"""

    interface_name = config["interface_name"]
    commands: list[list[str]] = []
    previous_interface_name = config.get("previous_interface_name")
    if previous_interface_name and previous_interface_name != interface_name:
        # 同一组 local/remote/key 不能同时创建两个 GRE 接口，改名时必须先移除旧接口。
        commands.append([ip_command(), "link", "del", previous_interface_name])
    commands.append([ip_command(), "link", "del", interface_name])
    commands.append(gre_tunnel_add_command(config))
    for tunnel_ip in config["tunnel_ips"]:
        commands.append([ip_command(), "addr", "add", tunnel_ip, "dev", interface_name])
    commands.append([ip_command(), "link", "set", "dev", interface_name, "mtu", str(config["mtu"]), "up"])
    for route in config["routes"]:
        commands.append(gre_route_replace_command(route, interface_name))
    return commands


def openwrt_gre_addr_section(interface_name: str) -> str:
    """返回承载 GRE 隧道内地址的 OpenWrt static 接口名。"""

    return f"{interface_name}_addr"


def openwrt_gre_device_name(interface_name: str, outer_ip_version: int = 4) -> str:
    """返回 OpenWrt netifd 为 GRE section 生成的内核设备名。"""

    return f"gre6-{interface_name}" if outer_ip_version == 6 else f"gre4-{interface_name}"


def openwrt_route_section(interface_name: str, version: int, index: int) -> str:
    """返回 Link42 管理的 OpenWrt route/route6 section 名称。"""

    family = "r6" if version == 6 else "r4"
    return f"{interface_name}_{family}_{index}"


def openwrt_gre_managed_sections(uci_show_output: str, interface_name: str) -> list[str]:
    """从 uci show network 输出中找出指定 GRE 接口的旧 Link42 section。"""

    sections = {interface_name, openwrt_gre_addr_section(interface_name)}
    marker = f".link42_gre_name='{interface_name}'"
    for line in uci_show_output.splitlines():
        if not line.startswith("network.") or marker not in line:
            continue
        section = line.removeprefix("network.").split(".", 1)[0]
        if section:
            sections.add(section)
    return sorted(sections, key=lambda value: (value in {interface_name, openwrt_gre_addr_section(interface_name)}, value))


def openwrt_delete_gre_config_commands(interface_name: str) -> list[list[str]]:
    """生成删除 OpenWrt GRE UCI 配置的命令序列。"""

    show_result = run_command([uci_command(), "-q", "show", "network"], allow_failure=True)
    sections = openwrt_gre_managed_sections(str(show_result.get("stdout") or ""), interface_name)
    return [[uci_command(), "-q", "delete", f"network.{section}"] for section in sections]


def openwrt_route_set_commands(interface_name: str, addr_section: str, routes: list[str]) -> list[list[str]]:
    """生成 OpenWrt GRE 静态路由 UCI 命令。"""

    commands: list[list[str]] = []
    ipv4_index = 0
    ipv6_index = 0
    for route in routes:
        network = ipaddress.ip_network(route, strict=False)
        if network.version == 6:
            section = openwrt_route_section(interface_name, 6, ipv6_index)
            ipv6_index += 1
            commands.extend(
                [
                    [uci_command(), "set", f"network.{section}=route6"],
                    [uci_command(), "set", f"network.{section}.interface={addr_section}"],
                    [uci_command(), "set", f"network.{section}.target={network.with_prefixlen}"],
                    [uci_command(), "set", f"network.{section}.link42_gre_name={interface_name}"],
                ]
            )
            continue
        section = openwrt_route_section(interface_name, 4, ipv4_index)
        ipv4_index += 1
        commands.extend(
            [
                [uci_command(), "set", f"network.{section}=route"],
                [uci_command(), "set", f"network.{section}.interface={addr_section}"],
                [uci_command(), "set", f"network.{section}.target={network.network_address}"],
                [uci_command(), "set", f"network.{section}.netmask={network.netmask}"],
                [uci_command(), "set", f"network.{section}.link42_gre_name={interface_name}"],
            ]
        )
    return commands


def openwrt_apply_gre_commands(config: dict[str, Any], *, autostart: bool = True) -> list[list[str]]:
    """生成 OpenWrt GRE UCI 配置命令，隧道地址通过 static alias 承载。"""

    interface_name = config["interface_name"]
    addr_section = openwrt_gre_addr_section(interface_name)
    outer_ip_version = gre_outer_ip_version(config)
    proto = "grev6" if outer_ip_version == 6 else "gre"
    local_field = "ip6addr" if outer_ip_version == 6 else "ipaddr"
    remote_field = "peer6addr" if outer_ip_version == 6 else "peeraddr"
    auto_value = "1" if autostart else "0"
    commands = openwrt_delete_gre_config_commands(interface_name)
    commands.extend(
        [
            [uci_command(), "set", f"network.{interface_name}=interface"],
            [uci_command(), "set", f"network.{interface_name}.proto={proto}"],
            [uci_command(), "set", f"network.{interface_name}.{local_field}={config['outer_local_ip']}"],
            [uci_command(), "set", f"network.{interface_name}.{remote_field}={config['outer_remote_ip']}"],
            [uci_command(), "set", f"network.{interface_name}.mtu={config['mtu']}"],
            [uci_command(), "set", f"network.{interface_name}.auto={auto_value}"],
            [uci_command(), "set", f"network.{interface_name}.link42_managed=1"],
            [uci_command(), "set", f"network.{interface_name}.link42_gre_name={interface_name}"],
            [uci_command(), "set", f"network.{addr_section}=interface"],
            [uci_command(), "set", f"network.{addr_section}.proto=static"],
            [uci_command(), "set", f"network.{addr_section}.device=@{interface_name}"],
            [uci_command(), "set", f"network.{addr_section}.auto={auto_value}"],
            [uci_command(), "set", f"network.{addr_section}.link42_managed=1"],
            [uci_command(), "set", f"network.{addr_section}.link42_gre_name={interface_name}"],
        ]
    )
    if outer_ip_version == 4:
        commands.append([uci_command(), "set", f"network.{interface_name}.df={'1' if config.get('pmtudisc', True) else '0'}"])
    if config.get("ttl") is not None:
        commands.append([uci_command(), "set", f"network.{interface_name}.ttl={config['ttl']}"])
    if config.get("key"):
        commands.append([uci_command(), "set", f"network.{interface_name}.ikey={config['key']}"])
        commands.append([uci_command(), "set", f"network.{interface_name}.okey={config['key']}"])
    for tunnel_ip in config["tunnel_ips"]:
        address = ipaddress.ip_interface(tunnel_ip)
        field = "ip6addr" if address.version == 6 else "ipaddr"
        commands.append([uci_command(), "add_list", f"network.{addr_section}.{field}={tunnel_ip}"])
    commands.extend(openwrt_route_set_commands(interface_name, addr_section, config["routes"]))
    commands.append([uci_command(), "commit", "network"])
    return commands


def run_openwrt_gre_commands(commands: list[list[str]], allow_delete_failure: bool = True) -> list[dict[str, Any]]:
    """执行 OpenWrt GRE UCI/ifup 命令并返回每条命令结果。"""

    results: list[dict[str, Any]] = []
    for command in commands:
        allow_failure = allow_delete_failure and (
            command[:3] == [uci_command(), "-q", "delete"]
            or command[0] == ifdown_command()
        )
        results.append(run_command(command, allow_failure=allow_failure))
    return results


def apply_openwrt_gre_config(config: dict[str, Any], config_dir: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    """写入 OpenWrt GRE UCI 配置，不主动拉起接口。"""

    require_openwrt_gre_family_supported(config)
    path = write_gre_config(config, config_dir)
    commands = openwrt_apply_gre_commands(config, autostart=True)
    if dry_run:
        return {
            "changed": True,
            "dry_run": True,
            "service_backend": "openwrt-uci",
            "config_path": str(path),
            "commands": commands,
        }
    results = run_openwrt_gre_commands(commands)
    return {
        "changed": True,
        "service_backend": "openwrt-uci",
        "config_path": str(path),
        "commands": results,
    }


def start_openwrt_gre_interface(config: dict[str, Any], config_dir: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    """通过 OpenWrt netifd 启动 GRE 隧道和承载地址的 static 接口。"""

    require_openwrt_gre_family_supported(config)
    path = write_gre_config(config, config_dir)
    addr_section = openwrt_gre_addr_section(config["interface_name"])
    commands = openwrt_apply_gre_commands(config, autostart=True)
    commands.extend(
        [
            [ifdown_command(), addr_section],
            [ifdown_command(), config["interface_name"]],
            [ifup_command(), config["interface_name"]],
            [ifup_command(), addr_section],
        ]
    )
    if dry_run:
        return {
            "changed": True,
            "dry_run": True,
            "service_backend": "openwrt-uci",
            "config_path": str(path),
            "commands": commands,
            "runtime_status": "running",
        }
    results = run_openwrt_gre_commands(commands)
    previous_cleanup = delete_openwrt_gre_config_file(config.get("previous_interface_name"), config_dir)
    return {
        "changed": True,
        "service_backend": "openwrt-uci",
        "config_path": str(path),
        "commands": results,
        "previous_config_cleanup": previous_cleanup,
        "runtime_status": "running",
    }


def stop_openwrt_gre_interface(interface_name: str, dry_run: bool = False) -> dict[str, Any]:
    """通过 OpenWrt netifd 停止 GRE，并关闭 UCI 自启动。"""

    addr_section = openwrt_gre_addr_section(interface_name)
    commands = [
        [ifdown_command(), addr_section],
        [ifdown_command(), interface_name],
        [uci_command(), "-q", "set", f"network.{interface_name}.auto=0"],
        [uci_command(), "-q", "set", f"network.{addr_section}.auto=0"],
        [uci_command(), "commit", "network"],
    ]
    if dry_run:
        return {
            "changed": True,
            "dry_run": True,
            "service_backend": "openwrt-uci",
            "commands": commands,
            "runtime_status": "stopped",
        }
    results = []
    for command in commands:
        results.append(run_command(command, allow_failure=command[0] in {ifdown_command(), uci_command()} and "-q" in command))
    return {
        "changed": True,
        "service_backend": "openwrt-uci",
        "commands": results,
        "runtime_status": "stopped",
    }


def delete_openwrt_gre_config_file(interface_name: str | None, config_dir: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    """删除 OpenWrt GRE UCI 配置和 Link42 JSON 配置。"""

    cleaned = str(interface_name or "").strip()
    if not cleaned:
        return {"interface_name": None, "config_path": None, "deleted": False}
    commands = openwrt_delete_gre_config_commands(cleaned)
    commands.append([uci_command(), "commit", "network"])
    if dry_run:
        config = delete_gre_config_file(cleaned, config_dir, dry_run=True)
        return {
            "interface_name": cleaned,
            "service_backend": "openwrt-uci",
            "commands": commands,
            "config_path": config["config_path"],
            "deleted": config["deleted"],
            "dry_run": True,
        }
    results = run_openwrt_gre_commands(commands)
    config = delete_gre_config_file(cleaned, config_dir, dry_run=False)
    return {
        "interface_name": cleaned,
        "service_backend": "openwrt-uci",
        "commands": results,
        "config_path": config["config_path"],
        "deleted": config["deleted"],
    }


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
    commands.extend(cleanup_commands)
    commands.extend(
        [
            [systemctl_command(), "daemon-reload"],
            [systemctl_command(), "enable", gre_systemd_unit_name(interface_name)],
            [systemctl_command(), "restart", gre_systemd_unit_name(interface_name)],
        ]
    )
    return commands


def apply_gre_config(payload: dict[str, Any], config_dir: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    """写入 GRE 配置，不直接改动运行中接口。"""

    config = normalize_gre_payload(payload)
    if openwrt_gre_available():
        return apply_openwrt_gre_config(config, config_dir, dry_run=dry_run)
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
    if use_service and openwrt_gre_available():
        return start_openwrt_gre_interface(config, config_dir, dry_run=dry_run)
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

    interface_name = validate_interface_name(payload["interface_name"])
    if use_service and openwrt_gre_available():
        return stop_openwrt_gre_interface(interface_name, dry_run=dry_run)
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

    if openwrt_gre_available():
        interface_name = validate_interface_name(payload["interface_name"])
        stop_result = stop_openwrt_gre_interface(interface_name, dry_run=dry_run)
        current_config = delete_openwrt_gre_config_file(interface_name, config_dir, dry_run=dry_run)
        previous_value = str(payload.get("previous_interface_name") or "").strip()
        previous_interface_name = validate_interface_name(previous_value, "previous interface name") if previous_value else None
        previous_stop = None
        previous_config = None
        if previous_interface_name and previous_interface_name != interface_name:
            previous_stop = stop_openwrt_gre_interface(previous_interface_name, dry_run=dry_run)
            previous_config = delete_openwrt_gre_config_file(previous_interface_name, config_dir, dry_run=dry_run)
        return {
            "changed": (
                bool(stop_result.get("changed"))
                or bool(current_config.get("deleted"))
                or bool(previous_stop and previous_stop.get("changed"))
                or bool(previous_config and previous_config.get("deleted"))
            ),
            "service_backend": "openwrt-uci",
            "stop": stop_result,
            "config_path": current_config["config_path"],
            "deleted": current_config["deleted"],
            "previous_stop": previous_stop,
            "previous_config": previous_config,
            "runtime_status": "stopped",
        }
    stop_result = stop_gre_interface(payload, dry_run=dry_run)
    interface_name = validate_interface_name(payload["interface_name"])
    current_config = delete_gre_config_file(interface_name, config_dir, dry_run=dry_run)
    previous_value = str(payload.get("previous_interface_name") or "").strip()
    previous_interface_name = validate_interface_name(previous_value, "previous interface name") if previous_value else None
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

    interface_name = validate_interface_name(payload["interface_name"])
    if openwrt_gre_available():
        ifstatus = run_command(["ifstatus", interface_name], allow_failure=True)
        status_payload: dict[str, Any] = {}
        if ifstatus["returncode"] == 0:
            try:
                status_payload = json.loads(str(ifstatus.get("stdout") or "{}"))
            except json.JSONDecodeError:
                status_payload = {}
        outer_ip_version = gre_outer_ip_version(payload)
        device_name = openwrt_gre_device_name(interface_name, outer_ip_version)
        result = run_command([ip_command(), "link", "show", "dev", device_name], allow_failure=True)
        running = bool(status_payload.get("up")) or (
            result["returncode"] == 0 and gre_link_stdout_is_running(str(result.get("stdout") or ""))
        )
        return {
            "runtime_status": "running" if running else "stopped",
            "service_backend": "openwrt-uci",
            "ifstatus": ifstatus,
            "link": result,
        }
    result = run_command([ip_command(), "link", "show", "dev", interface_name], allow_failure=True)
    running = result["returncode"] == 0 and gre_link_stdout_is_running(str(result.get("stdout") or ""))
    return {
        "runtime_status": "running" if running else "stopped",
        "link": result,
    }
