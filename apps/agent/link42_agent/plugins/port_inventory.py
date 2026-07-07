from __future__ import annotations

from pathlib import Path
import re
import shutil
from typing import Any

from ..system import run_command
from .base import AgentNodePlugin, AgentPluginContext


class PortInventoryAgentPlugin(AgentNodePlugin):
    """扫描节点本机指定范围内的 TCP/UDP/WireGuard 端口占用。"""

    type = "port-inventory"
    capabilities = [
        "node_plugin",
        "node_plugin.port_inventory",
        "node_plugin.port_inventory.scan",
    ]
    actions = {"scan"}

    def detect(self, context: AgentPluginContext) -> dict[str, Any]:
        """检测是否存在可用于扫描端口占用的系统工具或配置目录。"""

        wireguard_config_dir = Path(context.config.wireguard_dir)
        return {
            "plugin_type": self.type,
            "available": bool(
                shutil.which("ss")
                or shutil.which("netstat")
                or shutil.which("wg")
                or shutil.which("uci")
                or wireguard_config_dir.exists()
            ),
        }

    def execute(self, action: str, payload: dict[str, Any], context: AgentPluginContext) -> dict[str, Any]:
        """执行端口范围扫描并返回端口占用列表。"""

        if action != "scan":
            raise ValueError(f"unsupported port inventory action: {action}")
        range_start = int(payload.get("range_start") or 0)
        range_end = int(payload.get("range_end") or 0)
        if not 1 <= range_start <= 65535 or not 1 <= range_end <= 65535 or range_start > range_end:
            raise ValueError("invalid port range")
        ports = scan_ports(range_start, range_end, context.config.wireguard_dir)
        return {
            "plugin_type": self.type,
            "action": action,
            "range_start": range_start,
            "range_end": range_end,
            "ports": ports,
        }


def scan_ports(range_start: int, range_end: int, wireguard_dir: str) -> list[dict[str, Any]]:
    """合并系统监听端口和 WireGuard 配置端口扫描结果。"""

    entries: dict[tuple[str, int, str], dict[str, Any]] = {}

    for entry in scan_socket_listeners(range_start, range_end):
        key = (entry["protocol"], int(entry["port"]), str(entry.get("detected_source") or "socket"))
        entries[key] = entry

    for entry in scan_wireguard_ports(range_start, range_end, wireguard_dir):
        key = (entry["protocol"], int(entry["port"]), str(entry.get("detected_source") or "wireguard"))
        entries[key] = entry

    return sorted(entries.values(), key=lambda item: (int(item["port"]), str(item["protocol"]), str(item.get("detected_source") or "")))


def scan_socket_listeners(range_start: int, range_end: int) -> list[dict[str, Any]]:
    """使用 ss 或 netstat 扫描系统当前监听的 TCP/UDP 端口。"""

    if shutil.which("ss"):
        result = run_command(["ss", "-H", "-lntup"], allow_failure=True)
        if result["returncode"] == 0:
            return parse_ss_output(str(result.get("stdout") or ""), range_start, range_end)
    if shutil.which("netstat"):
        result = run_command(["netstat", "-lntup"], allow_failure=True)
        if result["returncode"] == 0:
            return parse_netstat_output(str(result.get("stdout") or ""), range_start, range_end)
    return []


def parse_ss_output(output: str, range_start: int, range_end: int) -> list[dict[str, Any]]:
    """解析 ss -lntup 输出中的端口、协议和进程信息。"""

    entries: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        protocol = protocol_from_token(parts[0])
        if protocol is None:
            continue
        port = first_port_in_range(parts, range_start, range_end)
        if port is None:
            continue
        process, pid = parse_process_info(line)
        entries.append({
            "protocol": protocol,
            "port": port,
            "purpose": "",
            "source": "scan",
            "detected_process": process,
            "detected_pid": pid,
            "detected_source": "socket",
        })
    return entries


def parse_netstat_output(output: str, range_start: int, range_end: int) -> list[dict[str, Any]]:
    """解析 netstat -lntup 输出中的端口、协议和进程信息。"""

    entries: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        protocol = protocol_from_token(parts[0])
        if protocol is None:
            continue
        port = port_from_address(parts[3])
        if port is None or not range_start <= port <= range_end:
            continue
        process = None
        pid = None
        if parts and "/" in parts[-1]:
            pid, process = parts[-1].split("/", 1)
        entries.append({
            "protocol": protocol,
            "port": port,
            "purpose": "",
            "source": "scan",
            "detected_process": process,
            "detected_pid": pid,
            "detected_source": "socket",
        })
    return entries


def scan_wireguard_ports(range_start: int, range_end: int, wireguard_dir: str) -> list[dict[str, Any]]:
    """从运行态、wg-quick 文件和 OpenWrt UCI 中扫描 WireGuard 监听端口。"""

    entries: list[dict[str, Any]] = []
    entries.extend(scan_wg_show_ports(range_start, range_end))
    entries.extend(scan_wg_quick_config_ports(range_start, range_end, wireguard_dir))
    entries.extend(scan_openwrt_uci_wireguard_ports(range_start, range_end))
    return entries


def scan_wg_show_ports(range_start: int, range_end: int) -> list[dict[str, Any]]:
    """通过 wg show all listen-port 扫描运行中的 WireGuard 监听端口。"""

    if not shutil.which("wg"):
        return []
    result = run_command(["wg", "show", "all", "listen-port"], allow_failure=True)
    if result["returncode"] != 0:
        return []
    entries: list[dict[str, Any]] = []
    for line in str(result.get("stdout") or "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            port = int(parts[1])
        except ValueError:
            continue
        if range_start <= port <= range_end:
            entries.append({
                "protocol": "UDP",
                "port": port,
                "purpose": "",
                "source": "scan",
                "detected_process": "wireguard",
                "detected_pid": None,
                "detected_source": f"wg:{parts[0]}",
            })
    return entries


def scan_wg_quick_config_ports(range_start: int, range_end: int, wireguard_dir: str) -> list[dict[str, Any]]:
    """从 wg-quick 配置文件 ListenPort 字段中扫描 WireGuard 端口。"""

    entries: list[dict[str, Any]] = []
    root = Path(wireguard_dir)
    if not root.exists():
        return entries
    for path in sorted(root.glob("*.conf")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        match = re.search(r"(?im)^\s*ListenPort\s*=\s*(\d+)\s*$", text)
        if not match:
            continue
        port = int(match.group(1))
        if range_start <= port <= range_end:
            entries.append({
                "protocol": "UDP",
                "port": port,
                "purpose": "",
                "source": "scan",
                "detected_process": "wireguard",
                "detected_pid": None,
                "detected_source": str(path),
            })
    return entries


def scan_openwrt_uci_wireguard_ports(range_start: int, range_end: int) -> list[dict[str, Any]]:
    """从 OpenWrt UCI network 配置中扫描 WireGuard listen_port。"""

    if not shutil.which("uci"):
        return []
    result = run_command(["uci", "show", "network"], allow_failure=True)
    if result["returncode"] != 0:
        return []
    entries: list[dict[str, Any]] = []
    section_types: dict[str, str] = {}
    section_proto: dict[str, str] = {}
    section_ports: dict[str, int] = {}
    for line in str(result.get("stdout") or "").splitlines():
        type_match = re.match(r"^network\.([^.]+)=interface$", line)
        if type_match:
            section_types[type_match.group(1)] = "interface"
            continue
        proto_match = re.match(r"^network\.([^.]+)\.proto='?([^']+)'?$", line)
        if proto_match:
            section_proto[proto_match.group(1)] = proto_match.group(2)
            continue
        port_match = re.match(r"^network\.([^.]+)\.listen_port='?(\d+)'?$", line)
        if port_match:
            section_ports[port_match.group(1)] = int(port_match.group(2))
    for section, port in section_ports.items():
        if section_types.get(section) == "interface" and section_proto.get(section) == "wireguard" and range_start <= port <= range_end:
            entries.append({
                "protocol": "UDP",
                "port": port,
                "purpose": "",
                "source": "scan",
                "detected_process": "wireguard",
                "detected_pid": None,
                "detected_source": f"uci:network.{section}.listen_port",
            })
    return entries


def protocol_from_token(token: str) -> str | None:
    """把 ss/netstat 协议列转换为 TCP 或 UDP。"""

    token = token.lower()
    if token.startswith("tcp"):
        return "TCP"
    if token.startswith("udp"):
        return "UDP"
    return None


def first_port_in_range(parts: list[str], range_start: int, range_end: int) -> int | None:
    """从命令输出分片中找出第一个落在指定范围内的端口。"""

    for part in parts:
        port = port_from_address(part)
        if port is not None and range_start <= port <= range_end:
            return port
    return None


def port_from_address(value: str) -> int | None:
    """从 address:port 或 [IPv6]:port 字符串末尾解析端口。"""

    value = value.strip().strip(",")
    if ":" not in value:
        return None
    candidate = value.rsplit(":", 1)[-1]
    if not candidate.isdigit():
        return None
    return int(candidate)


def parse_process_info(line: str) -> tuple[str | None, str | None]:
    """从 ss 输出行中提取监听进程名和 pid。"""

    process_match = re.search(r'users:\(\("([^"]+)"', line)
    pid_match = re.search(r"pid=(\d+)", line)
    return (
        process_match.group(1) if process_match else None,
        pid_match.group(1) if pid_match else None,
    )
