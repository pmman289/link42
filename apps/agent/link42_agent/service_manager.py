from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Optional, Tuple

from link42_wireguard import parse_wg_quick


CommandRunner = Callable[[list[str], bool], dict[str, Any]]

SYSTEMD_ENABLED_STATES = {"enabled", "enabled-runtime", "linked", "linked-runtime", "alias"}
OPENRC_RUNLEVEL = "default"
OPENRC_INIT_DIR = Path("/etc/init.d")
OPENWRT_WIREGUARD_PROTO = "/lib/netifd/proto/wireguard.sh"


class ServiceManager(ABC):
    """通过宿主机 init 系统管理 wg-quick 生命周期的抽象接口。"""

    name: str

    @abstractmethod
    def state(self, interface_name: str) -> dict[str, Any]:
        """返回适合写入任务结果的稳定服务状态结构。"""

    @abstractmethod
    def enable(self, interface_name: str) -> dict[str, Any]:
        """设置指定 wg-quick 接口开机自启。"""

    @abstractmethod
    def restart(self, interface_name: str) -> dict[str, Any]:
        """重启或重新创建指定 WireGuard 接口。"""

    @abstractmethod
    def start(self, interface_name: str) -> dict[str, Any]:
        """启动指定 WireGuard 接口。"""

    @abstractmethod
    def stop(self, interface_name: str) -> dict[str, Any]:
        """停止指定 WireGuard 接口。"""


class SystemdServiceManager(ServiceManager):
    """使用 systemd 管理 wg-quick@.service 的后端。"""

    name = "systemd"

    def __init__(self, run_command: CommandRunner):
        """保存命令执行器，便于测试中替换系统命令。"""

        self.run_command = run_command

    def unit(self, interface_name: str) -> str:
        """根据接口名生成 systemd unit 名称。"""

        return f"wg-quick@{interface_name}.service"

    def state(self, interface_name: str) -> dict[str, Any]:
        """读取 systemd active/enabled 状态并归一化为任务结果。"""

        unit = self.unit(interface_name)
        active_result = self.run_command(["systemctl", "is-active", unit], True)
        enabled_result = self.run_command(["systemctl", "is-enabled", unit], True)
        active_state = active_result["stdout"].strip()
        enabled_state = enabled_result["stdout"].strip()
        managed = active_state == "active" or enabled_state in SYSTEMD_ENABLED_STATES
        return {
            "manager": self.name,
            "unit": unit,
            "managed": managed,
            "active_state": active_state or "unknown",
            "enabled_state": enabled_state or "unknown",
            "active": active_result,
            "enabled": enabled_result,
        }

    def enable(self, interface_name: str) -> dict[str, Any]:
        """通过 systemctl enable 设置接口开机自启。"""

        return self.run_command(["systemctl", "enable", self.unit(interface_name)], False)

    def restart(self, interface_name: str) -> dict[str, Any]:
        """通过 systemctl restart 重启接口服务。"""

        return self.run_command(["systemctl", "restart", self.unit(interface_name)], False)

    def start(self, interface_name: str) -> dict[str, Any]:
        """通过 systemctl start 启动接口服务。"""

        return self.run_command(["systemctl", "start", self.unit(interface_name)], False)

    def stop(self, interface_name: str) -> dict[str, Any]:
        """通过 systemctl stop 停止接口服务。"""

        return self.run_command(["systemctl", "stop", self.unit(interface_name)], False)


class OpenRCServiceManager(ServiceManager):
    """使用 OpenRC 管理 wg-quick 或 Link42 兼容 init 脚本的后端。"""

    name = "openrc"

    def __init__(self, run_command: CommandRunner):
        """保存命令执行器，便于测试中替换系统命令。"""

        self.run_command = run_command

    def unit_candidates(self, interface_name: str) -> list[str]:
        """返回 OpenRC 上可能存在的 wg-quick 服务名候选。"""

        return [f"wg-quick@{interface_name}", f"wg-quick.{interface_name}", f"link42-wg-quick.{interface_name}"]

    def unit(self, interface_name: str) -> str:
        """选择当前系统上最合适的 OpenRC 服务名。"""

        for candidate in self.unit_candidates(interface_name):
            result = self.run_command(["rc-service", "--exists", candidate], True)
            if result["returncode"] == 0:
                return candidate
        if (OPENRC_INIT_DIR / "wg-quick").exists():
            return f"wg-quick.{interface_name}"
        return f"link42-wg-quick.{interface_name}"

    def ensure_link42_unit(self, interface_name: str) -> str:
        """确保 OpenRC 上存在可操作的 Link42 兼容服务脚本。"""

        unit = self.unit(interface_name)
        if unit.startswith("wg-quick."):
            path = OPENRC_INIT_DIR / unit
            if not path.exists():
                path.symlink_to(OPENRC_INIT_DIR / "wg-quick")
            return unit
        if not unit.startswith("link42-wg-quick."):
            return unit
        path = OPENRC_INIT_DIR / unit
        if not path.exists():
            path.write_text(
                f"""#!/sbin/openrc-run
name="Link42 WireGuard {interface_name}"
description="Link42 managed WireGuard interface {interface_name}"

depend() {{
  need net
  after firewall
}}

start() {{
  ebegin "Starting WireGuard {interface_name}"
  wg-quick up {interface_name}
  eend $?
}}

stop() {{
  ebegin "Stopping WireGuard {interface_name}"
  wg-quick down {interface_name}
  eend $?
}}

status() {{
  wg show {interface_name} >/dev/null 2>&1
}}
""",
                encoding="utf-8",
            )
            path.chmod(0o755)
        return unit

    def state(self, interface_name: str) -> dict[str, Any]:
        """读取 OpenRC 服务运行和开机自启状态。"""

        unit = self.unit(interface_name)
        active_result = self.run_command(["rc-service", unit, "status"], True)
        enabled_result = self.run_command(["rc-update", "show", OPENRC_RUNLEVEL], True)
        active_state = "active" if active_result["returncode"] == 0 else "inactive"
        enabled = unit in enabled_result["stdout"]
        enabled_state = "enabled" if enabled else "disabled"
        return {
            "manager": self.name,
            "unit": unit,
            "managed": active_state == "active" or enabled,
            "active_state": active_state,
            "enabled_state": enabled_state,
            "active": active_result,
            "enabled": enabled_result,
        }

    def enable(self, interface_name: str) -> dict[str, Any]:
        """把接口服务加入 OpenRC 默认 runlevel。"""

        return self.run_command(["rc-update", "add", self.ensure_link42_unit(interface_name), OPENRC_RUNLEVEL], False)

    def restart(self, interface_name: str) -> dict[str, Any]:
        """通过 rc-service restart 重启接口服务。"""

        return self.run_command(["rc-service", self.ensure_link42_unit(interface_name), "restart"], False)

    def start(self, interface_name: str) -> dict[str, Any]:
        """通过 rc-service start 启动接口服务。"""

        return self.run_command(["rc-service", self.ensure_link42_unit(interface_name), "start"], False)

    def stop(self, interface_name: str) -> dict[str, Any]:
        """通过 rc-service stop 停止接口服务。"""

        return self.run_command(["rc-service", self.unit(interface_name), "stop"], False)


class DirectWgQuickManager(ServiceManager):
    """没有可用 init 系统时直接调用 wg-quick 的兜底后端。"""

    name = "direct"

    def __init__(self, run_command: CommandRunner):
        """保存命令执行器，便于测试中替换系统命令。"""

        self.run_command = run_command

    def state(self, interface_name: str) -> dict[str, Any]:
        """返回 direct 模式下无法持久管理服务的状态。"""

        return {
            "manager": self.name,
            "unit": None,
            "managed": False,
            "active_state": "unknown",
            "enabled_state": "unsupported",
        }

    def enable(self, interface_name: str) -> dict[str, Any]:
        """direct 模式不支持开机自启，返回失败结构给调用方。"""

        return {
            "command": [],
            "returncode": 1,
            "stdout": "",
            "stderr": "boot enable is unsupported without an init service manager",
        }

    def restart(self, interface_name: str) -> dict[str, Any]:
        """直接执行 wg-quick down/up 重建接口。"""

        return {
            "down": self.run_command(["wg-quick", "down", interface_name], True),
            "up": self.run_command(["wg-quick", "up", interface_name], False),
        }

    def start(self, interface_name: str) -> dict[str, Any]:
        """直接执行 wg-quick up 启动接口。"""

        return self.run_command(["wg-quick", "up", interface_name], False)

    def stop(self, interface_name: str) -> dict[str, Any]:
        """直接执行 wg-quick down 停止接口。"""

        return self.run_command(["wg-quick", "down", interface_name], True)


class OpenWrtUciManager(ServiceManager):
    """使用 OpenWrt UCI/network 管理 WireGuard 接口的后端。"""

    name = "openwrt-uci"

    def __init__(self, run_command: CommandRunner):
        """保存命令执行器，便于测试中替换 uci/ifup 命令。"""

        self.run_command = run_command

    def state(self, interface_name: str) -> dict[str, Any]:
        """读取 OpenWrt 上接口运行状态和 UCI 配置状态。"""

        active_result = self.run_command(["wg", "show", interface_name], True)
        config_result = self.run_command(["uci", "-q", "show", f"network.{interface_name}.proto"], True)
        managed = config_result["returncode"] == 0 and "wireguard" in config_result["stdout"]
        return {
            "manager": self.name,
            "unit": f"network.{interface_name}",
            "managed": managed,
            "active_state": "active" if active_result["returncode"] == 0 else "inactive",
            "enabled_state": "enabled" if managed else "disabled",
            "active": active_result,
            "enabled": config_result,
        }

    def enable(self, interface_name: str) -> dict[str, Any]:
        """OpenWrt 接口由已提交 UCI 配置实现自启。"""

        return {
            "command": [],
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "message": "OpenWrt network interfaces are enabled through committed UCI network config",
        }

    def restart(self, interface_name: str) -> dict[str, Any]:
        """通过 ifdown/ifup 重启 OpenWrt 网络接口。"""

        return {
            "down": self.run_command(["ifdown", interface_name], True),
            "up": self.run_command(["ifup", interface_name], False),
        }

    def start(self, interface_name: str) -> dict[str, Any]:
        """通过 ifup 启动 OpenWrt 网络接口。"""

        return self.run_command(["ifup", interface_name], False)

    def stop(self, interface_name: str) -> dict[str, Any]:
        """通过 ifdown 停止 OpenWrt 网络接口。"""

        return self.run_command(["ifdown", interface_name], True)

    def apply_config(self, interface_name: str, config_text: str, enable_on_boot: bool = False) -> dict[str, Any]:
        """把 wg-quick 配置转换为 OpenWrt UCI network 配置并重启接口。"""

        parsed = parse_wg_quick(config_text, name=interface_name)
        if not parsed.private_key:
            raise ValueError("OpenWrt UCI deployment requires Interface.PrivateKey")

        commands: list[dict[str, Any]] = []
        commands.extend(self._delete_existing_config(interface_name))
        commands.append(self.run_command(["uci", "set", f"network.{interface_name}=interface"], False))
        commands.append(self.run_command(["uci", "set", f"network.{interface_name}.proto=wireguard"], False))
        commands.append(self.run_command(["uci", "set", f"network.{interface_name}.private_key={parsed.private_key}"], False))
        for address in parsed.addresses:
            commands.append(self.run_command(["uci", "add_list", f"network.{interface_name}.addresses={address}"], False))
        if parsed.listen_port is not None:
            commands.append(self.run_command(["uci", "set", f"network.{interface_name}.listen_port={parsed.listen_port}"], False))
        if parsed.mtu is not None:
            commands.append(self.run_command(["uci", "set", f"network.{interface_name}.mtu={parsed.mtu}"], False))
        if parsed.fwmark:
            commands.append(self.run_command(["uci", "set", f"network.{interface_name}.fwmark={parsed.fwmark}"], False))

        route_allowed_ips = "0" if (parsed.table or "").lower() == "off" else "1"
        for peer in parsed.peers:
            if not peer.public_key:
                raise ValueError("OpenWrt UCI deployment requires every Peer.PublicKey")
            add_result = self.run_command(["uci", "add", "network", f"wireguard_{interface_name}"], False)
            commands.append(add_result)
            section = add_result["stdout"].strip() or f"@wireguard_{interface_name}[-1]"
            commands.append(self.run_command(["uci", "set", f"network.{section}.public_key={peer.public_key}"], False))
            if peer.preshared_key:
                commands.append(self.run_command(["uci", "set", f"network.{section}.preshared_key={peer.preshared_key}"], False))
            for allowed_ip in peer.allowed_ips:
                commands.append(self.run_command(["uci", "add_list", f"network.{section}.allowed_ips={allowed_ip}"], False))
            commands.append(self.run_command(["uci", "set", f"network.{section}.route_allowed_ips={route_allowed_ips}"], False))
            endpoint_host, endpoint_port = _split_endpoint(peer.endpoint)
            if endpoint_host:
                commands.append(self.run_command(["uci", "set", f"network.{section}.endpoint_host={endpoint_host}"], False))
            if endpoint_port:
                commands.append(self.run_command(["uci", "set", f"network.{section}.endpoint_port={endpoint_port}"], False))
            if peer.persistent_keepalive is not None:
                commands.append(
                    self.run_command(["uci", "set", f"network.{section}.persistent_keepalive={peer.persistent_keepalive}"], False)
                )

        commands.append(self.run_command(["uci", "commit", "network"], False))
        restart_result = self.restart(interface_name)
        return {
            "changed": True,
            "manager": self.name,
            "config_backend": "uci",
            "enable_on_boot": enable_on_boot,
            "warnings": parsed.warnings + [warning for peer in parsed.peers for warning in peer.warnings],
            "commands": commands,
            "restart": restart_result,
        }

    def delete_config(self, interface_name: str) -> dict[str, Any]:
        """删除指定接口及其 peer 的 OpenWrt UCI 配置。"""

        commands = self._delete_existing_config(interface_name)
        commands.append(self.run_command(["uci", "commit", "network"], False))
        return {"changed": True, "manager": self.name, "commands": commands}

    def _delete_existing_config(self, interface_name: str) -> list[dict[str, Any]]:
        """删除接口和它关联的所有 wireguard peer section。"""

        commands: list[dict[str, Any]] = []
        show_result = self.run_command(["uci", "-q", "show", "network"], True)
        for section in _wireguard_peer_sections(show_result["stdout"], interface_name):
            commands.append(self.run_command(["uci", "-q", "delete", f"network.{section}"], True))
        commands.append(self.run_command(["uci", "-q", "delete", f"network.{interface_name}"], True))
        return commands


class UnsupportedServiceManager(ServiceManager):
    """系统缺少可用 WireGuard 管理工具时返回明确错误的后端。"""

    name = "unsupported"

    def state(self, interface_name: str) -> dict[str, Any]:
        """返回无法管理 WireGuard 的诊断状态。"""

        return {
            "manager": self.name,
            "unit": None,
            "managed": False,
            "active_state": "unknown",
            "enabled_state": "unsupported",
            "message": "no supported wg-quick, systemd, OpenRC, or OpenWrt UCI backend was detected",
        }

    def enable(self, interface_name: str) -> dict[str, Any]:
        """在不支持的系统上拒绝设置开机自启。"""

        raise RuntimeError("boot enable is unsupported on this host")

    def restart(self, interface_name: str) -> dict[str, Any]:
        """在不支持的系统上拒绝重启接口。"""

        raise RuntimeError("WireGuard service management is unsupported on this host")

    def start(self, interface_name: str) -> dict[str, Any]:
        """在不支持的系统上拒绝启动接口。"""

        raise RuntimeError("WireGuard service management is unsupported on this host")

    def stop(self, interface_name: str) -> dict[str, Any]:
        """在不支持的系统上拒绝停止接口。"""

        raise RuntimeError("WireGuard service management is unsupported on this host")


def _split_endpoint(endpoint: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    """拆分 OpenWrt UCI 需要的 endpoint host 和 port。"""

    if not endpoint:
        return None, None
    if endpoint.startswith("[") and "]:" in endpoint:
        host, port = endpoint[1:].rsplit("]:", 1)
    elif ":" in endpoint:
        host, port = endpoint.rsplit(":", 1)
    else:
        return endpoint, None
    try:
        return host, int(port)
    except ValueError:
        return host, None


def _wireguard_peer_sections(uci_show_output: str, interface_name: str) -> list[str]:
    """从 uci show network 输出中找出指定接口的 peer section。"""

    prefix = f"network.@wireguard_{interface_name}["
    sections: list[tuple[int, str]] = []
    for line in uci_show_output.splitlines():
        if not line.startswith(prefix) or "]=" not in line:
            continue
        index_text = line.removeprefix(prefix).split("]", 1)[0]
        try:
            index = int(index_text)
        except ValueError:
            continue
        sections.append((index, f"@wireguard_{interface_name}[{index}]"))
    return [section for _, section in sorted(sections, reverse=True)]


def detect_service_manager(run_command: CommandRunner) -> ServiceManager:
    """按系统环境选择最合适的 wg-quick 服务管理后端。"""

    if shutil.which("systemctl"):
        return SystemdServiceManager(run_command)
    if shutil.which("rc-service") and shutil.which("rc-update"):
        return OpenRCServiceManager(run_command)
    if shutil.which("uci") and shutil.which("ifup") and Path(OPENWRT_WIREGUARD_PROTO).exists():
        return OpenWrtUciManager(run_command)
    if shutil.which("wg-quick"):
        return DirectWgQuickManager(run_command)
    return UnsupportedServiceManager()
