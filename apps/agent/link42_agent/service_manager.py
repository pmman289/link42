from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable

from link42_wireguard import parse_wg_quick


CommandRunner = Callable[[list[str], bool], dict[str, Any]]

SYSTEMD_ENABLED_STATES = {"enabled", "enabled-runtime", "linked", "linked-runtime", "alias"}
OPENRC_RUNLEVEL = "default"
OPENWRT_WIREGUARD_PROTO = "/lib/netifd/proto/wireguard.sh"


class ServiceManager(ABC):
    """Manage wg-quick lifecycle through the host init system."""

    name: str

    @abstractmethod
    def state(self, interface_name: str) -> dict[str, Any]:
        """Return a stable service state payload for task results."""

    @abstractmethod
    def enable(self, interface_name: str) -> dict[str, Any]:
        """Enable wg-quick at boot."""

    @abstractmethod
    def restart(self, interface_name: str) -> dict[str, Any]:
        """Restart or recreate the interface."""

    @abstractmethod
    def start(self, interface_name: str) -> dict[str, Any]:
        """Start the interface."""

    @abstractmethod
    def stop(self, interface_name: str) -> dict[str, Any]:
        """Stop the interface."""


class SystemdServiceManager(ServiceManager):
    name = "systemd"

    def __init__(self, run_command: CommandRunner):
        self.run_command = run_command

    def unit(self, interface_name: str) -> str:
        return f"wg-quick@{interface_name}.service"

    def state(self, interface_name: str) -> dict[str, Any]:
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
        return self.run_command(["systemctl", "enable", self.unit(interface_name)], False)

    def restart(self, interface_name: str) -> dict[str, Any]:
        return self.run_command(["systemctl", "restart", self.unit(interface_name)], False)

    def start(self, interface_name: str) -> dict[str, Any]:
        return self.run_command(["systemctl", "start", self.unit(interface_name)], False)

    def stop(self, interface_name: str) -> dict[str, Any]:
        return self.run_command(["systemctl", "stop", self.unit(interface_name)], False)


class OpenRCServiceManager(ServiceManager):
    name = "openrc"

    def __init__(self, run_command: CommandRunner):
        self.run_command = run_command

    def unit_candidates(self, interface_name: str) -> list[str]:
        return [f"wg-quick@{interface_name}", f"wg-quick.{interface_name}", "wg-quick"]

    def unit(self, interface_name: str) -> str:
        for candidate in self.unit_candidates(interface_name):
            result = self.run_command(["rc-service", "--exists", candidate], True)
            if result["returncode"] == 0:
                return candidate
        return self.unit_candidates(interface_name)[0]

    def state(self, interface_name: str) -> dict[str, Any]:
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
        return self.run_command(["rc-update", "add", self.unit(interface_name), OPENRC_RUNLEVEL], False)

    def restart(self, interface_name: str) -> dict[str, Any]:
        return self.run_command(["rc-service", self.unit(interface_name), "restart"], False)

    def start(self, interface_name: str) -> dict[str, Any]:
        return self.run_command(["rc-service", self.unit(interface_name), "start"], False)

    def stop(self, interface_name: str) -> dict[str, Any]:
        return self.run_command(["rc-service", self.unit(interface_name), "stop"], False)


class DirectWgQuickManager(ServiceManager):
    name = "direct"

    def __init__(self, run_command: CommandRunner):
        self.run_command = run_command

    def state(self, interface_name: str) -> dict[str, Any]:
        return {
            "manager": self.name,
            "unit": None,
            "managed": False,
            "active_state": "unknown",
            "enabled_state": "unsupported",
        }

    def enable(self, interface_name: str) -> dict[str, Any]:
        return {
            "command": [],
            "returncode": 1,
            "stdout": "",
            "stderr": "boot enable is unsupported without an init service manager",
        }

    def restart(self, interface_name: str) -> dict[str, Any]:
        return {
            "down": self.run_command(["wg-quick", "down", interface_name], True),
            "up": self.run_command(["wg-quick", "up", interface_name], False),
        }

    def start(self, interface_name: str) -> dict[str, Any]:
        return self.run_command(["wg-quick", "up", interface_name], False)

    def stop(self, interface_name: str) -> dict[str, Any]:
        return self.run_command(["wg-quick", "down", interface_name], True)


class OpenWrtUciManager(ServiceManager):
    name = "openwrt-uci"

    def __init__(self, run_command: CommandRunner):
        self.run_command = run_command

    def state(self, interface_name: str) -> dict[str, Any]:
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
        return {
            "command": [],
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "message": "OpenWrt network interfaces are enabled through committed UCI network config",
        }

    def restart(self, interface_name: str) -> dict[str, Any]:
        return {
            "down": self.run_command(["ifdown", interface_name], True),
            "up": self.run_command(["ifup", interface_name], False),
        }

    def start(self, interface_name: str) -> dict[str, Any]:
        return self.run_command(["ifup", interface_name], False)

    def stop(self, interface_name: str) -> dict[str, Any]:
        return self.run_command(["ifdown", interface_name], True)

    def apply_config(self, interface_name: str, config_text: str, enable_on_boot: bool = False) -> dict[str, Any]:
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
        commands = self._delete_existing_config(interface_name)
        commands.append(self.run_command(["uci", "commit", "network"], False))
        return {"changed": True, "manager": self.name, "commands": commands}

    def _delete_existing_config(self, interface_name: str) -> list[dict[str, Any]]:
        commands: list[dict[str, Any]] = []
        show_result = self.run_command(["uci", "-q", "show", "network"], True)
        for section in _wireguard_peer_sections(show_result["stdout"], interface_name):
            commands.append(self.run_command(["uci", "-q", "delete", f"network.{section}"], True))
        commands.append(self.run_command(["uci", "-q", "delete", f"network.{interface_name}"], True))
        return commands


class UnsupportedServiceManager(ServiceManager):
    name = "unsupported"

    def state(self, interface_name: str) -> dict[str, Any]:
        return {
            "manager": self.name,
            "unit": None,
            "managed": False,
            "active_state": "unknown",
            "enabled_state": "unsupported",
            "message": "no supported wg-quick, systemd, OpenRC, or OpenWrt UCI backend was detected",
        }

    def enable(self, interface_name: str) -> dict[str, Any]:
        raise RuntimeError("boot enable is unsupported on this host")

    def restart(self, interface_name: str) -> dict[str, Any]:
        raise RuntimeError("WireGuard service management is unsupported on this host")

    def start(self, interface_name: str) -> dict[str, Any]:
        raise RuntimeError("WireGuard service management is unsupported on this host")

    def stop(self, interface_name: str) -> dict[str, Any]:
        raise RuntimeError("WireGuard service management is unsupported on this host")


def _split_endpoint(endpoint: str | None) -> tuple[str | None, int | None]:
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
    """Select the best available service manager for wg-quick."""

    if shutil.which("systemctl"):
        return SystemdServiceManager(run_command)
    if shutil.which("rc-service") and shutil.which("rc-update"):
        return OpenRCServiceManager(run_command)
    if shutil.which("uci") and shutil.which("ifup") and Path(OPENWRT_WIREGUARD_PROTO).exists():
        return OpenWrtUciManager(run_command)
    if shutil.which("wg-quick"):
        return DirectWgQuickManager(run_command)
    return UnsupportedServiceManager()
