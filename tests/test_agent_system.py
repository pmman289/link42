from __future__ import annotations

from pathlib import Path
from typing import Any

from link42_agent import main, service_manager, system, upgrade


def command_result(command: list[str], returncode: int = 0, stdout: str = "") -> dict[str, Any]:
    return {"command": command, "returncode": returncode, "stdout": stdout, "stderr": ""}


def use_service_binaries(
    monkeypatch,
    *,
    systemd: bool = True,
    openrc: bool = False,
    openwrt: bool = False,
    wg_quick: bool = True,
) -> None:
    """让 service manager 探测在测试里可控，不依赖宿主机 init 系统。"""

    def fake_which(binary: str) -> str | None:
        if binary == "systemctl" and systemd:
            return "/bin/systemctl"
        if binary in {"rc-service", "rc-update"} and openrc:
            return f"/sbin/{binary}"
        if binary in {"uci", "ifup", "ifdown"} and openwrt:
            return f"/sbin/{binary}"
        if binary == "wg-quick" and wg_quick:
            return "/usr/bin/wg-quick"
        return None

    monkeypatch.setattr(service_manager.shutil, "which", fake_which)


def test_apply_config_restarts_existing_systemd_service(tmp_path: Path, monkeypatch) -> None:
    """验证已有 systemd 管理的 wg-quick 接口下发时不会绕开 service。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        if command == ["systemctl", "is-active", "wg-quick@wg0.service"]:
            return command_result(command, stdout="active\n")
        if command == ["systemctl", "is-enabled", "wg-quick@wg0.service"]:
            return command_result(command, stdout="enabled\n")
        if command == ["systemctl", "restart", "wg-quick@wg0.service"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=True)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.apply_wireguard_config(
        {"interface_name": "wg0", "config": "[Interface]\nPrivateKey = private\n"},
        wireguard_dir=str(tmp_path),
    )

    assert result["service"]["managed"] is True
    assert ["systemctl", "restart", "wg-quick@wg0.service"] in commands
    assert not any(command[:1] == ["wg-quick"] for command in commands)
    assert (tmp_path / "wg0.conf").exists()


def test_apply_config_enables_existing_systemd_service_when_requested(tmp_path: Path, monkeypatch) -> None:
    """验证受管连接下发到已有 service 时会同时设置开机自启。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        if command == ["systemctl", "is-active", "wg-quick@wg0.service"]:
            return command_result(command, stdout="active\n")
        if command == ["systemctl", "is-enabled", "wg-quick@wg0.service"]:
            return command_result(command, stdout="disabled\n")
        if command == ["systemctl", "restart", "wg-quick@wg0.service"]:
            return command_result(command)
        if command == ["systemctl", "enable", "wg-quick@wg0.service"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=True)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.apply_wireguard_config(
        {"interface_name": "wg0", "config": "[Interface]\nPrivateKey = private\n", "enable_on_boot": True},
        wireguard_dir=str(tmp_path),
    )

    assert result["service"]["managed"] is True
    assert ["systemctl", "restart", "wg-quick@wg0.service"] in commands
    assert ["systemctl", "enable", "wg-quick@wg0.service"] in commands


def test_apply_config_falls_back_to_wg_quick_when_no_systemd_unit(tmp_path: Path, monkeypatch) -> None:
    """验证没有 systemd 接管的配置仍按直接 wg-quick 路径执行。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        if command[:2] == ["systemctl", "is-active"]:
            return command_result(command, returncode=3, stdout="inactive\n")
        if command[:2] == ["systemctl", "is-enabled"]:
            return command_result(command, returncode=1, stdout="disabled\n")
        if command[:2] == ["wg-quick", "down"]:
            return command_result(command, returncode=1)
        if command[:2] == ["wg-quick", "up"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=True)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.apply_wireguard_config(
        {"interface_name": "wg0", "config": "[Interface]\nPrivateKey = private\n"},
        wireguard_dir=str(tmp_path),
    )

    assert result["service"]["managed"] is False
    assert ["wg-quick", "down", "wg0"] in commands
    assert ["wg-quick", "up", "wg0"] in commands


def test_apply_config_uses_direct_wg_quick_without_init_manager(tmp_path: Path, monkeypatch) -> None:
    """验证无 systemd/OpenRC 环境下仍可直接通过 wg-quick 应用配置。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        if command[:2] == ["wg-quick", "down"]:
            return command_result(command, returncode=1)
        if command[:2] == ["wg-quick", "up"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=False, openrc=False)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.apply_wireguard_config(
        {"interface_name": "wg0", "config": "[Interface]\nPrivateKey = private\n"},
        wireguard_dir=str(tmp_path),
    )

    assert result["service"]["manager"] == "direct"
    assert result["service"]["managed"] is False
    assert ["wg-quick", "down", "wg0"] in commands
    assert ["wg-quick", "up", "wg0"] in commands


def test_apply_config_uses_systemd_enable_and_restart_when_requested(tmp_path: Path, monkeypatch) -> None:
    """验证新受管连接会通过 systemd 启动并启用开机自启。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        if command[:2] == ["systemctl", "is-active"]:
            return command_result(command, returncode=3, stdout="inactive\n")
        if command[:2] == ["systemctl", "is-enabled"]:
            return command_result(command, returncode=1, stdout="disabled\n")
        if command == ["systemctl", "enable", "wg-quick@wg0.service"]:
            return command_result(command)
        if command == ["systemctl", "restart", "wg-quick@wg0.service"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=True)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.apply_wireguard_config(
        {"interface_name": "wg0", "config": "[Interface]\nPrivateKey = private\n", "enable_on_boot": True},
        wireguard_dir=str(tmp_path),
    )

    assert result["service"]["managed"] is False
    assert ["systemctl", "enable", "wg-quick@wg0.service"] in commands
    assert ["systemctl", "restart", "wg-quick@wg0.service"] in commands
    assert not any(command[:1] == ["wg-quick"] for command in commands)


def test_stop_interface_uses_systemd_for_managed_service(monkeypatch) -> None:
    """验证停止已由 systemd 管理的接口时使用 systemctl stop。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        if command == ["wg", "show", "wg0"]:
            return command_result(command)
        if command == ["systemctl", "is-active", "wg-quick@wg0.service"]:
            return command_result(command, stdout="active\n")
        if command == ["systemctl", "is-enabled", "wg-quick@wg0.service"]:
            return command_result(command, stdout="enabled\n")
        if command == ["systemctl", "stop", "wg-quick@wg0.service"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=True)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.stop_wireguard_interface({"interface_name": "wg0"})

    assert result["service"]["managed"] is True
    assert ["systemctl", "stop", "wg-quick@wg0.service"] in commands
    assert ["wg-quick", "down", "wg0"] not in commands


def test_apply_config_uses_openrc_when_service_is_managed(tmp_path: Path, monkeypatch) -> None:
    """验证 OpenRC 已管理接口下发时通过 rc-service restart。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        if command == ["rc-service", "--exists", "wg-quick@wg0"]:
            return command_result(command)
        if command == ["rc-service", "wg-quick@wg0", "status"]:
            return command_result(command)
        if command == ["rc-update", "show", "default"]:
            return command_result(command, stdout="wg-quick@wg0 | default\n")
        if command == ["rc-service", "wg-quick@wg0", "restart"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=False, openrc=True)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.apply_wireguard_config(
        {"interface_name": "wg0", "config": "[Interface]\nPrivateKey = private\n"},
        wireguard_dir=str(tmp_path),
    )

    assert result["service"]["manager"] == "openrc"
    assert result["service"]["managed"] is True
    assert ["rc-service", "wg-quick@wg0", "restart"] in commands
    assert not any(command[:1] == ["systemctl"] for command in commands)


def test_apply_config_enables_openrc_service_when_requested(tmp_path: Path, monkeypatch) -> None:
    """验证 OpenRC 新受管连接会 rc-update add 并 restart。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        if command == ["rc-service", "--exists", "wg-quick@wg0"]:
            return command_result(command)
        if command == ["rc-service", "wg-quick@wg0", "status"]:
            return command_result(command, returncode=3, stdout="stopped\n")
        if command == ["rc-update", "show", "default"]:
            return command_result(command, stdout="")
        if command == ["rc-update", "add", "wg-quick@wg0", "default"]:
            return command_result(command)
        if command == ["rc-service", "wg-quick@wg0", "restart"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=False, openrc=True)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.apply_wireguard_config(
        {"interface_name": "wg0", "config": "[Interface]\nPrivateKey = private\n", "enable_on_boot": True},
        wireguard_dir=str(tmp_path),
    )

    assert result["service"]["manager"] == "openrc"
    assert result["service"]["managed"] is False
    assert ["rc-update", "add", "wg-quick@wg0", "default"] in commands
    assert ["rc-service", "wg-quick@wg0", "restart"] in commands


def test_stop_interface_uses_openrc_for_managed_service(monkeypatch) -> None:
    """验证 OpenRC 管理接口停止时使用 rc-service stop。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        if command == ["rc-service", "--exists", "wg-quick@wg0"]:
            return command_result(command)
        if command == ["wg", "show", "wg0"]:
            return command_result(command)
        if command == ["rc-service", "wg-quick@wg0", "status"]:
            return command_result(command)
        if command == ["rc-update", "show", "default"]:
            return command_result(command, stdout="wg-quick@wg0 | default\n")
        if command == ["rc-service", "wg-quick@wg0", "stop"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=False, openrc=True)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.stop_wireguard_interface({"interface_name": "wg0"})

    assert result["service"]["manager"] == "openrc"
    assert result["service"]["managed"] is True
    assert ["rc-service", "wg-quick@wg0", "stop"] in commands


def test_apply_config_uses_openwrt_uci_backend(tmp_path: Path, monkeypatch) -> None:
    """验证 OpenWrt 环境下配置会写入 UCI，而不是写 /etc/wireguard 或调用 wg-quick。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        if command == ["uci", "-q", "show", "network"]:
            return command_result(command, stdout="network.@wireguard_wg0[0]=wireguard_wg0\n")
        if command == ["uci", "add", "network", "wireguard_wg0"]:
            return command_result(command, stdout="cfg123\n")
        return command_result(command)

    use_service_binaries(monkeypatch, systemd=False, openrc=False, openwrt=True, wg_quick=False)
    monkeypatch.setattr(service_manager.Path, "exists", lambda self: str(self) == service_manager.OPENWRT_WIREGUARD_PROTO)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.apply_wireguard_config(
        {
            "interface_name": "wg0",
            "config": "\n".join(
                [
                    "[Interface]",
                    "PrivateKey = private",
                    "Address = 10.42.0.1/32, fd42::1/64",
                    "ListenPort = 51820",
                    "MTU = 1420",
                    "Table = off",
                    "",
                    "[Peer]",
                    "PublicKey = peer-public",
                    "AllowedIPs = 10.42.0.2/32, fd42::2/128",
                    "Endpoint = [fd00::1]:51821",
                    "PersistentKeepalive = 25",
                ]
            ),
            "enable_on_boot": True,
        },
        wireguard_dir=str(tmp_path),
    )

    assert result["manager"] == "openwrt-uci"
    assert not (tmp_path / "wg0.conf").exists()
    assert ["uci", "-q", "delete", "network.@wireguard_wg0[0]"] in commands
    assert ["uci", "-q", "delete", "network.wg0"] in commands
    assert ["uci", "set", "network.wg0.proto=wireguard"] in commands
    assert ["uci", "add_list", "network.wg0.addresses=10.42.0.1/32"] in commands
    assert ["uci", "add_list", "network.wg0.addresses=fd42::1/64"] in commands
    assert ["uci", "set", "network.cfg123.route_allowed_ips=0"] in commands
    assert ["uci", "set", "network.cfg123.endpoint_host=fd00::1"] in commands
    assert ["uci", "set", "network.cfg123.endpoint_port=51821"] in commands
    assert ["uci", "commit", "network"] in commands
    assert ["ifdown", "wg0"] in commands
    assert ["ifup", "wg0"] in commands
    assert not any(command[:1] == ["wg-quick"] for command in commands)


def test_openwrt_backend_is_reported_as_agent_capability(monkeypatch, tmp_path: Path) -> None:
    """验证 OpenWrt 节点会上报 UCI 后端能力。"""

    seen_capabilities: list[str] = []

    class FakeClient:
        def heartbeat(self) -> None:
            return None

        def poll_tasks(self, capabilities: list[str] | None = None) -> list[dict[str, Any]]:
            seen_capabilities.extend(capabilities or [])
            return []

    use_service_binaries(monkeypatch, systemd=False, openrc=False, openwrt=True, wg_quick=False)
    monkeypatch.setattr(service_manager.Path, "exists", lambda self: str(self) == service_manager.OPENWRT_WIREGUARD_PROTO)

    main.run_once(FakeClient(), str(tmp_path))

    assert "service:openwrt-uci" in seen_capabilities


def test_run_once_reports_service_manager_capability(monkeypatch, tmp_path: Path) -> None:
    """验证 Agent 拉任务时会上报当前 wg-quick 服务管理能力。"""

    seen_capabilities: list[str] = []

    class FakeClient:
        def heartbeat(self) -> None:
            return None

        def poll_tasks(self, capabilities: list[str] | None = None) -> list[dict[str, Any]]:
            seen_capabilities.extend(capabilities or [])
            return []

    use_service_binaries(monkeypatch, systemd=False, openrc=True)
    monkeypatch.setattr(system, "run_command", lambda command, allow_failure: command_result(command))

    main.run_once(FakeClient(), str(tmp_path))

    assert "wireguard" in seen_capabilities
    assert "wg_quick_import" in seen_capabilities
    assert "service:openrc" in seen_capabilities
    assert "agent.self_upgrade" in seen_capabilities


def test_self_upgrade_rejects_foreign_download_url() -> None:
    """验证 Agent 自升级只能从当前主控下载资产。"""

    config = type("Config", (), {"server_url": "http://controller:8000", "token": "token"})()

    try:
        upgrade.self_upgrade(
            {
                "download_url": "https://evil.example/agent",
                "target_version": "0.2.1",
                "sha256": "abc123",
            },
            config,
            dry_run=True,
        )
    except ValueError as exc:
        assert "configured controller" in str(exc)
    else:
        raise AssertionError("foreign download url was accepted")


def test_self_upgrade_dry_run_stages_when_systemd(monkeypatch) -> None:
    """验证 dry-run 下自升级任务会走到 staged，不写真实二进制。"""

    config = type("Config", (), {"server_url": "http://controller:8000", "token": "token"})()
    monkeypatch.setattr(upgrade, "get_service_manager_name", lambda: "systemd")

    result = upgrade.self_upgrade(
        {
            "download_url": "http://controller:8000/api/agent/releases/0.2.1/download?platform=linux-x64",
            "target_version": "0.2.1",
            "sha256": "abc123",
        },
        config,
        dry_run=True,
    )

    assert result == {"status": "staged", "dry_run": True, "target_version": "0.2.1"}
