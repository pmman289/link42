from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Any

from link42_common.connection_types import WIREGUARD_TASKS
from link42_agent import main, middleware, service_manager, system, upgrade
from link42_agent.task_handlers import TASK_HANDLERS


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


def test_run_command_passes_timeout_to_subprocess(monkeypatch) -> None:
    """验证 Agent 执行系统命令时会设置超时。"""

    seen: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any):
        seen["command"] = command
        seen["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

    monkeypatch.setenv("LINK42_COMMAND_TIMEOUT", "7")
    monkeypatch.setattr(system.subprocess, "run", fake_run)

    result = system.run_command(["systemctl", "status", "link42-agent"], allow_failure=False)

    assert result["stdout"] == "ok\n"
    assert seen == {"command": ["systemctl", "status", "link42-agent"], "timeout": 7.0}


def test_run_command_timeout_returns_result_or_raises(monkeypatch) -> None:
    """验证命令超时不会卡死任务，允许失败时返回结果，不允许失败时抛错。"""

    def fake_run(command: list[str], **kwargs: Any):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output="partial")

    monkeypatch.setenv("LINK42_COMMAND_TIMEOUT", "3")
    monkeypatch.setattr(system.subprocess, "run", fake_run)

    result = system.run_command(["systemctl", "restart", "wg-quick@wg0.service"], allow_failure=True)

    assert result["returncode"] == 124
    assert result["timeout"] == 3.0
    assert "timed out" in result["stderr"]
    try:
        system.run_command(["systemctl", "restart", "wg-quick@wg0.service"], allow_failure=False)
    except RuntimeError as exc:
        assert "timed out" in str(exc)
    else:
        raise AssertionError("timeout did not raise for required command")


def test_agent_task_registry_keeps_wireguard_handlers() -> None:
    """验证 Agent 标准连接任务通过注册表分发，方便后续扩展非 WireGuard 后端。"""

    for task_type in [
        WIREGUARD_TASKS.import_scan,
        WIREGUARD_TASKS.apply_config,
        WIREGUARD_TASKS.read_config,
        WIREGUARD_TASKS.status,
        WIREGUARD_TASKS.start,
        WIREGUARD_TASKS.stop,
        WIREGUARD_TASKS.delete_config,
    ]:
        assert task_type in TASK_HANDLERS


def test_udp2raw_remove_last_instance_deletes_config_file(tmp_path: Path) -> None:
    """验证删除 udp2raw 最后一个实例时移除配置文件，而不是留下 0 字节文件。"""

    config_file = tmp_path / "client"
    config_file.write_text("link42-1 -c -l127.0.0.1:12312\n", encoding="utf-8")

    middleware.remove_instance(config_file, "link42-1")

    assert not config_file.exists()


def test_udp2raw_delete_uses_payload_mode_only(tmp_path: Path, monkeypatch) -> None:
    """验证 udp2raw delete 只操作本节点实际角色对应的 unit。"""

    commands: list[list[str]] = []
    monkeypatch.setattr(middleware, "UDP2RAW_CONFIG_DIR", tmp_path)
    (tmp_path / "client").write_text("link42-1 -c -l127.0.0.1:12312\n", encoding="utf-8")

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        return command_result(command)

    monkeypatch.setattr(middleware, "run_command", fake_run_command)

    result = middleware.delete_udp2raw({"instance": "link42-1", "mode": "client"})

    assert result["modes"] == ["client"]
    assert ["systemctl", "disable", "--now", "link42-udp2raw-client@link42-1.service"] in commands
    assert not any("link42-udp2raw-server@link42-1.service" in command for command in commands)
    assert not (tmp_path / "client").exists()


def test_udp2raw_stop_uses_payload_mode_only(monkeypatch) -> None:
    """验证 udp2raw stop 不再同时尝试 server/client 两种 unit。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        return command_result(command)

    monkeypatch.setattr(middleware, "run_command", fake_run_command)

    result = middleware.stop_udp2raw({"instance": "link42-1", "mode": "server"})

    assert result["modes"] == ["server"]
    assert commands == [["systemctl", "stop", "link42-udp2raw-server@link42-1.service"]]


def test_udp2raw_apply_uses_openwrt_procd(tmp_path: Path, monkeypatch) -> None:
    """验证 OpenWrt 节点会为 udp2raw 实例生成 procd init 脚本并重启对应实例。"""

    commands: list[list[str]] = []
    config_dir = tmp_path / "udp2raw"
    init_dir = tmp_path / "init.d"
    binary = tmp_path / "udp2raw-bin"
    monkeypatch.setattr(middleware, "UDP2RAW_CONFIG_DIR", config_dir)
    monkeypatch.setattr(middleware, "OPENWRT_INIT_DIR", init_dir)
    monkeypatch.setattr(middleware, "UDP2RAW_BIN", binary)
    monkeypatch.setattr(middleware, "udp2raw_service_backend", lambda: "openwrt-procd")

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        return command_result(command)

    monkeypatch.setattr(middleware, "run_command", fake_run_command)

    result = middleware.apply_udp2raw(
        {
            "instance": "link42-1-2",
            "mode": "server",
            "listen_host": "0.0.0.0",
            "listen_port": 23002,
            "remote_host": "127.0.0.1",
            "remote_port": 51820,
            "password": "secret",
        }
    )
    init_script = init_dir / "link42-udp2raw-server-link42-1-2"

    assert result["changed"] is True
    server_config = (config_dir / "server").read_text(encoding="utf-8")
    assert server_config.startswith("link42-1-2 -s -l0.0.0.0:23002")
    assert "-a" in server_config
    assert "--keep-rule" not in server_config
    assert init_script.exists()
    init_content = init_script.read_text(encoding="utf-8")
    assert "USE_PROCD=1" in init_content
    assert "status_service()" in init_content
    assert commands == [
        [str(init_script), "enable"],
        [str(init_script), "restart"],
    ]


def test_udp2raw_openwrt_result_drops_successful_rc_common_noise() -> None:
    """验证 OpenWrt rc.common 成功路径中的固定 stderr 噪音会被清掉。"""

    for stderr in ["Command failed: Not found.\n", "Command failed: Not found\n"]:
        result = middleware.normalize_openwrt_result(
            {
                "command": ["/etc/init.d/link42-udp2raw-server-link42-1", "restart"],
                "returncode": 0,
                "stdout": "",
                "stderr": stderr,
            }
        )

        assert result["stderr"] == ""


def test_udp2raw_install_uses_openwrt_backend_without_systemd_units(tmp_path: Path, monkeypatch) -> None:
    """验证 OpenWrt 安装 udp2raw 只安装二进制和目录，不写入 systemd 单元。"""

    commands: list[list[str]] = []
    config_dir = tmp_path / "udp2raw"
    init_dir = tmp_path / "init.d"
    binary = tmp_path / "bin" / "udp2raw"
    libexec = tmp_path / "libexec" / "link42-udp2raw-systemd"
    server_unit = tmp_path / "systemd" / "link42-udp2raw-server@.service"
    client_unit = tmp_path / "systemd" / "link42-udp2raw-client@.service"
    monkeypatch.setattr(middleware, "UDP2RAW_CONFIG_DIR", config_dir)
    monkeypatch.setattr(middleware, "OPENWRT_INIT_DIR", init_dir)
    monkeypatch.setattr(middleware, "UDP2RAW_BIN", binary)
    monkeypatch.setattr(middleware, "UDP2RAW_LIBEXEC", libexec)
    monkeypatch.setattr(middleware, "UDP2RAW_SERVER_UNIT", server_unit)
    monkeypatch.setattr(middleware, "UDP2RAW_CLIENT_UNIT", client_unit)
    monkeypatch.setattr(middleware, "udp2raw_service_backend", lambda: "openwrt-procd")
    monkeypatch.setattr(middleware, "detect_udp2raw_asset", lambda: "udp2raw_arm")

    def fake_download(config: Any, asset: str, target: Path) -> None:
        target.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        return command_result(command)

    monkeypatch.setattr(middleware, "download_asset", fake_download)
    monkeypatch.setattr(middleware, "run_command", fake_run_command)

    result = middleware.install_udp2raw(middleware.AgentConfig(server_url="http://controller", node_id=1, token="t"))

    assert result["changed"] is True
    assert result["backend"] == "openwrt-procd"
    assert result["asset"] == "udp2raw_arm"
    assert binary.exists()
    assert init_dir.exists()
    assert not libexec.exists()
    assert not server_unit.exists()
    assert not client_unit.exists()
    assert commands == []


def test_udp2raw_delete_uses_openwrt_role_init(tmp_path: Path, monkeypatch) -> None:
    """验证 OpenWrt 删除 udp2raw 只停止并移除本节点实际角色的 init 脚本和配置。"""

    commands: list[list[str]] = []
    config_dir = tmp_path / "udp2raw"
    init_dir = tmp_path / "init.d"
    config_dir.mkdir()
    init_dir.mkdir()
    (config_dir / "client").write_text(
        "link42-1-2 -c -l127.0.0.1:12312 -r198.51.100.20:23002 --raw-mode faketcp -a\n",
        encoding="utf-8",
    )
    init_script = init_dir / "link42-udp2raw-client-link42-1-2"
    init_script.write_text("#!/bin/sh /etc/rc.common\n", encoding="utf-8")
    monkeypatch.setattr(middleware, "UDP2RAW_CONFIG_DIR", config_dir)
    monkeypatch.setattr(middleware, "OPENWRT_INIT_DIR", init_dir)
    monkeypatch.setattr(middleware, "udp2raw_service_backend", lambda: "openwrt-procd")

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        return command_result(command)

    monkeypatch.setattr(middleware, "run_command", fake_run_command)

    result = middleware.delete_udp2raw({"instance": "link42-1-2", "mode": "client"})

    assert result["modes"] == ["client"]
    assert commands == [
        [str(init_script), "stop"],
        [str(init_script), "disable"],
    ]
    assert not init_script.exists()
    assert not (config_dir / "client").exists()


def test_udp2raw_openwrt_does_not_insert_direct_iptables_drop(tmp_path: Path, monkeypatch) -> None:
    """验证 OpenWrt procd 后端不插入会吞掉 faketcp SYN 的 direct DROP 规则。"""

    commands: list[list[str]] = []
    config_dir = tmp_path / "udp2raw"
    init_dir = tmp_path / "init.d"
    monkeypatch.setattr(middleware, "UDP2RAW_CONFIG_DIR", config_dir)
    monkeypatch.setattr(middleware, "OPENWRT_INIT_DIR", init_dir)
    monkeypatch.setattr(middleware, "udp2raw_service_backend", lambda: "openwrt-procd")

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        commands.append(command)
        return command_result(command)

    monkeypatch.setattr(middleware, "run_command", fake_run_command)

    middleware.apply_udp2raw(
        {
            "instance": "link42-udp",
            "mode": "server",
            "listen_host": "0.0.0.0",
            "listen_port": 23002,
            "remote_host": "127.0.0.1",
            "remote_port": 51820,
            "password": "secret",
            "raw_mode": "udp",
        }
    )

    assert not any(command and command[0] in {"iptables", "ip6tables"} for command in commands)


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


def test_apply_config_keeps_only_one_wireguard_backup(tmp_path: Path, monkeypatch) -> None:
    """验证同一接口重复下发时只保留一个 Link42 备份文件。"""

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
    target = tmp_path / "wg0.conf"
    target.write_text("old-config\n", encoding="utf-8")
    (tmp_path / "wg0.conf.link42-backup-20260101010101").write_text("older\n", encoding="utf-8")

    first = system.apply_wireguard_config(
        {"interface_name": "wg0", "config": "first-config\n"},
        wireguard_dir=str(tmp_path),
    )
    second = system.apply_wireguard_config(
        {"interface_name": "wg0", "config": "second-config\n"},
        wireguard_dir=str(tmp_path),
    )

    backups = sorted(tmp_path.glob("wg0.conf.link42-backup*"))
    assert [path.name for path in backups] == ["wg0.conf.link42-backup"]
    assert backups[0].read_text(encoding="utf-8") == "first-config\n"
    assert first["backup_path"] == str(tmp_path / "wg0.conf.link42-backup")
    assert second["backup_path"] == str(tmp_path / "wg0.conf.link42-backup")
    assert target.read_text(encoding="utf-8") == "second-config\n"


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
    assert "wireguard" in seen_capabilities
    assert "wg_quick_import" not in seen_capabilities
    assert "agent.self_upgrade" not in seen_capabilities
    assert "middleware.install" in seen_capabilities
    assert "middleware.udp2raw" in seen_capabilities
    assert "middleware.udp2raw.openwrt-procd" in seen_capabilities
    assert "middleware.udp2raw.systemd" not in seen_capabilities


def test_run_once_reports_service_manager_capability(monkeypatch, tmp_path: Path) -> None:
    """验证 Agent 拉任务时会上报当前 wg-quick 服务管理能力。"""

    seen_capabilities: list[str] = []

    class FakeClient:
        def heartbeat(self) -> None:
            return None

        def poll_tasks(self, capabilities: list[str] | None = None) -> list[dict[str, Any]]:
            seen_capabilities.extend(capabilities or [])
            return []

    use_service_binaries(monkeypatch, systemd=True)
    monkeypatch.setattr(system, "run_command", lambda command, allow_failure: command_result(command))

    main.run_once(FakeClient(), str(tmp_path))

    assert "wireguard" in seen_capabilities
    assert "wg_quick_import" in seen_capabilities
    assert "service:systemd" in seen_capabilities
    assert "agent.self_upgrade" in seen_capabilities
    assert "middleware.udp2raw.systemd" in seen_capabilities


def test_agent_platform_reports_musl_libc(monkeypatch) -> None:
    """验证 OpenWrt/musl 平台不会被误报为 glibc 资产。"""

    use_service_binaries(monkeypatch, systemd=False, openrc=False, openwrt=True, wg_quick=False)
    monkeypatch.setattr(service_manager.Path, "exists", lambda self: str(self) == service_manager.OPENWRT_WIREGUARD_PROTO)
    monkeypatch.setattr(system.platform, "system", lambda: "Linux")
    monkeypatch.setattr(system.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(system.platform, "libc_ver", lambda: ("glibc", "2.0"))
    def fake_which(binary: str) -> str | None:
        if binary == "ldd":
            return "/usr/bin/ldd"
        if binary in {"uci", "ifup", "ifdown"}:
            return f"/sbin/{binary}"
        return None

    monkeypatch.setattr(system.shutil, "which", fake_which)

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        if command == ["ldd", "--version"]:
            return command_result(command, stdout="musl libc (aarch64)\nVersion 1.2.3\n")
        return command_result(command)

    monkeypatch.setattr(system, "run_command", fake_run_command)

    platform = system.get_agent_platform()

    assert platform["service_manager"] == "openwrt-uci"
    assert platform["libc"] == "musl"
    assert platform["glibc"] is None


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
