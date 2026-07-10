from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import threading
from typing import Any

import pytest

from link42_common.connection_types import GRE_TASKS, LOOKING_GLASS_BIRD_ROUTE_LOOKUP_TASK, WIREGUARD_TASKS
from link42_agent import gre, link_monitor, looking_glass, main, middleware, service_manager, system, upgrade
from link42_agent.client import AgentHttpError
from link42_agent.config import AgentConfig
from link42_agent.plugins import bird
from link42_agent.plugins import port_inventory
from link42_agent.task_handlers import TASK_HANDLERS, execute_registered_task


def command_result(command: list[str], returncode: int = 0, stdout: str = "") -> dict[str, Any]:
    """构造测试用的命令执行结果。"""
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
        """模拟 shutil.which 的返回结果。"""
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
        """模拟 subprocess.run 的返回或异常。"""
        seen["command"] = command
        seen["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

    monkeypatch.setenv("LINK42_COMMAND_TIMEOUT", "7")
    monkeypatch.setattr(system.subprocess, "run", fake_run)

    result = system.run_command(["systemctl", "status", "link42-agent"], allow_failure=False)

    assert result["stdout"] == "ok\n"
    assert seen == {"command": ["systemctl", "status", "link42-agent"], "timeout": 7.0}


def test_run_command_masks_sensitive_arguments(monkeypatch) -> None:
    """验证命令结果和异常中的私钥参数会被遮罩，避免日志泄露。"""

    def fake_run(command: list[str], **kwargs: Any):
        """模拟 subprocess.run 返回失败命令。"""
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="bad key")

    monkeypatch.setattr(system.subprocess, "run", fake_run)

    result = system.run_command(["uci", "set", "network.wg0.private_key=secret-key"], allow_failure=True)

    assert result["command"] == ["uci", "set", "network.wg0.private_key=***"]
    with pytest.raises(RuntimeError) as exc_info:
        system.run_command(["uci", "set", "network.wg0.private_key=secret-key"], allow_failure=False)
    assert "secret-key" not in str(exc_info.value)
    assert "network.wg0.private_key=***" in str(exc_info.value)


def test_node_plugin_port_inventory_capability_and_scan(monkeypatch, tmp_path) -> None:
    """验证 Agent 侧端口台账插件会上报能力并能扫描 WireGuard ListenPort。"""

    use_service_binaries(monkeypatch, systemd=True)
    monkeypatch.setattr(main, "mimic_installable", lambda platform: False)
    monkeypatch.setattr(main, "mimic_runtime_supported", lambda platform: False)
    monkeypatch.setattr(port_inventory.shutil, "which", lambda binary: f"/usr/bin/{binary}" if binary in {"ss"} else None)
    monkeypatch.setattr(port_inventory, "scan_socket_listeners", lambda range_start, range_end: [])
    wg_dir = tmp_path / "wireguard"
    wg_dir.mkdir()
    (wg_dir / "wg0.conf").write_text("[Interface]\nListenPort = 23001\n", encoding="utf-8")

    capabilities = main.build_capabilities()
    result = execute_registered_task(
        "node_plugin.port_inventory.scan",
        {"range_start": 23000, "range_end": 23099},
        AgentConfig(server_url="http://controller", node_id=1, token="token", wireguard_dir=str(wg_dir), dry_run=True),
    )

    assert "node_plugin.port_inventory" in capabilities
    assert "node_plugin.port_inventory.scan" in capabilities
    assert {
        "protocol": "UDP",
        "port": 23001,
        "purpose": "",
        "source": "scan",
        "detected_process": "wireguard",
        "detected_pid": None,
        "detected_source": str(wg_dir / "wg0.conf"),
    } in result["ports"]


def test_bird_plugin_lists_and_reads_recursive_config_tree(monkeypatch, tmp_path) -> None:
    """验证 Bird 插件能递归发现 /etc/bird 下的多个配置文件。"""

    bird_root = tmp_path / "etc" / "bird"
    bird_root.mkdir(parents=True)
    main_config = bird_root / "bird.conf"
    include_dir = bird_root / "conf.d"
    include_dir.mkdir()
    peer_config = include_dir / "peer.conf"
    envvars = bird_root / "envvars"
    main_config.write_text("router id 10.0.0.1;\ninclude \"/etc/bird/conf.d/*.conf\";\n", encoding="utf-8")
    peer_config.write_text("protocol device {}\n", encoding="utf-8")
    envvars.write_text("BIRD_ARGS=\"\"\n", encoding="utf-8")

    monkeypatch.setattr(bird, "BIRD_ROOT", bird_root)
    monkeypatch.setattr(bird, "BIRD_DEFAULT_MAIN", main_config)
    monkeypatch.setattr(bird, "BIRD_LEGACY_MAIN", tmp_path / "etc" / "bird.conf")
    monkeypatch.setattr(bird.shutil, "which", lambda binary: f"/usr/sbin/{binary}" if binary in {"bird", "birdc"} else None)

    listed = bird.list_bird_resources()
    read = bird.read_bird_resource(str(peer_config))

    assert listed["main_config"] == str(main_config)
    assert {item["path"] for item in listed["files"]} == {str(main_config), str(peer_config)}
    assert read["content"] == "protocol device {}\n"


def test_bird_plugin_rejects_path_outside_config_roots(monkeypatch, tmp_path) -> None:
    """验证 Bird 插件不会读取声明根目录之外的任意文件。"""

    bird_root = tmp_path / "etc" / "bird"
    bird_root.mkdir(parents=True)
    monkeypatch.setattr(bird, "BIRD_ROOT", bird_root)
    monkeypatch.setattr(bird, "BIRD_DEFAULT_MAIN", bird_root / "bird.conf")
    monkeypatch.setattr(bird, "BIRD_LEGACY_MAIN", tmp_path / "etc" / "bird.conf")

    with pytest.raises(ValueError):
        bird.resolve_bird_resource(str(tmp_path / "etc" / "shadow"))


def test_bird_plugin_rejects_non_conf_files_under_bird_root(monkeypatch, tmp_path) -> None:
    """验证 envvars 这类非 BIRD 配置语法文件不会被插件读写。"""

    bird_root = tmp_path / "etc" / "bird"
    bird_root.mkdir(parents=True)
    envvars = bird_root / "envvars"
    envvars.write_text("BIRD_ARGS=\"\"\n", encoding="utf-8")

    monkeypatch.setattr(bird, "BIRD_ROOT", bird_root)
    monkeypatch.setattr(bird, "BIRD_DEFAULT_MAIN", bird_root / "bird.conf")
    monkeypatch.setattr(bird, "BIRD_LEGACY_MAIN", tmp_path / "etc" / "bird.conf")

    listed = bird.list_bird_resources()

    assert listed["files"] == []
    with pytest.raises(ValueError, match="not a BIRD configuration file"):
        bird.read_bird_resource(str(envvars))


def test_bird_validate_restores_original_file_metadata(monkeypatch, tmp_path) -> None:
    """验证 validate 后内容和 mtime 都恢复，避免一次校验就改变文件状态。"""

    bird_root = tmp_path / "etc" / "bird"
    bird_root.mkdir(parents=True)
    main_config = bird_root / "bird.conf"
    main_config.write_text("router id 10.0.0.1;\n", encoding="utf-8")
    original_mtime_ns = 1_700_000_000_123_456_789
    os.utime(main_config, ns=(original_mtime_ns, original_mtime_ns))

    monkeypatch.setattr(bird, "BIRD_ROOT", bird_root)
    monkeypatch.setattr(bird, "BIRD_DEFAULT_MAIN", main_config)
    monkeypatch.setattr(bird, "BIRD_LEGACY_MAIN", tmp_path / "etc" / "bird.conf")
    monkeypatch.setattr(
        bird,
        "run_bird_config_check",
        lambda main_config=None: command_result(["bird", "-p", "-c", str(main_config or bird.default_main_config())]),
    )

    result = bird.validate_bird_resource(str(main_config), "router id 10.0.0.2;\n")

    assert result["valid"] is True
    assert main_config.read_text(encoding="utf-8") == "router id 10.0.0.1;\n"
    assert main_config.stat().st_mtime_ns == original_mtime_ns


def test_bird_apply_restores_original_content_when_validation_fails(monkeypatch, tmp_path) -> None:
    """验证 Bird 配置应用失败时会恢复原文件，避免节点配置被半写入。"""

    bird_root = tmp_path / "etc" / "bird"
    backup_root = tmp_path / "var" / "lib" / "link42" / "backups" / "bird"
    bird_root.mkdir(parents=True)
    main_config = bird_root / "bird.conf"
    main_config.write_text("router id 10.0.0.1;\n", encoding="utf-8")
    original_sha = bird.file_sha256(main_config)

    monkeypatch.setattr(bird, "BIRD_ROOT", bird_root)
    monkeypatch.setattr(bird, "BIRD_DEFAULT_MAIN", main_config)
    monkeypatch.setattr(bird, "BIRD_LEGACY_MAIN", tmp_path / "etc" / "bird.conf")
    monkeypatch.setattr(bird, "BIRD_BACKUP_DIR", backup_root)
    monkeypatch.setattr(bird.shutil, "which", lambda binary: f"/usr/sbin/{binary}" if binary in {"bird", "birdc"} else None)
    monkeypatch.setattr(
        bird,
        "run_bird_config_check",
        lambda main_config=None: command_result(["bird", "-p", "-c", str(main_config or bird.default_main_config())], 1, ""),
    )

    result = bird.apply_bird_resource(
        str(main_config),
        "this is not bird config\n",
        original_sha,
        reload=True,
        dry_run=False,
    )

    assert result["applied"] is False
    assert result["restored"] is True
    assert main_config.read_text(encoding="utf-8") == "router id 10.0.0.1;\n"
    assert Path(str(result["backup_ref"])).exists()


def test_bird_apply_same_content_keeps_file_hash(monkeypatch, tmp_path) -> None:
    """验证带末尾换行的同内容应用不会因为处理链路改变文件字节。"""

    bird_root = tmp_path / "etc" / "bird"
    backup_root = tmp_path / "var" / "lib" / "link42" / "backups" / "bird"
    bird_root.mkdir(parents=True)
    main_config = bird_root / "bird.conf"
    content = "router id 10.0.0.1;\n\n"
    main_config.write_text(content, encoding="utf-8")
    original_sha = bird.file_sha256(main_config)

    monkeypatch.setattr(bird, "BIRD_ROOT", bird_root)
    monkeypatch.setattr(bird, "BIRD_DEFAULT_MAIN", main_config)
    monkeypatch.setattr(bird, "BIRD_LEGACY_MAIN", tmp_path / "etc" / "bird.conf")
    monkeypatch.setattr(bird, "BIRD_BACKUP_DIR", backup_root)
    monkeypatch.setattr(bird.shutil, "which", lambda binary: f"/usr/sbin/{binary}" if binary == "bird" else None)
    monkeypatch.setattr(
        bird,
        "run_bird_config_check",
        lambda main_config=None: command_result(["bird", "-p", "-c", str(main_config or bird.default_main_config())]),
    )

    result = bird.apply_bird_resource(
        str(main_config),
        content,
        original_sha,
        reload=False,
        dry_run=False,
    )

    assert result["applied"] is True
    assert result["sha256"] == original_sha
    assert bird.file_sha256(main_config) == original_sha


def test_bird_apply_many_writes_all_files_and_checks_hashes(monkeypatch, tmp_path) -> None:
    """验证批量保存会一次提交多个配置文件，并返回每个文件的新 sha。"""

    bird_root = tmp_path / "etc" / "bird"
    backup_root = tmp_path / "var" / "lib" / "link42" / "backups" / "bird"
    include_dir = bird_root / "conf.d"
    include_dir.mkdir(parents=True)
    main_config = bird_root / "bird.conf"
    peer_config = include_dir / "peer.conf"
    main_config.write_text("router id 10.0.0.1;\n", encoding="utf-8")
    peer_config.write_text("protocol device {}\n", encoding="utf-8")
    main_sha = bird.file_sha256(main_config)
    peer_sha = bird.file_sha256(peer_config)

    monkeypatch.setattr(bird, "BIRD_ROOT", bird_root)
    monkeypatch.setattr(bird, "BIRD_DEFAULT_MAIN", main_config)
    monkeypatch.setattr(bird, "BIRD_LEGACY_MAIN", tmp_path / "etc" / "bird.conf")
    monkeypatch.setattr(bird, "BIRD_BACKUP_DIR", backup_root)
    monkeypatch.setattr(bird.shutil, "which", lambda binary: f"/usr/sbin/{binary}" if binary == "bird" else None)
    monkeypatch.setattr(
        bird,
        "run_bird_config_check",
        lambda main_config=None: command_result(["bird", "-p", "-c", str(main_config or bird.default_main_config())]),
    )

    result = bird.apply_bird_resources(
        [
            {"resource_key": str(main_config), "content": "router id 10.0.0.2;\n", "base_sha256": main_sha},
            {"resource_key": str(peer_config), "content": "protocol direct {}\n", "base_sha256": peer_sha},
        ],
        reload=False,
        dry_run=False,
    )

    assert result["applied"] is True
    assert main_config.read_text(encoding="utf-8") == "router id 10.0.0.2;\n"
    assert peer_config.read_text(encoding="utf-8") == "protocol direct {}\n"
    assert {item["resource_key"] for item in result["files"]} == {str(main_config), str(peer_config)}


def test_bird_apply_many_reload_runs_birdc_configure(monkeypatch, tmp_path) -> None:
    """验证批量保存 reload 时会执行 birdc configure 刷新 BIRD。"""

    bird_root = tmp_path / "etc" / "bird"
    backup_root = tmp_path / "var" / "lib" / "link42" / "backups" / "bird"
    bird_root.mkdir(parents=True)
    main_config = bird_root / "bird.conf"
    main_config.write_text("router id 10.0.0.1;\n", encoding="utf-8")
    main_sha = bird.file_sha256(main_config)
    configure_calls: list[str] = []

    monkeypatch.setattr(bird, "BIRD_ROOT", bird_root)
    monkeypatch.setattr(bird, "BIRD_DEFAULT_MAIN", main_config)
    monkeypatch.setattr(bird, "BIRD_LEGACY_MAIN", tmp_path / "etc" / "bird.conf")
    monkeypatch.setattr(bird, "BIRD_BACKUP_DIR", backup_root)
    monkeypatch.setattr(
        bird,
        "run_bird_config_check",
        lambda main_config=None: command_result(["bird", "-p", "-c", str(main_config or bird.default_main_config())]),
    )

    def fake_configure() -> dict[str, Any]:
        """模拟 birdc configure 调用。"""
        configure_calls.append("configure")
        return command_result(["birdc", "configure"])

    monkeypatch.setattr(bird, "run_bird_configure", fake_configure)

    result = bird.apply_bird_resources(
        [{"resource_key": str(main_config), "content": "router id 10.0.0.2;\n", "base_sha256": main_sha}],
        reload=True,
        dry_run=False,
    )

    assert result["applied"] is True
    assert result["reload"]["command"] == ["birdc", "configure"]
    assert configure_calls == ["configure"]
    assert main_config.read_text(encoding="utf-8") == "router id 10.0.0.2;\n"


def test_bird_apply_many_reload_failure_restores_files(monkeypatch, tmp_path) -> None:
    """验证 birdc configure 失败时会恢复本次写入的所有文件。"""

    bird_root = tmp_path / "etc" / "bird"
    backup_root = tmp_path / "var" / "lib" / "link42" / "backups" / "bird"
    include_dir = bird_root / "conf.d"
    include_dir.mkdir(parents=True)
    main_config = bird_root / "bird.conf"
    peer_config = include_dir / "peer.conf"
    main_original = "router id 10.0.0.1;\n"
    peer_original = "protocol device {}\n"
    main_config.write_text(main_original, encoding="utf-8")
    peer_config.write_text(peer_original, encoding="utf-8")

    monkeypatch.setattr(bird, "BIRD_ROOT", bird_root)
    monkeypatch.setattr(bird, "BIRD_DEFAULT_MAIN", main_config)
    monkeypatch.setattr(bird, "BIRD_LEGACY_MAIN", tmp_path / "etc" / "bird.conf")
    monkeypatch.setattr(bird, "BIRD_BACKUP_DIR", backup_root)
    monkeypatch.setattr(
        bird,
        "run_bird_config_check",
        lambda main_config=None: command_result(["bird", "-p", "-c", str(main_config or bird.default_main_config())]),
    )
    monkeypatch.setattr(
        bird,
        "run_bird_configure",
        lambda: {"command": ["birdc", "configure"], "returncode": 1, "stdout": "", "stderr": "reload failed"},
    )

    result = bird.apply_bird_resources(
        [
            {"resource_key": str(main_config), "content": "router id 10.0.0.2;\n", "base_sha256": bird.file_sha256(main_config)},
            {"resource_key": str(peer_config), "content": "protocol direct {}\n", "base_sha256": bird.file_sha256(peer_config)},
        ],
        reload=True,
        dry_run=False,
    )

    assert result["applied"] is False
    assert result["valid"] is True
    assert result["reload"]["stderr"] == "reload failed"
    assert result["restored"] is True
    assert main_config.read_text(encoding="utf-8") == main_original
    assert peer_config.read_text(encoding="utf-8") == peer_original


def test_bird_apply_many_rejects_changed_or_deleted_file_before_writing(monkeypatch, tmp_path) -> None:
    """验证批量保存前会发现被别人修改或删除的文件，不会写入其它文件。"""

    bird_root = tmp_path / "etc" / "bird"
    include_dir = bird_root / "conf.d"
    include_dir.mkdir(parents=True)
    main_config = bird_root / "bird.conf"
    peer_config = include_dir / "peer.conf"
    main_config.write_text("router id 10.0.0.1;\n", encoding="utf-8")
    peer_config.write_text("protocol device {}\n", encoding="utf-8")
    main_sha = bird.file_sha256(main_config)
    peer_sha = bird.file_sha256(peer_config)
    peer_config.unlink()

    monkeypatch.setattr(bird, "BIRD_ROOT", bird_root)
    monkeypatch.setattr(bird, "BIRD_DEFAULT_MAIN", main_config)
    monkeypatch.setattr(bird, "BIRD_LEGACY_MAIN", tmp_path / "etc" / "bird.conf")

    with pytest.raises(ValueError, match="does not exist"):
        bird.apply_bird_resources(
            [
                {"resource_key": str(main_config), "content": "router id 10.0.0.2;\n", "base_sha256": main_sha},
                {"resource_key": str(peer_config), "content": "protocol direct {}\n", "base_sha256": peer_sha},
            ],
            reload=False,
            dry_run=False,
        )

    assert main_config.read_text(encoding="utf-8") == "router id 10.0.0.1;\n"


def test_run_command_timeout_returns_result_or_raises(monkeypatch) -> None:
    """验证命令超时不会卡死任务，允许失败时返回结果，不允许失败时抛错。"""

    def fake_run(command: list[str], **kwargs: Any):
        """模拟 subprocess.run 的返回或异常。"""
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


def test_run_command_strips_pyinstaller_library_path(monkeypatch) -> None:
    """验证 PyInstaller 私有 LD_LIBRARY_PATH 不会污染 apt/dpkg 等子进程。"""

    seen: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any):
        """模拟 subprocess.run 的返回或异常。"""
        seen["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEIabc123")
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG", raising=False)
    monkeypatch.setattr(system.subprocess, "run", fake_run)

    system.run_command(["dpkg-deb", "--version"], allow_failure=False)

    assert "LD_LIBRARY_PATH" not in seen["env"]


def test_run_command_restores_original_library_path(monkeypatch) -> None:
    """验证存在 LD_LIBRARY_PATH_ORIG 时会恢复给子进程使用。"""

    seen: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any):
        """模拟 subprocess.run 的返回或异常。"""
        seen["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEIabc123")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/usr/local/lib")
    monkeypatch.setattr(system.subprocess, "run", fake_run)

    system.run_command(["dpkg-deb", "--version"], allow_failure=False)

    assert seen["env"]["LD_LIBRARY_PATH"] == "/usr/local/lib"


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

    for task_type in [
        GRE_TASKS.apply_config,
        GRE_TASKS.read_config,
        GRE_TASKS.status,
        GRE_TASKS.start,
        GRE_TASKS.stop,
        GRE_TASKS.delete_config,
    ]:
        assert task_type in TASK_HANDLERS

    for task_type in [
        "middleware.mimic.apply",
        "middleware.mimic.start",
        "middleware.mimic.stop",
        "middleware.mimic.delete",
        "middleware.mimic.status",
    ]:
        assert task_type in TASK_HANDLERS


def test_gre_capability_depends_on_iproute2(monkeypatch) -> None:
    """验证 Agent 只有检测到 iproute2 GRE 能力时才上报 GRE。"""

    platform_info = {
        "service_manager": "systemd",
        "kernel_version": "6.6.12",
        "is_openwrt": False,
        "os": "linux",
        "arch": "x86_64",
        "distro_id": "debian",
        "distro_codename": "bookworm",
        "has_mimic": False,
    }
    monkeypatch.setattr(main, "gre_runtime_supported", lambda: True)
    monkeypatch.setattr(main, "mimic_installable", lambda platform: False)
    monkeypatch.setattr(main, "mimic_runtime_supported", lambda platform: False)

    assert "gre" in main.build_capabilities(platform_info)
    assert "gre.iproute2" in main.build_capabilities(platform_info)

    monkeypatch.setattr(main, "gre_runtime_supported", lambda: False)
    assert "gre" not in main.build_capabilities(platform_info)


def test_looking_glass_bird_capability_depends_on_birdc(monkeypatch) -> None:
    """验证检测到 birdc 时 Agent 上报 Looking Glass BIRD 查询能力。"""

    platform_info = {
        "service_manager": "systemd",
        "kernel_version": "6.6.12",
        "is_openwrt": False,
        "os": "linux",
        "arch": "x86_64",
        "distro_id": "debian",
        "distro_codename": "bookworm",
        "has_mimic": False,
    }
    monkeypatch.setattr(main, "gre_runtime_supported", lambda: False)
    monkeypatch.setattr(main, "mimic_installable", lambda platform: False)
    monkeypatch.setattr(main, "mimic_runtime_supported", lambda platform: False)
    monkeypatch.setattr(main.shutil, "which", lambda binary: "/usr/bin/birdc" if binary == "birdc" else None)

    capabilities = main.build_capabilities(platform_info)

    assert "bird" in capabilities
    assert "looking_glass.bird.route_lookup" in capabilities


def test_looking_glass_bird_route_lookup_uses_fixed_argv(monkeypatch) -> None:
    """验证 Looking Glass BIRD 查询只能执行固定 birdc 参数。"""

    commands: list[list[str]] = []

    def fake_run(command, text, capture_output, timeout, check):
        """记录 subprocess 参数并返回模拟 birdc 输出。"""

        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="raw output", stderr="")

    monkeypatch.setattr(looking_glass.shutil, "which", lambda binary: "/usr/sbin/birdc" if binary == "birdc" else None)
    monkeypatch.setattr(looking_glass.subprocess, "run", fake_run)

    result = looking_glass.execute_bird_route_lookup(
        {"ip": "2001:db8::1", "command_timeout_seconds": 3, "output_limit_bytes": 20}
    )

    assert commands == [["/usr/sbin/birdc", "show", "route", "for", "2001:db8::1", "all"]]
    assert result["command"] == "birdc show route for 2001:db8::1 all"
    assert result["stdout"] == "raw output"
    assert result["exit_code"] == 0


def test_looking_glass_bird_route_lookup_task_registered() -> None:
    """验证 Looking Glass BIRD 查询任务已注册到 Agent 分派表。"""

    assert LOOKING_GLASS_BIRD_ROUTE_LOOKUP_TASK in TASK_HANDLERS


def test_openwrt_gre_capability_uses_uci_backend(monkeypatch) -> None:
    """验证 OpenWrt 节点检测到 netifd GRE 后上报 UCI 后端能力。"""

    platform_info = {
        "service_manager": "openwrt-uci",
        "kernel_version": "5.4.281",
        "is_openwrt": True,
        "os": "linux",
        "arch": "aarch64",
        "distro_id": "openwrt",
        "distro_codename": "21.02",
        "has_mimic": False,
    }
    monkeypatch.setattr(main, "openwrt_gre_supported", lambda: True)
    monkeypatch.setattr(main, "gre_runtime_supported", lambda: True)
    monkeypatch.setattr(main, "mimic_installable", lambda platform: False)
    monkeypatch.setattr(main, "mimic_runtime_supported", lambda platform: False)

    capabilities = main.build_capabilities(platform_info)

    assert "gre" in capabilities
    assert "gre.openwrt-uci" in capabilities
    assert "gre.iproute2" not in capabilities


def test_run_gre_service_command_outputs_json(monkeypatch, capsys) -> None:
    """验证 systemd 调用的 gre-start 子命令会输出 JSON 结果。"""

    def fake_start_gre_from_config(interface_name: str, config_dir: str | None) -> dict[str, str | None]:
        """模拟从配置文件启动 GRE 接口。"""

        return {"interface_name": interface_name, "config_dir": config_dir}

    monkeypatch.setenv("LINK42_GRE_DIR", "/tmp/link42-gre")
    monkeypatch.setattr(main, "start_gre_from_config", fake_start_gre_from_config)

    handled = main.run_gre_service_command(["link42-agent", "gre-start", "gre0"])
    output = json.loads(capsys.readouterr().out)

    assert handled is True
    assert output == {"config_dir": "/tmp/link42-gre", "interface_name": "gre0"}


def test_gre_start_rebuilds_interface_and_routes(monkeypatch, tmp_path: Path) -> None:
    """验证 GRE 改名启动会先建新接口，成功后再清理旧接口和旧配置。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """记录 GRE 启动时调用的系统命令。"""

        commands.append(command)
        return command_result(command)

    monkeypatch.setattr(gre, "ip_command", lambda: "/sbin/ip")
    monkeypatch.setattr(gre, "gre_systemd_available", lambda: False)
    monkeypatch.setattr(gre, "run_command", fake_run_command)

    result = gre.start_gre_interface(
        {
            "interface_name": "gre_new",
            "previous_interface_name": "gre_old",
            "outer_local_ip": "203.0.113.10",
            "outer_remote_ip": "198.51.100.20",
            "tunnel_ips": ["10.42.8.1/30", "fd42::1/64"],
            "routes": ["10.77.0.0/24", "fd77::/64"],
            "mtu": 1476,
            "key": "42",
            "ttl": 255,
            "pmtudisc": True,
        },
        str(tmp_path),
    )
    saved = (tmp_path / "gre_new.json").read_text(encoding="utf-8")

    assert result["runtime_status"] == "running"
    assert result["previous_config_cleanup"]["config_path"] == str(tmp_path / "gre_old.json")
    assert '"interface_name": "gre_new"' in saved
    assert commands == [
        ["/sbin/ip", "link", "del", "gre_new"],
        [
            "/sbin/ip",
            "tunnel",
            "add",
            "gre_new",
            "mode",
            "gre",
            "local",
            "203.0.113.10",
            "remote",
            "198.51.100.20",
            "key",
            "42",
            "ttl",
            "255",
            "pmtudisc",
        ],
        ["/sbin/ip", "addr", "add", "10.42.8.1/30", "dev", "gre_new"],
        ["/sbin/ip", "addr", "add", "fd42::1/64", "dev", "gre_new"],
        ["/sbin/ip", "link", "set", "dev", "gre_new", "mtu", "1476", "up"],
        ["/sbin/ip", "route", "replace", "10.77.0.0/24", "dev", "gre_new"],
        ["/sbin/ip", "-6", "route", "replace", "fd77::/64", "dev", "gre_new"],
        ["/sbin/ip", "link", "del", "gre_old"],
    ]


def test_gre_rejects_ttl_without_pmtu_discovery(tmp_path: Path) -> None:
    """验证 Agent 拒绝 iproute2 不支持的 GRE TTL 和 nopmtudisc 组合。"""

    with pytest.raises(ValueError, match="GRE ttl requires PMTU discovery"):
        gre.start_gre_interface(
            {
                "interface_name": "gre-bad",
                "outer_local_ip": "203.0.113.10",
                "outer_remote_ip": "198.51.100.20",
                "tunnel_ips": ["10.42.8.1/30"],
                "routes": [],
                "ttl": 63,
                "pmtudisc": False,
            },
            str(tmp_path),
        )


def test_gre_delete_config_removes_previous_rename_files(monkeypatch, tmp_path: Path) -> None:
    """验证 GRE 删除任务会同时清理改名前后的配置文件。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """记录删除 GRE 配置时调用的系统命令。"""

        commands.append(command)
        return command_result(command)

    (tmp_path / "gre_new.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "gre_old.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(gre, "ip_command", lambda: "/sbin/ip")
    monkeypatch.setattr(gre, "gre_systemd_available", lambda: False)
    monkeypatch.setattr(gre, "run_command", fake_run_command)

    result = gre.delete_gre_config(
        {"interface_name": "gre_new", "previous_interface_name": "gre_old"},
        str(tmp_path),
    )

    assert result["deleted"] is True
    assert result["previous_config"]["deleted"] is True
    assert not (tmp_path / "gre_new.json").exists()
    assert not (tmp_path / "gre_old.json").exists()
    assert commands == [
        ["/sbin/ip", "link", "del", "gre_new"],
        ["/sbin/ip", "link", "del", "gre_old"],
    ]


def test_gre_status_accepts_unknown_state_with_up_flag(monkeypatch) -> None:
    """验证 GRE 接口 state UNKNOWN 但 flags 带 UP 时仍识别为运行中。"""

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟 ip link show 返回 GRE 常见的 UNKNOWN 状态。"""

        return command_result(
            command,
            stdout=(
                "72: l42grren@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> "
                "mtu 1476 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n"
            ),
        )

    monkeypatch.setattr(gre, "ip_command", lambda: "/sbin/ip")
    monkeypatch.setattr(gre, "run_command", fake_run_command)

    result = gre.gre_status({"interface_name": "l42grren"})

    assert result["runtime_status"] == "running"


def test_openwrt_gre_start_writes_uci_and_reloads_netifd(monkeypatch, tmp_path: Path) -> None:
    """验证 OpenWrt GRE 启动会写入 UCI 并通过 ifup 拉起隧道和地址接口。"""

    commands: list[tuple[list[str], bool]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """记录 OpenWrt GRE 启动时调用的 UCI 和 netifd 命令。"""

        commands.append((command, allow_failure))
        if command == ["/sbin/uci", "-q", "show", "network"]:
            return command_result(command, stdout="network.old_r4_0.link42_gre_name='gre_ab'\n")
        return command_result(command)

    monkeypatch.setattr(gre, "openwrt_gre_available", lambda: True)
    monkeypatch.setattr(gre, "uci_command", lambda: "/sbin/uci")
    monkeypatch.setattr(gre, "ifup_command", lambda: "/sbin/ifup")
    monkeypatch.setattr(gre, "ifdown_command", lambda: "/sbin/ifdown")
    monkeypatch.setattr(gre, "run_command", fake_run_command)

    result = gre.start_gre_interface(
        {
            "interface_name": "gre_ab",
            "previous_interface_name": "gre_old",
            "outer_local_ip": "203.0.113.10",
            "outer_remote_ip": "198.51.100.20",
            "tunnel_ips": ["10.42.8.1/30", "fd42::1/64"],
            "routes": ["10.77.0.0/24", "fd77::/64"],
            "mtu": 1476,
            "key": "42",
            "ttl": 255,
            "pmtudisc": True,
        },
        str(tmp_path),
    )
    command_values = [command for command, _allow_failure in commands]

    assert result["service_backend"] == "openwrt-uci"
    assert result["runtime_status"] == "running"
    assert (tmp_path / "gre_ab.json").exists()
    assert ["/sbin/uci", "set", "network.gre_ab=interface"] in command_values
    assert ["/sbin/uci", "set", "network.gre_ab.proto=gre"] in command_values
    assert ["/sbin/uci", "set", "network.gre_ab.ipaddr=203.0.113.10"] in command_values
    assert ["/sbin/uci", "set", "network.gre_ab.peeraddr=198.51.100.20"] in command_values
    assert ["/sbin/uci", "set", "network.gre_ab.ikey=42"] in command_values
    assert ["/sbin/uci", "set", "network.gre_ab.okey=42"] in command_values
    assert ["/sbin/uci", "add_list", "network.gre_ab_addr.ipaddr=10.42.8.1/30"] in command_values
    assert ["/sbin/uci", "add_list", "network.gre_ab_addr.ip6addr=fd42::1/64"] in command_values
    assert ["/sbin/uci", "set", "network.gre_ab_r4_0.target=10.77.0.0"] in command_values
    assert ["/sbin/uci", "set", "network.gre_ab_r6_0.target=fd77::/64"] in command_values
    assert ["/sbin/ifup", "gre_ab"] in command_values
    assert ["/sbin/ifup", "gre_ab_addr"] in command_values
    assert any(command == ["/sbin/ifdown", "gre_ab"] and allow_failure for command, allow_failure in commands)


def test_openwrt_gre_status_reads_ifstatus_and_generated_device(monkeypatch) -> None:
    """验证 OpenWrt GRE 状态优先读取 ifstatus，并检查 netifd 生成设备。"""

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟 OpenWrt ifstatus 和 ip link 输出。"""

        if command == ["ifstatus", "gre_ab"]:
            return command_result(command, stdout='{"up": true}\n')
        if command == ["/sbin/ip", "link", "show", "dev", "gre4-gre_ab"]:
            return command_result(
                command,
                stdout="9: gre4-gre_ab@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> state UNKNOWN\n",
            )
        return command_result(command, returncode=1)

    monkeypatch.setattr(gre, "openwrt_gre_available", lambda: True)
    monkeypatch.setattr(gre, "ip_command", lambda: "/sbin/ip")
    monkeypatch.setattr(gre, "run_command", fake_run_command)

    result = gre.gre_status({"interface_name": "gre_ab"})

    assert result["runtime_status"] == "running"
    assert result["service_backend"] == "openwrt-uci"
    assert result["link"]["command"] == ["/sbin/ip", "link", "show", "dev", "gre4-gre_ab"]


def test_gre_systemd_start_uses_agent_service_entry(monkeypatch, tmp_path: Path) -> None:
    """验证 systemd 节点会通过 link42-gre@.service 持久化 GRE 接口。"""

    monkeypatch.setattr(gre, "gre_systemd_available", lambda: True)
    monkeypatch.setattr(gre, "systemctl_command", lambda: "/bin/systemctl")
    monkeypatch.setattr(gre, "ip_command", lambda: "/sbin/ip")
    monkeypatch.setattr(gre, "agent_binary_path", lambda: "/usr/local/bin/link42-agent")
    monkeypatch.setattr(gre.shutil, "which", lambda binary: "/usr/local/bin/link42-agent" if binary == "link42-agent" else None)

    result = gre.start_gre_interface(
        {
            "interface_name": "gre_a_b",
            "outer_local_ip": "203.0.113.10",
            "outer_remote_ip": "198.51.100.20",
            "tunnel_ips": ["10.42.8.1/30"],
            "routes": [],
        },
        str(tmp_path),
        dry_run=True,
    )

    assert result["service_backend"] == "systemd"
    assert "ExecStart=/usr/local/bin/link42-agent gre-start %i" in result["unit"]["content"]
    assert "PYTHONPATH=" not in result["unit"]["content"]
    assert result["commands"] == [
        ["/bin/systemctl", "daemon-reload"],
        ["/bin/systemctl", "enable", "link42-gre@gre_a_b.service"],
        ["/bin/systemctl", "restart", "link42-gre@gre_a_b.service"],
    ]


def test_gre_systemd_unit_falls_back_to_python_entry(monkeypatch) -> None:
    """验证未安装 link42-agent 命令时 systemd unit 不直接执行源码文件。"""

    monkeypatch.setattr(gre.shutil, "which", lambda binary: None)
    monkeypatch.setattr(gre.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(gre, "agent_source_pythonpath", lambda: "/root/repo/link42/apps/agent:/root/repo/link42/packages")

    content = gre.render_gre_systemd_unit("/etc/link42/gre")

    assert "Environment=PYTHONPATH=/root/repo/link42/apps/agent:/root/repo/link42/packages" in content
    assert "ExecStart=/usr/bin/python3 -m link42_agent.main gre-start %i" in content
    assert "/root/repo/link42/apps/agent/link42_agent/main.py gre-start" not in content


def test_mimic_capability_requires_systemd_kernel_newer_than_61_and_binary(monkeypatch) -> None:
    """验证 mimic 能力只在非 OpenWrt、systemd、kernel > 6.1 且已安装 mimic 时上报。"""

    monkeypatch.setattr(main, "get_service_manager_name", lambda: "systemd")
    monkeypatch.setattr(
        main,
        "get_agent_platform",
        lambda: {
            "service_manager": "systemd",
            "kernel_version": "6.6.12",
            "is_openwrt": False,
            "os": "linux",
            "arch": "x86_64",
            "distro_id": "debian",
            "distro_codename": "bookworm",
            "has_mimic": True,
        },
    )
    monkeypatch.setattr(
        main.shutil,
        "which",
        lambda binary: f"/usr/bin/{binary}" if binary in {"mimic", "dpkg", "apt-get"} else None,
    )

    assert "middleware.mimic" in main.build_capabilities()

    monkeypatch.setattr(
        main,
        "get_agent_platform",
        lambda: {
            "service_manager": "systemd",
            "kernel_version": "6.1.90",
            "is_openwrt": False,
            "os": "linux",
            "arch": "x86_64",
            "distro_id": "debian",
            "distro_codename": "bookworm",
            "has_mimic": True,
        },
    )
    assert "middleware.mimic" not in main.build_capabilities()

    monkeypatch.setattr(
        main,
        "get_agent_platform",
        lambda: {
            "service_manager": "systemd",
            "kernel_version": "6.6.12",
            "is_openwrt": True,
            "os": "linux",
            "arch": "x86_64",
            "distro_id": "debian",
            "distro_codename": "bookworm",
            "has_mimic": True,
        },
    )
    assert "middleware.mimic" not in main.build_capabilities()


def test_mimic_install_capability_requires_official_release_codename(monkeypatch) -> None:
    """验证 Ubuntu Jammy 这类没有官方 mimic 资产的系统不上报安装能力。"""

    monkeypatch.setattr(main, "get_service_manager_name", lambda: "systemd")
    monkeypatch.setattr(
        main.shutil,
        "which",
        lambda binary: f"/usr/bin/{binary}" if binary in {"dpkg", "apt-get"} else None,
    )
    monkeypatch.setattr(
        main,
        "get_agent_platform",
        lambda: {
            "service_manager": "systemd",
            "kernel_version": "6.8.0-1060-aws",
            "is_openwrt": False,
            "os": "linux",
            "arch": "x86_64",
            "distro_id": "ubuntu",
            "distro_codename": "jammy",
            "has_mimic": False,
        },
    )

    assert "middleware.install.mimic" not in main.build_capabilities()


def test_mimic_runtime_capability_allows_manually_installed_unsupported_codename(monkeypatch) -> None:
    """验证没有官方安装资产的系统手工装好 mimic 后仍可上报运行能力。"""

    monkeypatch.setattr(main, "get_service_manager_name", lambda: "systemd")
    monkeypatch.setattr(main.shutil, "which", lambda binary: None)
    monkeypatch.setattr(
        main,
        "get_agent_platform",
        lambda: {
            "service_manager": "systemd",
            "kernel_version": "6.8.0-1060-aws",
            "is_openwrt": False,
            "os": "linux",
            "arch": "x86_64",
            "distro_id": "ubuntu",
            "distro_codename": "jammy",
            "has_mimic": True,
        },
    )

    capabilities = main.build_capabilities()

    assert "middleware.install.mimic" not in capabilities
    assert "middleware.mimic" in capabilities


def test_mimic_apply_renders_systemd_config(tmp_path: Path, monkeypatch) -> None:
    """验证 mimic apply 写入 Link42 管理片段并重启对应 mimic@网卡服务。"""

    commands: list[list[str]] = []
    monkeypatch.setattr(middleware, "MIMIC_CONFIG_DIR", tmp_path / "link42-mimic")
    monkeypatch.setattr(middleware, "MIMIC_SYSTEM_CONFIG_DIR", tmp_path / "mimic")
    monkeypatch.setattr(middleware, "mimic_service_backend", lambda: "systemd")
    monkeypatch.setattr(middleware.shutil, "which", lambda binary: "/usr/bin/mimic" if binary == "mimic" else None)

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
        commands.append(command)
        return command_result(command)

    monkeypatch.setattr(middleware, "run_command", fake_run_command)

    result = middleware.apply_mimic(
        {
            "instance": "link42-1-2",
            "bind_interface": "eth0",
            "local_host": "203.0.113.10",
            "local_port": 51820,
            "peer_host": "203.0.113.20",
            "peer_port": 51821,
            "xdp_mode": "skb",
            "link_type": "eth",
        }
    )
    config = (tmp_path / "mimic" / "eth0.conf").read_text(encoding="utf-8")

    assert result["changed"] is True
    assert "filter = remote=203.0.113.20:51821" in config
    assert "xdp_mode = skb" in config
    assert "ingress_ifname" not in config
    assert "egress_ifname" not in config
    assert commands == [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "mimic@eth0.service"],
        ["systemctl", "restart", "mimic@eth0.service"],
    ]


def test_mimic_snippet_uses_official_filter_format_for_ipv6() -> None:
    """验证 mimic filter 使用官方 local/remote 格式，IPv6 地址带方括号。"""

    snippet = middleware.build_mimic_snippet(
        {
            "instance": "link42-1-2",
            "bind_interface": "eth0",
            "peer_host": "2001:db8::20",
            "peer_port": 51821,
            "filter_origin": "remote",
            "xdp_mode": "skb",
            "link_type": "eth",
            "handshake_interval": 5,
            "keepalive_interval": 60,
            "padding": 8,
        }
    )

    assert "link_type = eth" in snippet
    assert "xdp_mode = skb" in snippet
    assert "handshake = 5:" in snippet
    assert "keepalive = 60:::" in snippet
    assert "padding = 8" in snippet
    assert "filter = remote=[2001:db8::20]:51821" in snippet
    assert "handshake_interval" not in snippet
    assert "keepalive_interval" not in snippet


def test_mimic_runtime_ready_rejects_half_installed_package(monkeypatch) -> None:
    """验证 mimic 半安装状态不会上报 runtime capability。"""

    def fake_run_command(command: list[str], allow_failure: bool, **kwargs: Any) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
        if command[:3] == ["dpkg-query", "-W", "-f=${db:Status-Abbrev}"]:
            package = command[-1]
            return command_result(command, stdout="iF " if package == "mimic-dkms" else "ii ")
        if command == ["systemctl", "cat", "mimic@.service"]:
            return command_result(command)
        if command == ["id", "-u", "mimic"]:
            return command_result(command)
        if command == ["modinfo", "mimic"]:
            return command_result(command, returncode=1)
        if command == ["mimic", "--version"]:
            return command_result(command, stdout="mimic 0.7.1\n")
        return command_result(command)

    monkeypatch.setattr(system.shutil, "which", lambda binary: "/usr/bin/mimic" if binary == "mimic" else None)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    health = system.mimic_runtime_health()

    assert health["ready"] is False
    assert system.mimic_runtime_ready() is False


def test_mimic_runtime_ready_accepts_complete_install(monkeypatch) -> None:
    """验证 mimic 包、unit、用户、模块和版本都正常时才上报 runtime capability。"""

    def fake_run_command(command: list[str], allow_failure: bool, **kwargs: Any) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
        if command[:3] == ["dpkg-query", "-W", "-f=${db:Status-Abbrev}"]:
            return command_result(command, stdout="ii ")
        if command in [
            ["systemctl", "cat", "mimic@.service"],
            ["id", "-u", "mimic"],
            ["modinfo", "mimic"],
        ]:
            return command_result(command)
        if command == ["mimic", "--version"]:
            return command_result(command, stdout="mimic 0.7.1\n")
        return command_result(command)

    monkeypatch.setattr(system.shutil, "which", lambda binary: "/usr/bin/mimic" if binary == "mimic" else None)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    health = system.mimic_runtime_health()

    assert health["ready"] is True
    assert system.mimic_runtime_ready() is True


def test_mimic_reboot_required_when_dkms_built_for_new_kernel() -> None:
    """验证 DKMS 已为新内核构建但当前内核未加载模块时提示重启。"""

    health = {
        "ready": False,
        "checks": {
            "binary": True,
            "packages": {"mimic": "ii", "mimic-dkms": "ii"},
            "systemd_unit": True,
            "user": True,
            "module": False,
            "dkms_status": "mimic/0.7.1, 6.12.94+deb13-amd64, x86_64: installed",
        },
    }

    assert middleware.mimic_reboot_required(health) is True


def test_agent_platform_has_mimic_uses_runtime_health(monkeypatch) -> None:
    """验证 platform.has_mimic 不再被半安装二进制误导。"""

    monkeypatch.setattr(system, "get_service_manager_name", lambda: "systemd")
    monkeypatch.setattr(system.platform, "system", lambda: "Linux")
    monkeypatch.setattr(system.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(system.platform, "release", lambda: "6.8.0")
    monkeypatch.setattr(system.platform, "libc_ver", lambda: ("glibc", "2.39"))
    monkeypatch.setattr(system, "read_os_release", lambda: {"ID": "ubuntu", "VERSION_CODENAME": "noble"})
    monkeypatch.setattr(system, "network_interfaces", lambda: ["enp3s0"])

    def fake_which(binary: str) -> str | None:
        """模拟 shutil.which 的返回结果。"""
        if binary in {"mimic", "systemctl", "ldd", "apt-get"}:
            return f"/usr/bin/{binary}"
        return None

    def fake_run_command(command: list[str], allow_failure: bool, **kwargs: Any) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
        if command == ["ldd", "--version"]:
            return command_result(command, stdout="ldd (Ubuntu GLIBC 2.39)\n")
        if command[:3] == ["dpkg-query", "-W", "-f=${db:Status-Abbrev}"]:
            return command_result(command, stdout="iF " if command[-1] == "mimic-dkms" else "ii ")
        if command == ["mimic", "--version"]:
            return command_result(command, stdout="mimic 0.7.1\n")
        return command_result(command, returncode=1)

    monkeypatch.setattr(system.shutil, "which", fake_which)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    platform_info = system.get_agent_platform()

    assert platform_info["mimic_binary_present"] is True
    assert platform_info["has_mimic"] is False
    assert platform_info["mimic_runtime_ready"] is False


def test_mimic_install_dependencies_include_headers_and_bubblewrap(monkeypatch) -> None:
    """验证 mimic 安装基础依赖不再被特定 kernel headers 包阻断。"""

    monkeypatch.setattr(middleware.platform, "release", lambda: "6.8.0-64-generic")

    assert middleware.mimic_install_dependency_packages() == [
        "dkms",
        "dwarves",
        "bubblewrap",
    ]
    assert middleware.mimic_kernel_header_package_groups() == [
        ["linux-headers-6.8.0-64-generic"],
        ["linux-headers-amd64"],
    ]


def test_mimic_cloud_kernel_headers_try_generic_fallback() -> None:
    """验证 cloud kernel 精确 headers 不存在时会继续尝试发行版通用 headers。"""

    assert middleware.mimic_kernel_header_package_groups("6.12.85+deb13-cloud-amd64", "x86_64") == [
        ["linux-headers-6.12.85+deb13-cloud-amd64"],
        ["linux-headers-cloud-amd64"],
        ["linux-headers-amd64"],
    ]


def test_mimic_apt_dependency_install_repairs_dpkg_and_retries(monkeypatch) -> None:
    """验证基础依赖安装遇到 dpkg 半配置错误时会自动修复并重试。"""

    commands: list[list[str]] = []
    install_attempts = 0

    def fake_run_command(
        command: list[str],
        allow_failure: bool,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
        nonlocal install_attempts
        commands.append(command)
        if command[:3] == ["apt-get", "install", "-y"] and "dkms" in command:
            install_attempts += 1
            if install_attempts == 1:
                return {
                    "command": command,
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "E: Sub-process /usr/bin/dpkg returned an error code (1)\n",
                }
        return command_result(command)

    monkeypatch.setattr(middleware, "run_command", fake_run_command)

    recorded: list[dict[str, Any]] = []
    result = middleware.run_apt_command_with_repair(
        recorded,
        ["apt-get", "install", "-y", "dkms", "dwarves", "bubblewrap"],
        {"DEBIAN_FRONTEND": "noninteractive"},
    )

    assert result["returncode"] == 0
    assert install_attempts == 2
    assert commands == [
        ["apt-get", "install", "-y", "dkms", "dwarves", "bubblewrap"],
        ["dpkg", "--configure", "-a"],
        ["apt-get", "-f", "install", "-y"],
        ["apt-get", "install", "-y", "dkms", "dwarves", "bubblewrap"],
    ]


def test_mimic_layout_and_system_config_permissions(tmp_path: Path, monkeypatch) -> None:
    """验证 /etc/mimic 和配置文件权限不受 root umask 影响。"""

    config_dir = tmp_path / "link42-mimic"
    system_config_dir = tmp_path / "mimic"
    monkeypatch.setattr(middleware, "MIMIC_CONFIG_DIR", config_dir)
    monkeypatch.setattr(middleware, "MIMIC_SYSTEM_CONFIG_DIR", system_config_dir)

    old_umask = os.umask(0o077)
    try:
        middleware.ensure_mimic_layout()
        config_path = system_config_dir / "enp3s0.conf"
        middleware.write_mimic_system_config(config_path, "filter = remote=203.0.113.20:51821\n")
    finally:
        os.umask(old_umask)

    assert oct(system_config_dir.stat().st_mode & 0o777) == "0o755"
    assert oct(config_path.stat().st_mode & 0o777) == "0o644"


def test_mimic_installer_selects_official_release_assets() -> None:
    """验证 mimic 安装器按发行版代号和架构选择官方 deb 资产。"""

    release = {
        "tag_name": "v0.7.1",
        "assets": [
            {"name": "bookworm_mimic-dkms_0.1.0_amd64.deb"},
            {"name": "bookworm_mimic_0.1.0_amd64.deb"},
            {"name": "bookworm_mimic-dkms_0.1.0_arm64.deb"},
            {"name": "bookworm_mimic_0.1.0_arm64.deb"},
            {"name": "noble_mimic_0.1.0_amd64.deb"},
        ]
    }

    selected = middleware.select_mimic_release_assets(release, "bookworm", "amd64")

    assert [asset["name"] for asset in selected] == [
        "bookworm_mimic-dkms_0.1.0_amd64.deb",
        "bookworm_mimic_0.1.0_amd64.deb",
    ]


def test_mimic_installer_reports_unsupported_official_release_codename() -> None:
    """验证官方 release 没有当前发行版资产时报告可用代号，而不是模糊缺包。"""

    release = {
        "tag_name": "v0.7.1",
        "assets": [
            {"name": "bookworm_mimic-dkms_0.7.1-1_amd64.deb"},
            {"name": "bookworm_mimic_0.7.1-1_amd64.deb"},
            {"name": "noble_mimic-dkms_0.7.1-1_amd64.deb"},
            {"name": "noble_mimic_0.7.1-1_amd64.deb"},
            {"name": "trixie_mimic-dkms_0.7.1-1_amd64.deb"},
            {"name": "trixie_mimic_0.7.1-1_amd64.deb"},
        ],
    }

    with pytest.raises(RuntimeError) as exc_info:
        middleware.select_mimic_release_assets(release, "jammy", "amd64")

    message = str(exc_info.value)
    assert "does not provide jammy amd64 packages" in message
    assert "available codenames for amd64: bookworm, noble, trixie" in message


def test_mimic_github_proxy_wraps_download_url() -> None:
    """验证 GitHub 代理 URL 会直接前缀包装官方 GitHub URL。"""

    assert (
        middleware.proxied_url("https://github.com/hack3ric/mimic/releases/download/v1/a.deb", "https://gh.example.com/")
        == "https://gh.example.com/https://github.com/hack3ric/mimic/releases/download/v1/a.deb"
    )
    assert middleware.validate_proxy_url(" https://gh.example.com ") == "https://gh.example.com/"


def test_mimic_fetch_release_falls_back_to_proxy(monkeypatch) -> None:
    """验证直连 GitHub API 失败时会尝试用户配置的代理。"""

    requested_urls: list[str] = []

    class FakeResponse:
        """模拟 HTTP 响应上下文对象。"""
        def __enter__(self) -> "FakeResponse":
            """进入模拟响应上下文。"""
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
            """退出模拟响应上下文。"""
            return None

        def read(self) -> bytes:
            """返回模拟响应体。"""
            return b'{"tag_name":"v1.0.0","prerelease":false,"assets":[]}'

    def fake_urlopen(request_obj: Any, timeout: int) -> FakeResponse:
        """模拟 urlopen 网络请求。"""
        url = request_obj.full_url
        requested_urls.append(url)
        if url.startswith("https://api.github.com/"):
            raise OSError("blocked")
        return FakeResponse()

    monkeypatch.setattr(middleware.request, "urlopen", fake_urlopen)

    release = middleware.fetch_github_release("hack3ric/mimic", False, "https://gh.example.com/")

    assert release["tag_name"] == "v1.0.0"
    assert requested_urls == [
        "https://api.github.com/repos/hack3ric/mimic/releases/latest",
        "https://gh.example.com/https://api.github.com/repos/hack3ric/mimic/releases/latest",
    ]


def test_agent_main_reports_401_without_traceback(monkeypatch, capsys) -> None:
    """验证 Agent 凭据错误时输出明确提示，而不是持续刷 traceback。"""

    class FakeClient:
        """模拟 AgentClient 与主控交互。"""
        def __init__(self, config: AgentConfig) -> None:
            """初始化测试替身对象。"""
            self.config = config

        def register(self, hostname: str, capabilities: list[str], platform: dict[str, Any]) -> None:
            """模拟 Agent 注册请求。"""
            raise AgentHttpError(401, "/api/agent/register", '{"detail":"invalid agent credentials"}')

    sleep_calls = 0

    def fake_sleep(seconds: int) -> None:
        """模拟 sleep 并控制测试轮询退出。"""
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls >= 1:
            raise KeyboardInterrupt

    monkeypatch.setattr(main, "load_config_from_env", lambda: AgentConfig("https://controller", 1, "bad-token"))
    monkeypatch.setattr(main, "AgentClient", FakeClient)
    monkeypatch.setattr(main, "get_hostname", lambda: "node-a")
    monkeypatch.setattr(main, "build_capabilities", lambda platform_info=None: ["wireguard"])
    monkeypatch.setattr(main, "get_agent_platform", lambda: {})
    monkeypatch.setattr(main.time, "sleep", fake_sleep)

    try:
        main.main()
    except KeyboardInterrupt:
        pass

    output = capsys.readouterr().out
    assert "agent authentication failed" in output
    assert "Traceback" not in output


def test_agent_install_script_openwrt_init_defines_rc_common_hooks() -> None:
    """验证 OpenWrt Agent 安装脚本生成必要 rc.common 钩子，避免成功时输出误导噪音。"""

    script = Path("deploy/sh/link42-agent.sh").read_text(encoding="utf-8")

    assert "install_openwrt_service()" in script
    assert "stop_service()" in script
    assert "reload_service()" in script
    assert "status_service()" in script


def test_agent_install_script_openwrt_checks_split_python_https_packages() -> None:
    """验证 OpenWrt 安装脚本会补齐 Python HTTPS/IDNA 所需拆分包。"""

    script = Path("deploy/sh/link42-agent.sh").read_text(encoding="utf-8")

    assert "import ssl" in script
    assert "python3-openssl" in script
    assert "import encodings.idna" in script
    assert "python3-codecs" in script


def test_agent_install_script_explicit_env_overrides_existing_env_file() -> None:
    """验证覆盖安装时命令行传入的新节点凭据优先于旧 agent.env。"""

    script = Path("deploy/sh/link42-agent.sh").read_text(encoding="utf-8")

    assert 'INPUT_LINK42_AGENT_TOKEN="${LINK42_AGENT_TOKEN-}"' in script
    assert '. "$ENV_FILE"' in script
    assert 'LINK42_AGENT_TOKEN="$INPUT_LINK42_AGENT_TOKEN"' in script
    assert script.index('INPUT_LINK42_AGENT_TOKEN="${LINK42_AGENT_TOKEN-}"') < script.index('. "$ENV_FILE"')
    assert script.index('. "$ENV_FILE"') < script.index('LINK42_AGENT_TOKEN="$INPUT_LINK42_AGENT_TOKEN"')


def test_agent_uninstall_script_removes_link42_middleware() -> None:
    """验证 Agent 卸载会清理 Link42 管理的中间层残留。"""

    script = Path("deploy/sh/link42-agent.sh").read_text(encoding="utf-8")

    assert "uninstall_middleware()" in script
    assert "uninstall_udp2raw_systemd" in script
    assert "uninstall_udp2raw_openwrt" in script
    assert "uninstall_mimic_systemd" in script
    assert "systemctl list-units --all 'link42-udp2raw-*.service'" in script
    assert "rm -f /etc/systemd/system/link42-udp2raw-server@.service" in script
    assert "rm -f /etc/systemd/system/link42-udp2raw-client@.service" in script
    assert "for script in /etc/init.d/link42-udp2raw-*;" in script
    assert 'systemctl disable --now "mimic@$iface.service"' in script
    assert 'rm -f "$MIMIC_SYSTEM_CONFIG_DIR/$iface.conf"' in script
    assert 'rm -rf "$UDP2RAW_CONFIG_DIR"' in script
    assert 'rm -rf "$MIMIC_CONFIG_DIR"' in script
    assert 'rm -f "$UDP2RAW_BIN"' in script
    assert "LINK42_KEEP_MIDDLEWARE=1" in script
    assert script.index("uninstall_middleware()") < script.index('rm -f "$BIN_PATH"')


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
        """模拟 Agent 系统命令执行器。"""
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
        """模拟 Agent 系统命令执行器。"""
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
        """模拟 Agent 系统命令执行器。"""
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
        """模拟二进制资产下载。"""
        target.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
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
        """模拟 Agent 系统命令执行器。"""
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
        """模拟 Agent 系统命令执行器。"""
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
        """模拟 Agent 系统命令执行器。"""
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
        """模拟 Agent 系统命令执行器。"""
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
        """模拟 Agent 系统命令执行器。"""
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
        """模拟 Agent 系统命令执行器。"""
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
        """模拟 Agent 系统命令执行器。"""
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


def test_apply_config_cleans_previous_interface_name(tmp_path: Path, monkeypatch) -> None:
    """验证接口改名部署时会先关闭并删除旧接口配置。"""

    commands: list[list[str]] = []
    wg_old_running = True

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
        nonlocal wg_old_running
        commands.append(command)
        if command == ["wg", "show", "wg-old"]:
            return command_result(command) if wg_old_running else command_result(command, returncode=1)
        if command[:2] == ["wg-quick", "down"]:
            if command[2] == "wg-old":
                wg_old_running = False
            return command_result(command)
        if command[:2] == ["wg-quick", "up"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=False, openrc=False)
    monkeypatch.setattr(system, "run_command", fake_run_command)
    old_config = tmp_path / "wg-old.conf"
    old_config.write_text("old-config\n", encoding="utf-8")

    result = system.apply_wireguard_config(
        {
            "interface_name": "wg-new",
            "previous_interface_name": "wg-old",
            "config": "[Interface]\nPrivateKey = private\n",
        },
        wireguard_dir=str(tmp_path),
    )

    assert ["wg", "show", "wg-old"] in commands
    assert ["wg-quick", "down", "wg-old"] in commands
    assert ["wg-quick", "down", "wg-new"] in commands
    assert ["wg-quick", "up", "wg-new"] in commands
    assert not old_config.exists()
    assert (tmp_path / "wg-new.conf").exists()
    assert result["rename_cleanup"]["delete_config"]["changed"] is True


def test_apply_config_uses_systemd_enable_and_restart_when_requested(tmp_path: Path, monkeypatch) -> None:
    """验证新受管连接会通过 systemd 启动并启用开机自启。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
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
    running = True

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
        nonlocal running
        commands.append(command)
        if command == ["wg", "show", "wg0"]:
            return command_result(command) if running else command_result(command, returncode=1)
        if command == ["systemctl", "is-active", "wg-quick@wg0.service"]:
            return command_result(command, stdout="active\n")
        if command == ["systemctl", "is-enabled", "wg-quick@wg0.service"]:
            return command_result(command, stdout="enabled\n")
        if command == ["systemctl", "stop", "wg-quick@wg0.service"]:
            running = False
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=True)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.stop_wireguard_interface({"interface_name": "wg0"})

    assert result["service"]["managed"] is True
    assert ["systemctl", "stop", "wg-quick@wg0.service"] in commands
    assert ["wg-quick", "down", "wg0"] not in commands


def test_delete_wireguard_config_disables_systemd_service(tmp_path: Path, monkeypatch) -> None:
    """验证删除 WireGuard 配置时会同步禁用残留的 systemd wg-quick 服务。"""

    commands: list[list[str]] = []
    target = tmp_path / "wg0.conf"
    target.write_text("[Interface]\nPrivateKey = private\n", encoding="utf-8")

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟已停止但仍 enable 的 wg-quick systemd 服务。"""

        commands.append(command)
        if command == ["wg", "show", "wg0"]:
            return command_result(command, returncode=1)
        if command == ["systemctl", "is-active", "wg-quick@wg0.service"]:
            return command_result(command, returncode=3, stdout="inactive\n")
        if command == ["systemctl", "is-enabled", "wg-quick@wg0.service"]:
            return command_result(command, stdout="enabled\n")
        if command == ["systemctl", "disable", "--now", "wg-quick@wg0.service"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=True)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.delete_wireguard_config({"interface_name": "wg0"}, wireguard_dir=str(tmp_path))

    assert result["changed"] is True
    assert result["service_disable"]["returncode"] == 0
    assert not target.exists()
    assert ["systemctl", "disable", "--now", "wg-quick@wg0.service"] in commands


def test_apply_config_uses_openrc_when_service_is_managed(tmp_path: Path, monkeypatch) -> None:
    """验证 OpenRC 已管理接口下发时通过 rc-service restart。"""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
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
        """模拟 Agent 系统命令执行器。"""
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


def test_apply_config_creates_openrc_wg_quick_symlink_when_missing(tmp_path: Path, monkeypatch) -> None:
    """验证 Alpine 只有 wg-quick 模板服务时会生成接口软链接并启动。"""

    commands: list[list[str]] = []
    init_dir = tmp_path / "init.d"
    init_dir.mkdir()
    template = init_dir / "wg-quick"
    template.write_text("#!/sbin/openrc-run\n", encoding="utf-8")

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
        commands.append(command)
        if command[:2] == ["rc-service", "--exists"]:
            return command_result(command, returncode=1)
        if command == ["rc-service", "wg-quick.wg0", "status"]:
            return command_result(command, returncode=3, stdout="stopped\n")
        if command == ["rc-update", "show", "default"]:
            return command_result(command, stdout="")
        if command == ["rc-update", "add", "wg-quick.wg0", "default"]:
            return command_result(command)
        if command == ["rc-service", "wg-quick.wg0", "restart"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=False, openrc=True)
    monkeypatch.setattr(service_manager, "OPENRC_INIT_DIR", init_dir)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.apply_wireguard_config(
        {"interface_name": "wg0", "config": "[Interface]\nPrivateKey = private\n", "enable_on_boot": True},
        wireguard_dir=str(tmp_path),
    )

    script = init_dir / "wg-quick.wg0"
    assert result["service"]["manager"] == "openrc"
    assert script.is_symlink()
    assert script.resolve() == template
    assert ["rc-update", "add", "wg-quick.wg0", "default"] in commands
    assert ["rc-service", "wg-quick.wg0", "restart"] in commands


def test_apply_config_creates_link42_openrc_service_without_template(tmp_path: Path, monkeypatch) -> None:
    """验证没有发行版 wg-quick 模板时仍能生成 Link42 自管服务。"""

    commands: list[list[str]] = []
    init_dir = tmp_path / "init.d"
    init_dir.mkdir()

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
        commands.append(command)
        if command[:2] == ["rc-service", "--exists"]:
            return command_result(command, returncode=1)
        if command == ["rc-service", "link42-wg-quick.wg0", "status"]:
            return command_result(command, returncode=3, stdout="stopped\n")
        if command == ["rc-update", "show", "default"]:
            return command_result(command, stdout="")
        if command == ["rc-update", "add", "link42-wg-quick.wg0", "default"]:
            return command_result(command)
        if command == ["rc-service", "link42-wg-quick.wg0", "restart"]:
            return command_result(command)
        raise AssertionError(f"unexpected command: {command}")

    use_service_binaries(monkeypatch, systemd=False, openrc=True)
    monkeypatch.setattr(service_manager, "OPENRC_INIT_DIR", init_dir)
    monkeypatch.setattr(system, "run_command", fake_run_command)

    result = system.apply_wireguard_config(
        {"interface_name": "wg0", "config": "[Interface]\nPrivateKey = private\n", "enable_on_boot": True},
        wireguard_dir=str(tmp_path),
    )

    script = init_dir / "link42-wg-quick.wg0"
    assert result["service"]["manager"] == "openrc"
    assert script.exists()
    assert "wg-quick up wg0" in script.read_text(encoding="utf-8")
    assert ["rc-update", "add", "link42-wg-quick.wg0", "default"] in commands
    assert ["rc-service", "link42-wg-quick.wg0", "restart"] in commands


def test_stop_interface_uses_openrc_for_managed_service(monkeypatch) -> None:
    """验证 OpenRC 管理接口停止时使用 rc-service stop。"""

    commands: list[list[str]] = []
    running = True

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
        nonlocal running
        commands.append(command)
        if command == ["rc-service", "--exists", "wg-quick@wg0"]:
            return command_result(command)
        if command == ["wg", "show", "wg0"]:
            return command_result(command) if running else command_result(command, returncode=1)
        if command == ["rc-service", "wg-quick@wg0", "status"]:
            return command_result(command)
        if command == ["rc-update", "show", "default"]:
            return command_result(command, stdout="wg-quick@wg0 | default\n")
        if command == ["rc-service", "wg-quick@wg0", "stop"]:
            running = False
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
        """模拟 Agent 系统命令执行器。"""
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
        """模拟 AgentClient 与主控交互。"""
        def heartbeat(self) -> None:
            """模拟 Agent 心跳请求。"""
            return None

        def poll_tasks(self, capabilities: list[str] | None = None) -> list[dict[str, Any]]:
            """模拟 Agent 轮询任务。"""
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
        """模拟 AgentClient 与主控交互。"""
        def heartbeat(self) -> None:
            """模拟 Agent 心跳请求。"""
            return None

        def poll_tasks(self, capabilities: list[str] | None = None) -> list[dict[str, Any]]:
            """模拟 Agent 轮询任务。"""
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


def test_run_once_polls_and_reports_link_monitors(monkeypatch, tmp_path: Path) -> None:
    """验证 Agent 每轮会执行到期链路监测并上报结果。"""

    reported: list[dict[str, Any]] = []

    class FakeClient:
        """模拟 AgentClient 与主控交互。"""
        def heartbeat(self, capabilities: list[str], platform: dict[str, Any]) -> None:
            """模拟 Agent 心跳请求。"""
            assert "link.monitor" in capabilities

        def poll_tasks(self, capabilities: list[str], platform: dict[str, Any]) -> list[dict[str, Any]]:
            """模拟 Agent 轮询任务。"""
            return []

        def poll_link_monitors(self, capabilities: list[str], platform: dict[str, Any]) -> list[dict[str, Any]]:
            """模拟 Agent 轮询链路监测目标。"""
            return [{"id": 7, "target_host": "10.42.0.2", "timeout_seconds": 1}]

        def report_link_monitor_results(self, results: list[dict[str, Any]]) -> None:
            """模拟 Agent 上报链路监测结果。"""
            reported.extend(results)

    use_service_binaries(monkeypatch, systemd=True)
    monkeypatch.setattr(system, "run_command", lambda command, allow_failure: command_result(command))
    monkeypatch.setattr(main, "probe_latency", lambda target, timeout: {"success": True, "latency_ms": 12.3, "error": None, "checked_at": "2026-06-30T00:00:00"})

    main.run_once(FakeClient(), str(tmp_path))

    assert reported == [{"monitor_id": 7, "success": True, "latency_ms": 12.3, "error": None, "checked_at": "2026-06-30T00:00:00"}]


def test_probe_link_monitors_runs_in_parallel(monkeypatch) -> None:
    """验证多个链路监测目标会并发探测，避免串行等待 ping 超时。"""

    entered = 0
    lock = threading.Lock()
    both_entered = threading.Event()

    def fake_probe_latency(target: str, timeout: float) -> dict[str, Any]:
        """模拟阻塞探测，并确认第二个探测能同时进入。"""
        nonlocal entered
        with lock:
            entered += 1
            if entered == 2:
                both_entered.set()
        if not both_entered.wait(1):
            raise AssertionError("link monitor probes did not run concurrently")
        return {"success": True, "latency_ms": float(target[-1]), "error": None, "checked_at": target}

    monkeypatch.setenv("LINK42_LINK_MONITOR_WORKERS", "2")
    monkeypatch.setattr(main, "probe_latency", fake_probe_latency)

    results = main.probe_link_monitors([
        {"id": 1, "target_host": "10.0.0.1", "timeout_seconds": 1},
        {"id": 2, "target_host": "10.0.0.2", "timeout_seconds": 1},
    ])

    assert [item["monitor_id"] for item in results] == [1, 2]
    assert [item["success"] for item in results] == [True, True]


def test_background_heartbeat_can_keep_running_and_stop() -> None:
    """验证长任务后台心跳会持续发送，并能被主线程正常停止。"""

    heartbeats = 0
    first_heartbeat = threading.Event()

    class FakeClient:
        """模拟 AgentClient 心跳。"""

        def heartbeat(self, capabilities: list[str], platform: dict[str, Any]) -> None:
            """记录后台心跳调用。"""
            nonlocal heartbeats
            assert capabilities == ["wireguard"]
            assert platform == {"service_manager": "systemd"}
            heartbeats += 1
            first_heartbeat.set()

    snapshot = main.AgentSnapshot(capabilities=["wireguard"], platform={"service_manager": "systemd"})
    stop_event, thread = main.start_background_heartbeat(FakeClient(), snapshot, 0.01)
    try:
        assert first_heartbeat.wait(1)
    finally:
        stop_event.set()
        thread.join(timeout=1)

    assert heartbeats >= 1
    assert not thread.is_alive()


def test_probe_latency_parses_ping_time(monkeypatch) -> None:
    """验证 Agent 能从 ping 输出中解析延迟。"""

    monkeypatch.setattr(link_monitor.shutil, "which", lambda binary: "/bin/ping" if binary == "ping" else None)
    monkeypatch.setattr(
        link_monitor,
        "run_command",
        lambda command, allow_failure: command_result(command, stdout="64 bytes from 10.42.0.2: icmp_seq=1 ttl=64 time=23.4 ms\n"),
    )

    result = link_monitor.probe_latency("10.42.0.2", 1)

    assert result["success"] is True
    assert result["latency_ms"] == 23.4


def test_agent_platform_reports_musl_libc(monkeypatch) -> None:
    """验证 OpenWrt/musl 平台不会被误报为 glibc 资产。"""

    use_service_binaries(monkeypatch, systemd=False, openrc=False, openwrt=True, wg_quick=False)
    monkeypatch.setattr(service_manager.Path, "exists", lambda self: str(self) == service_manager.OPENWRT_WIREGUARD_PROTO)
    monkeypatch.setattr(system.platform, "system", lambda: "Linux")
    monkeypatch.setattr(system.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(system.platform, "libc_ver", lambda: ("glibc", "2.0"))
    def fake_which(binary: str) -> str | None:
        """模拟 shutil.which 的返回结果。"""
        if binary == "ldd":
            return "/usr/bin/ldd"
        if binary in {"uci", "ifup", "ifdown"}:
            return f"/sbin/{binary}"
        return None

    monkeypatch.setattr(system.shutil, "which", fake_which)

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
        """模拟 Agent 系统命令执行器。"""
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
