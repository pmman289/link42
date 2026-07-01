from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Any

from link42_common.connection_types import WIREGUARD_TASKS
from link42_agent import link_monitor, main, middleware, service_manager, system, upgrade
from link42_agent.client import AgentHttpError
from link42_agent.config import AgentConfig
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


def test_run_command_strips_pyinstaller_library_path(monkeypatch) -> None:
    """验证 PyInstaller 私有 LD_LIBRARY_PATH 不会污染 apt/dpkg 等子进程。"""

    seen: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any):
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
        "middleware.mimic.apply",
        "middleware.mimic.start",
        "middleware.mimic.stop",
        "middleware.mimic.delete",
        "middleware.mimic.status",
    ]:
        assert task_type in TASK_HANDLERS


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
            "has_mimic": True,
        },
    )
    assert "middleware.mimic" not in main.build_capabilities()


def test_mimic_apply_renders_systemd_config(tmp_path: Path, monkeypatch) -> None:
    """验证 mimic apply 写入 Link42 管理片段并重启对应 mimic@网卡服务。"""

    commands: list[list[str]] = []
    monkeypatch.setattr(middleware, "MIMIC_CONFIG_DIR", tmp_path / "link42-mimic")
    monkeypatch.setattr(middleware, "MIMIC_SYSTEM_CONFIG_DIR", tmp_path / "mimic")
    monkeypatch.setattr(middleware, "mimic_service_backend", lambda: "systemd")
    monkeypatch.setattr(middleware.shutil, "which", lambda binary: "/usr/bin/mimic" if binary == "mimic" else None)

    def fake_run_command(command: list[str], allow_failure: bool) -> dict[str, Any]:
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
        if binary in {"mimic", "systemctl", "ldd", "apt-get"}:
            return f"/usr/bin/{binary}"
        return None

    def fake_run_command(command: list[str], allow_failure: bool, **kwargs: Any) -> dict[str, Any]:
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
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"tag_name":"v1.0.0","prerelease":false,"assets":[]}'

    def fake_urlopen(request_obj: Any, timeout: int) -> FakeResponse:
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
        def __init__(self, config: AgentConfig) -> None:
            self.config = config

        def register(self, hostname: str, capabilities: list[str], platform: dict[str, Any]) -> None:
            raise AgentHttpError(401, "/api/agent/register", '{"detail":"invalid agent credentials"}')

    sleep_calls = 0

    def fake_sleep(seconds: int) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls >= 1:
            raise KeyboardInterrupt

    monkeypatch.setattr(main, "load_config_from_env", lambda: AgentConfig("https://controller", 1, "bad-token"))
    monkeypatch.setattr(main, "AgentClient", FakeClient)
    monkeypatch.setattr(main, "get_hostname", lambda: "node-a")
    monkeypatch.setattr(main, "build_capabilities", lambda: ["wireguard"])
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


def test_run_once_polls_and_reports_link_monitors(monkeypatch, tmp_path: Path) -> None:
    """验证 Agent 每轮会执行到期链路监测并上报结果。"""

    reported: list[dict[str, Any]] = []

    class FakeClient:
        def heartbeat(self, capabilities: list[str], platform: dict[str, Any]) -> None:
            assert "link.monitor" in capabilities

        def poll_tasks(self, capabilities: list[str], platform: dict[str, Any]) -> list[dict[str, Any]]:
            return []

        def poll_link_monitors(self, capabilities: list[str], platform: dict[str, Any]) -> list[dict[str, Any]]:
            return [{"id": 7, "target_host": "10.42.0.2", "timeout_seconds": 1}]

        def report_link_monitor_results(self, results: list[dict[str, Any]]) -> None:
            reported.extend(results)

    use_service_binaries(monkeypatch, systemd=True)
    monkeypatch.setattr(system, "run_command", lambda command, allow_failure: command_result(command))
    monkeypatch.setattr(main, "probe_latency", lambda target, timeout: {"success": True, "latency_ms": 12.3, "error": None, "checked_at": "2026-06-30T00:00:00"})

    main.run_once(FakeClient(), str(tmp_path))

    assert reported == [{"monitor_id": 7, "success": True, "latency_ms": 12.3, "error": None, "checked_at": "2026-06-30T00:00:00"}]


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
