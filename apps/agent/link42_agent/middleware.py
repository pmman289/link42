from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional
from urllib import request

from .config import AgentConfig
from .service_manager import OpenWrtUciManager, detect_service_manager
from .system import kernel_newer_than, mimic_runtime_health, mimic_runtime_ready, read_os_release, run_command
from .validation import (
    atomic_write_text,
    managed_child_path,
    validate_instance_name as validate_managed_instance_name,
    validate_interface_name,
)


UDP2RAW_BIN = Path(os.getenv("LINK42_UDP2RAW_BIN", "/usr/local/bin/udp2raw"))
UDP2RAW_CONFIG_DIR = Path(os.getenv("LINK42_UDP2RAW_CONFIG_DIR", "/etc/link42/middleware/udp2raw"))
UDP2RAW_LIBEXEC = Path(os.getenv("LINK42_UDP2RAW_LIBEXEC", "/usr/local/libexec/link42-udp2raw-systemd"))
UDP2RAW_SERVICE_PREFIX = os.getenv("LINK42_UDP2RAW_SERVICE_PREFIX", "link42-udp2raw")
UDP2RAW_SERVER_UNIT = Path(
    os.getenv("LINK42_UDP2RAW_SERVER_UNIT", f"/etc/systemd/system/{UDP2RAW_SERVICE_PREFIX}-server@.service")
)
UDP2RAW_CLIENT_UNIT = Path(
    os.getenv("LINK42_UDP2RAW_CLIENT_UNIT", f"/etc/systemd/system/{UDP2RAW_SERVICE_PREFIX}-client@.service")
)
OPENWRT_INIT_DIR = Path("/etc/init.d")
MIMIC_CONFIG_DIR = Path("/etc/link42/middleware/mimic")
MIMIC_SYSTEM_CONFIG_DIR = Path("/etc/mimic")
MIMIC_BIN = Path("/usr/bin/mimic")
MIMIC_BLOCK_BEGIN = "# BEGIN Link42 managed mimic filters"
MIMIC_BLOCK_END = "# END Link42 managed mimic filters"
MIMIC_OFFICIAL_RELEASE_CODENAMES = {"bookworm", "noble", "trixie"}


def install_middleware(payload: dict[str, Any], config: AgentConfig, dry_run: bool = False) -> dict[str, Any]:
    """安装连接中间层插件资产。"""

    if payload.get("plugin") == "mimic":
        return install_mimic(payload, config, dry_run=dry_run)
    if payload.get("plugin") != "udp2raw":
        raise ValueError("unsupported middleware plugin")
    return install_udp2raw(config, dry_run=dry_run)


def install_mimic(payload: dict[str, Any], config: AgentConfig, dry_run: bool = False) -> dict[str, Any]:
    """从官方 GitHub latest release 安装 mimic。"""

    if mimic_service_backend() != "systemd":
        raise RuntimeError("mimic middleware requires a systemd Linux node")
    validate_mimic_install_environment()
    if dry_run:
        return {"changed": False, "dry_run": True, "source": "github_latest", "backend": "systemd"}
    ensure_mimic_layout()
    return install_mimic_from_github_latest(payload, dry_run=dry_run)


def install_mimic_from_github_latest(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """从 mimic 官方 GitHub release 选择、下载并安装本机匹配的 deb 包。"""

    repo = str(payload.get("repo") or "hack3ric/mimic")
    if repo != "hack3ric/mimic":
        raise ValueError("unsupported mimic release repository")
    proxy_url = validate_proxy_url(payload.get("github_proxy_url"))
    release = fetch_github_release(repo, bool(payload.get("allow_prerelease")), proxy_url)
    os_release = read_os_release()
    codename = os_release.get("VERSION_CODENAME") or os_release.get("UBUNTU_CODENAME")
    arch = deb_arch(platform.machine())
    assets = select_mimic_release_assets(release, codename, arch)
    if dry_run:
        return {
            "changed": False,
            "dry_run": True,
            "plugin": "mimic",
            "source": "github_latest",
            "release": release.get("tag_name"),
            "assets": [asset["name"] for asset in assets],
        }
    with tempfile.TemporaryDirectory(prefix="link42-mimic-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        package_paths = []
        for asset in assets:
            package_path = download_release_asset(asset, tmp_path, proxy_url)
            sha_asset = find_sha256_asset(release, asset["name"])
            sha_path = download_release_asset(sha_asset, tmp_path, proxy_url)
            verify_sha256_file(package_path, sha_path)
            package_paths.append(package_path)
        install_env = {"DEBIAN_FRONTEND": "noninteractive"}
        commands = []
        commands.append(run_command(["apt-get", "update"], True, timeout=300, env=install_env))
        repair_apt_state(commands, install_env)
        run_apt_command_with_repair(
            commands,
            ["apt-get", "install", "-y", *mimic_install_dependency_packages()],
            install_env,
            timeout=900,
        )
        for header_packages in mimic_kernel_header_package_groups():
            commands.append(run_command(["apt-get", "install", "-y", *header_packages], True, timeout=900, env=install_env))
            if commands[-1]["returncode"] == 0:
                break
        commands.append(run_command(["dpkg", "-i", *[str(path) for path in package_paths]], True, timeout=900, env=install_env))
        if commands[-1]["returncode"] != 0:
            commands.append(run_command(["apt-get", "-f", "install", "-y"], True, timeout=900, env=install_env))
            if commands[-1]["returncode"] != 0:
                commands.append(run_command(["dpkg", "--configure", "-a"], True, timeout=900, env=install_env))
                commands.append(run_command(["apt-get", "-f", "install", "-y"], True, timeout=900, env=install_env))
        commands.append(run_command(["systemctl", "daemon-reload"], True))
        health = mimic_runtime_health()
        if not health["ready"]:
            if mimic_reboot_required(health):
                return {
                    "plugin": "mimic",
                    "source": "github_latest",
                    "repo": repo,
                    "release": release.get("tag_name"),
                    "assets": [asset["name"] for asset in assets],
                    "changed": True,
                    "installed": True,
                    "ready": False,
                    "reboot_required": True,
                    "health": health,
                    "commands": commands,
                    "message": "mimic installed, but the DKMS module is built for a different installed kernel; reboot into the new kernel to enable mimic",
                }
            raise RuntimeError(f"mimic installation did not pass health checks: {json.dumps(health, ensure_ascii=False)}")
        version_result = run_command(["mimic", "--version"], False)
    return {
        "plugin": "mimic",
        "source": "github_latest",
        "repo": repo,
        "release": release.get("tag_name"),
        "assets": [asset["name"] for asset in assets],
        "changed": True,
        "installed": True,
        "version": version_result.get("stdout", "").strip(),
        "commands": commands + [version_result],
    }


def mimic_reboot_required(health: dict[str, Any]) -> bool:
    """判断 mimic 是否已装好但需要重启进 DKMS 已构建的内核。"""

    checks = health.get("checks") or {}
    packages = checks.get("packages") or {}
    dkms_status = str(checks.get("dkms_status") or "")
    return (
        bool(checks.get("binary"))
        and all(packages.get(package) == "ii" for package in ["mimic", "mimic-dkms"])
        and bool(checks.get("systemd_unit"))
        and bool(checks.get("user"))
        and not bool(checks.get("module"))
        and ": installed" in dkms_status
    )


def repair_apt_state(commands: list[dict[str, Any]], install_env: dict[str, str]) -> None:
    """修复上一次 apt/dpkg 半安装状态，避免基础依赖安装被历史残留打断。"""

    commands.append(run_command(["dpkg", "--configure", "-a"], True, timeout=900, env=install_env))
    commands.append(run_command(["apt-get", "-f", "install", "-y"], True, timeout=900, env=install_env))


def run_apt_command_with_repair(
    commands: list[dict[str, Any]],
    command: list[str],
    install_env: dict[str, str],
    *,
    timeout: int = 900,
) -> dict[str, Any]:
    """执行关键 apt 命令；失败时修复 dpkg 状态并重试一次。"""

    result = run_command(command, True, timeout=timeout, env=install_env)
    commands.append(result)
    if result["returncode"] == 0:
        return result
    repair_apt_state(commands, install_env)
    retry = run_command(command, True, timeout=timeout, env=install_env)
    commands.append(retry)
    if retry["returncode"] != 0:
        raise RuntimeError(command_failure_message(retry))
    return retry


def command_failure_message(result: dict[str, Any]) -> str:
    """把失败的系统命令结果整理成可读异常信息。"""

    output = "\n".join(str(result.get(key) or "").strip() for key in ["stdout", "stderr"] if result.get(key))
    suffix = f"\n{output}" if output else ""
    return f"command failed: {' '.join(result['command'])}{suffix}"


def validate_mimic_install_environment() -> None:
    """校验当前系统是否满足官方 mimic deb 安装的基础条件。"""

    os_release = read_os_release()
    distro = (os_release.get("ID") or "").lower()
    if distro not in {"debian", "ubuntu"}:
        raise RuntimeError("mimic installer currently supports Debian/Ubuntu only")
    if not kernel_newer_than(platform.release(), 6, 1):
        raise RuntimeError("mimic install requires Linux kernel newer than 6.1")
    if not shutil.which("dpkg") or not shutil.which("apt-get"):
        raise RuntimeError("mimic install requires dpkg and apt-get")
    deb_arch(platform.machine())


def mimic_install_dependency_packages() -> list[str]:
    """返回 mimic DKMS 构建所需的必装基础依赖。"""

    return ["dkms", "dwarves", "bubblewrap"]


def mimic_kernel_header_package_groups(release: str | None = None, machine: str | None = None) -> list[list[str]]:
    """返回可尝试安装的 kernel headers 包组合。

    云厂商或发行版 cloud kernel 不一定提供精确的 linux-headers-$(uname -r) 包。
    headers 是 DKMS 能否构建的关键条件，但不能阻断基础依赖和 mimic 包安装流程；
    后续 runtime health 会明确暴露模块是否可用。
    """

    kernel_release = release or platform.release()
    arch = deb_arch(machine or platform.machine())
    groups = [[f"linux-headers-{kernel_release}"]]
    if "cloud" in kernel_release:
        groups.append([f"linux-headers-cloud-{arch}"])
    groups.append([f"linux-headers-{arch}"])
    return groups


def deb_arch(machine: str) -> str:
    """把 platform.machine() 结果转换为 Debian 包架构名。"""

    machine = machine.lower()
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    raise RuntimeError(f"unsupported mimic architecture: {machine}")


def validate_proxy_url(value: Any) -> str | None:
    """校验可选 GitHub 代理前缀，空值返回空。"""

    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if any(char.isspace() or char in "'\"" for char in text):
        raise ValueError("github proxy url must not contain whitespace or quotes")
    if not re.match(r"^https?://[^/]+", text):
        raise ValueError("github proxy url must start with http:// or https://")
    return text.rstrip("/") + "/"


def proxied_url(url: str, proxy_url: str | None) -> str:
    """按配置把下载地址转换为直连或代理后的地址。"""

    return f"{proxy_url}{url}" if proxy_url else url


def fetch_github_release(repo: str, allow_prerelease: bool, proxy_url: str | None) -> dict[str, Any]:
    """读取 GitHub latest release 元数据，代理失败时保留错误信息。"""

    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    errors: list[str] = []
    for url in [api_url, proxied_url(api_url, proxy_url)] if proxy_url else [api_url]:
        try:
            request_obj = request.Request(
                url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "link42-agent",
                },
            )
            with request.urlopen(request_obj, timeout=60) as response:
                release = json.loads(response.read().decode("utf-8"))
            if release.get("prerelease") and not allow_prerelease:
                raise RuntimeError("latest mimic release is a prerelease")
            return release
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
    raise RuntimeError(f"failed to fetch GitHub release: {'; '.join(errors)}")


def select_mimic_release_assets(release: dict[str, Any], codename: str | None, arch: str) -> list[dict[str, Any]]:
    """从 release assets 中选择当前发行版和架构需要的 mimic 包。"""

    if not codename:
        raise RuntimeError("missing distro codename for mimic release asset selection")
    assets = release.get("assets") or []
    available_codenames = available_mimic_release_codenames(assets, arch)
    selected = []
    for package in ["mimic-dkms", "mimic"]:
        pattern = re.compile(rf"^{re.escape(codename)}_{re.escape(package)}_.+_{re.escape(arch)}\.deb$")
        matches = [asset for asset in assets if pattern.match(str(asset.get("name") or ""))]
        if not matches:
            if codename not in available_codenames:
                available = ", ".join(available_codenames) or "none"
                raise RuntimeError(
                    f"official mimic release {release.get('tag_name') or ''} does not provide {codename} {arch} packages; "
                    f"available codenames for {arch}: {available}"
                )
            raise RuntimeError(f"missing official mimic release asset for {codename} {package} {arch}")
        selected.append(matches[0])
    return selected


def available_mimic_release_codenames(assets: list[dict[str, Any]], arch: str) -> list[str]:
    """返回 release 中当前架构可安装的 mimic 发行版代号。"""

    codenames: set[str] = set()
    for asset in assets:
        name = str(asset.get("name") or "")
        match = re.match(rf"^([a-z0-9]+)_mimic(?:-dkms)?_.+_{re.escape(arch)}\.deb$", name)
        if match:
            codenames.add(match.group(1))
    return sorted(codenames)


def mimic_official_release_codename_supported(codename: str | None) -> bool:
    """判断当前发行版代号是否有官方 mimic 预编译安装资产。"""

    return bool(codename and codename.lower() in MIMIC_OFFICIAL_RELEASE_CODENAMES)


def find_sha256_asset(release: dict[str, Any], package_name: str) -> dict[str, Any]:
    """查找指定 deb 包对应的 sha256 校验文件。"""

    sha_name = f"{package_name}.sha256"
    for asset in release.get("assets") or []:
        if asset.get("name") == sha_name:
            return asset
    raise RuntimeError(f"missing sha256 asset for {package_name}")


def download_release_asset(asset: dict[str, Any], directory: Path, proxy_url: str | None) -> Path:
    """下载 release asset 到临时目录，并限制文件名和来源地址。"""

    name = str(asset.get("name") or "")
    if not re.fullmatch(r"[A-Za-z0-9_.:+~-]+", name):
        raise ValueError("release asset name contains unsupported characters")
    url = str(asset.get("browser_download_url") or "")
    if not url.startswith("https://github.com/"):
        raise ValueError("release asset download url must be a GitHub URL")
    target = directory / name
    with request.urlopen(proxied_url(url, proxy_url), timeout=180) as response:
        target.write_bytes(response.read())
    return target


def verify_sha256_file(package_path: Path, sha_path: Path) -> None:
    """使用旁路 sha256 文件校验下载后的 deb 包。"""

    expected = sha_path.read_text(encoding="utf-8").split()[0].strip().lower()
    actual = hashlib.sha256(package_path.read_bytes()).hexdigest()
    if not expected or actual != expected:
        raise RuntimeError(f"sha256 mismatch for {package_path.name}")


def apply_mimic(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """写入 mimic 单连接 filter 片段并重启对应网卡服务。"""

    if mimic_service_backend() != "systemd":
        raise RuntimeError("mimic middleware requires a systemd Linux node")
    instance = validate_instance_name(str(payload["instance"]))
    bind_interface = validate_mimic_interface(str(payload["bind_interface"]))
    snippet = build_mimic_snippet(payload)
    config_path = mimic_system_config_path(bind_interface)
    if dry_run:
        rendered = render_mimic_config(bind_interface, instance, snippet)
        return {
            "changed": False,
            "dry_run": True,
            "instance": instance,
            "bind_interface": bind_interface,
            "config_path": str(config_path),
            "config": rendered,
        }
    if not shutil.which("mimic"):
        raise RuntimeError("mimic is not installed on this node")
    ensure_mimic_layout()
    instance_path = mimic_instance_path(bind_interface, instance)
    instance_path.parent.mkdir(parents=True, exist_ok=True)
    instance_path.write_text(snippet, encoding="utf-8")
    write_mimic_system_config(config_path, render_mimic_config(bind_interface))
    commands = [
        run_command(["systemctl", "daemon-reload"], False),
        run_command(["systemctl", "enable", mimic_unit_name(bind_interface)], False),
        run_command(["systemctl", "restart", mimic_unit_name(bind_interface)], False),
    ]
    return {
        "changed": True,
        "instance": instance,
        "bind_interface": bind_interface,
        "config_path": str(config_path),
        "commands": commands,
    }


def start_mimic(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """启动指定 mimic 绑定网卡的 systemd 服务。"""

    return mimic_service_action(payload, "start", dry_run=dry_run)


def stop_mimic(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """停止指定 mimic 绑定网卡的 systemd 服务。"""

    return mimic_service_action(payload, "stop", dry_run=dry_run)


def delete_mimic(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """删除 Link42 管理的 mimic 实例片段，并按剩余配置决定重启或停用服务。"""

    instance = validate_instance_name(str(payload["instance"]))
    bind_interface = validate_mimic_interface(str(payload["bind_interface"]))
    config_path = mimic_system_config_path(bind_interface)
    if dry_run:
        return {"changed": False, "dry_run": True, "instance": instance, "bind_interface": bind_interface}
    instance_path = mimic_instance_path(bind_interface, instance)
    instance_path.unlink(missing_ok=True)
    rendered = render_mimic_config(bind_interface)
    commands: list[dict[str, Any]] = []
    if rendered.strip():
        write_mimic_system_config(config_path, rendered)
        commands.append(run_command(["systemctl", "restart", mimic_unit_name(bind_interface)], True))
    else:
        config_path.unlink(missing_ok=True)
        commands.append(run_command(["systemctl", "disable", "--now", mimic_unit_name(bind_interface)], True))
    return {"changed": True, "instance": instance, "bind_interface": bind_interface, "commands": commands}


def status_mimic(payload: dict[str, Any]) -> dict[str, Any]:
    """查询指定 mimic 绑定网卡服务是否处于 active 状态。"""

    bind_interface = validate_mimic_interface(str(payload["bind_interface"]))
    return run_command(["systemctl", "is-active", mimic_unit_name(bind_interface)], True)


def apply_udp2raw(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """写入 udp2raw 单实例配置并重启服务。"""

    args = build_udp2raw_args(payload)
    mode = validate_mode(str(payload["mode"]))
    instance = validate_instance_name(str(payload["instance"]))
    config_file = config_file_for_mode(mode)
    if dry_run:
        return {"changed": False, "dry_run": True, "args": args, "config_file": str(config_file)}
    ensure_udp2raw_layout()
    upsert_instance(config_file, instance, args)
    commands = apply_service(mode, instance, payload)
    return {"changed": True, "mode": mode, "instance": instance, "config_file": str(config_file), "commands": commands}


def start_udp2raw(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """启动指定 udp2raw 实例。"""

    return service_action(payload, "start", dry_run=dry_run)


def stop_udp2raw(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """停止指定 udp2raw 实例。"""

    return service_action(payload, "stop", dry_run=dry_run)


def delete_udp2raw(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """删除指定 udp2raw 实例配置和对应服务。"""

    instance = validate_instance_name(str(payload["instance"]))
    modes = payload_modes(payload)
    if dry_run:
        return {"changed": False, "dry_run": True, "instance": instance, "modes": modes}
    results: list[dict[str, Any]] = []
    for mode in modes:
        results.extend(delete_service(mode, instance))
        remove_instance(config_file_for_mode(mode), instance)
    results.extend(reload_services())
    return {"changed": True, "instance": instance, "modes": modes, "commands": results}


def status_udp2raw(payload: dict[str, Any]) -> dict[str, Any]:
    """查询指定 udp2raw 实例在各角色配置中的服务状态。"""

    instance = validate_instance_name(str(payload["instance"]))
    return {mode: service_status(mode, instance) for mode in payload_modes(payload)}


def install_udp2raw(config: AgentConfig, dry_run: bool = False) -> dict[str, Any]:
    """从主控下载匹配架构的 udp2raw 二进制并安装本机服务后端。"""

    backend = udp2raw_service_backend()
    if backend not in ["systemd", "openwrt-procd"]:
        raise RuntimeError("udp2raw middleware requires systemd or OpenWrt procd")
    asset = detect_udp2raw_asset()
    if dry_run:
        return {"changed": False, "dry_run": True, "asset": asset, "backend": backend}
    ensure_udp2raw_layout()
    download_asset(config, asset, UDP2RAW_BIN)
    UDP2RAW_BIN.chmod(0o755)
    if backend == "systemd":
        write_wrapper()
        write_units()
    result = reload_services()
    return {"changed": True, "asset": asset, "binary": str(UDP2RAW_BIN), "backend": backend, "service_reload": result}


def detect_udp2raw_asset() -> str:
    """按 CPU 架构和 AES 能力选择主控内置的 udp2raw 二进制资产。"""

    machine = platform.machine().lower()
    if machine in ["x86_64", "amd64"]:
        return "udp2raw_amd64_hw_aes" if cpu_has_aes() else "udp2raw_amd64"
    if machine in ["i386", "i486", "i586", "i686"]:
        return "udp2raw_x86_asm_aes" if cpu_has_aes() else "udp2raw_x86"
    if machine in ["aarch64", "arm64"] or machine.startswith("arm"):
        return "udp2raw_arm"
    if machine.startswith("mips"):
        return "udp2raw_mips24kc_le" if machine_endian() == "le" else "udp2raw_mips24kc_be"
    raise RuntimeError(f"unsupported udp2raw architecture: {machine}")


def cpu_has_aes() -> bool:
    """从 /proc/cpuinfo 判断当前 CPU 是否声明 AES 指令能力。"""

    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.exists():
        return False
    return " aes " in f" {cpuinfo.read_text(encoding='utf-8', errors='ignore').lower()} "


def machine_endian() -> str:
    """返回当前机器字节序，用于选择 mips udp2raw 资产。"""

    return "le" if os.sys.byteorder == "little" else "be"


def download_asset(config: AgentConfig, asset: str, target: Path) -> None:
    """从主控下载中间层内置二进制资产并原子替换目标文件。"""

    url = f"/api/agent/plugins/udp2raw/assets/{asset}"
    fd, tmp_name = tempfile.mkstemp(prefix="udp2raw-", dir=str(target.parent))
    try:
        with request.urlopen(f"{config.server_url}{url}", timeout=60) as response:
            with os.fdopen(fd, "wb") as handle:
                shutil.copyfileobj(response, handle)
        Path(tmp_name).replace(target)
    finally:
        if Path(tmp_name).exists():
            Path(tmp_name).unlink()


def ensure_udp2raw_layout() -> None:
    """创建 udp2raw 二进制、配置和服务文件需要的目录结构。"""

    backend = udp2raw_service_backend()
    UDP2RAW_BIN.parent.mkdir(parents=True, exist_ok=True)
    UDP2RAW_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if backend == "systemd":
        UDP2RAW_LIBEXEC.parent.mkdir(parents=True, exist_ok=True)
        UDP2RAW_SERVER_UNIT.parent.mkdir(parents=True, exist_ok=True)
    if backend == "openwrt-procd":
        OPENWRT_INIT_DIR.mkdir(parents=True, exist_ok=True)
    for name in ["server", "client"]:
        path = UDP2RAW_CONFIG_DIR / name
        if not path.exists():
            path.write_text("", encoding="utf-8")


def write_wrapper() -> None:
    """写入 systemd 后端读取实例配置并启动 udp2raw 的包装脚本。"""

    UDP2RAW_LIBEXEC.write_text(
        """#!/bin/sh
set -eu
mode="$1"
instance="$2"
config="/etc/link42/middleware/udp2raw/$mode"
line=$(awk -v name="$instance" 'NF && $1 !~ /^#/ { key=$1; sub(/=$/, "", key); if (key == name) { sub(/^[[:space:]]*[^[:space:]=]+[[:space:]]*=?[[:space:]]*/, ""); print; found=1; exit } } END { if (!found) exit 1 }' "$config")
eval "set -- $line"
exec /usr/local/bin/udp2raw "$@"
""",
        encoding="utf-8",
    )
    UDP2RAW_LIBEXEC.chmod(0o755)


def write_units() -> None:
    """写入 systemd 模板 unit，用于管理 udp2raw server/client 实例。"""

    for mode, path in [("server", UDP2RAW_SERVER_UNIT), ("client", UDP2RAW_CLIENT_UNIT)]:
        path.write_text(
            f"""[Unit]
Description=Link42 udp2raw {mode} instance %i
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart={UDP2RAW_LIBEXEC} {mode} %i
User=root
Group=root
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
""",
            encoding="utf-8",
        )


def build_udp2raw_args(payload: dict[str, Any]) -> str:
    """把任务 payload 渲染成 udp2raw 命令行参数。"""

    mode = validate_mode(str(payload["mode"]))
    listen_host = validate_udp2raw_ip(str(payload["listen_host"]), "udp2raw listen host")
    listen_port = validate_udp2raw_port(payload["listen_port"], "udp2raw listen port")
    remote_host = validate_udp2raw_ip(str(payload["remote_host"]), "udp2raw remote host")
    remote_port = validate_udp2raw_port(payload["remote_port"], "udp2raw remote port")
    password = shell_quote(str(payload["password"]))
    raw_mode = validate_udp2raw_raw_mode(str(payload.get("raw_mode") or "faketcp"))
    cipher_mode = validate_udp2raw_cipher_mode(str(payload.get("cipher_mode") or "xor"))
    auth_mode = validate_udp2raw_auth_mode(str(payload.get("auth_mode") or "md5"))
    args = [
        "-s" if mode == "server" else "-c",
        f"-l{format_udp2raw_endpoint(listen_host, listen_port)}",
        f"-r{format_udp2raw_endpoint(remote_host, remote_port)}",
        f"-k {password}",
        f"--raw-mode {raw_mode}",
        f"--cipher-mode {cipher_mode}",
        f"--auth-mode {auth_mode}",
    ]
    if payload.get("auto_rule", True):
        args.append(auto_rule_arg())
    return " ".join(args)


def validate_udp2raw_ip(value: str, field_name: str) -> str:
    """校验 udp2raw 地址并返回压缩后的 IP 字面量。"""

    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an IPv4 or IPv6 address") from exc


def validate_udp2raw_port(value: Any, field_name: str) -> int:
    """校验 udp2raw 端口；ICMP 模式仍使用端口作为本地绑定和会话标识。"""

    port = int(value)
    if port < 1 or port > 65535:
        raise ValueError(f"{field_name} must be between 1 and 65535")
    return port


def validate_udp2raw_raw_mode(value: str) -> str:
    """限制 udp2raw raw-mode 为 Link42 支持的模式。"""

    if value not in {"faketcp", "udp", "icmp"}:
        raise ValueError("udp2raw raw mode must be faketcp, udp, or icmp")
    return value


def validate_udp2raw_cipher_mode(value: str) -> str:
    """限制 udp2raw cipher-mode 为 Link42 表单支持的模式。"""

    if value not in {"xor", "aes128cbc", "none"}:
        raise ValueError("udp2raw cipher mode must be xor, aes128cbc, or none")
    return value


def validate_udp2raw_auth_mode(value: str) -> str:
    """限制 udp2raw auth-mode 为 Link42 表单支持的模式。"""

    if value not in {"hmac_sha1", "md5", "crc32", "simple", "none"}:
        raise ValueError("udp2raw auth mode must be hmac_sha1, md5, crc32, simple, or none")
    return value


def format_udp2raw_endpoint(host: str, port: int) -> str:
    """渲染 udp2raw 的 host:port 参数，并为 IPv6 地址补方括号。"""

    ip = ipaddress.ip_address(host)
    host_text = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    return f"{host_text}:{port}"


def auto_rule_arg() -> str:
    """返回当前服务后端适用的 udp2raw 防火墙辅助参数。"""

    return "-a"


def shell_quote(value: str) -> str:
    """为写入配置文件的 shell 参数做单引号转义。"""

    return "'" + value.replace("'", "'\\''") + "'"


def config_file_for_mode(mode: str) -> Path:
    """按 udp2raw 角色返回对应实例配置文件路径。"""

    if mode not in ["server", "client"]:
        raise ValueError("udp2raw mode must be server or client")
    return UDP2RAW_CONFIG_DIR / mode


def unit_name(mode: str, instance: str) -> str:
    """生成 systemd udp2raw 实例 unit 名称。"""

    return f"{validate_service_prefix()}-{validate_mode(mode)}@{validate_instance_name(instance)}.service"


def init_name(mode: str, instance: str) -> str:
    """生成 OpenWrt procd init 脚本名称。"""

    return f"{validate_service_prefix()}-{validate_mode(mode)}-{validate_instance_name(instance)}"


def validate_service_prefix() -> str:
    """校验 udp2raw 服务前缀，允许测试环境与生产实例隔离。"""

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", UDP2RAW_SERVICE_PREFIX):
        raise ValueError("udp2raw service prefix contains unsupported characters")
    return UDP2RAW_SERVICE_PREFIX


def init_path(mode: str, instance: str) -> Path:
    """生成 OpenWrt procd init 脚本路径。"""

    return OPENWRT_INIT_DIR / init_name(mode, instance)


def validate_instance_name(instance: str) -> str:
    """校验中间层实例名只包含服务名安全字符。"""

    return validate_managed_instance_name(instance, "udp2raw instance")


def udp2raw_service_backend() -> str:
    """检测 udp2raw 应使用 systemd、OpenWrt procd 还是不支持。"""

    manager = detect_service_manager(run_command)
    if isinstance(manager, OpenWrtUciManager):
        return "openwrt-procd"
    if shutil.which("systemctl"):
        return "systemd"
    return "unsupported"


def service_command(mode: str, instance: str, action: str) -> list[str]:
    """生成当前后端执行 udp2raw 服务动作的命令。"""

    if udp2raw_service_backend() == "openwrt-procd":
        return [str(init_path(mode, instance)), action]
    return ["systemctl", action, unit_name(mode, instance)]


def apply_service(mode: str, instance: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    """启用并重启指定 udp2raw 实例服务。"""

    if udp2raw_service_backend() == "openwrt-procd":
        write_openwrt_init(mode, instance)
        return run_openwrt_service_commands(
            [
                [str(init_path(mode, instance)), "enable"],
                [str(init_path(mode, instance)), "restart"],
            ],
            allow_failure=False,
        )
    return [
        run_command(["systemctl", "daemon-reload"], False),
        run_command(["systemctl", "enable", unit_name(mode, instance)], False),
        run_command(["systemctl", "restart", unit_name(mode, instance)], False),
    ]


def delete_service(mode: str, instance: str) -> list[dict[str, Any]]:
    """停止、禁用并清理指定 udp2raw 实例服务。"""

    if udp2raw_service_backend() == "openwrt-procd":
        path = init_path(mode, instance)
        results = run_openwrt_service_commands(
            [
                [str(path), "stop"],
                [str(path), "disable"],
            ],
            allow_failure=True,
        )
        path.unlink(missing_ok=True)
        return results
    return [run_command(["systemctl", "disable", "--now", unit_name(mode, instance)], True)]


def reload_services() -> list[dict[str, Any]]:
    """在需要时重新加载服务管理器配置。"""

    if udp2raw_service_backend() == "systemd":
        return [run_command(["systemctl", "daemon-reload"], False)]
    return []


def service_status(mode: str, instance: str) -> dict[str, Any]:
    """查询指定 udp2raw 实例服务状态。"""

    if udp2raw_service_backend() == "openwrt-procd":
        return normalize_openwrt_result(run_command([str(init_path(mode, instance)), "status"], True))
    return run_command(["systemctl", "is-active", unit_name(mode, instance)], True)


def run_openwrt_service_commands(commands: list[list[str]], allow_failure: bool) -> list[dict[str, Any]]:
    """批量执行 OpenWrt init 脚本命令并归一化返回结果。"""

    return [normalize_openwrt_result(run_command(command, allow_failure)) for command in commands]


def normalize_openwrt_result(result: dict[str, Any]) -> dict[str, Any]:
    """清理 rc.common 成功时仍输出到 stderr 的误导性文本。"""

    stderr = str(result.get("stderr") or "")
    if result.get("returncode") == 0 and stderr.strip().rstrip(".") == "Command failed: Not found":
        return {**result, "stderr": ""}
    return result


def payload_from_config(mode: str, instance: str) -> Optional[dict[str, Any]]:
    """从本机 udp2raw 配置反解析指定实例 payload。"""

    args = instance_args_from_config(config_file_for_mode(mode), instance)
    if not args:
        return None
    return parse_udp2raw_args(mode, instance, args)


def instance_args_from_config(path: Path, instance: str) -> Optional[str]:
    """从实例配置文件中读取指定实例的命令行参数。"""

    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split(maxsplit=1)
        key = parts[0].removesuffix("=") if parts else ""
        if key == instance and len(parts) > 1:
            return parts[1]
    return None


def parse_udp2raw_args(mode: str, instance: str, args: str) -> dict[str, Any]:
    """把已有 udp2raw 命令行参数反解析为结构化 payload。"""

    payload: dict[str, Any] = {"mode": mode, "instance": instance, "auto_rule": "-a" in args or "--keep-rule" in args}
    tokens = args.split()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("-l"):
            payload["listen_host"], payload["listen_port"] = split_host_port(token[2:])
        elif token.startswith("-r"):
            payload["remote_host"], payload["remote_port"] = split_host_port(token[2:])
        elif token == "--raw-mode" and index + 1 < len(tokens):
            payload["raw_mode"] = tokens[index + 1]
            index += 1
        elif token == "--cipher-mode" and index + 1 < len(tokens):
            payload["cipher_mode"] = tokens[index + 1]
            index += 1
        elif token == "--auth-mode" and index + 1 < len(tokens):
            payload["auth_mode"] = tokens[index + 1]
            index += 1
        index += 1
    return payload


def split_host_port(value: str) -> tuple[str, int]:
    """拆分 udp2raw 参数中的 host:port，兼容方括号 IPv6。"""

    if value.startswith("[") and "]:" in value:
        host, port = value[1:].rsplit("]:", 1)
        return host, int(port)
    host, port = value.rsplit(":", 1)
    return host, int(port)


def write_openwrt_init(mode: str, instance: str) -> None:
    """写入 OpenWrt procd init 脚本，用于管理单个 udp2raw 实例。"""

    path = init_path(mode, instance)
    config = config_file_for_mode(mode)
    awk_script = (
        "NF && $1 !~ /^#/ { "
        'key=$1; sub(/=$/, "", key); '
        "if (key == name) { "
        'sub(/^[[:space:]]*[^[:space:]=]+[[:space:]]*=?[[:space:]]*/, ""); '
        "print; found=1; exit "
        "} "
        "} END { if (!found) exit 1 }"
    )
    path.write_text(
        f"""#!/bin/sh /etc/rc.common

START=95
STOP=10
USE_PROCD=1

MODE={shell_quote(mode)}
INSTANCE={shell_quote(instance)}
CONFIG={shell_quote(str(config))}
UDP2RAW_BIN={shell_quote(str(UDP2RAW_BIN))}

start_service() {{
  procd_open_instance "$MODE-$INSTANCE"
  procd_set_param command /bin/sh -c 'set -eu
bin="$3"
line=$(awk -v name="$1" '"'"'{awk_script}'"'"' "$2")
eval "set -- $line"
exec "$bin" "$@"' -- "$INSTANCE" "$CONFIG" "$UDP2RAW_BIN"
  procd_set_param respawn 10 5 5
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}}

stop_service() {{
  return 0
}}

reload_service() {{
  stop
  start
}}

status_service() {{
  if service_running "$MODE-$INSTANCE"; then
    echo "running"
    return 0
  fi
  echo "inactive"
  return 3
}}
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def upsert_instance(path: Path, instance: str, args: str) -> None:
    """在实例配置文件中新增或替换指定 udp2raw 实例参数。"""

    lines = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            key = line.split(None, 1)[0].removesuffix("=") if line.split() else ""
            if key != instance:
                lines.append(line)
    lines.append(f"{instance} {args}")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def remove_instance(path: Path, instance: str) -> None:
    """从实例配置文件中移除指定 udp2raw 实例。"""

    if not path.exists():
        return
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        key = parts[0].removesuffix("=") if parts else ""
        if key != instance:
            lines.append(line)
    if lines:
        path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    else:
        path.unlink()


def service_action(payload: dict[str, Any], action: str, dry_run: bool = False) -> dict[str, Any]:
    """对 payload 指向的 udp2raw 实例执行 start/stop/status 等服务动作。"""

    instance = validate_instance_name(str(payload["instance"]))
    changed = False
    commands = []
    modes = payload_modes(payload)
    for mode in modes:
        if dry_run:
            commands.append({"command": service_command(mode, instance, action), "dry_run": True})
            continue
        result = run_command(service_command(mode, instance, action), True)
        if udp2raw_service_backend() == "openwrt-procd":
            result = normalize_openwrt_result(result)
        commands.append(result)
        changed = changed or result["returncode"] == 0
    return {"changed": changed, "instance": instance, "modes": modes, "commands": commands}


def payload_modes(payload: dict[str, Any]) -> list[str]:
    """按任务 payload 判断本节点实际 udp2raw 角色；旧任务缺少 mode 时才回退扫描配置。"""

    mode = payload.get("mode")
    if mode:
        return [validate_mode(str(mode))]
    instance = validate_instance_name(str(payload["instance"]))
    modes = [mode for mode in ["server", "client"] if instance_exists(config_file_for_mode(mode), instance)]
    return modes or ["server", "client"]


def validate_mode(mode: str) -> str:
    """校验 udp2raw 角色只能是 server 或 client。"""

    if mode not in ["server", "client"]:
        raise ValueError("udp2raw mode must be server or client")
    return mode


def instance_exists(path: Path, instance: str) -> bool:
    """判断实例配置文件中是否存在指定 udp2raw 实例。"""

    if not path.exists():
        return False
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        key = parts[0].removesuffix("=") if parts else ""
        if key == instance:
            return True
    return False


def mimic_service_backend() -> str:
    """检测当前节点是否支持以 systemd 方式运行 mimic。"""

    if udp2raw_service_backend() == "systemd":
        return "systemd"
    return "unsupported"


def ensure_mimic_layout() -> None:
    """创建 Link42 管理 mimic 配置所需目录并设置基础权限。"""

    MIMIC_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    MIMIC_SYSTEM_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    MIMIC_CONFIG_DIR.chmod(0o755)
    MIMIC_SYSTEM_CONFIG_DIR.chmod(0o755)


def write_mimic_system_config(path: Path, content: str) -> None:
    """写入 mimic 系统配置文件并设置可读权限。"""

    ensure_mimic_layout()
    atomic_write_text(path, content, mode=0o644)
    path.chmod(0o644)


def validate_mimic_interface(name: str) -> str:
    """校验 mimic 绑定接口名只包含安全字符。"""

    return validate_interface_name(name, "mimic bind interface")


def mimic_unit_name(bind_interface: str) -> str:
    """生成 mimic systemd 实例 unit 名称。"""

    return f"mimic@{validate_mimic_interface(bind_interface)}.service"


def mimic_instance_path(bind_interface: str, instance: str) -> Path:
    """返回 Link42 管理的单个 mimic 实例片段路径。"""

    interface_name = validate_mimic_interface(bind_interface)
    instance_name = validate_instance_name(instance)
    return managed_child_path(MIMIC_CONFIG_DIR, interface_name, f"{instance_name}.conf")


def mimic_system_config_path(bind_interface: str) -> Path:
    """返回受管 mimic 系统配置路径并拒绝符号链接穿越。"""

    interface_name = validate_mimic_interface(bind_interface)
    return managed_child_path(MIMIC_SYSTEM_CONFIG_DIR, f"{interface_name}.conf")


def build_mimic_snippet(payload: dict[str, Any]) -> str:
    """把任务 payload 渲染为单连接 mimic filter 配置片段。"""

    link_type = str(payload.get("link_type") or "eth")
    if link_type not in {"eth", "none"}:
        raise ValueError("mimic link_type must be eth or none")
    xdp_mode = str(payload.get("xdp_mode") or "skb")
    if xdp_mode not in {"auto", "native", "skb"}:
        raise ValueError("mimic xdp_mode must be auto, native, or skb")
    peer_host = str(payload["peer_host"])
    peer_port = int(payload["peer_port"])
    filter_origin = str(payload.get("filter_origin") or "remote")
    if filter_origin not in {"local", "remote"}:
        raise ValueError("mimic filter_origin must be local or remote")
    lines = [
        f"# instance {validate_instance_name(str(payload['instance']))}",
        f"link_type = {link_type}",
        f"xdp_mode = {xdp_mode}",
    ]
    if payload.get("handshake_interval") is not None:
        lines.append(f"handshake = {int(payload['handshake_interval'])}:")
    if payload.get("keepalive_interval") is not None:
        lines.append(f"keepalive = {int(payload['keepalive_interval'])}:::")
    if payload.get("padding") is not None:
        lines.append(f"padding = {int(payload['padding'])}")
    lines.append(f"filter = {filter_origin}={format_mimic_endpoint(peer_host, peer_port)}")
    return "\n".join(lines).rstrip() + "\n"


def format_mimic_endpoint(host: str, port: int) -> str:
    """把 IP 和端口格式化为 mimic filter 接受的 endpoint 字符串。"""

    ip = ipaddress.ip_address(host)
    host_text = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    return f"{host_text}:{port}"


def render_mimic_config(bind_interface: str, instance: str | None = None, snippet: str | None = None) -> str:
    """合并原有 mimic 配置和 Link42 管理片段，生成最终系统配置。"""

    snippets: list[str] = []
    directory = managed_child_path(MIMIC_CONFIG_DIR, validate_mimic_interface(bind_interface))
    if directory.exists():
        snippets.extend(path.read_text(encoding="utf-8").strip() for path in sorted(directory.glob("*.conf")))
    if instance and snippet:
        existing_path = mimic_instance_path(bind_interface, instance)
        snippets = [
            item
            for item in snippets
            if not existing_path.exists() or item != existing_path.read_text(encoding="utf-8").strip()
        ]
        snippets.append(snippet.strip())
    link42_block = ""
    if snippets:
        link42_block = f"{MIMIC_BLOCK_BEGIN}\n" + "\n\n".join(snippets).strip() + f"\n{MIMIC_BLOCK_END}\n"
    config_path = mimic_system_config_path(bind_interface)
    base = strip_mimic_link42_block(config_path.read_text(encoding="utf-8") if config_path.exists() else "")
    parts = [part for part in [base.strip(), link42_block.strip()] if part]
    return "\n\n".join(parts).rstrip() + ("\n" if parts else "")


def strip_mimic_link42_block(content: str) -> str:
    """移除配置中旧的 Link42 管理片段，保留用户自定义内容。"""

    pattern = re.compile(
        rf"{re.escape(MIMIC_BLOCK_BEGIN)}.*?{re.escape(MIMIC_BLOCK_END)}\n?",
        flags=re.DOTALL,
    )
    return pattern.sub("", content).strip() + ("\n" if content.strip() else "")


def mimic_service_action(payload: dict[str, Any], action: str, dry_run: bool = False) -> dict[str, Any]:
    """对 mimic 绑定接口执行指定 systemd 服务动作。"""

    bind_interface = validate_mimic_interface(str(payload["bind_interface"]))
    command = ["systemctl", action, mimic_unit_name(bind_interface)]
    if dry_run:
        return {"changed": False, "dry_run": True, "bind_interface": bind_interface, "command": command}
    result = run_command(command, True)
    return {"changed": result["returncode"] == 0, "bind_interface": bind_interface, "command": result}
