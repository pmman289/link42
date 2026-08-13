from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any
from urllib import request
from urllib.parse import urlparse

from .config import AgentConfig
from .system import get_service_manager_name


UPGRADE_DIR = Path(os.getenv("LINK42_AGENT_UPGRADE_DIR", "/var/lib/link42/agent"))
NEW_BINARY = UPGRADE_DIR / "link42-agent.new"
NEW_SOURCE_ARCHIVE = UPGRADE_DIR / "link42-agent-source.new.tar.gz"
UPGRADE_SCRIPT = UPGRADE_DIR / "upgrade.sh"
STATE_FILE = UPGRADE_DIR / "upgrade-state.json"
OPENWRT_SOURCE_DIR = Path(os.getenv("LINK42_AGENT_SOURCE_DIR", "/opt/link42-agent/src"))
AGENT_SERVICE_NAME = os.getenv("LINK42_AGENT_SERVICE_NAME", "link42-agent")


def self_upgrade(payload: dict[str, Any], config: AgentConfig, dry_run: bool = False) -> dict[str, Any]:
    """按当前服务后端暂存二进制或源码包，并安排后台原子升级。"""

    service_manager = get_service_manager_name()
    if service_manager not in {"systemd", "openwrt-uci"}:
        raise RuntimeError("agent self upgrade requires systemd or OpenWrt procd")
    download_url = str(payload["download_url"])
    ensure_controller_url(download_url, config.server_url)
    target_version = str(payload["target_version"])
    expected_sha256 = str(payload["sha256"])
    upgrade_mode = str(payload.get("upgrade_mode") or "binary")
    install_path = Path(str(payload.get("install_path") or "/usr/local/bin/link42-agent"))
    source_dir = OPENWRT_SOURCE_DIR
    service_name = AGENT_SERVICE_NAME
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", service_name):
        raise ValueError("unsupported agent service name")
    if service_manager == "systemd" and upgrade_mode != "binary":
        raise ValueError("systemd agent upgrade requires binary asset")
    if service_manager == "openwrt-uci" and upgrade_mode != "source":
        raise ValueError("OpenWrt agent upgrade requires source asset")
    if upgrade_mode == "binary" and install_path != Path("/usr/local/bin/link42-agent"):
        raise ValueError("unsupported agent install path")
    if upgrade_mode == "source" and not dry_run and not source_dir.is_dir():
        raise RuntimeError("current agent source directory is missing")
    if dry_run:
        return {
            "status": "staged",
            "dry_run": True,
            "target_version": target_version,
            "upgrade_mode": upgrade_mode,
        }

    UPGRADE_DIR.mkdir(parents=True, exist_ok=True)
    target = NEW_SOURCE_ARCHIVE if upgrade_mode == "source" else NEW_BINARY
    staged_source = source_dir.parent / ".link42-agent-src.new"
    state_context = {"target_version": target_version, "upgrade_mode": upgrade_mode}
    try:
        write_state({"status": "downloading", **state_context})
        download_file(config, download_url, target)
        actual_sha256 = sha256_file(target)
        if actual_sha256 != expected_sha256:
            raise RuntimeError("agent upgrade sha256 mismatch")
        write_state({"status": "verified", **state_context})
        if upgrade_mode == "source":
            extract_source_archive(target, staged_source, target_version)
            write_openwrt_upgrade_script(service_name, source_dir, staged_source, target_version)
        else:
            verify_binary_version(target, target_version, payload.get("binary_args") or ["--version"])
            write_systemd_upgrade_script(service_name, install_path)
        schedule_upgrade_script(service_manager)
        write_state({"status": "staged", **state_context})
    except Exception as exc:
        if upgrade_mode == "source" and staged_source.exists():
            shutil.rmtree(staged_source, ignore_errors=True)
        write_state({"status": "failed", "error": str(exc), **state_context})
        raise
    return {
        "status": "staged",
        "target_version": target_version,
        "sha256": actual_sha256,
        "upgrade_mode": upgrade_mode,
        "upgrade_script": str(UPGRADE_SCRIPT),
    }


def ensure_controller_url(download_url: str, server_url: str) -> None:
    """限制升级包只能从当前主控下载。"""

    download = urlparse(download_url)
    server = urlparse(server_url)
    if download.scheme != server.scheme or download.netloc != server.netloc:
        raise ValueError("agent upgrade download url must belong to the configured controller")


def download_file(config: AgentConfig, url: str, target: Path) -> None:
    """从当前主控下载升级资产，并以临时文件原子落盘。"""

    tmp = target.with_suffix(".tmp")
    http_request = request.Request(url)
    with request.urlopen(http_request, timeout=120) as response:
        with tmp.open("wb") as handle:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
    os.chmod(tmp, 0o755 if target == NEW_BINARY else 0o600)
    tmp.replace(target)


def sha256_file(path: Path) -> str:
    """计算文件的 sha256 摘要。"""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_binary_version(path: Path, target_version: str, args: list[Any]) -> None:
    """执行下载后的 Agent 二进制，确认其版本符合目标版本。"""

    command = [str(path), *[str(arg) for arg in args]]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    output = (result.stdout or result.stderr).strip()
    if target_version not in output:
        raise RuntimeError(f"downloaded agent version mismatch: {output}")


def write_state(data: dict[str, Any]) -> None:
    """写入自升级状态文件，供主控或用户排查升级进度。"""

    UPGRADE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(data, ensure_ascii=False) + "\n", encoding="utf-8")


def write_systemd_upgrade_script(service_name: str, install_path: Path) -> None:
    """生成负责停服务、替换二进制和失败回滚的升级脚本。"""

    backup_path = UPGRADE_DIR / "link42-agent.bak"
    script = f"""#!/bin/sh
set -eu
SERVICE_NAME={shell_quote(service_name)}
INSTALL_PATH={shell_quote(str(install_path))}
STATE_DIR={shell_quote(str(UPGRADE_DIR))}
NEW_BIN={shell_quote(str(NEW_BINARY))}
BACKUP_BIN={shell_quote(str(backup_path))}
STATE_FILE={shell_quote(str(STATE_FILE))}

write_state() {{
  printf '%s\\n' "$1" > "$STATE_FILE"
}}

write_state '{{"status":"restarting"}}'
systemctl stop "$SERVICE_NAME"
cp "$INSTALL_PATH" "$BACKUP_BIN"
install -m 0755 "$NEW_BIN" "$INSTALL_PATH"

if systemctl start "$SERVICE_NAME"; then
  sleep 5
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    write_state '{{"status":"healthy"}}'
    exit 0
  fi
fi

install -m 0755 "$BACKUP_BIN" "$INSTALL_PATH"
systemctl start "$SERVICE_NAME" || true
write_state '{{"status":"rolled_back"}}'
exit 1
"""
    UPGRADE_SCRIPT.write_text(script, encoding="utf-8")
    UPGRADE_SCRIPT.chmod(0o755)


def extract_source_archive(archive_path: Path, destination: Path, target_version: str) -> None:
    """安全解压 OpenWrt Agent 源码包，并确认包内版本符合升级目标。"""

    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 10000 or sum(member.size for member in members) > 64 * 1024 * 1024:
            raise RuntimeError("agent source archive exceeds safety limits")
        for member in members:
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or member.issym()
                or member.islnk()
                or not (member.isdir() or member.isfile())
            ):
                raise RuntimeError(f"unsafe agent source archive member: {member.name}")
        archive.extractall(destination, members=members)
    version_file = destination / "packages/link42_common/version.py"
    if not version_file.exists():
        raise RuntimeError("agent source archive is missing version metadata")
    match = re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', version_file.read_text(encoding="utf-8"))
    if not match or match.group(1) != target_version:
        found = match.group(1) if match else "unknown"
        raise RuntimeError(f"downloaded agent source version mismatch: {found}")


def write_openwrt_upgrade_script(
    service_name: str,
    source_dir: Path,
    staged_source: Path,
    target_version: str,
) -> None:
    """生成 OpenWrt procd 源码替换、健康检查和失败回滚脚本。"""

    backup_source = source_dir.parent / ".link42-agent-src.bak"
    service_path = Path("/etc/init.d") / service_name
    script = f"""#!/bin/sh
set -eu
SERVICE={shell_quote(str(service_path))}
SOURCE_DIR={shell_quote(str(source_dir))}
NEW_SOURCE={shell_quote(str(staged_source))}
BACKUP_SOURCE={shell_quote(str(backup_source))}
STATE_FILE={shell_quote(str(STATE_FILE))}
TARGET_VERSION={shell_quote(target_version)}

write_state() {{
  printf '{{"status":"%s","target_version":"%s","upgrade_mode":"source"}}\n' "$1" "$TARGET_VERSION" > "$STATE_FILE"
}}

write_state restarting
"$SERVICE" stop >/dev/null 2>&1 || true
rm -rf "$BACKUP_SOURCE"
if [ -d "$SOURCE_DIR" ]; then
  mv "$SOURCE_DIR" "$BACKUP_SOURCE"
fi
mv "$NEW_SOURCE" "$SOURCE_DIR"

if "$SERVICE" start >/dev/null 2>&1; then
  sleep 5
  if "$SERVICE" status >/dev/null 2>&1; then
    write_state healthy
    exit 0
  fi
fi

"$SERVICE" stop >/dev/null 2>&1 || true
rm -rf "$SOURCE_DIR"
if [ -d "$BACKUP_SOURCE" ]; then
  mv "$BACKUP_SOURCE" "$SOURCE_DIR"
fi
"$SERVICE" start >/dev/null 2>&1 || true
write_state rolled_back
exit 1
"""
    UPGRADE_SCRIPT.write_text(script, encoding="utf-8")
    UPGRADE_SCRIPT.chmod(0o755)


def schedule_upgrade_script(service_manager: str) -> None:
    """让后台进程替换当前正在运行的 Agent。"""

    if service_manager == "systemd" and shutil.which("systemd-run"):
        subprocess.run(
            ["systemd-run", "--unit=link42-agent-upgrade", "--on-active=1", str(UPGRADE_SCRIPT)],
            check=True,
        )
        return
    subprocess.Popen(  # noqa: S603
        ["sh", "-c", f"sleep 2; exec sh {shell_quote(str(UPGRADE_SCRIPT))}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def shell_quote(value: str) -> str:
    """为生成 shell 脚本时的单引号参数做安全转义。"""

    return "'" + value.replace("'", "'\\''") + "'"
