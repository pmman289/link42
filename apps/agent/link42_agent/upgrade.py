from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib import request
from urllib.parse import urlparse

from .config import AgentConfig
from .system import get_service_manager_name


UPGRADE_DIR = Path("/var/lib/link42/agent")
NEW_BINARY = UPGRADE_DIR / "link42-agent.new"
UPGRADE_SCRIPT = UPGRADE_DIR / "upgrade.sh"
STATE_FILE = UPGRADE_DIR / "upgrade-state.json"


def self_upgrade(payload: dict[str, Any], config: AgentConfig, dry_run: bool = False) -> dict[str, Any]:
    """下载并暂存新 Agent 二进制，然后安排后台脚本替换当前服务。"""

    if get_service_manager_name() != "systemd":
        raise RuntimeError("agent self upgrade currently requires systemd")
    download_url = str(payload["download_url"])
    ensure_controller_url(download_url, config.server_url)
    target_version = str(payload["target_version"])
    expected_sha256 = str(payload["sha256"])
    install_path = Path(str(payload.get("install_path") or "/usr/local/bin/link42-agent"))
    service_name = str(payload.get("service_name") or "link42-agent")
    if install_path != Path("/usr/local/bin/link42-agent"):
        raise ValueError("unsupported agent install path")
    if dry_run:
        return {"status": "staged", "dry_run": True, "target_version": target_version}

    UPGRADE_DIR.mkdir(parents=True, exist_ok=True)
    write_state({"status": "downloading", "target_version": target_version})

    download_file(config, download_url, NEW_BINARY)
    actual_sha256 = sha256_file(NEW_BINARY)
    if actual_sha256 != expected_sha256:
        write_state({"status": "failed", "error": "sha256 mismatch", "actual_sha256": actual_sha256})
        raise RuntimeError("agent upgrade sha256 mismatch")
    write_state({"status": "verified", "target_version": target_version})
    verify_binary_version(NEW_BINARY, target_version, payload.get("binary_args") or ["--version"])
    write_upgrade_script(service_name, install_path)
    schedule_upgrade_script()
    write_state({"status": "staged", "target_version": target_version})
    return {
        "status": "staged",
        "target_version": target_version,
        "sha256": actual_sha256,
        "upgrade_script": str(UPGRADE_SCRIPT),
    }


def ensure_controller_url(download_url: str, server_url: str) -> None:
    """限制升级包只能从当前主控下载。"""

    download = urlparse(download_url)
    server = urlparse(server_url)
    if download.scheme != server.scheme or download.netloc != server.netloc:
        raise ValueError("agent upgrade download url must belong to the configured controller")


def download_file(config: AgentConfig, url: str, target: Path) -> None:
    """使用 Agent token 下载升级二进制。"""

    tmp = target.with_suffix(".tmp")
    http_request = request.Request(url)
    with request.urlopen(http_request, timeout=120) as response:
        with tmp.open("wb") as handle:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
    os.chmod(tmp, 0o755)
    tmp.replace(target)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_binary_version(path: Path, target_version: str, args: list[Any]) -> None:
    command = [str(path), *[str(arg) for arg in args]]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    output = (result.stdout or result.stderr).strip()
    if target_version not in output:
        raise RuntimeError(f"downloaded agent version mismatch: {output}")


def write_state(data: dict[str, Any]) -> None:
    UPGRADE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(data, ensure_ascii=False) + "\n", encoding="utf-8")


def write_upgrade_script(service_name: str, install_path: Path) -> None:
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


def schedule_upgrade_script() -> None:
    """让后台进程替换当前正在运行的 Agent。"""

    if shutil.which("systemd-run"):
        subprocess.run(
            ["systemd-run", "--unit=link42-agent-upgrade", "--on-active=1", str(UPGRADE_SCRIPT)],
            check=True,
        )
        return
    subprocess.Popen(  # noqa: S603
        ["nohup", "sh", str(UPGRADE_SCRIPT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"
