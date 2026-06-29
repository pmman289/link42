from __future__ import annotations

import os
import platform
import shutil
import tempfile
from pathlib import Path
from typing import Any

import httpx

from .config import AgentConfig
from .system import run_command


UDP2RAW_BIN = Path("/usr/local/bin/udp2raw")
UDP2RAW_CONFIG_DIR = Path("/etc/link42/middleware/udp2raw")
UDP2RAW_LIBEXEC = Path("/usr/local/libexec/link42-udp2raw-systemd")
UDP2RAW_SERVER_UNIT = Path("/etc/systemd/system/link42-udp2raw-server@.service")
UDP2RAW_CLIENT_UNIT = Path("/etc/systemd/system/link42-udp2raw-client@.service")


def install_middleware(payload: dict[str, Any], config: AgentConfig, dry_run: bool = False) -> dict[str, Any]:
    """安装连接中间层插件资产。"""

    if payload.get("plugin") != "udp2raw":
        raise ValueError("unsupported middleware plugin")
    return install_udp2raw(config, dry_run=dry_run)


def apply_udp2raw(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """写入 udp2raw 单实例配置并重启服务。"""

    args = build_udp2raw_args(payload)
    mode = payload["mode"]
    instance = payload["instance"]
    config_file = config_file_for_mode(mode)
    if dry_run:
        return {"changed": False, "dry_run": True, "args": args, "config_file": str(config_file)}
    ensure_udp2raw_layout()
    upsert_instance(config_file, instance, args)
    commands = [
        run_command(["systemctl", "daemon-reload"], False),
        run_command(["systemctl", "enable", unit_name(mode, instance)], False),
        run_command(["systemctl", "restart", unit_name(mode, instance)], False),
    ]
    return {"changed": True, "mode": mode, "instance": instance, "config_file": str(config_file), "commands": commands}


def start_udp2raw(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    return service_action(payload, "start", dry_run=dry_run)


def stop_udp2raw(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    return service_action(payload, "stop", dry_run=dry_run)


def delete_udp2raw(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    instance = payload["instance"]
    modes = payload_modes(payload)
    if dry_run:
        return {"changed": False, "dry_run": True, "instance": instance, "modes": modes}
    results: list[dict[str, Any]] = []
    for mode in modes:
        results.append(run_command(["systemctl", "disable", "--now", unit_name(mode, instance)], True))
        remove_instance(config_file_for_mode(mode), instance)
    results.append(run_command(["systemctl", "daemon-reload"], False))
    return {"changed": True, "instance": instance, "modes": modes, "commands": results}


def status_udp2raw(payload: dict[str, Any]) -> dict[str, Any]:
    instance = payload["instance"]
    return {
        mode: run_command(["systemctl", "is-active", unit_name(mode, instance)], True)
        for mode in payload_modes(payload)
    }


def install_udp2raw(config: AgentConfig, dry_run: bool = False) -> dict[str, Any]:
    """从主控下载匹配架构的 udp2raw 二进制并安装 systemd 单元。"""

    if not shutil.which("systemctl"):
        raise RuntimeError("udp2raw middleware currently requires systemd")
    asset = detect_udp2raw_asset()
    if dry_run:
        return {"changed": False, "dry_run": True, "asset": asset}
    ensure_udp2raw_layout()
    download_asset(config, asset, UDP2RAW_BIN)
    UDP2RAW_BIN.chmod(0o755)
    write_wrapper()
    write_units()
    result = run_command(["systemctl", "daemon-reload"], False)
    return {"changed": True, "asset": asset, "binary": str(UDP2RAW_BIN), "daemon_reload": result}


def detect_udp2raw_asset() -> str:
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
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.exists():
        return False
    return " aes " in f" {cpuinfo.read_text(encoding='utf-8', errors='ignore').lower()} "


def machine_endian() -> str:
    return "le" if os.sys.byteorder == "little" else "be"


def download_asset(config: AgentConfig, asset: str, target: Path) -> None:
    url = f"/api/agent/plugins/udp2raw/assets/{asset}"
    with httpx.Client(base_url=config.server_url, timeout=60) as client:
        with client.stream("GET", url) as response:
            response.raise_for_status()
            fd, tmp_name = tempfile.mkstemp(prefix="udp2raw-", dir=str(target.parent))
            try:
                with os.fdopen(fd, "wb") as handle:
                    for chunk in response.iter_bytes():
                        handle.write(chunk)
                Path(tmp_name).replace(target)
            finally:
                if Path(tmp_name).exists():
                    Path(tmp_name).unlink()


def ensure_udp2raw_layout() -> None:
    UDP2RAW_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    UDP2RAW_LIBEXEC.parent.mkdir(parents=True, exist_ok=True)
    UDP2RAW_SERVER_UNIT.parent.mkdir(parents=True, exist_ok=True)
    for name in ["server", "client"]:
        path = UDP2RAW_CONFIG_DIR / name
        if not path.exists():
            path.write_text("", encoding="utf-8")


def write_wrapper() -> None:
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
    mode = payload["mode"]
    listen_host = payload["listen_host"]
    listen_port = int(payload["listen_port"])
    remote_host = payload["remote_host"]
    remote_port = int(payload["remote_port"])
    password = shell_quote(str(payload["password"]))
    raw_mode = payload.get("raw_mode") or "faketcp"
    cipher_mode = payload.get("cipher_mode") or "xor"
    args = [
        "-s" if mode == "server" else "-c",
        f"-l{listen_host}:{listen_port}",
        f"-r{remote_host}:{remote_port}",
        f"-k {password}",
        f"--raw-mode {raw_mode}",
        f"--cipher-mode {cipher_mode}",
    ]
    if payload.get("auto_rule", True):
        args.append("-a")
    return " ".join(args)


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def config_file_for_mode(mode: str) -> Path:
    if mode not in ["server", "client"]:
        raise ValueError("udp2raw mode must be server or client")
    return UDP2RAW_CONFIG_DIR / mode


def unit_name(mode: str, instance: str) -> str:
    return f"link42-udp2raw-{mode}@{instance}.service"


def upsert_instance(path: Path, instance: str, args: str) -> None:
    lines = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            key = line.split(None, 1)[0].removesuffix("=") if line.split() else ""
            if key != instance:
                lines.append(line)
    lines.append(f"{instance} {args}")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def remove_instance(path: Path, instance: str) -> None:
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
    instance = payload["instance"]
    changed = False
    commands = []
    modes = payload_modes(payload)
    for mode in modes:
        if dry_run:
            commands.append({"command": ["systemctl", action, unit_name(mode, instance)], "dry_run": True})
            continue
        result = run_command(["systemctl", action, unit_name(mode, instance)], True)
        commands.append(result)
        changed = changed or result["returncode"] == 0
    return {"changed": changed, "instance": instance, "modes": modes, "commands": commands}


def payload_modes(payload: dict[str, Any]) -> list[str]:
    """按任务 payload 判断本节点实际 udp2raw 角色；旧任务缺少 mode 时才回退扫描配置。"""

    mode = payload.get("mode")
    if mode:
        return [validate_mode(str(mode))]
    instance = payload["instance"]
    modes = [mode for mode in ["server", "client"] if instance_exists(config_file_for_mode(mode), instance)]
    return modes or ["server", "client"]


def validate_mode(mode: str) -> str:
    if mode not in ["server", "client"]:
        raise ValueError("udp2raw mode must be server or client")
    return mode


def instance_exists(path: Path, instance: str) -> bool:
    if not path.exists():
        return False
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        key = parts[0].removesuffix("=") if parts else ""
        if key == instance:
            return True
    return False
