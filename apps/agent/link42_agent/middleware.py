from __future__ import annotations

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
from .system import run_command


UDP2RAW_BIN = Path("/usr/local/bin/udp2raw")
UDP2RAW_CONFIG_DIR = Path("/etc/link42/middleware/udp2raw")
UDP2RAW_LIBEXEC = Path("/usr/local/libexec/link42-udp2raw-systemd")
UDP2RAW_SERVER_UNIT = Path("/etc/systemd/system/link42-udp2raw-server@.service")
UDP2RAW_CLIENT_UNIT = Path("/etc/systemd/system/link42-udp2raw-client@.service")
OPENWRT_INIT_DIR = Path("/etc/init.d")


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
    commands = apply_service(mode, instance, payload)
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
        results.extend(delete_service(mode, instance))
        remove_instance(config_file_for_mode(mode), instance)
    results.extend(reload_services())
    return {"changed": True, "instance": instance, "modes": modes, "commands": results}


def status_udp2raw(payload: dict[str, Any]) -> dict[str, Any]:
    instance = payload["instance"]
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
        args.append(auto_rule_arg())
    return " ".join(args)


def auto_rule_arg() -> str:
    """Return the udp2raw firewall helper flag for the local service backend."""

    return "-a"


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def config_file_for_mode(mode: str) -> Path:
    if mode not in ["server", "client"]:
        raise ValueError("udp2raw mode must be server or client")
    return UDP2RAW_CONFIG_DIR / mode


def unit_name(mode: str, instance: str) -> str:
    return f"link42-udp2raw-{mode}@{instance}.service"


def init_name(mode: str, instance: str) -> str:
    validate_instance_name(instance)
    return f"link42-udp2raw-{mode}-{instance}"


def init_path(mode: str, instance: str) -> Path:
    return OPENWRT_INIT_DIR / init_name(mode, instance)


def validate_instance_name(instance: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", instance):
        raise ValueError("udp2raw instance contains unsupported characters")
    return instance


def udp2raw_service_backend() -> str:
    manager = detect_service_manager(run_command)
    if isinstance(manager, OpenWrtUciManager):
        return "openwrt-procd"
    if shutil.which("systemctl"):
        return "systemd"
    return "unsupported"


def service_command(mode: str, instance: str, action: str) -> list[str]:
    if udp2raw_service_backend() == "openwrt-procd":
        return [str(init_path(mode, instance)), action]
    return ["systemctl", action, unit_name(mode, instance)]


def apply_service(mode: str, instance: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
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
    if udp2raw_service_backend() == "systemd":
        return [run_command(["systemctl", "daemon-reload"], False)]
    return []


def service_status(mode: str, instance: str) -> dict[str, Any]:
    if udp2raw_service_backend() == "openwrt-procd":
        return normalize_openwrt_result(run_command([str(init_path(mode, instance)), "status"], True))
    return run_command(["systemctl", "is-active", unit_name(mode, instance)], True)


def run_openwrt_service_commands(commands: list[list[str]], allow_failure: bool) -> list[dict[str, Any]]:
    return [normalize_openwrt_result(run_command(command, allow_failure)) for command in commands]


def normalize_openwrt_result(result: dict[str, Any]) -> dict[str, Any]:
    """Drop rc.common's misleading successful stderr noise from task results."""

    stderr = str(result.get("stderr") or "")
    if result.get("returncode") == 0 and stderr.strip().rstrip(".") == "Command failed: Not found":
        return {**result, "stderr": ""}
    return result


def payload_from_config(mode: str, instance: str) -> Optional[dict[str, Any]]:
    args = instance_args_from_config(config_file_for_mode(mode), instance)
    if not args:
        return None
    return parse_udp2raw_args(mode, instance, args)


def instance_args_from_config(path: Path, instance: str) -> Optional[str]:
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split(maxsplit=1)
        key = parts[0].removesuffix("=") if parts else ""
        if key == instance and len(parts) > 1:
            return parts[1]
    return None


def parse_udp2raw_args(mode: str, instance: str, args: str) -> dict[str, Any]:
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
        index += 1
    return payload


def split_host_port(value: str) -> tuple[str, int]:
    if value.startswith("[") and "]:" in value:
        host, port = value[1:].rsplit("]:", 1)
        return host, int(port)
    host, port = value.rsplit(":", 1)
    return host, int(port)


def write_openwrt_init(mode: str, instance: str) -> None:
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
