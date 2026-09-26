"""Link42 UDPspeeder 中间层的安装、配置和服务管理实现。"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from .service_manager import OpenWrtUciManager, detect_service_manager
from .system import run_command
from .validation import atomic_write_text, managed_child_path, validate_instance_name


UDPSPEEDER_BIN = Path(os.getenv("LINK42_UDPSPEEDER_BIN", "/usr/local/bin/udpspeeder"))
UDPSPEEDER_DIR = Path(os.getenv("LINK42_UDPSPEEDER_CONFIG_DIR", "/etc/link42/middleware/udpspeeder"))
UDPSPEEDER_PREFIX = os.getenv("LINK42_UDPSPEEDER_SERVICE_PREFIX", "link42-udpspeeder")
MAX_FEC_PACKET_COUNT = 255


def validate_udpspeeder_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """校验并归一化 UDPspeeder 实例配置。"""

    instance = validate_instance_name(str(payload.get("instance") or ""), "udpspeeder instance")
    mode = str(payload.get("mode") or "")
    if mode not in {"client", "server"}:
        raise ValueError("udpspeeder mode must be client or server")
    listen = _endpoint(payload.get("listen_host"), payload.get("listen_port"), "listen")
    remote = _endpoint(payload.get("remote_host"), payload.get("remote_port"), "remote")
    for name, minimum, maximum in [("fec_data", 1, 255), ("fec_redundancy", 0, 254), ("fec_timeout_ms", 0, 1000), ("fec_mode", 0, 1), ("fec_mtu", 100, 2000), ("fec_queue_len", 1, 10000), ("decode_buffer", 300, 20000)]:
        value = int(payload.get(name))
        if not minimum <= value <= maximum:
            raise ValueError(f"{name} must be between {minimum} and {maximum}")
    if int(payload.get("fec_data")) + int(payload.get("fec_redundancy")) > MAX_FEC_PACKET_COUNT:
        raise ValueError("fec_data + fec_redundancy must be less than or equal to 255")
    return {
        "instance": instance,
        "mode": mode,
        "listen_host": listen[0],
        "listen_port": listen[1],
        "remote_host": remote[0],
        "remote_port": remote[1],
        "fec_data": int(payload.get("fec_data")),
        "fec_redundancy": int(payload.get("fec_redundancy")),
        "fec_timeout_ms": int(payload.get("fec_timeout_ms")),
        "fec_mode": int(payload.get("fec_mode")),
        "fec_mtu": int(payload.get("fec_mtu")),
        "fec_queue_len": int(payload.get("fec_queue_len")),
        "decode_buffer": int(payload.get("decode_buffer")),
    }


def _endpoint(host: Any, port: Any, field: str) -> tuple[str, int]:
    """校验 IP 和端口并返回标准化 endpoint。"""

    try:
        address = ipaddress.ip_address(str(host))
        number = int(port)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"udpspeeder {field} must contain an IP address and port") from exc
    if not 1 <= number <= 65535:
        raise ValueError(f"udpspeeder {field} port must be between 1 and 65535")
    return address.compressed, number


def render_udpspeeder_args(payload: dict[str, Any]) -> list[str]:
    """将已校验配置渲染为 UDPspeeder 参数数组。"""

    config = validate_udpspeeder_payload(payload)
    flag = "-c" if config["mode"] == "client" else "-s"
    return [
        flag,
        "-l",
        _format_endpoint(config["listen_host"], config["listen_port"]),
        "-r",
        _format_endpoint(config["remote_host"], config["remote_port"]),
        "-f",
        f"{config['fec_data']}:{config['fec_redundancy']}",
        "--timeout",
        str(config["fec_timeout_ms"]),
        "--mode",
        str(config["fec_mode"]),
        "--mtu",
        str(config["fec_mtu"]),
        "-q",
        str(config["fec_queue_len"]),
        "--decode-buf",
        str(config["decode_buffer"]),
    ]


def _format_endpoint(host: str, port: int) -> str:
    """为 UDPspeeder 生成兼容 IPv4/IPv6 的 host:port 文本。"""

    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def apply_udpspeeder(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """写入 UDPspeeder 配置并重启对应实例。"""

    config = validate_udpspeeder_payload(payload)
    path = managed_child_path(UDPSPEEDER_DIR, f"{config['instance']}.json")
    args = render_udpspeeder_args(config)
    if dry_run:
        return {"changed": False, "dry_run": True, "args": args, "config_path": str(path)}
    UDPSPEEDER_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps({**config, "args": args}, ensure_ascii=False, indent=2) + "\n", mode=0o600)
    ensure_udpspeeder_service(config["mode"], config["instance"])
    return {"changed": True, "config_path": str(path), "commands": service_action(config["mode"], config["instance"], "restart")}


def start_udpspeeder(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """启动 UDPspeeder 实例。"""

    return {
        "changed": not dry_run,
        "commands": service_action(
            str(payload.get("mode")),
            validate_instance_name(str(payload.get("instance")), "udpspeeder instance"),
            "start",
            dry_run,
        ),
    }


def stop_udpspeeder(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """停止 UDPspeeder 实例。"""

    return {
        "changed": not dry_run,
        "commands": service_action(
            str(payload.get("mode")),
            validate_instance_name(str(payload.get("instance")), "udpspeeder instance"),
            "stop",
            dry_run,
        ),
    }


def status_udpspeeder(payload: dict[str, Any]) -> dict[str, Any]:
    """查询 UDPspeeder 实例状态。"""

    mode = str(payload.get("mode"))
    instance = validate_instance_name(str(payload.get("instance")), "udpspeeder instance")
    return {"backend": service_backend(), "status": service_action(mode, instance, "status"), "binary": str(UDPSPEEDER_BIN)}


def delete_udpspeeder(payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """停止服务并删除 UDPspeeder 实例配置。"""

    mode = str(payload.get("mode"))
    instance = validate_instance_name(str(payload.get("instance")), "udpspeeder instance")
    path = managed_child_path(UDPSPEEDER_DIR, f"{instance}.json")
    if dry_run:
        return {"changed": False, "dry_run": True, "config_path": str(path)}
    commands = service_action(mode, instance, "stop")
    commands.extend(service_action(mode, instance, "disable"))
    if service_backend() == "openwrt-procd":
        Path(f"/etc/init.d/{UDPSPEEDER_PREFIX}-{mode}-{instance}").unlink(missing_ok=True)
    path.unlink(missing_ok=True)
    return {"changed": True, "commands": commands, "config_path": str(path)}


def install_udpspeeder(config: Any, dry_run: bool = False) -> dict[str, Any]:
    """安装主控提供的 UDPspeeder 二进制资产。"""

    backend = service_backend()
    if backend == "unsupported":
        raise RuntimeError("udpspeeder requires systemd or OpenWrt procd")
    asset = detect_udpspeeder_asset()
    if dry_run:
        return {"changed": False, "dry_run": True, "asset": asset, "backend": backend}
    UDPSPEEDER_BIN.parent.mkdir(parents=True, exist_ok=True)
    from .middleware import download_asset
    download_asset(config, asset, UDPSPEEDER_BIN, plugin="udpspeeder")
    UDPSPEEDER_BIN.chmod(0o755)
    check = run_command([str(UDPSPEEDER_BIN), "--help"], True)
    if check["returncode"] not in {0, 1, 2}:
        raise RuntimeError("udpspeeder binary self-check failed")
    return {"changed": True, "asset": asset, "backend": backend, "check": check}


def detect_udpspeeder_asset() -> str:
    """根据 CPU 架构选择 UDPspeeder 资产名。"""

    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "udpspeeder-x64-static"
    if machine in {"aarch64", "arm64"}:
        return "udpspeeder-arm64-musl"
    if machine.startswith("arm"):
        return "udpspeeder-arm-musl"
    if machine.startswith("mips"):
        return "udpspeeder-mips24kc-le-musl" if os.sys.byteorder == "little" else "udpspeeder-mips24kc-be-musl"
    raise RuntimeError(f"unsupported udpspeeder architecture: {machine}")


def service_backend() -> str:
    """检测 UDPspeeder 使用的服务管理器。"""

    if isinstance(detect_service_manager(run_command), OpenWrtUciManager):
        return "openwrt-procd"
    if shutil.which("systemctl"):
        return "systemd"
    return "unsupported"


def ensure_udpspeeder_service(mode: str, instance: str) -> None:
    """确保 UDPspeeder 实例服务模板或 procd 脚本存在。"""

    if service_backend() == "systemd":
        unit = Path(f"/etc/systemd/system/{UDPSPEEDER_PREFIX}-{mode}@.service")
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(render_udpspeeder_systemd_unit(mode), encoding="utf-8")
        run_command(["systemctl", "daemon-reload"], False)
    elif service_backend() == "openwrt-procd":
        config_path = managed_child_path(UDPSPEEDER_DIR, f"{instance}.json")
        config = json.loads(config_path.read_text(encoding="utf-8"))
        args = " ".join(_shell_quote(argument) for argument in config["args"])
        init = Path(f"/etc/init.d/{UDPSPEEDER_PREFIX}-{mode}-{instance}")
        init.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(
            init,
            "#!/bin/sh /etc/rc.common\n"
            "START=99\n"
            "USE_PROCD=1\n"
            "start_service() {\n"
            "  procd_open_instance\n"
            f"  procd_set_param command {UDPSPEEDER_BIN} {args}\n"
            "  procd_set_param respawn 3600 5 5\n"
            "  procd_close_instance\n"
            "}\n",
            mode=0o700,
        )


def _shell_quote(value: str) -> str:
    """为已校验的服务参数生成安全的单引号 shell 文本。"""

    return "'" + str(value).replace("'", "'\\''") + "'"


def agent_binary_path() -> str:
    """返回适用于 systemd 的正式 Agent 启动入口。"""

    discovered = shutil.which("link42-agent")
    if discovered:
        return discovered
    return f"{shutil.which('python3') or sys.executable} -m link42_agent.main"


def agent_environment_file() -> Path:
    """返回正式 Agent 安装时保存连接参数的环境文件路径。"""

    return Path(os.getenv("LINK42_AGENT_ENV_FILE", "/etc/link42/agent.env"))


def render_udpspeeder_systemd_unit(mode: str) -> str:
    """渲染加载 Agent 环境文件的 UDPspeeder systemd 模板。"""

    if mode not in {"client", "server"}:
        raise ValueError("udpspeeder mode must be client or server")
    environment_file = agent_environment_file()
    environment = f"EnvironmentFile=-{environment_file}\n" if environment_file.is_file() else ""
    return f"[Unit]\nDescription=Link42 UDPspeeder {mode} %i\nAfter=network.target\n\n[Service]\nType=simple\n{environment}ExecStart={agent_binary_path()} udpspeeder-{mode}-start %i\nRestart=on-failure\nRestartSec=5s\n\n[Install]\nWantedBy=multi-user.target\n"


def service_action(mode: str, instance: str, action: str, dry_run: bool = False) -> list[dict[str, Any]]:
    """执行 UDPspeeder 实例服务动作。"""

    if mode not in {"client", "server"}:
        raise ValueError("udpspeeder mode must be client or server")
    if dry_run:
        return [{"command": service_command(mode, instance, action), "dry_run": True}]
    return [run_command(service_command(mode, instance, action), action == "stop" or action == "status")]


def service_command(mode: str, instance: str, action: str) -> list[str]:
    """生成 systemd 或 procd 服务动作命令。"""

    if service_backend() == "openwrt-procd":
        return [f"/etc/init.d/{UDPSPEEDER_PREFIX}-{mode}-{instance}", action]
    return ["systemctl", action, f"{UDPSPEEDER_PREFIX}-{mode}@{instance}.service"]


def run_udpspeeder_service_command(argv: list[str]) -> bool:
    """处理 systemd 直接调用的 UDPspeeder 启动命令。"""

    if len(argv) != 3 or argv[1] not in {"udpspeeder-start", "udpspeeder-server-start", "udpspeeder-client-start"}:
        return False
    instance = validate_instance_name(argv[2], "udpspeeder instance")
    mode = "server" if argv[1] == "udpspeeder-server-start" else "client"
    path = managed_child_path(UDPSPEEDER_DIR, f"{instance}.json")
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("mode") != mode:
        raise ValueError("udpspeeder service mode does not match configuration")
    os.execv(str(UDPSPEEDER_BIN), [str(UDPSPEEDER_BIN), *config["args"]])
    return True
