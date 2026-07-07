from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
import inspect
import json
import logging
import os
import re
import sys
import threading
import time
import traceback
import shutil
from typing import Any, Union

from link42_common.version import AGENT_VERSION

from .client import AgentClient, AgentHttpError
from .config import AgentConfig
from .config import load_config_from_env
from .gre import gre_runtime_supported, start_gre_from_config
from .link_monitor import probe_latency
from .middleware import mimic_official_release_codename_supported
from .plugins import node_plugin_capabilities
from .system import (
    get_agent_platform,
    get_hostname,
    kernel_newer_than,
    get_service_manager_name,
)
from .task_handlers import execute_registered_task


LOGGER_NAME = "link42.agent"
logger = logging.getLogger(LOGGER_NAME)
IDLE_DEBUG_LOG_INTERVAL_SECONDS = 60.0
SNAPSHOT_LOG_PLATFORM_KEYS = [
    "os",
    "arch",
    "service_manager",
    "kernel_version",
    "distro_id",
    "distro_codename",
    "has_mimic",
    "mimic_runtime_ready",
]


@dataclass(frozen=True)
class AgentSnapshot:
    """保存一轮 Agent 请求复用的平台和能力快照。"""

    capabilities: list[str]
    platform: dict[str, Any]


@dataclass
class AgentLogState:
    """记录上一次日志状态，用于降低 DEBUG 下的重复输出。"""

    snapshot_signature: tuple[Any, ...] | None = None
    last_idle_debug_at: float = 0.0


def build_capabilities(platform_info: dict[str, Any] | None = None) -> list[str]:
    """返回当前 Agent 支持的任务能力。"""

    if platform_info is None:
        platform_info = get_agent_platform()
    service_manager = str(platform_info.get("service_manager") or get_service_manager_name())
    capabilities = [
        "wireguard",
        "link.monitor",
        f"service:{service_manager}",
    ]
    if service_manager != "openwrt-uci":
        capabilities.append("wg_quick_import")
    if gre_runtime_supported():
        capabilities.extend([
            "gre",
            "gre.iproute2",
        ])
    if service_manager in ["systemd", "openwrt-uci"]:
        capabilities.extend([
            "middleware",
            "middleware.install",
            "middleware.udp2raw",
        ])
    if service_manager == "systemd":
        capabilities.extend([
            "agent.self_upgrade",
        ])
        capabilities.append("middleware.udp2raw.systemd")
        if mimic_installable(platform_info):
            capabilities.append("middleware.install.mimic")
        if mimic_runtime_supported(platform_info) and platform_info.get("has_mimic"):
            capabilities.append("middleware.mimic")
    if service_manager == "openwrt-uci":
        capabilities.append("middleware.udp2raw.openwrt-procd")
    capabilities.extend(node_plugin_capabilities(platform=platform_info))
    return capabilities


def collect_agent_snapshot() -> AgentSnapshot:
    """采集当前平台信息，并基于同一份信息生成能力列表。"""

    platform = get_agent_platform()
    capabilities = build_capabilities(platform)
    return AgentSnapshot(capabilities=capabilities, platform=platform)


def snapshot_log_signature(snapshot: AgentSnapshot) -> tuple[Any, ...]:
    """生成平台和能力签名，只有发生变化时才重复输出详情。"""

    platform_part = tuple((key, snapshot.platform.get(key)) for key in SNAPSHOT_LOG_PLATFORM_KEYS)
    return (tuple(snapshot.capabilities), platform_part)


def log_snapshot_if_changed(snapshot: AgentSnapshot, log_state: AgentLogState) -> None:
    """在平台或能力变化时输出一次 DEBUG 详情。"""

    signature = snapshot_log_signature(snapshot)
    if signature == log_state.snapshot_signature:
        return
    platform_summary = {key: snapshot.platform.get(key) for key in SNAPSHOT_LOG_PLATFORM_KEYS}
    logger.debug(
        "Agent 平台能力快照更新 capabilities=%s platform=%s",
        snapshot.capabilities,
        platform_summary,
    )
    log_state.snapshot_signature = signature


def log_idle_cycle(log_state: AgentLogState | None) -> None:
    """节流输出空闲轮询日志，避免 DEBUG 下每秒刷屏。"""

    if log_state is None:
        return
    now = time.monotonic()
    if now - log_state.last_idle_debug_at < IDLE_DEBUG_LOG_INTERVAL_SECONDS:
        return
    logger.debug("Agent 空闲：本轮没有待执行任务")
    log_state.last_idle_debug_at = now


def configure_logging(level_name: str) -> None:
    """配置 Agent 日志输出到标准输出，便于 systemd、Docker 和 OpenRC 采集。"""

    level = getattr(logging, str(level_name or "INFO").upper(), logging.INFO)
    root_logger = logging.getLogger("link42")
    existing_handler = next(
        (handler for handler in root_logger.handlers if getattr(handler, "_link42_handler", False)),
        None,
    )
    if isinstance(existing_handler, logging.StreamHandler):
        try:
            existing_handler.setStream(sys.stdout)
        except ValueError:
            root_logger.removeHandler(existing_handler)
            existing_handler.close()
            existing_handler = None
    if not isinstance(existing_handler, logging.StreamHandler):
        handler = logging.StreamHandler(sys.stdout)
        handler._link42_handler = True  # type: ignore[attr-defined]
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root_logger.addHandler(handler)
    root_logger.setLevel(level)
    root_logger.propagate = False


def run_gre_service_command(argv: list[str]) -> bool:
    """处理 link42-gre@.service 调用的轻量 GRE 子命令。"""

    if len(argv) < 3 or argv[1] != "gre-start":
        return False
    configure_logging(os.getenv("LINK42_LOG_LEVEL", "INFO"))
    result = start_gre_from_config(argv[2], os.getenv("LINK42_GRE_DIR"))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return True


def summarize_task(task: dict[str, Any]) -> dict[str, Any]:
    """生成不包含配置正文和密钥的任务日志摘要。"""

    payload = task.get("payload") or {}
    safe_payload_keys = [
        "node_id",
        "interface_id",
        "interface_name",
        "plugin",
        "mode",
        "instance",
        "depends_on_task_id",
    ]
    return {
        "id": task.get("id"),
        "type": task.get("type"),
        "payload": {key: payload.get(key) for key in safe_payload_keys if key in payload},
    }


def scrub_text_for_log(value: object, limit: int = 500) -> str:
    """清洗日志文本，避免常见密钥字段直接出现在日志中。"""

    text = str(value)
    for key in ["private_key", "preshared_key", "password", "token", "agent_token"]:
        text = re.sub(rf"({key}[\"']?\s*[=:]\s*[\"']?)[^,\s\"']+", r"\1***", text, flags=re.IGNORECASE)
    return text[:limit]


def summarize_task_result(result: dict[str, Any]) -> dict[str, Any]:
    """生成任务结果日志摘要，避免输出完整配置内容。"""

    summary: dict[str, Any] = {"keys": sorted(result.keys())}
    if "error" in result:
        summary["error"] = scrub_text_for_log(result.get("error"))
    if "runtime_status" in result:
        summary["runtime_status"] = result.get("runtime_status")
    if "changed" in result:
        summary["changed"] = result.get("changed")
    if "applied" in result:
        summary["applied"] = result.get("applied")
    if "valid" in result:
        summary["valid"] = result.get("valid")
    return summary


def mimic_installable(platform_info: dict[str, Any]) -> bool:
    """判断当前节点环境是否允许安装 mimic。"""

    arch = str(platform_info.get("arch") or "").lower()
    distro_id = str(platform_info.get("distro_id") or "").lower()
    distro_codename = str(platform_info.get("distro_codename") or "").lower()
    return (
        mimic_runtime_supported(platform_info)
        and distro_id in {"debian", "ubuntu"}
        and mimic_official_release_codename_supported(distro_codename)
        and arch in {"x86_64", "amd64", "aarch64", "arm64"}
        and bool(shutil.which("dpkg"))
        and bool(shutil.which("apt-get"))
    )


def mimic_runtime_supported(platform_info: dict[str, Any]) -> bool:
    """判断当前节点环境是否允许运行已安装的 mimic。"""

    arch = str(platform_info.get("arch") or "").lower()
    return (
        not platform_info.get("is_openwrt")
        and str(platform_info.get("os") or "linux").lower() == "linux"
        and str(platform_info.get("service_manager") or "") == "systemd"
        and kernel_newer_than(str(platform_info.get("kernel_version") or ""), 6, 1)
        and arch in {"x86_64", "amd64", "aarch64", "arm64"}
    )


def execute_task(task: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    """根据任务类型执行本机操作。"""

    task_type = task["type"]
    payload = task.get("payload", {})
    return execute_registered_task(task_type, payload, config)


def method_accepts_args(method: Any, *args: Any) -> bool:
    """判断方法签名是否能接收指定参数，避免用 TypeError 做兼容分支。"""

    try:
        inspect.signature(method).bind(*args)
    except (TypeError, ValueError):
        return False
    return True


def send_heartbeat(client: AgentClient, snapshot: AgentSnapshot) -> None:
    """发送一次心跳，并兼容测试替身的旧签名。"""

    heartbeat = client.heartbeat
    if method_accepts_args(heartbeat, snapshot.capabilities, snapshot.platform):
        heartbeat(snapshot.capabilities, snapshot.platform)
        return
    heartbeat()


def poll_tasks(client: AgentClient, snapshot: AgentSnapshot) -> list[dict[str, Any]]:
    """拉取待执行任务，并兼容测试替身的旧签名。"""

    poll = client.poll_tasks
    if method_accepts_args(poll, snapshot.capabilities, snapshot.platform):
        return poll(snapshot.capabilities, snapshot.platform)
    if method_accepts_args(poll, snapshot.capabilities):
        return poll(snapshot.capabilities)
    return poll()


def heartbeat_interval_seconds(config: AgentConfig) -> float:
    """返回长任务期间后台心跳间隔。"""

    return max(1.0, float(config.poll_interval))


def start_background_heartbeat(
    client: AgentClient,
    snapshot: AgentSnapshot,
    interval_seconds: float,
) -> tuple[threading.Event, threading.Thread]:
    """启动后台心跳线程，避免长任务期间节点被判离线。"""

    stop_event = threading.Event()

    def loop() -> None:
        """按固定间隔发送心跳直到主线程通知停止。"""

        while not stop_event.wait(interval_seconds):
            try:
                send_heartbeat(client, snapshot)
            except Exception as exc:  # noqa: BLE001
                # 心跳失败不应中断正在执行的任务，下一轮继续尝试。
                logger.warning("长任务后台心跳失败 error=%s", exc)

    thread = threading.Thread(target=loop, name="link42-agent-heartbeat", daemon=True)
    thread.start()
    return stop_event, thread


def link_monitor_worker_count(total: int) -> int:
    """计算链路监测并发数，默认最多 8 个探测同时执行。"""

    if total <= 0:
        return 0
    try:
        configured = int(os.getenv("LINK42_LINK_MONITOR_WORKERS", "8"))
    except ValueError:
        configured = 8
    return max(1, min(total, configured if configured > 0 else 1))


def probe_single_link_monitor(monitor: dict[str, Any]) -> dict[str, Any]:
    """探测单个链路监测目标并带上 monitor_id。"""

    probe = probe_latency(monitor["target_host"], float(monitor.get("timeout_seconds") or 2))
    return {"monitor_id": monitor["id"], **probe}


def failed_link_monitor_result(monitor: dict[str, Any], exc: BaseException) -> dict[str, Any]:
    """把链路探测异常转换成可上报的失败样本。"""

    return {
        "monitor_id": monitor["id"],
        "checked_at": datetime.utcnow().isoformat(),
        "success": False,
        "latency_ms": None,
        "error": str(exc),
    }


def probe_link_monitors(monitors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """并发执行链路监测，避免多个 ping 目标串行阻塞整轮 Agent。"""

    if not monitors:
        return []
    results: list[dict[str, Any] | None] = [None] * len(monitors)
    worker_count = link_monitor_worker_count(len(monitors))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(probe_single_link_monitor, monitor): (index, monitor)
            for index, monitor in enumerate(monitors)
        }
        for future in as_completed(futures):
            index, monitor = futures[future]
            try:
                results[index] = future.result()
            except Exception as exc:  # noqa: BLE001
                results[index] = failed_link_monitor_result(monitor, exc)
    return [item for item in results if item is not None]


def run_once(
    client: AgentClient,
    config: Union[AgentConfig, str],
    snapshot: AgentSnapshot | None = None,
    log_state: AgentLogState | None = None,
) -> None:
    """执行一次心跳、拉取任务和处理任务的循环。"""

    if isinstance(config, str):
        config = AgentConfig(server_url="", node_id=0, token="", wireguard_dir=config)
    snapshot = snapshot or collect_agent_snapshot()
    send_heartbeat(client, snapshot)
    tasks = poll_tasks(client, snapshot)
    if tasks:
        logger.info("拉取到 %d 个待执行任务 tasks=%s", len(tasks), [summarize_task(task) for task in tasks])
    else:
        log_idle_cycle(log_state)
    heartbeat_stop: threading.Event | None = None
    heartbeat_thread: threading.Thread | None = None
    if tasks:
        heartbeat_stop, heartbeat_thread = start_background_heartbeat(
            client,
            snapshot,
            heartbeat_interval_seconds(config),
        )
    try:
        for task in tasks:
            task_id = task["id"]
            task_type = task["type"]
            started_at = time.monotonic()
            logger.info("开始执行任务 task_id=%s task_type=%s summary=%s", task_id, task_type, summarize_task(task))
            try:
                result = execute_task(task, config)
                logger.info(
                    "任务执行成功 task_id=%s task_type=%s duration=%.2fs result=%s",
                    task_id,
                    task_type,
                    time.monotonic() - started_at,
                    summarize_task_result(result),
                )
                client.report_task(task_id, "succeeded", result)
                logger.debug("任务结果已上报 task_id=%s task_type=%s status=succeeded", task_id, task_type)
            except Exception as exc:  # noqa: BLE001
                # Agent 不能因为单个任务失败而退出；失败信息上报后继续处理后续任务。
                logger.exception(
                    "任务执行失败 task_id=%s task_type=%s duration=%.2fs error=%s",
                    task_id,
                    task_type,
                    time.monotonic() - started_at,
                    scrub_text_for_log(exc),
                )
                client.report_task(
                    task_id,
                    "failed",
                    {"error": str(exc), "traceback": traceback.format_exc()},
                )
                logger.debug("任务结果已上报 task_id=%s task_type=%s status=failed", task_id, task_type)
    finally:
        if heartbeat_stop is not None:
            heartbeat_stop.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=1)
    if hasattr(client, "poll_link_monitors") and hasattr(client, "report_link_monitor_results"):
        monitors = client.poll_link_monitors(snapshot.capabilities, snapshot.platform)
        if monitors:
            logger.info("开始执行链路监测 count=%d monitor_ids=%s", len(monitors), [item.get("id") for item in monitors])
        monitor_results = probe_link_monitors(monitors)
        if monitor_results:
            client.report_link_monitor_results(monitor_results)
            failed_count = sum(1 for item in monitor_results if not item.get("success"))
            logger.info(
                "链路监测结果已上报 count=%d failed=%d monitor_ids=%s",
                len(monitor_results),
                failed_count,
                [item.get("monitor_id") for item in monitor_results],
            )


def main() -> None:
    """Agent 命令行入口，持续轮询中心 API。"""

    if run_gre_service_command(sys.argv):
        return

    if "--version" in sys.argv or "version" in sys.argv[1:]:
        print(AGENT_VERSION)
        return

    config = load_config_from_env()
    configure_logging(config.log_level)
    logger.info(
        "Link42 Agent 启动 version=%s node_id=%s server_url=%s poll_interval=%ss wireguard_dir=%s dry_run=%s log_level=%s",
        AGENT_VERSION,
        config.node_id,
        config.server_url,
        config.poll_interval,
        config.wireguard_dir,
        config.dry_run,
        config.log_level,
    )
    client = AgentClient(config)
    log_state = AgentLogState()
    while True:
        try:
            snapshot = collect_agent_snapshot()
            client.register(get_hostname(), snapshot.capabilities, snapshot.platform)
            log_snapshot_if_changed(snapshot, log_state)
            run_once(client, config, snapshot, log_state)
        except AgentHttpError as exc:
            if exc.status_code == 401:
                logger.error(
                    "agent authentication failed: invalid node id or token; "
                    "rotate/copy a fresh deployment command from the controller"
                )
            else:
                logger.warning("Agent API 请求失败 status=%s path=%s body=%s", exc.status_code, exc.path, exc.body[:500])
        except Exception:  # noqa: BLE001
            # 中心 API 重启或网络短暂中断时，Agent 保持运行并在下一轮重试。
            logger.exception("Agent 主循环异常，等待下一轮重试")
        time.sleep(config.poll_interval)


if __name__ == "__main__":
    main()
