from __future__ import annotations

import json
from datetime import datetime, timedelta
import ipaddress
import logging
from pathlib import Path
import secrets
import subprocess
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from link42_common.security import generate_token, hash_token, verify_token
from link42_common.version import AGENT_VERSION, CONTROLLER_VERSION

from . import models, schemas
from .config import settings
from .database import get_db, init_db
from .wireguard_service import (
    build_apply_plan,
    build_apply_payload_from_config,
    build_diff,
    count_enabled_peers,
    render_interface_config,
    split_endpoint,
)


logging.getLogger("uvicorn.access").disabled = True


# FastAPI 应用实例，所有 API 路由都挂载在这里。
app = FastAPI(title="Link42 API", version=CONTROLLER_VERSION)
app.add_middleware(
    CORSMiddleware,
    # 第一版定位小型内网系统，允许前端预览服务跨端口访问 API。
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

DEFAULT_ADMIN_USERNAME = "pmman"
ADMIN_USERNAME = DEFAULT_ADMIN_USERNAME
SETTING_ADMIN_USERNAME = "admin_username"
SETTING_ADMIN_PASSWORD_HASH = "admin_password_hash"
SETTING_ADMIN_SESSION_HASH = "admin_session_hash"
SETTING_CONTROLLER_URL = "controller_url"

TASK_REQUIREMENTS = {
    "wireguard.import_scan": {"min_agent_version": "0.1.0", "capabilities": ["wg_quick_import"]},
    "wireguard.apply_config": {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    "wireguard.read_config": {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    "wireguard.status": {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    "wireguard.start_interface": {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    "wireguard.stop_interface": {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    "wireguard.delete_config": {"min_agent_version": "0.1.0", "capabilities": ["wireguard"]},
    "middleware.install": {"min_agent_version": "0.2.0", "capabilities": ["middleware.install"]},
    "middleware.udp2raw.apply": {"min_agent_version": "0.2.0", "capabilities": ["middleware.udp2raw"]},
    "middleware.udp2raw.start": {"min_agent_version": "0.2.0", "capabilities": ["middleware.udp2raw"]},
    "middleware.udp2raw.stop": {"min_agent_version": "0.2.0", "capabilities": ["middleware.udp2raw"]},
    "middleware.udp2raw.delete": {"min_agent_version": "0.2.0", "capabilities": ["middleware.udp2raw"]},
    "middleware.udp2raw.status": {"min_agent_version": "0.2.0", "capabilities": ["middleware.udp2raw"]},
    "agent.self_upgrade": {"min_agent_version": "0.2.0", "capabilities": ["agent.self_upgrade"]},
}


def mount_web_panel() -> None:
    """按配置挂载前端静态文件，让主控镜像可以单端口运行。"""

    if not settings.web_dist_dir:
        return
    web_dist_dir = Path(settings.web_dist_dir)
    index_file = web_dist_dir / "index.html"
    assets_dir = web_dist_dir / "assets"
    if not index_file.exists():
        return
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="web-assets")

    @app.get("/", include_in_schema=False)
    def serve_web_index() -> FileResponse:
        """返回前端入口页面。"""

        return FileResponse(index_file)

    @app.get("/{path:path}", include_in_schema=False)
    def serve_web_fallback(path: str) -> FileResponse:
        """为前端路由提供 index.html 兜底，同时不接管 API 路径。"""

        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail="not found")
        return FileResponse(index_file)


def get_setting(db: Session, key: str) -> str | None:
    """读取系统设置值。"""

    setting = db.get(models.SystemSetting, key)
    return setting.value if setting else None


def set_setting(db: Session, key: str, value: str) -> None:
    """写入系统设置值。"""

    setting = db.get(models.SystemSetting, key)
    if setting:
        setting.value = value
    else:
        db.add(models.SystemSetting(key=key, value=value))


def ensure_admin_credentials() -> None:
    """首次启动时生成单用户管理员密码，并输出到容器日志。"""

    db = next(get_db())
    try:
        if get_setting(db, SETTING_ADMIN_PASSWORD_HASH):
            if not get_setting(db, SETTING_ADMIN_USERNAME):
                set_setting(db, SETTING_ADMIN_USERNAME, DEFAULT_ADMIN_USERNAME)
                db.commit()
            return
        password = secrets.token_urlsafe(18)
        set_setting(db, SETTING_ADMIN_USERNAME, DEFAULT_ADMIN_USERNAME)
        set_setting(db, SETTING_ADMIN_PASSWORD_HASH, hash_token(password))
        set_setting(db, SETTING_CONTROLLER_URL, get_setting(db, SETTING_CONTROLLER_URL) or "")
        db.commit()
    finally:
        db.close()
    print(f"Link42 initial login: username={DEFAULT_ADMIN_USERNAME} password={password}", flush=True)


def admin_username(db: Session) -> str:
    """读取当前管理员用户名，旧库默认 pmman。"""

    return get_setting(db, SETTING_ADMIN_USERNAME) or DEFAULT_ADMIN_USERNAME


def bearer_token_from_request(request: Request) -> str | None:
    """从 Authorization header 中提取 Bearer token。"""

    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def is_api_auth_exempt(path: str) -> bool:
    """API 鉴权白名单：健康检查、登录和 Agent 自身 token 接口。"""

    return path in {"/api/health", "/api/auth/login"} or path.startswith("/api/agent/")


def require_web_session(request: Request, db: Session) -> None:
    """校验 Web 管理端会话 token。"""

    token = bearer_token_from_request(request)
    session_hash = get_setting(db, SETTING_ADMIN_SESSION_HASH)
    if not token or not session_hash or not verify_token(token, session_hash):
        raise HTTPException(status_code=401, detail="not authenticated")


@app.middleware("http")
async def require_api_authentication(request: Request, call_next):
    """为所有非白名单 API 统一加 Web 鉴权，避免遗漏单个路由。"""

    if request.url.path.startswith("/api/") and not is_api_auth_exempt(request.url.path):
        db = next(get_db())
        try:
            require_web_session(request, db)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        finally:
            db.close()
    return await call_next(request)


@app.on_event("startup")
def on_startup() -> None:
    """应用启动时初始化数据库。"""
    init_db()
    ensure_admin_credentials()


def require_agent(db: Session, node_id: int, token: str) -> models.Node:
    """校验 Agent 身份，并返回对应节点。"""
    node = db.get(models.Node, node_id)
    if node is None or not verify_token(token, node.agent_token_hash):
        raise HTTPException(status_code=401, detail="invalid agent credentials")
    return node


def is_node_online(node: models.Node, now: datetime | None = None) -> bool:
    """根据状态和最近心跳判断节点是否在线。"""

    if node.status != "online" or node.last_seen_at is None:
        return False
    current_time = now or datetime.utcnow()
    return current_time - node.last_seen_at <= timedelta(seconds=settings.agent_offline_after_seconds)


def refresh_node_runtime_status(node: models.Node, now: datetime | None = None) -> models.Node:
    """把心跳超时的节点标记为离线，避免前端看到过期在线状态。"""

    if node.status == "online" and not is_node_online(node, now=now):
        node.status = "offline"
    return node


def parse_version(value: str | None) -> tuple[int, int, int]:
    """把 SemVer 前三段解析成可比较元组。"""

    if not value:
        return (0, 1, 0)
    parts = value.split("-", 1)[0].split(".")
    parsed: list[int] = []
    for part in parts[:3]:
        try:
            parsed.append(int(part))
        except ValueError:
            parsed.append(0)
    while len(parsed) < 3:
        parsed.append(0)
    return tuple(parsed)  # type: ignore[return-value]


def update_agent_metadata(
    node: models.Node,
    agent_version: str | None,
    protocol_version: int | None,
    capabilities: list[str] | None,
    platform: dict | None,
) -> None:
    """保存 Agent 上报的版本、能力和平台信息。"""

    previous_version = node.agent_version
    if agent_version:
        node.agent_version = agent_version
    if protocol_version is not None:
        node.agent_protocol_version = protocol_version
    if capabilities:
        node.agent_capabilities = sorted(set(capabilities))
    if platform:
        node.agent_platform = platform
    if node.agent_update_status in {None, "queued", "staged", "restarting", "healthy", "failed", "rolled_back"}:
        if not previous_version or previous_version != agent_version or node.agent_update_status in {None, "healthy"}:
            node.agent_update_status = "ok"
            node.agent_last_error = None


def agent_satisfies_task(node: models.Node, task_type: str) -> bool:
    """判断节点当前 Agent 是否满足任务要求。"""

    requirement = TASK_REQUIREMENTS.get(task_type)
    if not requirement:
        return True
    if parse_version(node.agent_version) < parse_version(requirement.get("min_agent_version")):
        return False
    capabilities = set(node.agent_capabilities or ["wireguard", "wg_quick_import"])
    return all(capability in capabilities for capability in requirement.get("capabilities", []))


def require_task_supported(node: models.Node, task_type: str) -> None:
    """创建任务前校验 Agent 版本和能力。"""

    if not agent_satisfies_task(node, task_type):
        raise HTTPException(status_code=409, detail=f"agent does not support task: {task_type}")


def agent_release_dir() -> Path:
    """返回 Agent 发布资产目录。"""

    return Path(settings.agent_release_dir)


def load_agent_release_manifest() -> dict:
    """读取 Agent release manifest；缺失时返回空 manifest。"""

    manifest_path = agent_release_dir() / "manifest.json"
    if not manifest_path.exists():
        return {"latest": None, "minimum_supported": None, "releases": {}}
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="invalid agent release manifest") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail="invalid agent release manifest")
    data.setdefault("releases", {})
    return data


def normalize_agent_arch(value: str | None) -> str | None:
    """把平台架构规整为 release manifest 使用的短名。"""

    if not value:
        return None
    arch = value.lower()
    if arch in {"x86_64", "amd64"}:
        return "x64"
    if arch in {"aarch64", "arm64"}:
        return "arm64"
    return arch


def agent_platform_candidates(node: models.Node) -> list[str]:
    """根据节点上报平台生成可接受的 release asset key。"""

    platform = node.agent_platform or {}
    os_name = str(platform.get("os") or "linux").lower()
    arch = normalize_agent_arch(str(platform.get("arch") or "")) or "x64"
    glibc = platform.get("glibc")
    service_manager = str(platform.get("service_manager") or "").lower()
    candidates: list[str] = []
    if service_manager == "openwrt-uci":
        candidates.append(f"openwrt-{arch}-musl")
    if glibc:
        candidates.append(f"{os_name}-{arch}-glibc{glibc}")
        candidates.append(f"{os_name}-{arch}-glibc")
    candidates.append(f"{os_name}-{arch}")
    return candidates


def select_agent_release_asset(node: models.Node, release: dict) -> tuple[str, dict] | tuple[None, None]:
    """为节点选择匹配的 Agent release asset。"""

    assets = release.get("assets") or {}
    if not isinstance(assets, dict):
        return (None, None)
    candidates = agent_platform_candidates(node)
    for candidate in candidates:
        if candidate in assets:
            asset = assets[candidate]
            return (candidate, asset) if isinstance(asset, dict) else (None, None)
    for candidate in candidates:
        for key, asset in assets.items():
            if key.startswith(candidate) and isinstance(asset, dict):
                return key, asset
    return (None, None)


def controller_url_for_agent(db: Session) -> str:
    """返回 Agent 访问主控时应使用的 URL。"""

    return (get_setting(db, SETTING_CONTROLLER_URL) or "").rstrip("/")


def build_agent_manual_upgrade_command(node: models.Node, target_version: str | None, db: Session) -> str:
    """生成旧 Agent 可执行的覆盖安装命令。"""

    env_parts = [
        f"LINK42_AGENT_VERSION={target_version or 'latest'}",
        f"LINK42_RES_BASE_URL={settings.agent_res_base_url}",
    ]
    controller_url = controller_url_for_agent(db)
    if controller_url:
        env_parts.append(f"LINK42_SERVER_URL={controller_url}")
    env_parts.append(f"LINK42_NODE_ID={node.id}")
    if node.agent_token_value:
        env_parts.append(f"LINK42_AGENT_TOKEN={node.agent_token_value}")
    return f"curl -fsSL {settings.agent_install_script_url} | sudo env {' '.join(env_parts)} sh"


def build_agent_upgrade_plan(
    node: models.Node,
    db: Session,
    target_version: str | None = None,
    force: bool = False,
) -> schemas.AgentUpgradePlan:
    """生成单节点 Agent 升级计划。"""

    manifest = load_agent_release_manifest()
    releases = manifest.get("releases") or {}
    selected_version = target_version or manifest.get("latest") or AGENT_VERSION
    release = releases.get(selected_version)
    manual_command = build_agent_manual_upgrade_command(node, selected_version, db)
    if not selected_version:
        return schemas.AgentUpgradePlan(
            node_id=node.id,
            current_version=node.agent_version,
            target_version=None,
            upgrade_mode="unavailable",
            reason="没有可用的 Agent 发布版本",
            manual_command=manual_command,
            status=node.agent_update_status,
        )
    if not is_node_online(node):
        return schemas.AgentUpgradePlan(
            node_id=node.id,
            current_version=node.agent_version,
            target_version=selected_version,
            upgrade_mode="manual",
            reason="节点离线，只能手动覆盖安装",
            manual_command=manual_command,
            status=node.agent_update_status,
        )
    if not force and node.agent_version and parse_version(node.agent_version) >= parse_version(selected_version):
        return schemas.AgentUpgradePlan(
            node_id=node.id,
            current_version=node.agent_version,
            target_version=selected_version,
            upgrade_mode="none",
            reason="当前 Agent 已是目标版本或更高版本",
            manual_command=manual_command,
            status=node.agent_update_status,
        )
    if "agent.self_upgrade" not in set(node.agent_capabilities or []):
        return schemas.AgentUpgradePlan(
            node_id=node.id,
            current_version=node.agent_version,
            target_version=selected_version,
            upgrade_mode="manual",
            reason="当前 Agent 不支持自升级",
            manual_command=manual_command,
            status=node.agent_update_status,
        )
    if not isinstance(release, dict):
        return schemas.AgentUpgradePlan(
            node_id=node.id,
            current_version=node.agent_version,
            target_version=selected_version,
            upgrade_mode="manual",
            reason="主控缺少目标版本 Agent 资产",
            manual_command=manual_command,
            status=node.agent_update_status,
        )
    platform_key, asset = select_agent_release_asset(node, release)
    if not platform_key or not asset:
        return schemas.AgentUpgradePlan(
            node_id=node.id,
            current_version=node.agent_version,
            target_version=selected_version,
            upgrade_mode="manual",
            reason="主控没有匹配该节点平台的 Agent 资产",
            manual_command=manual_command,
            status=node.agent_update_status,
        )
    return schemas.AgentUpgradePlan(
        node_id=node.id,
        current_version=node.agent_version,
        target_version=selected_version,
        upgrade_mode="self_upgrade",
        matched_platform=platform_key,
        matched_asset=schemas.AgentReleaseAsset.model_validate(asset),
        manual_command=manual_command,
        status=node.agent_update_status,
    )


def normalize_udp2raw_config(payload: schemas.Udp2RawMiddlewareConfig | None) -> dict | None:
    """清洗 udp2raw 插件配置，未启用时返回 None。"""

    if payload is None or not payload.enabled:
        return None
    if payload.server_listen_port is None:
        raise HTTPException(status_code=400, detail="udp2raw server listen port is required")
    if payload.client_listen_port is None:
        raise HTTPException(status_code=400, detail="udp2raw client listen port is required")
    server_listen_host = require_udp2raw_ip(
        payload.server_listen_host.strip() or "0.0.0.0",
        "udp2raw server listen host",
    )
    server_connect_host = (
        require_udp2raw_ip(payload.server_connect_host.strip(), "udp2raw server connect host")
        if payload.server_connect_host
        else None
    )
    server_forward_host = (
        require_udp2raw_ip(payload.server_forward_host.strip(), "udp2raw server forward host")
        if payload.server_forward_host
        else None
    )
    client_listen_host = require_udp2raw_ip(
        payload.client_listen_host.strip() or "127.0.0.1",
        "udp2raw client listen host",
    )
    return {
        "type": "udp2raw",
        "enabled": True,
        "server_side": payload.server_side,
        "server_listen_host": server_listen_host,
        "server_connect_host": server_connect_host,
        "server_listen_port": payload.server_listen_port,
        "server_forward_host": server_forward_host,
        "server_forward_port": payload.server_forward_port,
        "client_listen_host": client_listen_host,
        "client_listen_port": payload.client_listen_port,
        "raw_mode": payload.raw_mode,
        "cipher_mode": payload.cipher_mode,
        "password": payload.password or generate_token("u2r"),
        "auto_rule": payload.auto_rule,
    }


def require_udp2raw_ip(value: str, field_name: str) -> str:
    """udp2raw 的 -r 目标必须是 IP 字面量，不能是域名。"""

    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"{field_name} must be an IP address for udp2raw") from exc
    return value


def managed_link_middleware(interface: models.WireGuardInterface) -> dict | None:
    """读取受管连接绑定的中间层配置。"""

    middleware = (interface.extras or {}).get("middleware")
    return middleware if isinstance(middleware, dict) and middleware.get("enabled") else None


def require_udp2raw_supported(node: models.Node) -> None:
    """要求节点 Agent 支持 systemd udp2raw 中间层。"""

    for task_type in ["middleware.install", "middleware.udp2raw.apply"]:
        require_task_supported(node, task_type)
    if "service:systemd" not in set(node.agent_capabilities or []):
        raise HTTPException(status_code=409, detail="udp2raw middleware currently requires systemd agent")


def apply_udp2raw_to_peers(
    middleware: dict | None,
    local_interface: models.WireGuardInterface,
    peer_interface: models.WireGuardInterface,
    local_peer: models.WireGuardPeer,
    peer_peer: models.WireGuardPeer,
    local_endpoint: str,
    peer_endpoint: str,
    local_endpoint_port: int | None = None,
    peer_endpoint_port: int | None = None,
) -> None:
    """根据单向 udp2raw 配置覆盖 WireGuard Peer Endpoint。"""

    if not middleware:
        local_peer.endpoint_host = peer_endpoint
        local_peer.endpoint_port = peer_endpoint_port or peer_interface.listen_port
        peer_peer.endpoint_host = local_endpoint
        peer_peer.endpoint_port = local_endpoint_port or local_interface.listen_port
        return

    server_side = middleware["server_side"]
    if server_side == "peer":
        if peer_interface.listen_port is None:
            raise HTTPException(status_code=400, detail="udp2raw server side requires WireGuard listen port")
        local_peer.endpoint_host = middleware["client_listen_host"]
        local_peer.endpoint_port = middleware["client_listen_port"]
        peer_peer.endpoint_host = None
        peer_peer.endpoint_port = None
    else:
        if local_interface.listen_port is None:
            raise HTTPException(status_code=400, detail="udp2raw server side requires WireGuard listen port")
        local_peer.endpoint_host = None
        local_peer.endpoint_port = None
        peer_peer.endpoint_host = middleware["client_listen_host"]
        peer_peer.endpoint_port = middleware["client_listen_port"]


def udp2raw_instance_name(local_interface: models.WireGuardInterface, peer_interface: models.WireGuardInterface) -> str:
    return f"link42-{min(local_interface.id, peer_interface.id)}-{max(local_interface.id, peer_interface.id)}"


def udp2raw_endpoint_payloads(
    middleware: dict | None,
    local_interface: models.WireGuardInterface,
    peer_interface: models.WireGuardInterface,
    local_endpoint: str,
    peer_endpoint: str,
) -> list[tuple[models.WireGuardInterface, str, dict]]:
    """生成双方 udp2raw Agent payload；返回 interface、task_type、payload。"""

    if not middleware:
        return []
    instance = udp2raw_instance_name(local_interface, peer_interface)
    server_side = middleware["server_side"]
    if server_side == "peer":
        server_interface = peer_interface
        client_interface = local_interface
        server_public_host = peer_endpoint
    else:
        server_interface = local_interface
        client_interface = peer_interface
        server_public_host = local_endpoint
    if server_interface.listen_port is None:
        raise HTTPException(status_code=400, detail="udp2raw server side requires WireGuard listen port")
    server_connect_host = require_udp2raw_ip(
        middleware.get("server_connect_host") or server_public_host,
        "udp2raw server connect host",
    )
    server_forward_host = require_udp2raw_ip(
        middleware.get("server_forward_host") or "127.0.0.1",
        "udp2raw server forward host",
    )
    server_forward_port = middleware.get("server_forward_port") or server_interface.listen_port

    common = {
        "plugin": "udp2raw",
        "instance": instance,
        "raw_mode": middleware["raw_mode"],
        "cipher_mode": middleware["cipher_mode"],
        "password": middleware["password"],
        "auto_rule": middleware["auto_rule"],
    }
    server_payload = {
        **common,
        "mode": "server",
        "listen_host": middleware["server_listen_host"],
        "listen_port": middleware["server_listen_port"],
        "remote_host": server_forward_host,
        "remote_port": server_forward_port,
    }
    client_payload = {
        **common,
        "mode": "client",
        "listen_host": middleware["client_listen_host"],
        "listen_port": middleware["client_listen_port"],
        "remote_host": server_connect_host,
        "remote_port": middleware["server_listen_port"],
    }
    return [
        (server_interface, "middleware.udp2raw.apply", server_payload),
        (client_interface, "middleware.udp2raw.apply", client_payload),
    ]


def enqueue_udp2raw_tasks(
    db: Session,
    middleware: dict | None,
    local_interface: models.WireGuardInterface,
    peer_interface: models.WireGuardInterface,
    local_endpoint: str,
    peer_endpoint: str,
) -> None:
    """为启用 udp2raw 的受管连接下发安装和配置任务。"""

    if not middleware:
        return
    for interface in [local_interface, peer_interface]:
        node = db.get(models.Node, interface.node_id)
        if node is not None:
            require_udp2raw_supported(node)
        enqueue_interface_task_once(db, interface, "middleware.install", {"plugin": "udp2raw"})
    for interface, task_type, payload in udp2raw_endpoint_payloads(
        middleware,
        local_interface,
        peer_interface,
        local_endpoint,
        peer_endpoint,
    ):
        enqueue_interface_task_once(db, interface, task_type, payload)


def require_online_node(db: Session, node_id: int) -> models.Node:
    """读取节点并要求 Agent 当前在线，否则返回可展示的业务错误。"""

    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    refresh_node_runtime_status(node)
    if node.status != "online":
        db.commit()
        raise HTTPException(status_code=409, detail="agent is offline")
    return node


def imported_secret_ref(value: str | None) -> str | None:
    """为导入配置生成密钥引用。"""

    if not value:
        return None
    return "imported-local-db"


def set_extra_value(model: models.WireGuardInterface | models.WireGuardPeer, key: str, value: str | None) -> None:
    """在 JSON extras 中保存可选扩展字段，空值会清理旧值。"""

    extras = dict(model.extras or {})
    cleaned = value.strip() if value else None
    if cleaned:
        extras[key] = cleaned
    else:
        extras.pop(key, None)
    model.extras = extras


def set_extra_object(model: models.WireGuardInterface | models.WireGuardPeer, key: str, value: dict | None) -> None:
    """在 JSON extras 中保存对象扩展字段。"""

    extras = dict(model.extras or {})
    if value:
        extras[key] = value
    else:
        extras.pop(key, None)
    model.extras = extras


def get_wireguard_config_or_404(config_id: int, db: Session) -> models.WireGuardInterface:
    """按配置 ID 读取 WireGuard 配置，不存在时返回 404。"""

    config = db.get(models.WireGuardInterface, config_id)
    if config is None:
        raise HTTPException(status_code=404, detail="wireguard config not found")
    return config


def ensure_unique_interface_name(
    db: Session,
    node_id: int,
    name: str,
    exclude_interface_id: int | None = None,
) -> None:
    """确保同一节点下 WireGuard 配置名唯一。"""

    query = select(models.WireGuardInterface).where(
        models.WireGuardInterface.node_id == node_id,
        models.WireGuardInterface.name == name,
    )
    if exclude_interface_id is not None:
        query = query.where(models.WireGuardInterface.id != exclude_interface_id)
    duplicate = db.scalar(query)
    if duplicate:
        raise HTTPException(status_code=409, detail="interface name already exists on node")


def set_unique_peer(
    config_id: int,
    payload: schemas.PeerCreate,
    db: Session,
) -> models.WireGuardPeer:
    """创建或更新某个 WireGuard 配置的唯一对端。

    第一版产品规则是“一份 wg-quick 配置只连接一个对端”。如果旧数据里
    已经存在多条对端记录，这里会保留第一条并删除其余记录。
    """

    config = get_wireguard_config_or_404(config_id, db)
    require_online_node(db, config.node_id)
    existing_peers = list(
        db.scalars(
            select(models.WireGuardPeer)
            .where(models.WireGuardPeer.interface_id == config_id)
            .order_by(models.WireGuardPeer.id)
        )
    )
    if existing_peers:
        existing_peer = existing_peers[0]
        existing_peer.name = payload.name
        existing_peer.public_key = payload.public_key
        existing_peer.preshared_key_ref = "local-db" if payload.preshared_key else None
        existing_peer.preshared_key_value = payload.preshared_key
        existing_peer.endpoint_host = payload.endpoint_host
        existing_peer.endpoint_port = payload.endpoint_port
        existing_peer.allowed_ips = payload.allowed_ips
        existing_peer.persistent_keepalive = payload.persistent_keepalive
        existing_peer.enabled = True
        set_extra_value(existing_peer, "custom_config", payload.peer_custom_config)
        for extra_peer in existing_peers[1:]:
            db.delete(extra_peer)
        db.commit()
        db.refresh(existing_peer)
        return existing_peer

    peer = models.WireGuardPeer(
        interface_id=config_id,
        name=payload.name,
        public_key=payload.public_key,
        preshared_key_ref="local-db" if payload.preshared_key else None,
        preshared_key_value=payload.preshared_key,
        endpoint_host=payload.endpoint_host,
        endpoint_port=payload.endpoint_port,
        allowed_ips=payload.allowed_ips,
        persistent_keepalive=payload.persistent_keepalive,
    )
    set_extra_value(peer, "custom_config", payload.peer_custom_config)
    db.add(peer)
    db.commit()
    db.refresh(peer)
    return peer


def get_unique_peer(config_id: int, db: Session) -> models.WireGuardPeer | None:
    """读取某个 WireGuard 配置的唯一对端，并清理历史重复记录。"""

    get_wireguard_config_or_404(config_id, db)
    peers = list(
        db.scalars(
            select(models.WireGuardPeer)
            .where(models.WireGuardPeer.interface_id == config_id)
            .order_by(models.WireGuardPeer.id)
        )
    )
    if len(peers) > 1:
        for extra_peer in peers[1:]:
            db.delete(extra_peer)
        db.commit()
    return peers[0] if peers else None


def create_interface_task(
    interface: models.WireGuardInterface,
    task_type: str,
    payload_extra: dict | None = None,
    change_plan_id: int | None = None,
) -> models.AgentTask:
    """为单个 WireGuard 配置创建 Agent 任务。"""

    payload = {
        "node_id": interface.node_id,
        "interface_id": interface.id,
        "interface_name": interface.name,
    }
    if payload_extra:
        payload.update(payload_extra)
    return models.AgentTask(
        node_id=interface.node_id,
        change_plan_id=change_plan_id,
        type=task_type,
        payload=payload,
    )


def has_active_interface_task(db: Session, interface_id: int, task_type: str) -> bool:
    """判断某接口是否已有同类型待执行任务，保证用户重复点击时幂等。"""

    existing = db.scalar(
        select(models.AgentTask).where(
            models.AgentTask.type == task_type,
            models.AgentTask.status.in_(["pending", "running"]),
            models.AgentTask.payload["interface_id"].as_integer() == interface_id,
        )
    )
    return existing is not None


def enqueue_interface_task_once(
    db: Session,
    interface: models.WireGuardInterface,
    task_type: str,
    payload_extra: dict | None = None,
) -> bool:
    """幂等创建接口任务；已存在待执行任务时不重复入队。"""

    if has_active_interface_task(db, interface.id, task_type):
        return False
    node = db.get(models.Node, interface.node_id)
    if node is not None:
        require_task_supported(node, task_type)
    db.add(create_interface_task(interface, task_type, payload_extra=payload_extra))
    return True


def mark_import_candidate_available_for_interface(
    db: Session,
    interface: models.WireGuardInterface,
) -> bool:
    """删除导入配置时释放原扫描候选，允许用户再次导入同一 wg-quick 文件。"""

    if interface.source != "imported" or not interface.import_path:
        return False
    candidate = db.scalar(
        select(models.ImportCandidate).where(
            models.ImportCandidate.node_id == interface.node_id,
            models.ImportCandidate.path == interface.import_path,
            models.ImportCandidate.imported.is_(True),
        )
    )
    if candidate is None:
        return False
    candidate.imported = False
    return True


def existing_interface_names(db: Session, node_id: int) -> set[str]:
    """返回节点下已存在的 WireGuard 接口名，用于排除重复导入候选。"""

    return set(
        db.scalars(
            select(models.WireGuardInterface.name).where(models.WireGuardInterface.node_id == node_id)
        )
    )


def should_offer_import_candidate(
    candidate: models.ImportCandidate,
    existing_names: set[str],
) -> bool:
    """判断扫描候选是否仍应展示给用户导入。"""

    return not candidate.imported and candidate.interface_name not in existing_names


def should_delete_node_config_file(interface: models.WireGuardInterface) -> bool:
    """判断删除 Link42 配置时是否应同步删除节点上的 wg-quick 文件。"""

    return interface.managed or interface.source != "imported"


def get_managed_link_bundle(
    db: Session,
    interface_id: int,
) -> tuple[models.WireGuardInterface, models.WireGuardInterface, models.WireGuardPeer, models.WireGuardPeer]:
    """读取受管节点连接的双端接口和互指 peer。"""

    interface = db.scalar(
        select(models.WireGuardInterface)
        .options(selectinload(models.WireGuardInterface.peers))
        .where(models.WireGuardInterface.id == interface_id)
    )
    if interface is None:
        raise HTTPException(status_code=404, detail="interface not found")
    local_peer = next(
        (peer for peer in interface.peers if peer.peer_interface_id and peer.source == "managed-node"),
        None,
    )
    if local_peer is None:
        raise HTTPException(status_code=400, detail="wireguard config is not a managed node link")

    peer_interface = db.scalar(
        select(models.WireGuardInterface)
        .options(selectinload(models.WireGuardInterface.peers))
        .where(models.WireGuardInterface.id == local_peer.peer_interface_id)
    )
    if peer_interface is None:
        raise HTTPException(status_code=404, detail="peer interface not found")
    peer_peer = next(
        (peer for peer in peer_interface.peers if peer.peer_interface_id == interface.id and peer.source == "managed-node"),
        None,
    )
    if peer_peer is None:
        raise HTTPException(status_code=400, detail="managed node link is incomplete")
    return interface, peer_interface, local_peer, peer_peer


def enqueue_apply_config(
    db: Session,
    interface: models.WireGuardInterface,
    enable_on_boot: bool = True,
) -> bool:
    """幂等下发某个受管接口配置。"""

    return enqueue_interface_task_once(
        db,
        interface,
        "wireguard.apply_config",
        payload_extra={
            "config": render_interface_config(interface),
            "managed": True,
            "enable_on_boot": enable_on_boot,
            "auto_start": True,
        },
    )


def get_replace_interface(
    db: Session,
    interface_id: int | None,
    node_id: int,
) -> models.WireGuardInterface | None:
    """读取准备被受管连接替换的旧接口。"""

    if interface_id is None:
        return None
    interface = db.get(models.WireGuardInterface, interface_id)
    if interface is None or interface.node_id != node_id:
        raise HTTPException(status_code=404, detail="replace interface not found")
    if interface.source != "imported" or interface.managed:
        raise HTTPException(status_code=400, detail="replace interface must be unmanaged imported config")
    return interface


def endpoint_points_to_node(endpoint_host: str | None, node: models.Node) -> bool:
    """判断旧导入配置中的 Endpoint 是否指向目标节点地址。"""

    return bool(endpoint_host and endpoint_host in node_endpoint_hosts(node))


def queue_replace_interface(db: Session, interface: models.WireGuardInterface) -> None:
    """替换旧配置时先请求 Agent 停止并删除节点文件，再删除数据库记录。"""

    enqueue_interface_task_once(db, interface, "wireguard.stop_interface")
    if should_delete_node_config_file(interface):
        enqueue_interface_task_once(db, interface, "wireguard.delete_config")
    mark_import_candidate_available_for_interface(db, interface)
    db.delete(interface)


def node_endpoint_hosts(node: models.Node) -> list[str]:
    """返回节点可被对端访问的地址列表，兼容旧数据中的单地址字段。"""

    values = [
        *(node.endpoint_ips or []),
        node.public_ip,
        node.management_ip,
        node.hostname,
    ]
    hosts: list[str] = []
    for value in values:
        if value and value not in hosts:
            hosts.append(value)
    return hosts


def require_node_endpoint(node: models.Node, host: str, detail: str) -> str:
    """校验并返回用户填写的入口地址。

    节点保存的入口地址用于下拉选项，但实机部署时常会临时填写内网地址、
    NAT 地址或域名，因此这里不强制要求 host 已登记到节点。
    """

    cleaned = host.strip()
    if not cleaned:
        raise HTTPException(status_code=400, detail=detail)
    return cleaned


def run_wg_text(args: list[str], input_text: str | None = None) -> str:
    """调用系统 wg 工具生成 WireGuard 密钥材料。"""

    try:
        completed = subprocess.run(
            ["wg", *args],
            input=input_text,
            check=False,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail="wireguard tool is not installed") from exc
    if completed.returncode != 0:
        raise HTTPException(status_code=500, detail=f"wireguard tool failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def generate_wireguard_keypair() -> tuple[str, str]:
    """生成 WireGuard 私钥和公钥。"""

    private_key = run_wg_text(["genkey"])
    public_key = run_wg_text(["pubkey"], input_text=f"{private_key}\n")
    return private_key, public_key


def generate_preshared_key() -> str:
    """生成 WireGuard 预共享密钥。"""

    return run_wg_text(["genpsk"])


@app.get("/api/health")
def health() -> dict[str, str]:
    """健康检查接口，用于确认 API 进程可响应。"""
    return {"status": "ok"}


@app.post("/api/auth/login", response_model=schemas.LoginResult)
def login(payload: schemas.LoginRequest, db: Session = Depends(get_db)) -> schemas.LoginResult:
    """单用户登录，成功后返回 Web 管理端 Bearer token。"""

    password_hash = get_setting(db, SETTING_ADMIN_PASSWORD_HASH)
    username = admin_username(db)
    if payload.username != username or not password_hash or not verify_token(payload.password, password_hash):
        raise HTTPException(status_code=401, detail="invalid username or password")
    token = generate_token("l42web")
    set_setting(db, SETTING_ADMIN_SESSION_HASH, hash_token(token))
    db.commit()
    return schemas.LoginResult(token=token, username=username)


@app.post("/api/auth/logout")
def logout(db: Session = Depends(get_db)) -> dict[str, str]:
    """退出当前 Web 管理端会话。"""

    set_setting(db, SETTING_ADMIN_SESSION_HASH, "")
    db.commit()
    return {"status": "logged out"}


@app.get("/api/auth/me", response_model=schemas.AuthStatus)
def auth_me(db: Session = Depends(get_db)) -> schemas.AuthStatus:
    """返回当前登录用户。"""

    return schemas.AuthStatus(authenticated=True, username=admin_username(db))


@app.get("/api/settings", response_model=schemas.ControllerSettingsRead)
def get_controller_settings(db: Session = Depends(get_db)) -> schemas.ControllerSettingsRead:
    """读取主控 Web 设置。"""

    return schemas.ControllerSettingsRead(
        controller_url=get_setting(db, SETTING_CONTROLLER_URL) or "",
        username=admin_username(db),
    )


@app.patch("/api/settings", response_model=schemas.ControllerSettingsRead)
def update_controller_settings(
    payload: schemas.ControllerSettingsUpdate,
    db: Session = Depends(get_db),
) -> schemas.ControllerSettingsRead:
    """保存主控访问地址和管理员凭据。"""

    controller_url = payload.controller_url.strip()
    if not controller_url:
        raise HTTPException(status_code=400, detail="controller url is required")
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="username is required")
    set_setting(db, SETTING_CONTROLLER_URL, controller_url)
    set_setting(db, SETTING_ADMIN_USERNAME, username)
    if payload.new_password:
        set_setting(db, SETTING_ADMIN_PASSWORD_HASH, hash_token(payload.new_password))
        set_setting(db, SETTING_ADMIN_SESSION_HASH, "")
    db.commit()
    return schemas.ControllerSettingsRead(controller_url=controller_url, username=username)


@app.get("/api/agent/releases", response_model=schemas.AgentReleaseManifest)
def list_agent_releases() -> schemas.AgentReleaseManifest:
    """返回主控内置的 Agent release manifest。"""

    return schemas.AgentReleaseManifest.model_validate(load_agent_release_manifest())


@app.get("/api/agent/releases/{version}/download")
def download_agent_release(version: str, platform: str) -> FileResponse:
    """Agent 下载匹配平台的版本化二进制。"""

    manifest = load_agent_release_manifest()
    release = (manifest.get("releases") or {}).get(version)
    if not isinstance(release, dict):
        raise HTTPException(status_code=404, detail="agent release not found")
    asset = (release.get("assets") or {}).get(platform)
    if not isinstance(asset, dict):
        raise HTTPException(status_code=404, detail="agent release asset not found")
    path = agent_release_dir() / str(asset.get("path") or "")
    try:
        path.resolve().relative_to(agent_release_dir().resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid agent release asset path") from exc
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="agent release asset file not found")
    return FileResponse(path, filename=path.name)


@app.get("/api/agent/releases/{version}/sha256")
def agent_release_sha256(version: str, platform: str) -> dict[str, str]:
    """返回 Agent release asset 的 SHA256。"""

    manifest = load_agent_release_manifest()
    release = (manifest.get("releases") or {}).get(version)
    if not isinstance(release, dict):
        raise HTTPException(status_code=404, detail="agent release not found")
    asset = (release.get("assets") or {}).get(platform)
    if not isinstance(asset, dict) or not asset.get("sha256"):
        raise HTTPException(status_code=404, detail="agent release asset not found")
    return {"sha256": str(asset["sha256"])}


@app.get("/api/nodes/{node_id}/agent/upgrade-plan", response_model=schemas.AgentUpgradePlan)
def get_agent_upgrade_plan(
    node_id: int,
    target_version: str | None = None,
    force: bool = False,
    db: Session = Depends(get_db),
) -> schemas.AgentUpgradePlan:
    """为节点生成 Agent 升级计划。"""

    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    refresh_node_runtime_status(node)
    return build_agent_upgrade_plan(node, db, target_version=target_version, force=force)


@app.post("/api/nodes/{node_id}/agent/upgrade", response_model=schemas.TaskRequestResult)
def request_agent_upgrade(
    node_id: int,
    payload: schemas.AgentUpgradeRequest,
    db: Session = Depends(get_db),
) -> schemas.TaskRequestResult:
    """创建 Agent 自升级任务。"""

    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    refresh_node_runtime_status(node)
    plan = build_agent_upgrade_plan(node, db, target_version=payload.target_version, force=payload.force)
    if plan.upgrade_mode != "self_upgrade" or not plan.target_version or not plan.matched_platform or not plan.matched_asset:
        raise HTTPException(status_code=409, detail=plan.reason or "agent self upgrade is not available")
    active = db.scalar(
        select(models.AgentTask).where(
            models.AgentTask.node_id == node_id,
            models.AgentTask.type == "agent.self_upgrade",
            models.AgentTask.status.in_(["pending", "running"]),
        )
    )
    if active:
        return schemas.TaskRequestResult(task_id=active.id, status=active.status, message="升级任务已存在")
    require_task_supported(node, "agent.self_upgrade")
    controller_url = controller_url_for_agent(db)
    if not controller_url:
        raise HTTPException(status_code=400, detail="controller url is required before agent upgrade")
    asset = plan.matched_asset
    task = models.AgentTask(
        node_id=node_id,
        type="agent.self_upgrade",
        payload={
            "target_version": plan.target_version,
            "download_url": (
                f"{controller_url}/api/agent/releases/{plan.target_version}/download"
                f"?platform={plan.matched_platform}"
            ),
            "sha256": asset.sha256,
            "size": asset.size,
            "binary_args": ["--version"],
            "service_name": "link42-agent",
            "install_path": "/usr/local/bin/link42-agent",
            "rollback": True,
        },
    )
    db.add(task)
    node.agent_update_status = "queued"
    node.agent_last_error = None
    db.commit()
    db.refresh(task)
    return schemas.TaskRequestResult(task_id=task.id, status=task.status, message="升级任务已创建")


@app.post("/api/nodes", response_model=schemas.NodeCreateResult)
def create_node(payload: schemas.NodeCreate, db: Session = Depends(get_db)) -> schemas.NodeCreateResult:
    """创建节点，并返回仅展示一次的 Agent token。"""
    existing = db.scalar(select(models.Node).where(models.Node.name == payload.name))
    if existing:
        raise HTTPException(status_code=409, detail="node name already exists")

    token = generate_token("l42agent")
    node = models.Node(
        name=payload.name,
        hostname=payload.hostname,
        management_ip=payload.management_ip,
        public_ip=payload.public_ip,
        endpoint_ips=payload.endpoint_ips,
        status="offline",
        agent_token_hash=hash_token(token),
        agent_token_value=token,
    )
    db.add(node)
    db.commit()
    db.refresh(node)
    return schemas.NodeCreateResult(node=node, agent_token=token)


@app.patch("/api/nodes/{node_id}", response_model=schemas.NodeRead)
def update_node(
    node_id: int,
    payload: schemas.NodeUpdate,
    db: Session = Depends(get_db),
) -> models.Node:
    """修改节点基础信息和入口地址。"""

    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    duplicate = db.scalar(
        select(models.Node).where(models.Node.name == payload.name, models.Node.id != node_id)
    )
    if duplicate:
        raise HTTPException(status_code=409, detail="node name already exists")

    node.name = payload.name
    node.hostname = payload.hostname
    node.management_ip = payload.management_ip
    node.public_ip = payload.public_ip
    node.endpoint_ips = payload.endpoint_ips
    db.commit()
    db.refresh(node)
    return node


@app.get("/api/nodes", response_model=list[schemas.NodeRead])
def list_nodes(db: Session = Depends(get_db)) -> list[models.Node]:
    """列出所有节点。"""
    nodes = list(db.scalars(select(models.Node).order_by(models.Node.id)))
    changed = False
    for node in nodes:
        old_status = node.status
        refresh_node_runtime_status(node)
        changed = changed or node.status != old_status
    if changed:
        db.commit()
    return nodes


@app.get("/api/nodes/{node_id}", response_model=schemas.NodeRead)
def get_node(node_id: int, db: Session = Depends(get_db)) -> models.Node:
    """读取单个节点详情。"""
    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    old_status = node.status
    refresh_node_runtime_status(node)
    if node.status != old_status:
        db.commit()
        db.refresh(node)
    return node


@app.delete("/api/nodes/{node_id}")
def delete_node(node_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    """删除节点；节点下存在 WireGuard 配置时必须先清空配置。"""

    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    interface_count = db.scalar(
        select(models.WireGuardInterface).where(models.WireGuardInterface.node_id == node_id).limit(1)
    )
    if interface_count is not None:
        raise HTTPException(status_code=409, detail="node has wireguard configs")
    for candidate in db.scalars(select(models.ImportCandidate).where(models.ImportCandidate.node_id == node_id)):
        db.delete(candidate)
    for task in db.scalars(select(models.AgentTask).where(models.AgentTask.node_id == node_id)):
        db.delete(task)
    db.delete(node)
    db.commit()
    return {"status": "deleted"}


@app.post("/api/nodes/{node_id}/rotate-agent-token", response_model=schemas.NodeCreateResult)
def rotate_agent_token(node_id: int, db: Session = Depends(get_db)) -> schemas.NodeCreateResult:
    """轮换节点 Agent token，旧 token 会立即失效。"""
    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    token = generate_token("l42agent")
    node.agent_token_hash = hash_token(token)
    node.agent_token_value = token
    db.commit()
    db.refresh(node)
    return schemas.NodeCreateResult(node=node, agent_token=token)


@app.post("/api/nodes/{node_id}/wireguard/interfaces", response_model=schemas.InterfaceRead)
@app.post("/api/nodes/{node_id}/wireguard/configs", response_model=schemas.InterfaceRead)
def create_interface(
    node_id: int,
    payload: schemas.InterfaceCreate,
    db: Session = Depends(get_db),
) -> models.WireGuardInterface:
    """在指定节点上创建 WireGuard 点对点配置期望状态。"""
    require_online_node(db, node_id)

    ensure_unique_interface_name(db, node_id, payload.name)

    interface = models.WireGuardInterface(
        node_id=node_id,
        name=payload.name,
        tunnel_ips=payload.tunnel_ips,
        listen_port=payload.listen_port,
        private_key_ref="local-db" if payload.private_key else None,
        private_key_value=payload.private_key,
        public_key=payload.public_key,
        mtu=payload.mtu,
        table_name=payload.table_name,
        dns=payload.dns,
        source="created",
        managed=True,
    )
    set_extra_value(interface, "custom_config", payload.interface_custom_config)
    db.add(interface)
    db.commit()
    db.refresh(interface)
    return interface


@app.post("/api/nodes/{node_id}/wireguard/managed-links", response_model=schemas.ManagedLinkCreateResult)
def create_managed_link(
    node_id: int,
    payload: schemas.ManagedLinkCreate,
    db: Session = Depends(get_db),
) -> schemas.ManagedLinkCreateResult:
    """在两个受管节点之间创建点对点 WireGuard 连接期望状态。"""

    if node_id == payload.peer_node_id:
        raise HTTPException(status_code=400, detail="peer node must be different")

    local_node = require_online_node(db, node_id)
    peer_node = require_online_node(db, payload.peer_node_id)
    replace_local = get_replace_interface(db, payload.replace_local_interface_id, node_id)
    replace_peer = get_replace_interface(db, payload.replace_peer_interface_id, payload.peer_node_id)
    replace_local_peer = get_unique_peer(replace_local.id, db) if replace_local else None
    replace_peer_peer = get_unique_peer(replace_peer.id, db) if replace_peer else None
    if replace_local_peer and not endpoint_points_to_node(replace_local_peer.endpoint_host, peer_node) and not payload.force_endpoint_mismatch:
        raise HTTPException(status_code=409, detail="local imported endpoint does not point to peer node")
    if replace_peer_peer and not endpoint_points_to_node(replace_peer_peer.endpoint_host, local_node) and not payload.force_endpoint_mismatch:
        raise HTTPException(status_code=409, detail="peer imported endpoint does not point to local node")
    local_endpoint = require_node_endpoint(
        local_node,
        payload.local_endpoint_host,
        "local endpoint address is not registered on node",
    )
    peer_endpoint = require_node_endpoint(
        peer_node,
        payload.peer_endpoint_host,
        "peer endpoint address is not registered on node",
    )
    udp2raw = normalize_udp2raw_config(payload.udp2raw)

    peer_interface_name = payload.peer_interface_name or payload.local_interface_name
    ensure_unique_interface_name(
        db,
        node_id,
        payload.local_interface_name,
        exclude_interface_id=replace_local.id if replace_local else None,
    )
    ensure_unique_interface_name(
        db,
        payload.peer_node_id,
        peer_interface_name,
        exclude_interface_id=replace_peer.id if replace_peer else None,
    )

    local_private_key, local_public_key = generate_wireguard_keypair()
    peer_private_key, peer_public_key = generate_wireguard_keypair()
    preshared_key = generate_preshared_key()

    local_interface = models.WireGuardInterface(
        node_id=node_id,
        name=payload.local_interface_name,
        tunnel_ips=payload.local_tunnel_ips,
        listen_port=payload.local_listen_port,
        private_key_ref="local-db",
        private_key_value=local_private_key,
        public_key=local_public_key,
        mtu=payload.mtu,
        table_name=payload.table_name,
        source="managed-node",
        managed=True,
        runtime_status="starting",
    )
    peer_interface = models.WireGuardInterface(
        node_id=payload.peer_node_id,
        name=peer_interface_name,
        tunnel_ips=payload.peer_tunnel_ips,
        listen_port=payload.peer_listen_port,
        private_key_ref="local-db",
        private_key_value=peer_private_key,
        public_key=peer_public_key,
        mtu=payload.mtu,
        table_name=payload.table_name,
        source="managed-node",
        managed=True,
        runtime_status="starting",
    )
    db.add_all([local_interface, peer_interface])
    db.flush()
    local_peer = models.WireGuardPeer(
        interface=local_interface,
        peer_node_id=payload.peer_node_id,
        peer_interface_id=peer_interface.id,
        name=peer_node.name,
        public_key=peer_public_key,
        preshared_key_ref="local-db",
        preshared_key_value=preshared_key,
        allowed_ips=payload.local_allowed_ips or payload.peer_tunnel_ips,
        persistent_keepalive=payload.persistent_keepalive,
        source="managed-node",
    )
    peer_peer = models.WireGuardPeer(
        interface=peer_interface,
        peer_node_id=node_id,
        peer_interface_id=local_interface.id,
        name=local_node.name,
        public_key=local_public_key,
        preshared_key_ref="local-db",
        preshared_key_value=preshared_key,
        allowed_ips=payload.peer_allowed_ips or payload.local_tunnel_ips,
        persistent_keepalive=payload.persistent_keepalive,
        source="managed-node",
    )
    set_extra_value(local_interface, "custom_config", payload.local_interface_custom_config)
    set_extra_value(peer_interface, "custom_config", payload.peer_interface_custom_config)
    set_extra_value(local_peer, "custom_config", payload.local_peer_custom_config)
    set_extra_value(peer_peer, "custom_config", payload.peer_peer_custom_config)
    set_extra_object(local_interface, "middleware", udp2raw)
    set_extra_object(peer_interface, "middleware", udp2raw)
    apply_udp2raw_to_peers(
        udp2raw,
        local_interface,
        peer_interface,
        local_peer,
        peer_peer,
        local_endpoint,
        peer_endpoint,
        payload.local_endpoint_port,
        payload.peer_endpoint_port,
    )
    db.add_all([local_peer, peer_peer])
    db.flush()
    if replace_local:
        queue_replace_interface(db, replace_local)
    if replace_peer:
        queue_replace_interface(db, replace_peer)
    enqueue_udp2raw_tasks(db, udp2raw, local_interface, peer_interface, local_endpoint, peer_endpoint)
    enqueue_apply_config(db, local_interface)
    enqueue_apply_config(db, peer_interface)
    db.commit()
    db.refresh(local_interface)
    db.refresh(peer_interface)
    return schemas.ManagedLinkCreateResult(local_interface=local_interface, peer_interface=peer_interface)


@app.get("/api/nodes/{node_id}/wireguard/interfaces", response_model=list[schemas.InterfaceRead])
@app.get("/api/nodes/{node_id}/wireguard/configs", response_model=list[schemas.InterfaceRead])
def list_interfaces(node_id: int, db: Session = Depends(get_db)) -> list[models.WireGuardInterface]:
    """列出指定节点上的 WireGuard 点对点配置。"""
    return list(
        db.scalars(
            select(models.WireGuardInterface)
            .options(selectinload(models.WireGuardInterface.peers))
            .where(models.WireGuardInterface.node_id == node_id)
            .order_by(models.WireGuardInterface.name)
        )
    )


@app.get("/api/wireguard/interfaces/{interface_id}", response_model=schemas.InterfaceRead)
@app.get("/api/wireguard/configs/{interface_id}", response_model=schemas.InterfaceRead)
def get_interface(interface_id: int, db: Session = Depends(get_db)) -> models.WireGuardInterface:
    """读取单个 WireGuard 点对点配置。"""
    interface = db.scalar(
        select(models.WireGuardInterface)
        .options(selectinload(models.WireGuardInterface.peers))
        .where(models.WireGuardInterface.id == interface_id)
    )
    if interface is None:
        raise HTTPException(status_code=404, detail="interface not found")
    return interface


@app.get("/api/wireguard/configs/{interface_id}/managed-link", response_model=schemas.ManagedLinkRead)
def get_managed_link(interface_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    """读取受管节点连接的双端配置。"""

    local_interface, peer_interface, local_peer, peer_peer = get_managed_link_bundle(db, interface_id)
    return {
        "local_interface": local_interface,
        "peer_interface": peer_interface,
        "local_peer": local_peer,
        "peer_peer": peer_peer,
        "middleware": managed_link_middleware(local_interface),
    }


@app.patch("/api/wireguard/configs/{interface_id}/managed-link", response_model=schemas.ManagedLinkRead)
def update_managed_link(
    interface_id: int,
    payload: schemas.ManagedLinkUpdate,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """编辑受管节点连接，并直接下发双方配置。"""

    local_interface, peer_interface, local_peer, peer_peer = get_managed_link_bundle(db, interface_id)
    local_node = require_online_node(db, local_interface.node_id)
    peer_node = require_online_node(db, peer_interface.node_id)
    local_endpoint = require_node_endpoint(
        local_node,
        payload.local_endpoint_host,
        "local endpoint address is not registered on node",
    )
    peer_endpoint = require_node_endpoint(
        peer_node,
        payload.peer_endpoint_host,
        "peer endpoint address is not registered on node",
    )
    udp2raw = normalize_udp2raw_config(payload.udp2raw)
    ensure_unique_interface_name(db, local_interface.node_id, payload.local_interface_name, local_interface.id)
    ensure_unique_interface_name(db, peer_interface.node_id, payload.peer_interface_name, peer_interface.id)

    local_interface.name = payload.local_interface_name
    local_interface.tunnel_ips = payload.local_tunnel_ips
    local_interface.listen_port = payload.local_listen_port
    local_interface.mtu = payload.mtu
    local_interface.table_name = payload.table_name
    local_interface.managed = True
    local_interface.source = "managed-node"
    peer_interface.name = payload.peer_interface_name
    peer_interface.tunnel_ips = payload.peer_tunnel_ips
    peer_interface.listen_port = payload.peer_listen_port
    peer_interface.mtu = payload.mtu
    peer_interface.table_name = payload.table_name
    peer_interface.managed = True
    peer_interface.source = "managed-node"

    local_peer.allowed_ips = payload.local_allowed_ips or payload.peer_tunnel_ips
    local_peer.persistent_keepalive = payload.persistent_keepalive
    local_peer.source = "managed-node"
    peer_peer.allowed_ips = payload.peer_allowed_ips or payload.local_tunnel_ips
    peer_peer.persistent_keepalive = payload.persistent_keepalive
    peer_peer.source = "managed-node"
    set_extra_value(local_interface, "custom_config", payload.local_interface_custom_config)
    set_extra_value(peer_interface, "custom_config", payload.peer_interface_custom_config)
    set_extra_value(local_peer, "custom_config", payload.local_peer_custom_config)
    set_extra_value(peer_peer, "custom_config", payload.peer_peer_custom_config)
    set_extra_object(local_interface, "middleware", udp2raw)
    set_extra_object(peer_interface, "middleware", udp2raw)
    apply_udp2raw_to_peers(
        udp2raw,
        local_interface,
        peer_interface,
        local_peer,
        peer_peer,
        local_endpoint,
        peer_endpoint,
        payload.local_endpoint_port,
        payload.peer_endpoint_port,
    )

    enqueue_udp2raw_tasks(db, udp2raw, local_interface, peer_interface, local_endpoint, peer_endpoint)
    if enqueue_apply_config(db, local_interface):
        local_interface.runtime_status = "starting"
    if enqueue_apply_config(db, peer_interface):
        peer_interface.runtime_status = "starting"
    db.commit()
    db.refresh(local_interface)
    db.refresh(peer_interface)
    db.refresh(local_peer)
    db.refresh(peer_peer)
    return {
        "local_interface": local_interface,
        "peer_interface": peer_interface,
        "local_peer": local_peer,
        "peer_peer": peer_peer,
        "middleware": managed_link_middleware(local_interface),
    }


@app.post("/api/wireguard/configs/{interface_id}/managed-link/start", response_model=schemas.ManagedLinkRead)
def start_managed_link(interface_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    """同时启动受管连接双方。"""

    local_interface, peer_interface, local_peer, peer_peer = get_managed_link_bundle(db, interface_id)
    require_online_node(db, local_interface.node_id)
    require_online_node(db, peer_interface.node_id)
    middleware = managed_link_middleware(local_interface)
    if middleware:
        for interface in [local_interface, peer_interface]:
            enqueue_interface_task_once(db, interface, "middleware.udp2raw.start", {
                "plugin": "udp2raw",
                "instance": udp2raw_instance_name(local_interface, peer_interface),
            })
    for interface in [local_interface, peer_interface]:
        if interface.runtime_status not in ["running", "starting"]:
            if enqueue_interface_task_once(db, interface, "wireguard.start_interface"):
                interface.runtime_status = "starting"
    db.commit()
    return {
        "local_interface": local_interface,
        "peer_interface": peer_interface,
        "local_peer": local_peer,
        "peer_peer": peer_peer,
        "middleware": middleware,
    }


@app.post("/api/wireguard/configs/{interface_id}/managed-link/stop", response_model=schemas.ManagedLinkRead)
def stop_managed_link(interface_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    """同时断开受管连接双方。"""

    local_interface, peer_interface, local_peer, peer_peer = get_managed_link_bundle(db, interface_id)
    require_online_node(db, local_interface.node_id)
    require_online_node(db, peer_interface.node_id)
    middleware = managed_link_middleware(local_interface)
    for interface in [local_interface, peer_interface]:
        if interface.runtime_status not in ["stopped", "stopping"]:
            if enqueue_interface_task_once(db, interface, "wireguard.stop_interface"):
                interface.runtime_status = "stopping"
    if middleware:
        for interface in [local_interface, peer_interface]:
            enqueue_interface_task_once(db, interface, "middleware.udp2raw.stop", {
                "plugin": "udp2raw",
                "instance": udp2raw_instance_name(local_interface, peer_interface),
            })
    db.commit()
    return {
        "local_interface": local_interface,
        "peer_interface": peer_interface,
        "local_peer": local_peer,
        "peer_peer": peer_peer,
        "middleware": middleware,
    }


@app.delete("/api/wireguard/configs/{interface_id}/managed-link")
def delete_managed_link(interface_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    """同时删除受管连接双方；必须先断开双方接口。"""

    local_interface, peer_interface, _, _ = get_managed_link_bundle(db, interface_id)
    require_online_node(db, local_interface.node_id)
    require_online_node(db, peer_interface.node_id)
    if any(interface.runtime_status in ["running", "starting", "stopping"] for interface in [local_interface, peer_interface]):
        raise HTTPException(status_code=409, detail="wireguard interface must be stopped before delete")
    middleware = managed_link_middleware(local_interface)
    for interface in [local_interface, peer_interface]:
        if middleware:
            enqueue_interface_task_once(db, interface, "middleware.udp2raw.delete", {
                "plugin": "udp2raw",
                "instance": udp2raw_instance_name(local_interface, peer_interface),
            })
        mark_import_candidate_available_for_interface(db, interface)
        if should_delete_node_config_file(interface):
            enqueue_interface_task_once(db, interface, "wireguard.delete_config")
        db.delete(interface)
    db.commit()
    return {"status": "deleted"}


@app.patch("/api/wireguard/interfaces/{interface_id}", response_model=schemas.InterfaceRead)
@app.patch("/api/wireguard/configs/{interface_id}", response_model=schemas.InterfaceRead)
def update_interface(
    interface_id: int,
    payload: schemas.InterfaceUpdate,
    db: Session = Depends(get_db),
) -> models.WireGuardInterface:
    """修改已有 WireGuard 点对点配置的期望状态。"""

    interface = db.get(models.WireGuardInterface, interface_id)
    if interface is None:
        raise HTTPException(status_code=404, detail="interface not found")
    require_online_node(db, interface.node_id)
    ensure_unique_interface_name(db, interface.node_id, payload.name, exclude_interface_id=interface.id)

    interface.name = payload.name
    interface.tunnel_ips = payload.tunnel_ips
    interface.listen_port = payload.listen_port
    interface.private_key_ref = "local-db" if payload.private_key else None
    interface.private_key_value = payload.private_key
    interface.public_key = payload.public_key
    interface.mtu = payload.mtu
    interface.table_name = payload.table_name
    interface.dns = payload.dns
    set_extra_value(interface, "custom_config", payload.interface_custom_config)
    db.commit()
    db.refresh(interface)
    return interface


@app.post("/api/wireguard/interfaces/{interface_id}/peers", response_model=schemas.PeerRead)
def create_peer(
    interface_id: int,
    payload: schemas.PeerCreate,
    db: Session = Depends(get_db),
) -> models.WireGuardPeer:
    """兼容旧接口：设置 WireGuard 配置的唯一对端。"""

    return set_unique_peer(interface_id, payload, db)


@app.put("/api/wireguard/configs/{config_id}/peer", response_model=schemas.PeerRead)
def put_config_peer(
    config_id: int,
    payload: schemas.PeerCreate,
    db: Session = Depends(get_db),
) -> models.WireGuardPeer:
    """设置 WireGuard 点对点配置的唯一对端。"""

    return set_unique_peer(config_id, payload, db)


@app.get("/api/wireguard/configs/{config_id}/peer", response_model=schemas.PeerRead | None)
def get_config_peer(config_id: int, db: Session = Depends(get_db)) -> models.WireGuardPeer | None:
    """读取 WireGuard 点对点配置的唯一对端。"""

    return get_unique_peer(config_id, db)


@app.delete("/api/wireguard/configs/{config_id}/peer")
def delete_config_peer(config_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    """删除 WireGuard 点对点配置的唯一对端。"""

    peer = get_unique_peer(config_id, db)
    if peer is not None:
        db.delete(peer)
        db.commit()
    return {"status": "deleted"}


@app.get("/api/wireguard/interfaces/{interface_id}/peers", response_model=list[schemas.PeerRead])
def list_peers(interface_id: int, db: Session = Depends(get_db)) -> list[models.WireGuardPeer]:
    """列出指定 WireGuard 配置下的对端；第一版最多返回一条。"""
    peer = get_unique_peer(interface_id, db)
    return [peer] if peer is not None else []


@app.post("/api/wireguard/interfaces/{interface_id}/plan-apply", response_model=schemas.ChangePlanRead)
@app.post("/api/wireguard/configs/{interface_id}/plan-apply", response_model=schemas.ChangePlanRead)
def plan_apply(interface_id: int, db: Session = Depends(get_db)) -> models.ChangePlan:
    """为 WireGuard 配置生成部署计划，但不立即下发到 Agent。"""
    interface = db.scalar(
        select(models.WireGuardInterface)
        .options(selectinload(models.WireGuardInterface.peers))
        .where(models.WireGuardInterface.id == interface_id)
    )
    if interface is None:
        raise HTTPException(status_code=404, detail="interface not found")
    require_online_node(db, interface.node_id)
    if interface.source == "managed-node":
        raise HTTPException(status_code=400, detail="managed node links are deployed directly")
    enabled_peer_count = count_enabled_peers(interface)
    if enabled_peer_count != 1:
        raise HTTPException(
            status_code=400,
            detail="deployable wireguard config must have exactly one enabled peer",
        )

    if interface.source == "imported" and not interface.managed and interface.deployed_config:
        # 未接管的导入配置表示“观察现有 wg-quick 文件”，直接使用现有文件作为目标。
        # 否则脱敏密钥会被错误渲染进 diff。
        new_config = interface.deployed_config
    else:
        new_config = render_interface_config(interface)
    old_config = interface.deployed_config or ""
    diff = build_diff(old_config, new_config, fromfile=f"{interface.name}.current", tofile=f"{interface.name}.link42")
    plan = models.ChangePlan(
        title=f"Apply WireGuard interface {interface.name}",
        summary=f"Deploy WireGuard config for node {interface.node_id} interface {interface.name}",
        affected_node_ids=[interface.node_id],
        diff=diff,
        payload={"task_type": "wireguard.apply_config", "task_payload": build_apply_plan(interface)},
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


@app.post("/api/wireguard/configs/{interface_id}/refresh-deployed", response_model=schemas.InterfaceRead)
def refresh_deployed_config(interface_id: int, db: Session = Depends(get_db)) -> models.WireGuardInterface:
    """请求 Agent 读取节点上的当前配置，供下一次部署计划生成真实 diff。"""

    interface = get_wireguard_config_or_404(interface_id, db)
    require_online_node(db, interface.node_id)
    enqueue_interface_task_once(db, interface, "wireguard.read_config")
    db.commit()
    db.refresh(interface)
    return interface


@app.post("/api/wireguard/configs/{interface_id}/refresh-status", response_model=schemas.InterfaceRead)
def refresh_interface_status(interface_id: int, db: Session = Depends(get_db)) -> models.WireGuardInterface:
    """请求 Agent 刷新 WireGuard 接口运行状态。"""

    interface = get_wireguard_config_or_404(interface_id, db)
    require_online_node(db, interface.node_id)
    enqueue_interface_task_once(db, interface, "wireguard.status")
    db.commit()
    db.refresh(interface)
    return interface


@app.post("/api/wireguard/configs/{interface_id}/start", response_model=schemas.InterfaceRead)
def start_interface(interface_id: int, db: Session = Depends(get_db)) -> models.WireGuardInterface:
    """创建启动 WireGuard 接口的 Agent 任务。"""

    interface = get_wireguard_config_or_404(interface_id, db)
    require_online_node(db, interface.node_id)
    if interface.source == "managed-node":
        raise HTTPException(status_code=400, detail="use managed link operation")
    if not interface.deployed_config:
        raise HTTPException(status_code=400, detail="wireguard config must be deployed before start")
    if interface.runtime_status in ["running", "starting"]:
        return interface
    if enqueue_interface_task_once(db, interface, "wireguard.start_interface"):
        interface.runtime_status = "starting"
    db.commit()
    db.refresh(interface)
    return interface


@app.post("/api/wireguard/configs/{interface_id}/stop", response_model=schemas.InterfaceRead)
def stop_interface(interface_id: int, db: Session = Depends(get_db)) -> models.WireGuardInterface:
    """创建关闭 WireGuard 接口的 Agent 任务。"""

    interface = get_wireguard_config_or_404(interface_id, db)
    require_online_node(db, interface.node_id)
    if interface.source == "managed-node":
        raise HTTPException(status_code=400, detail="use managed link operation")
    if interface.runtime_status in ["stopped", "stopping"]:
        return interface
    if enqueue_interface_task_once(db, interface, "wireguard.stop_interface"):
        interface.runtime_status = "stopping"
    db.commit()
    db.refresh(interface)
    return interface


@app.delete("/api/wireguard/configs/{interface_id}")
def delete_interface(interface_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    """删除 WireGuard 配置；运行中的配置必须先关闭。"""

    interface = get_wireguard_config_or_404(interface_id, db)
    if interface.source == "imported" and not interface.managed:
        mark_import_candidate_available_for_interface(db, interface)
        db.delete(interface)
        db.commit()
        return {"status": "deleted"}

    require_online_node(db, interface.node_id)
    if interface.runtime_status in ["running", "starting", "stopping"]:
        raise HTTPException(status_code=409, detail="wireguard interface must be stopped before delete")
    mark_import_candidate_available_for_interface(db, interface)
    if should_delete_node_config_file(interface):
        enqueue_interface_task_once(db, interface, "wireguard.delete_config")
    db.delete(interface)
    db.commit()
    return {"status": "deleted"}


@app.post("/api/change-plans/{plan_id}/confirm", response_model=schemas.ChangePlanRead)
def confirm_change_plan(plan_id: int, db: Session = Depends(get_db)) -> models.ChangePlan:
    """确认部署计划，并创建等待 Agent 拉取的任务。"""
    plan = db.get(models.ChangePlan, plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="change plan not found")
    if plan.status != "draft":
        raise HTTPException(status_code=409, detail="change plan is not draft")
    if not plan.diff.strip():
        raise HTTPException(status_code=400, detail="change plan has no diff")

    task_payload = plan.payload.get("task_payload")
    task_type = plan.payload.get("task_type")
    if not task_payload or not task_type:
        raise HTTPException(status_code=400, detail="change plan has no task payload")
    node = require_online_node(db, task_payload["node_id"])
    require_task_supported(node, task_type)

    plan.status = "confirmed"
    plan.confirmed_at = datetime.utcnow()
    post_confirm = plan.payload.get("post_confirm") or {}
    managed_interface_id = post_confirm.get("set_interface_managed")
    if managed_interface_id:
        # 接管导入配置必须等用户确认后才改变归属，避免草稿计划影响真实状态。
        interface = db.get(models.WireGuardInterface, managed_interface_id)
        if interface is not None:
            interface.managed = True
    task = models.AgentTask(
        node_id=task_payload["node_id"],
        change_plan_id=plan.id,
        type=task_type,
        payload=task_payload,
    )
    db.add(task)
    db.commit()
    db.refresh(plan)
    return plan


@app.get("/api/change-plans/{plan_id}", response_model=schemas.ChangePlanRead)
def get_change_plan(plan_id: int, db: Session = Depends(get_db)) -> models.ChangePlan:
    """读取部署计划状态，供前端确认 Agent 是否执行完成。"""

    plan = db.get(models.ChangePlan, plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="change plan not found")
    return plan


@app.post("/api/nodes/{node_id}/wireguard/import-scan", response_model=schemas.TaskRequestResult)
def request_import_scan(node_id: int, db: Session = Depends(get_db)) -> schemas.TaskRequestResult:
    """直接创建扫描现有 wg-quick 配置的 Agent 任务。"""

    require_online_node(db, node_id)

    existing = db.scalar(
        select(models.AgentTask).where(
            models.AgentTask.node_id == node_id,
            models.AgentTask.type == "wireguard.import_scan",
            models.AgentTask.status.in_(["pending", "running"]),
        )
    )
    if existing is not None:
        return schemas.TaskRequestResult(
            task_id=existing.id,
            status=existing.status,
            message="scan task already queued",
        )

    task = models.AgentTask(
        node_id=node_id,
        type="wireguard.import_scan",
        payload={"node_id": node_id},
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return schemas.TaskRequestResult(
        task_id=task.id,
        status=task.status,
        message="scan task queued",
    )


@app.get("/api/agent/tasks/{task_id}", response_model=schemas.AgentTaskStatusRead)
def get_agent_task(task_id: int, db: Session = Depends(get_db)) -> models.AgentTask:
    """读取 Agent 任务状态，供前端轮询直接任务。"""

    task = db.get(models.AgentTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    return task


@app.get("/api/agent/plugins/udp2raw/assets/{asset_name}")
def get_udp2raw_asset(asset_name: str) -> FileResponse:
    """为 Agent 提供主控内置的 udp2raw 二进制资产。"""

    allowed = {
        "udp2raw_amd64",
        "udp2raw_amd64_hw_aes",
        "udp2raw_x86",
        "udp2raw_x86_asm_aes",
        "udp2raw_arm",
        "udp2raw_arm_asm_aes",
        "udp2raw_mips24kc_le",
        "udp2raw_mips24kc_le_asm_aes",
        "udp2raw_mips24kc_be",
        "udp2raw_mips24kc_be_asm_aes",
    }
    if asset_name not in allowed:
        raise HTTPException(status_code=404, detail="udp2raw asset not found")
    candidates = [
        Path("/opt/link42/plugins/udp2raw/assets") / asset_name,
        Path(__file__).resolve().parents[3] / "plugins" / "udp2raw" / "assets" / asset_name,
        Path(__file__).resolve().parents[3] / "udp2raw_sh" / "udp2raw_bin" / asset_name,
    ]
    for path in candidates:
        if path.exists():
            return FileResponse(path)
    raise HTTPException(status_code=404, detail="udp2raw asset not found")


@app.get("/api/nodes/{node_id}/wireguard/import-candidates", response_model=list[schemas.ImportCandidateRead])
def list_import_candidates(node_id: int, db: Session = Depends(get_db)) -> list[models.ImportCandidate]:
    """列出 Agent 扫描回来的 wg-quick 导入候选。"""
    existing_names = existing_interface_names(db, node_id)
    candidates = list(
        db.scalars(
            select(models.ImportCandidate)
            .where(
                models.ImportCandidate.node_id == node_id,
                models.ImportCandidate.imported.is_(False),
            )
            .order_by(models.ImportCandidate.id.desc())
        )
    )
    return [candidate for candidate in candidates if should_offer_import_candidate(candidate, existing_names)]


@app.post("/api/nodes/{node_id}/wireguard/import", response_model=schemas.InterfaceRead)
def import_candidate(
    node_id: int,
    payload: schemas.ImportRequest,
    db: Session = Depends(get_db),
) -> models.WireGuardInterface:
    """把某个导入候选保存为 Link42 中的未接管接口。"""
    candidate = db.get(models.ImportCandidate, payload.candidate_id)
    if candidate is None or candidate.node_id != node_id:
        raise HTTPException(status_code=404, detail="import candidate not found")
    if candidate.imported:
        raise HTTPException(status_code=409, detail="candidate already imported")

    parsed = candidate.parsed
    import_warnings = list(parsed.get("warnings", []))
    if len(parsed.get("peers", [])) > 1:
        import_warnings.append(
            "此配置包含多个 Peer，已按观察模式导入；请拆分为单对端配置后再接管管理。"
        )
    interface = models.WireGuardInterface(
        node_id=node_id,
        name=parsed["name"],
        tunnel_ips=parsed.get("addresses", []),
        listen_port=parsed.get("listen_port"),
        private_key_ref=imported_secret_ref(parsed.get("private_key")),
        private_key_value=parsed.get("private_key"),
        mtu=parsed.get("mtu"),
        fwmark=parsed.get("fwmark"),
        table_name=parsed.get("table"),
        dns=parsed.get("dns", []),
        pre_up=parsed.get("pre_up", []),
        post_up=parsed.get("post_up", []),
        pre_down=parsed.get("pre_down", []),
        post_down=parsed.get("post_down", []),
        source="imported",
        managed=False,
        deployed_config=candidate.parsed.get("raw_config"),
        import_path=candidate.path,
        extras=parsed.get("extras", {}),
        warnings=import_warnings,
    )
    db.add(interface)
    db.flush()
    for peer_data in parsed.get("peers", [])[:1]:
        # 第一版只管理点对点配置；多 Peer 导入时只保留第一条用于观察，接管会被校验拦住。
        endpoint_host, endpoint_port = split_endpoint(peer_data.get("endpoint"))
        db.add(
            models.WireGuardPeer(
                interface_id=interface.id,
                public_key=peer_data.get("public_key") or "",
                preshared_key_ref=imported_secret_ref(peer_data.get("preshared_key")),
                preshared_key_value=peer_data.get("preshared_key"),
                endpoint_host=endpoint_host,
                endpoint_port=endpoint_port,
                allowed_ips=peer_data.get("allowed_ips", []),
                persistent_keepalive=peer_data.get("persistent_keepalive"),
                source="imported",
                extras=peer_data.get("extras", {}),
                warnings=peer_data.get("warnings", []),
            )
        )
    candidate.imported = True
    db.commit()
    db.refresh(interface)
    return interface


@app.post("/api/wireguard/interfaces/{interface_id}/take-over", response_model=schemas.ChangePlanRead)
@app.post("/api/wireguard/configs/{interface_id}/take-over", response_model=schemas.ChangePlanRead)
def take_over_imported_interface(interface_id: int, db: Session = Depends(get_db)) -> models.ChangePlan:
    """为导入配置生成接管计划，确认后才会覆盖节点配置。"""
    interface = db.scalar(
        select(models.WireGuardInterface)
        .options(selectinload(models.WireGuardInterface.peers))
        .where(models.WireGuardInterface.id == interface_id)
    )
    if interface is None:
        raise HTTPException(status_code=404, detail="interface not found")
    require_online_node(db, interface.node_id)
    if interface.source != "imported":
        raise HTTPException(status_code=400, detail="only imported interfaces need takeover")
    if any("多个 Peer" in warning for warning in interface.warnings):
        raise HTTPException(
            status_code=400,
            detail="imported config contains multiple peers and must be split before takeover",
        )
    enabled_peer_count = count_enabled_peers(interface)
    if enabled_peer_count != 1:
        raise HTTPException(
            status_code=400,
            detail="imported config must have exactly one enabled peer before takeover",
        )

    if interface.deployed_config:
        # 已导入的 wg-quick 文件本来就在节点上；接管只是改变 Link42 管理状态，不应重写文件。
        interface.managed = True
        plan = models.ChangePlan(
            title=f"Take over WireGuard interface {interface.name}",
            summary=(
                f"Use existing wg-quick config for node {interface.node_id} interface {interface.name}"
            ),
            status="succeeded",
            affected_node_ids=[interface.node_id],
            diff="",
            payload={},
            confirmed_at=datetime.utcnow(),
        )
        db.add(plan)
        db.commit()
        db.refresh(plan)
        return plan

    new_config = render_interface_config(interface)
    diff = build_diff("", new_config, fromfile=f"{interface.name}.imported", tofile=f"{interface.name}.link42")
    plan = models.ChangePlan(
        title=f"Take over WireGuard interface {interface.name}",
        summary=f"Back up and replace imported config for node {interface.node_id} interface {interface.name}",
        affected_node_ids=[interface.node_id],
        diff=diff,
        payload={
            "task_type": "wireguard.apply_config",
            "task_payload": build_apply_payload_from_config(interface, new_config),
            "post_confirm": {"set_interface_managed": interface.id},
        },
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


@app.post("/api/agent/register")
def agent_register(payload: schemas.AgentRegisterRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    """Agent 首次注册或重新注册节点信息。"""
    node = require_agent(db, payload.node_id, payload.token)
    node.hostname = payload.hostname or node.hostname
    node.management_ip = payload.management_ip or node.management_ip
    node.public_ip = payload.public_ip or node.public_ip
    update_agent_metadata(node, payload.agent_version, payload.protocol_version, payload.capabilities, payload.platform)
    node.status = "online"
    node.last_seen_at = datetime.utcnow()
    db.commit()
    return {"status": "registered"}


@app.post("/api/agent/heartbeat")
def agent_heartbeat(payload: schemas.AgentHeartbeatRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    """Agent 心跳，用于更新节点在线状态。"""
    node = require_agent(db, payload.node_id, payload.token)
    update_agent_metadata(node, payload.agent_version, payload.protocol_version, payload.capabilities, payload.platform)
    node.status = "online"
    node.last_seen_at = datetime.utcnow()
    db.commit()
    return {"status": "ok"}


@app.post("/api/agent/tasks/poll", response_model=schemas.AgentPollResponse)
def agent_poll(payload: schemas.AgentPollRequest, db: Session = Depends(get_db)) -> schemas.AgentPollResponse:
    """Agent 轮询待执行任务，并把任务标记为 running。"""
    node = require_agent(db, payload.node_id, payload.token)
    update_agent_metadata(node, payload.agent_version, payload.protocol_version, payload.capabilities, payload.platform)
    tasks = list(
        db.scalars(
            select(models.AgentTask)
            .where(models.AgentTask.node_id == payload.node_id, models.AgentTask.status == "pending")
            .order_by(models.AgentTask.id)
            .limit(5)
        )
    )
    tasks = [task for task in tasks if agent_satisfies_task(node, task.type)]
    for task in tasks:
        task.status = "running"
        task.started_at = datetime.utcnow()
    db.commit()
    return schemas.AgentPollResponse(tasks=[schemas.AgentTaskRead(id=t.id, type=t.type, payload=t.payload) for t in tasks])


@app.post("/api/agent/tasks/{task_id}/result")
def agent_task_result(
    task_id: int,
    payload: schemas.AgentTaskResultRequest,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Agent 上报任务执行结果，并更新相关 Change Plan 状态。"""
    require_agent(db, payload.node_id, payload.token)
    task = db.get(models.AgentTask, task_id)
    if task is None or task.node_id != payload.node_id:
        raise HTTPException(status_code=404, detail="task not found")

    task.status = payload.status
    task.result = payload.result
    task.finished_at = datetime.utcnow()
    node = db.get(models.Node, payload.node_id)

    if task.type == "agent.self_upgrade" and node is not None:
        reported_status = str(payload.result.get("status") or payload.status)
        node.agent_update_status = reported_status
        if payload.status == "failed" or reported_status in {"failed", "rolled_back"}:
            node.agent_last_error = str(payload.result.get("error") or payload.result)
        else:
            node.agent_last_error = None

    if task.change_plan_id:
        plan = db.get(models.ChangePlan, task.change_plan_id)
        if plan is not None:
            plan.status = "succeeded" if payload.status == "succeeded" else "failed"

    # import_scan 的结果由 Agent 返回候选配置，API 在这里转存为 ImportCandidate。
    if task.type == "wireguard.import_scan" and payload.status == "succeeded":
        candidates = payload.result.get("candidates", [])
        scanned_paths = {candidate["path"] for candidate in candidates if candidate.get("path")}
        imported_interface_names = existing_interface_names(db, payload.node_id)
        stale_candidates = db.scalars(
            select(models.ImportCandidate).where(
                models.ImportCandidate.node_id == payload.node_id,
                models.ImportCandidate.imported.is_(False),
                models.ImportCandidate.path.not_in(scanned_paths),
            )
        )
        for stale_candidate in stale_candidates:
            db.delete(stale_candidate)
        for candidate in candidates:
            parsed = candidate.get("parsed")
            if parsed is None or not candidate.get("path"):
                continue
            parsed["raw_config"] = candidate.get("content") or parsed.get("raw_config") or ""
            interface_name = parsed["name"]
            existing_candidate = db.scalar(
                select(models.ImportCandidate).where(
                    models.ImportCandidate.node_id == payload.node_id,
                    models.ImportCandidate.path == candidate["path"],
                )
            )
            if interface_name in imported_interface_names:
                if existing_candidate and not existing_candidate.imported:
                    db.delete(existing_candidate)
                continue
            if existing_candidate:
                if existing_candidate.imported:
                    continue
                # 重复扫描同一路径时更新候选，避免前端出现多条相同导入项。
                existing_candidate.interface_name = interface_name
                existing_candidate.parsed = parsed
                existing_candidate.warnings = candidate.get("warnings", [])
                continue
            db.add(
                models.ImportCandidate(
                    node_id=payload.node_id,
                    path=candidate["path"],
                    interface_name=interface_name,
                    parsed=parsed,
                    warnings=candidate.get("warnings", []),
                )
            )

    interface_id = task.payload.get("interface_id")
    if interface_id and payload.status == "succeeded":
        interface = db.get(models.WireGuardInterface, interface_id)
        if interface is not None:
            if task.type == "wireguard.apply_config":
                # 部署成功后记录节点上的已部署配置，后续 Change Plan diff 才能对比真实基线。
                interface.deployed_config = task.payload.get("config")
                interface.runtime_status = "running"
            elif task.type == "wireguard.read_config":
                interface.deployed_config = payload.result.get("config") or ""
            elif task.type == "wireguard.start_interface":
                interface.runtime_status = "running"
            elif task.type == "wireguard.stop_interface":
                interface.runtime_status = "stopped"
            elif task.type == "wireguard.status":
                interface.runtime_status = payload.result.get("runtime_status") or interface.runtime_status

    db.commit()
    return {"status": "recorded"}


mount_web_panel()
