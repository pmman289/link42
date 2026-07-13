from __future__ import annotations

import json
from datetime import datetime, timedelta
import hashlib
import ipaddress
import logging
import re
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import time
from typing import Any
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from link42_common.connection_types import (
    CONNECTION_TYPE_GRE,
    CONNECTION_TYPE_WIREGUARD,
    GRE_TASKS,
    LOOKING_GLASS_BIRD_PROTOCOL_DETAIL_TASK,
    LOOKING_GLASS_BIRD_PROTOCOLS_TASK,
    LOOKING_GLASS_BIRD_ROUTE_LOOKUP_TASK,
    LOOKING_GLASS_BIRD_ROUTES_BY_ORIGIN_AS_TASK,
    LOOKING_GLASS_PING_TASK,
    LOOKING_GLASS_TRACEROUTE_TASK,
    TASK_REQUIREMENTS,
    WIREGUARD_TASKS,
)
from sqlalchemy import String, delete, func, or_, select
from sqlalchemy.orm import Session, selectinload

from link42_common.security import generate_token, hash_token, verify_token
from link42_common.version import AGENT_VERSION, CONTROLLER_VERSION

from . import models, schemas
from .config import settings
from .connection_drivers import connection_driver_for_interface
from .database import get_db, init_db
from .node_plugins import NODE_PLUGINS, get_node_plugin
from .node_plugins.base import NodePluginContext
from .wireguard_service import (
    build_apply_plan,
    build_apply_payload_from_config,
    build_diff,
    build_interface_rename_diff,
    count_enabled_peers,
    render_interface_config,
    split_endpoint,
)


LOGGER_NAME = "link42.api"
logger = logging.getLogger(LOGGER_NAME)


def configure_logging(level_name: str) -> None:
    """配置主控业务日志输出，方便容器、systemd 和前台开发服务直接采集。"""

    level = getattr(logging, str(level_name or "INFO").upper(), logging.INFO)
    root_logger = logging.getLogger("link42")
    existing_handler = next(
        (handler for handler in root_logger.handlers if getattr(handler, "_link42_handler", False)),
        None,
    )
    if isinstance(existing_handler, logging.StreamHandler):
        existing_handler.setStream(sys.stdout)
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler._link42_handler = True  # type: ignore[attr-defined]
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root_logger.addHandler(handler)
    root_logger.setLevel(level)
    root_logger.propagate = False


def scrub_text_for_log(value: object, limit: int = 500) -> str:
    """清洗日志文本，避免常见密钥字段直接出现在日志中。"""

    text = str(value)
    for key in ["private_key", "preshared_key", "password", "token", "agent_token"]:
        text = re.sub(rf"({key}[\"']?\s*[=:]\s*[\"']?)[^,\s\"']+", r"\1***", text, flags=re.IGNORECASE)
    return text[:limit]


def summarize_task_payload(payload: dict | None) -> dict[str, object]:
    """生成可安全写入日志的任务 payload 摘要。"""

    payload = payload or {}
    safe_keys = [
        "node_id",
        "interface_id",
        "interface_name",
        "plugin",
        "mode",
        "instance",
        "depends_on_task_id",
        "range_start",
        "range_end",
        "ip",
        "asn",
        "target",
        "protocol_name",
        "count",
        "max_hops",
        "command_timeout_seconds",
        "output_limit_bytes",
    ]
    return {key: payload[key] for key in safe_keys if key in payload}


def summarize_agent_task(task: models.AgentTask) -> dict[str, object]:
    """生成 AgentTask 的日志摘要。"""

    return {
        "id": task.id,
        "node_id": task.node_id,
        "type": task.type,
        "status": task.status,
        "payload": summarize_task_payload(task.payload),
    }


def summarize_task_result(result: dict | None) -> dict[str, object]:
    """生成 Agent 任务结果摘要，避免输出配置正文。"""

    result = result or {}
    summary: dict[str, object] = {"keys": sorted(result.keys())}
    for key in ["error", "message", "runtime_status"]:
        if key in result:
            summary[key] = scrub_text_for_log(result[key])
    for key in ["changed", "applied", "valid", "restored", "reboot_required"]:
        if key in result:
            summary[key] = result[key]
    return summary


configure_logging(settings.log_level)
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


class LookingGlassApiError(Exception):
    """第三方 Looking Glass API 使用的稳定错误对象。"""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        """保存 HTTP 状态码、机器可读错误码和用户可读错误信息。"""

        self.status_code = status_code
        self.code = code
        self.message = message
        super().__init__(message)


@app.exception_handler(LookingGlassApiError)
async def looking_glass_api_error_handler(request: Request, exc: LookingGlassApiError) -> JSONResponse:
    """把 Looking Glass 专用异常渲染成第三方 API 文档约定的错误格式。"""

    logger.warning(
        "Looking Glass API 请求被拒绝 method=%s path=%s status=%s code=%s",
        request.method,
        request.url.path,
        exc.status_code,
        exc.code,
    )
    return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code, "message": exc.message}})


@app.exception_handler(RequestValidationError)
async def looking_glass_validation_error_handler(request: Request, exc: RequestValidationError):
    """把第三方 Looking Glass 请求校验错误转换成稳定错误格式。"""

    if request.url.path.startswith(LOOKING_GLASS_API_PREFIX):
        logger.warning(
            "Looking Glass API 请求参数无效 method=%s path=%s errors=%s",
            request.method,
            request.url.path,
            scrub_text_for_log(exc.errors(), limit=300),
        )
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "invalid_request", "message": "请求参数无效"}},
        )
    return await request_validation_exception_handler(request, exc)

DEFAULT_ADMIN_USERNAME = "pmman"
ADMIN_USERNAME = DEFAULT_ADMIN_USERNAME
SETTING_ADMIN_USERNAME = "admin_username"
SETTING_ADMIN_PASSWORD_HASH = "admin_password_hash"
SETTING_ADMIN_SESSION_HASH = "admin_session_hash"
SETTING_CONTROLLER_URL = "controller_url"
SETTING_SITE_TITLE = "site_title"
SETTING_SITE_LOGO_URL = "site_logo_url"
SETTING_CONTROLLER_VERSION = "controller_version"
DEFAULT_SITE_TITLE = "Link42"
DEFAULT_SITE_LOGO_URL = "/logo.png"
BRANDING_LOGO_MAX_BYTES = 3 * 1024 * 1024
MONITOR_SUMMARY_WINDOW = timedelta(hours=1)
AGENT_TASK_RUNNING_TIMEOUT = timedelta(hours=2)
AGENT_TASK_POLL_BATCH_SIZE = 5
AGENT_TASK_POLL_SCAN_LIMIT = 50
LOOKING_GLASS_API_PREFIX = "/third-party-api/looking-glass/v1"
LOOKING_GLASS_NODE_READ_SCOPE = "looking_glass.nodes.read"
LOOKING_GLASS_BIRD_ROUTE_SCOPE = "looking_glass.bird.route"
LOOKING_GLASS_QUERY_QUEUE_LIMIT = 20
LOOKING_GLASS_QUEUE_TIMEOUT = timedelta(seconds=30)
LOOKING_GLASS_COMMAND_TIMEOUT_SECONDS = 15
LOOKING_GLASS_TOTAL_DEADLINE = timedelta(seconds=60)
LOOKING_GLASS_RESULT_RETENTION = timedelta(minutes=10)
LOOKING_GLASS_CACHE_WINDOW = timedelta(seconds=5)
LOOKING_GLASS_OUTPUT_LIMIT_BYTES = 256 * 1024


def uploaded_logo_path() -> Path | None:
    """返回当前上传 Logo 文件路径。"""

    logo_dir = Path(settings.config_dir) / "branding"
    for suffix in ["png", "jpg", "webp"]:
        path = logo_dir / f"logo.{suffix}"
        if path.exists():
            return path
    return None


def detect_logo_extension(content_type: str, data: bytes) -> str:
    """根据 content-type 和文件头判断 Logo 类型。"""

    normalized = content_type.split(";", 1)[0].strip().lower()
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    if normalized not in {"image/png", "image/jpeg", "image/jpg", "image/webp"}:
        raise HTTPException(status_code=400, detail="logo must be PNG, JPEG, or WebP")
    raise HTTPException(status_code=400, detail="logo must be PNG, JPEG, or WebP")

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
    @app.get("/branding/logo", include_in_schema=False)
    def serve_uploaded_logo() -> FileResponse:
        """返回用户上传并保存在配置目录中的 Logo。"""

        path = uploaded_logo_path()
        if not path:
            raise HTTPException(status_code=404, detail="logo not uploaded")
        return FileResponse(path)

    logo_file = web_dist_dir / "logo.png"
    if logo_file.exists():
        @app.get("/logo.png", include_in_schema=False)
        def serve_web_logo() -> FileResponse:
            """返回默认站点 Logo。"""

            return FileResponse(logo_file)

    @app.get("/", include_in_schema=False)
    def serve_web_index() -> FileResponse:
        """返回前端入口页面。"""

        return FileResponse(index_file)

    @app.get("/{path:path}", include_in_schema=False)
    def serve_web_fallback(path: str) -> FileResponse:
        """为前端路由提供 index.html 兜底，同时不接管 API 路径。"""

        if path.startswith(("api/", "third-party-api/")):
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
        set_setting(db, SETTING_SITE_TITLE, get_setting(db, SETTING_SITE_TITLE) or DEFAULT_SITE_TITLE)
        set_setting(db, SETTING_SITE_LOGO_URL, get_setting(db, SETTING_SITE_LOGO_URL) or DEFAULT_SITE_LOGO_URL)
        db.commit()
    finally:
        db.close()
    logger.warning("Link42 初始登录信息 username=%s password=%s", DEFAULT_ADMIN_USERNAME, password)


def controller_version_in_database() -> str | None:
    """读取数据库中记录的上次主控版本；旧库可能没有该设置。"""

    db = next(get_db())
    try:
        return get_setting(db, SETTING_CONTROLLER_VERSION)
    except Exception:
        return None
    finally:
        db.close()


def record_controller_version() -> None:
    """记录当前主控版本，用于下次启动判断是否发生升级。"""

    db = next(get_db())
    try:
        set_setting(db, SETTING_CONTROLLER_VERSION, CONTROLLER_VERSION)
        db.commit()
    finally:
        db.close()


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

    if path in {
        "/api/health",
        "/api/auth/login",
        "/api/branding",
        "/api/agent/register",
        "/api/agent/heartbeat",
        "/api/agent/tasks/poll",
        "/api/agent/link-monitors/poll",
        "/api/agent/link-monitors/result",
    }:
        return True
    return (
        re.fullmatch(r"/api/agent/tasks/\d+/result", path) is not None
        or path.startswith("/api/agent/releases/")
        or path.startswith("/api/agent/plugins/udp2raw/assets/")
    )


def require_web_session(request: Request, db: Session) -> None:
    """校验 Web 管理端会话 token。"""

    token = bearer_token_from_request(request)
    session_hash = get_setting(db, SETTING_ADMIN_SESSION_HASH)
    if not token or not session_hash or not verify_token(token, session_hash):
        raise HTTPException(status_code=401, detail="not authenticated")


def generate_integration_token() -> tuple[str, str, str]:
    """生成第三方集成 Token，并返回明文、可检索前缀和尾部提示。"""

    public_id = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    token_prefix = f"l42lg_{public_id}"
    token = f"{token_prefix}_{secret}"
    return token, token_prefix, token[-10:]


def integration_token_prefix(token: str) -> str | None:
    """从第三方 Token 中提取可用于数据库检索的前缀。"""

    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != "l42lg" or not parts[1]:
        return None
    return f"{parts[0]}_{parts[1]}"


def api_error(status_code: int, code: str, message: str) -> LookingGlassApiError:
    """生成第三方 API 使用的稳定错误结构。"""

    return LookingGlassApiError(status_code=status_code, code=code, message=message)


def normalized_header_ip(value: str) -> str | None:
    """从反向代理来源头中提取合法 IP，无法识别时返回空。"""

    candidate = value.strip().strip('"')
    if not candidate:
        return None
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def request_source_ip(request: Request) -> str | None:
    """获取请求真实来源 IP，兼容常见反向代理转发头。"""

    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        for value in x_forwarded_for.split(","):
            parsed = normalized_header_ip(value)
            if parsed:
                return parsed
    for header_name in ["x-real-ip", "cf-connecting-ip"]:
        parsed = normalized_header_ip(request.headers.get(header_name, ""))
        if parsed:
            return parsed
    forwarded = request.headers.get("forwarded")
    if forwarded:
        for section in forwarded.split(","):
            for item in section.split(";"):
                key, _, value = item.strip().partition("=")
                if key.lower() == "for":
                    parsed = normalized_header_ip(value)
                    if parsed:
                        return parsed
    return request.client.host if request.client else None


def require_looking_glass_api_key(
    request: Request,
    db: Session = Depends(get_db),
) -> models.IntegrationApiKey:
    """校验 Looking Glass 第三方 API Token，并返回对应授权记录。"""

    token = bearer_token_from_request(request)
    prefix = integration_token_prefix(token or "")
    if not token or not prefix:
        raise api_error(401, "invalid_api_key", "API Token 无效或已过期")
    api_key = db.scalar(select(models.IntegrationApiKey).where(models.IntegrationApiKey.token_prefix == prefix))
    now = datetime.utcnow()
    if (
        api_key is None
        or not api_key.enabled
        or api_key.revoked_at is not None
        or (api_key.expires_at is not None and api_key.expires_at <= now)
        or not verify_token(token, api_key.token_hash)
    ):
        logger.warning("第三方 API Token 鉴权失败 prefix=%s path=%s", prefix, request.url.path)
        raise api_error(401, "invalid_api_key", "API Token 无效或已过期")
    api_key.last_used_at = now
    api_key.last_used_ip = request_source_ip(request)
    db.commit()
    db.refresh(api_key)
    return api_key


def require_looking_glass_scope(api_key: models.IntegrationApiKey, scope: str) -> None:
    """校验第三方 API Token 是否包含指定权限范围。"""

    if scope not in set(api_key.scopes or []):
        raise api_error(403, "permission_denied", "API Token 缺少访问权限")


def parse_node_ref(node_ref: str) -> int:
    """解析第三方 API 使用的节点引用。"""

    match = re.fullmatch(r"node_(\d+)", node_ref.strip())
    if not match:
        raise api_error(404, "node_not_found", "节点不存在")
    return int(match.group(1))


def node_ref(node_id: int) -> str:
    """生成第三方 API 使用的节点引用。"""

    return f"node_{node_id}"


def node_supports_bird_route_lookup(node: models.Node) -> bool:
    """判断节点 Agent 是否上报 Looking Glass BIRD 查询能力。"""

    capabilities = set(node.agent_capabilities or [])
    return "looking_glass.bird.route_lookup" in capabilities


def node_supports_bird_routes_by_origin_as(node: models.Node) -> bool:
    """判断节点 Agent 是否上报 Looking Glass BIRD ASN 路由查询能力。"""

    capabilities = set(node.agent_capabilities or [])
    return "looking_glass.bird.routes_by_origin_as" in capabilities


def node_supports_bird_protocols(node: models.Node) -> bool:
    """判断节点 Agent 是否上报 Looking Glass BIRD 协议查询能力。"""

    capabilities = set(node.agent_capabilities or [])
    return "looking_glass.bird.protocols" in capabilities


def node_supports_looking_glass_ping(node: models.Node) -> bool:
    """判断节点 Agent 是否上报 Looking Glass ping 查询能力。"""

    capabilities = set(node.agent_capabilities or [])
    return "looking_glass.ping" in capabilities


def node_supports_looking_glass_traceroute(node: models.Node) -> bool:
    """判断节点 Agent 是否上报 Looking Glass traceroute 查询能力。"""

    capabilities = set(node.agent_capabilities or [])
    return "looking_glass.traceroute" in capabilities


def looking_glass_node_read(node: models.Node, now: datetime | None = None) -> schemas.LookingGlassNodeRead:
    """把内部节点模型转换成第三方 Looking Glass 可读取的节点信息。"""

    online = is_node_online(node, now=now)
    capabilities = set(node.agent_capabilities or [])
    return schemas.LookingGlassNodeRead(
        node_ref=node_ref(node.id),
        name=node.name,
        region=node.region,
        online=online,
        last_seen_at=node.last_seen_at,
        ips=schemas.LookingGlassNodeIps(
            management_ip=node.management_ip,
            public_ip=node.public_ip,
            endpoint_ips=node.endpoint_ips or [],
        ),
        capabilities=schemas.LookingGlassNodeCapabilities(
            bird=bool(
                {
                    "bird",
                    "looking_glass.bird.route_lookup",
                    "looking_glass.bird.routes_by_origin_as",
                    "looking_glass.bird.protocols",
                }
                & capabilities
            ),
            bird_route_lookup=node_supports_bird_route_lookup(node),
            bird_routes_by_origin_as=node_supports_bird_routes_by_origin_as(node),
            bird_protocols=node_supports_bird_protocols(node),
            ping=node_supports_looking_glass_ping(node),
            traceroute=node_supports_looking_glass_traceroute(node),
        ),
    )


def looking_glass_query_public_id() -> str:
    """生成不暴露内部自增 ID 的 Looking Glass 查询 ID。"""

    return f"lgq_{secrets.token_urlsafe(18)}"


def looking_glass_request_fingerprint(api_key_id: int, node_id: int, operation: str, normalized_ip: str) -> str:
    """生成短时间复用查询结果所需的请求指纹。"""

    raw = f"{api_key_id}:{node_id}:{operation}:{normalized_ip}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def looking_glass_query_read(query: models.LookingGlassQuery) -> schemas.LookingGlassQueryRead:
    """把 Looking Glass 查询模型转换成第三方 API 响应。"""

    error = None
    if query.error_code or query.error_message:
        error = schemas.LookingGlassQueryError(
            code=query.error_code or "query_failed",
            message=query.error_message or "查询失败",
        )
    return schemas.LookingGlassQueryRead(
        query_id=query.public_id,
        status=query.status,
        node_ref=node_ref(query.node_id),
        operation=query.operation,
        request=query.request or {},
        created_at=query.created_at,
        started_at=query.started_at,
        finished_at=query.finished_at,
        deadline_at=query.deadline_at,
        expires_at=query.expires_at,
        result=query.result,
        error=error,
    )


def refresh_looking_glass_query_from_task(query: models.LookingGlassQuery, now: datetime | None = None) -> None:
    """根据内部 AgentTask 状态刷新 Looking Glass 查询状态和结果。"""

    now = now or datetime.utcnow()
    task = query.agent_task
    if task is None:
        if query.status in {"queued", "running"} and query.deadline_at and query.deadline_at <= now:
            query.status = "failed"
            query.error_code = "query_timeout"
            query.error_message = "查询等待 Agent 执行超时"
            query.finished_at = now
        return
    if task.status == "pending":
        if task.deadline_at and task.deadline_at <= now:
            task.status = "failed"
            task.finished_at = now
            task.result = {
                "error_code": "query_timeout",
                "error": "query queue timeout before agent polling",
            }
            query.status = "failed"
            query.error_code = "query_timeout"
            query.error_message = "查询等待 Agent 执行超时"
            query.finished_at = now
        else:
            query.status = "queued"
    elif task.status == "running":
        query.status = "running"
        query.started_at = query.started_at or task.started_at
    elif task.status == "succeeded":
        query.started_at = query.started_at or task.started_at
        query.finished_at = query.finished_at or task.finished_at or now
        query.result = task.result or {}
        if isinstance(task.result, dict) and task.result.get("error_code"):
            query.status = "failed"
            query.error_code = str(task.result.get("error_code"))
            query.error_message = str(task.result.get("error") or "查询执行失败")[:500]
        else:
            query.status = "succeeded"
            query.error_code = None
            query.error_message = None
    elif task.status in {"failed", "cancelled"}:
        result = task.result or {}
        query.status = "failed" if task.status == "failed" else "cancelled"
        query.started_at = query.started_at or task.started_at
        query.finished_at = query.finished_at or task.finished_at or now
        query.error_code = str(result.get("error_code") or result.get("code") or task.status)
        query.error_message = str(result.get("error") or result.get("message") or "查询执行失败")[:500]
    if query.status in {"queued", "running"} and query.deadline_at and query.deadline_at <= now:
        query.status = "failed"
        query.error_code = "query_timeout"
        query.error_message = "查询执行超时"
        query.finished_at = now


@app.middleware("http")
async def require_api_authentication(request: Request, call_next):
    """为所有非白名单 API 统一加 Web 鉴权，避免遗漏单个路由。"""

    started_at = time.monotonic()
    if request.method == "OPTIONS":
        return await call_next(request)
    if request.url.path.startswith("/api/") and not is_api_auth_exempt(request.url.path):
        db = next(get_db())
        try:
            require_web_session(request, db)
        except HTTPException as exc:
            logger.warning(
                "Web API 鉴权失败 method=%s path=%s client=%s status=%s",
                request.method,
                request.url.path,
                request.client.host if request.client else None,
                exc.status_code,
            )
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        finally:
            db.close()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "HTTP 请求处理异常 method=%s path=%s client=%s duration=%.2fs",
            request.method,
            request.url.path,
            request.client.host if request.client else None,
            time.monotonic() - started_at,
        )
        raise
    duration = time.monotonic() - started_at
    if response.status_code >= 500:
        logger.error("HTTP 请求失败 method=%s path=%s status=%s duration=%.2fs", request.method, request.url.path, response.status_code, duration)
    elif response.status_code >= 400:
        logger.warning("HTTP 请求被拒绝 method=%s path=%s status=%s duration=%.2fs", request.method, request.url.path, response.status_code, duration)
    else:
        logger.debug("HTTP 请求完成 method=%s path=%s status=%s duration=%.2fs", request.method, request.url.path, response.status_code, duration)
    return response


def token_read_with_plaintext(api_key: models.IntegrationApiKey, token: str) -> schemas.IntegrationApiTokenCreateResult:
    """生成包含一次性明文 Token 的管理端响应。"""

    base = schemas.IntegrationApiTokenRead.model_validate(api_key).model_dump()
    return schemas.IntegrationApiTokenCreateResult(**base, token=token)


@app.get("/api/integrations/looking-glass/tokens", response_model=schemas.IntegrationApiTokenList)
def list_looking_glass_tokens(db: Session = Depends(get_db)) -> schemas.IntegrationApiTokenList:
    """列出 Looking Glass 第三方 API Token 元数据。"""

    tokens = list(db.scalars(select(models.IntegrationApiKey).order_by(models.IntegrationApiKey.id)))
    return schemas.IntegrationApiTokenList(items=[schemas.IntegrationApiTokenRead.model_validate(token) for token in tokens])


@app.post("/api/integrations/looking-glass/tokens", response_model=schemas.IntegrationApiTokenCreateResult)
def create_looking_glass_token(
    payload: schemas.IntegrationApiTokenCreate,
    db: Session = Depends(get_db),
) -> schemas.IntegrationApiTokenCreateResult:
    """创建 Looking Glass 第三方 API Token，并仅本次返回明文。"""

    token, token_prefix, token_hint = generate_integration_token()
    api_key = models.IntegrationApiKey(
        name=payload.name.strip(),
        token_prefix=token_prefix,
        token_hash=hash_token(token),
        token_hint=token_hint,
        scopes=payload.scopes,
        allowed_node_ids=[],
        enabled=True,
        expires_at=payload.expires_at,
        created_by=admin_username(db),
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    logger.info("创建 Looking Glass API Token id=%s prefix=%s scopes=%s", api_key.id, api_key.token_prefix, api_key.scopes)
    return token_read_with_plaintext(api_key, token)


@app.patch("/api/integrations/looking-glass/tokens/{token_id}", response_model=schemas.IntegrationApiTokenRead)
def update_looking_glass_token(
    token_id: int,
    payload: schemas.IntegrationApiTokenUpdate,
    db: Session = Depends(get_db),
) -> models.IntegrationApiKey:
    """更新 Looking Glass 第三方 API Token 元数据。"""

    api_key = db.get(models.IntegrationApiKey, token_id)
    if api_key is None:
        raise HTTPException(status_code=404, detail="token not found")
    if payload.name is not None:
        api_key.name = payload.name.strip()
    if payload.scopes is not None:
        api_key.scopes = payload.scopes
    if payload.enabled is not None:
        api_key.enabled = payload.enabled
    if "expires_at" in payload.model_fields_set:
        api_key.expires_at = payload.expires_at
    db.commit()
    db.refresh(api_key)
    logger.info("更新 Looking Glass API Token id=%s enabled=%s scopes=%s", api_key.id, api_key.enabled, api_key.scopes)
    return api_key


@app.post("/api/integrations/looking-glass/tokens/{token_id}/rotate", response_model=schemas.IntegrationApiTokenCreateResult)
def rotate_looking_glass_token(token_id: int, db: Session = Depends(get_db)) -> schemas.IntegrationApiTokenCreateResult:
    """轮换 Looking Glass 第三方 API Token，并仅本次返回新明文。"""

    api_key = db.get(models.IntegrationApiKey, token_id)
    if api_key is None:
        raise HTTPException(status_code=404, detail="token not found")
    token, token_prefix, token_hint = generate_integration_token()
    api_key.token_prefix = token_prefix
    api_key.token_hash = hash_token(token)
    api_key.token_hint = token_hint
    api_key.enabled = True
    api_key.revoked_at = None
    db.commit()
    db.refresh(api_key)
    logger.info("轮换 Looking Glass API Token id=%s prefix=%s", api_key.id, api_key.token_prefix)
    return token_read_with_plaintext(api_key, token)


@app.post("/api/integrations/looking-glass/tokens/{token_id}/revoke", response_model=schemas.IntegrationApiTokenRead)
def revoke_looking_glass_token(token_id: int, db: Session = Depends(get_db)) -> models.IntegrationApiKey:
    """吊销 Looking Glass 第三方 API Token 并保留审计记录。"""

    api_key = db.get(models.IntegrationApiKey, token_id)
    if api_key is None:
        raise HTTPException(status_code=404, detail="token not found")
    api_key.enabled = False
    api_key.revoked_at = datetime.utcnow()
    db.commit()
    db.refresh(api_key)
    logger.info("吊销 Looking Glass API Token id=%s prefix=%s", api_key.id, api_key.token_prefix)
    return api_key


@app.delete("/api/integrations/looking-glass/tokens/{token_id}")
def delete_looking_glass_token(token_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    """彻底删除 Looking Glass 第三方 API Token 和关联查询记录。"""

    api_key = db.get(models.IntegrationApiKey, token_id)
    if api_key is None:
        raise HTTPException(status_code=404, detail="token not found")
    token_prefix = api_key.token_prefix
    query_count = db.scalar(
        select(func.count(models.LookingGlassQuery.id)).where(models.LookingGlassQuery.api_key_id == token_id)
    )
    api_key.enabled = False
    api_key.revoked_at = datetime.utcnow()
    db.flush()
    db.execute(delete(models.LookingGlassQuery).where(models.LookingGlassQuery.api_key_id == token_id))
    db.delete(api_key)
    db.commit()
    logger.info("删除 Looking Glass API Token id=%s prefix=%s queries=%s", token_id, token_prefix, int(query_count or 0))
    return {"status": "deleted"}


@app.get(f"{LOOKING_GLASS_API_PREFIX}/nodes", response_model=schemas.LookingGlassNodeList)
def list_looking_glass_nodes(
    region: str | None = None,
    online: bool | None = None,
    limit: int = 100,
    cursor: str | None = None,
    api_key: models.IntegrationApiKey = Depends(require_looking_glass_api_key),
    db: Session = Depends(get_db),
) -> schemas.LookingGlassNodeList:
    """返回第三方 Looking Glass 可展示的节点信息列表。"""

    require_looking_glass_scope(api_key, LOOKING_GLASS_NODE_READ_SCOPE)
    limit = max(1, min(int(limit or 100), 500))
    cursor_id = 0
    if cursor:
        try:
            cursor_id = max(0, int(cursor))
        except ValueError as exc:
            raise api_error(400, "invalid_request", "分页游标无效") from exc
    query = (
        select(models.Node)
        .where(models.Node.id > cursor_id)
        .order_by(models.Node.id)
        .limit(limit + 1)
    )
    if region is not None:
        query = query.where(models.Node.region == region)
    nodes = list(db.scalars(query))
    now = datetime.utcnow()
    filtered_nodes: list[models.Node] = []
    for node in nodes:
        node_online = is_node_online(node, now=now)
        if online is not None and node_online != online:
            continue
        filtered_nodes.append(node)
    page_nodes = filtered_nodes[:limit]
    next_cursor = str(page_nodes[-1].id) if len(filtered_nodes) > limit and page_nodes else None
    return schemas.LookingGlassNodeList(
        items=[looking_glass_node_read(node, now=now) for node in page_nodes],
        next_cursor=next_cursor,
    )


@app.get(f"{LOOKING_GLASS_API_PREFIX}/nodes/{{node_ref_value}}", response_model=schemas.LookingGlassNodeRead)
def get_looking_glass_node(
    node_ref_value: str,
    api_key: models.IntegrationApiKey = Depends(require_looking_glass_api_key),
    db: Session = Depends(get_db),
) -> schemas.LookingGlassNodeRead:
    """返回第三方 Looking Glass 可展示的单个节点信息。"""

    require_looking_glass_scope(api_key, LOOKING_GLASS_NODE_READ_SCOPE)
    node_id = parse_node_ref(node_ref_value)
    node = db.get(models.Node, node_id)
    if node is None:
        raise api_error(404, "node_not_found", "节点不存在")
    return looking_glass_node_read(node)


def create_looking_glass_query_task(
    node_ref_value: str,
    response: Response,
    api_key: models.IntegrationApiKey,
    db: Session,
    operation: str,
    task_type: str,
    task_payload: dict[str, Any],
    request_payload: dict[str, Any],
    fingerprint_value: str,
    required_capability: str,
    capability_error_message: str,
) -> schemas.LookingGlassQueryRead:
    """创建 Looking Glass 异步查询任务，并返回可轮询的 query_id。"""

    node_id = parse_node_ref(node_ref_value)
    node = db.get(models.Node, node_id)
    if node is None:
        raise api_error(404, "node_not_found", "节点不存在")
    now = datetime.utcnow()
    if not is_node_online(node, now=now):
        raise api_error(409, "node_offline", "节点当前离线，无法执行查询")
    if required_capability not in set(node.agent_capabilities or []):
        raise api_error(409, "capability_missing", capability_error_message)
    queued_count = db.scalar(
        select(func.count(models.AgentTask.id)).where(
            models.AgentTask.node_id == node_id,
            models.AgentTask.queue == "query",
            models.AgentTask.status.in_(["pending", "running"]),
        )
    )
    if int(queued_count or 0) >= LOOKING_GLASS_QUERY_QUEUE_LIMIT:
        raise api_error(429, "query_queue_full", "节点查询队列已满，请稍后重试")
    fingerprint = looking_glass_request_fingerprint(api_key.id, node_id, operation, fingerprint_value)
    reusable_query = db.scalar(
        select(models.LookingGlassQuery)
        .where(
            models.LookingGlassQuery.api_key_id == api_key.id,
            models.LookingGlassQuery.node_id == node_id,
            models.LookingGlassQuery.request_fingerprint == fingerprint,
            models.LookingGlassQuery.created_at >= now - LOOKING_GLASS_CACHE_WINDOW,
            models.LookingGlassQuery.status.in_(["queued", "running", "succeeded"]),
        )
        .order_by(models.LookingGlassQuery.id.desc())
    )
    if reusable_query is not None:
        refresh_looking_glass_query_from_task(reusable_query, now=now)
        db.commit()
        response.status_code = 202
        response.headers["Location"] = f"{LOOKING_GLASS_API_PREFIX}/queries/{reusable_query.public_id}"
        response.headers["Retry-After"] = "1"
        return looking_glass_query_read(reusable_query)
    deadline_at = now + LOOKING_GLASS_TOTAL_DEADLINE
    task_deadline_at = now + LOOKING_GLASS_QUEUE_TIMEOUT
    expires_at = now + LOOKING_GLASS_RESULT_RETENTION
    task = models.AgentTask(
        node_id=node_id,
        type=task_type,
        queue="query",
        priority=50,
        payload={
            **task_payload,
            "command_timeout_seconds": LOOKING_GLASS_COMMAND_TIMEOUT_SECONDS,
            "output_limit_bytes": LOOKING_GLASS_OUTPUT_LIMIT_BYTES,
        },
        deadline_at=task_deadline_at,
    )
    db.add(task)
    db.flush()
    query_record = models.LookingGlassQuery(
        public_id=looking_glass_query_public_id(),
        api_key_id=api_key.id,
        node_id=node_id,
        operation=operation,
        request=request_payload,
        request_fingerprint=fingerprint,
        status="queued",
        agent_task_id=task.id,
        deadline_at=deadline_at,
        expires_at=expires_at,
    )
    db.add(query_record)
    db.commit()
    db.refresh(query_record)
    response.status_code = 202
    response.headers["Location"] = f"{LOOKING_GLASS_API_PREFIX}/queries/{query_record.public_id}"
    response.headers["Retry-After"] = "1"
    logger.info(
        "创建 Looking Glass 查询 query_id=%s node_id=%s operation=%s request=%s",
        query_record.public_id,
        node_id,
        operation,
        request_payload,
    )
    return looking_glass_query_read(query_record)


@app.post(f"{LOOKING_GLASS_API_PREFIX}/nodes/{{node_ref_value}}/bird/routes:lookup", response_model=schemas.LookingGlassQueryRead)
def submit_looking_glass_bird_route_lookup(
    node_ref_value: str,
    payload: schemas.LookingGlassRouteLookupRequest,
    response: Response,
    api_key: models.IntegrationApiKey = Depends(require_looking_glass_api_key),
    db: Session = Depends(get_db),
) -> schemas.LookingGlassQueryRead:
    """提交 Looking Glass BIRD 路由查询任务，返回可轮询的 query_id。"""

    require_looking_glass_scope(api_key, LOOKING_GLASS_BIRD_ROUTE_SCOPE)
    normalized_ip = payload.ip
    return create_looking_glass_query_task(
        node_ref_value,
        response,
        api_key,
        db,
        "bird.route_lookup",
        LOOKING_GLASS_BIRD_ROUTE_LOOKUP_TASK,
        {"ip": normalized_ip},
        {"ip": payload.ip, "normalized_ip": normalized_ip},
        normalized_ip,
        "looking_glass.bird.route_lookup",
        "节点不支持 BIRD 路由查询",
    )


@app.post(f"{LOOKING_GLASS_API_PREFIX}/nodes/{{node_ref_value}}/bird/routes:lookup-origin-as", response_model=schemas.LookingGlassQueryRead)
def submit_looking_glass_bird_routes_by_origin_as(
    node_ref_value: str,
    payload: schemas.LookingGlassRoutesByOriginAsRequest,
    response: Response,
    api_key: models.IntegrationApiKey = Depends(require_looking_glass_api_key),
    db: Session = Depends(get_db),
) -> schemas.LookingGlassQueryRead:
    """提交 Looking Glass BIRD ASN 路由查询任务，返回可轮询的 query_id。"""

    require_looking_glass_scope(api_key, LOOKING_GLASS_BIRD_ROUTE_SCOPE)
    request_payload = {"asn": payload.asn}
    return create_looking_glass_query_task(
        node_ref_value,
        response,
        api_key,
        db,
        "bird.routes_by_origin_as",
        LOOKING_GLASS_BIRD_ROUTES_BY_ORIGIN_AS_TASK,
        request_payload,
        request_payload,
        str(payload.asn),
        "looking_glass.bird.routes_by_origin_as",
        "节点不支持 BIRD ASN 路由查询",
    )


@app.post(f"{LOOKING_GLASS_API_PREFIX}/nodes/{{node_ref_value}}/bird/protocols:lookup", response_model=schemas.LookingGlassQueryRead)
def submit_looking_glass_bird_protocols(
    node_ref_value: str,
    response: Response,
    api_key: models.IntegrationApiKey = Depends(require_looking_glass_api_key),
    db: Session = Depends(get_db),
) -> schemas.LookingGlassQueryRead:
    """提交 Looking Glass BIRD 协议列表查询任务，返回可轮询的 query_id。"""

    require_looking_glass_scope(api_key, LOOKING_GLASS_BIRD_ROUTE_SCOPE)
    return create_looking_glass_query_task(
        node_ref_value,
        response,
        api_key,
        db,
        "bird.protocols",
        LOOKING_GLASS_BIRD_PROTOCOLS_TASK,
        {},
        {},
        "bird.protocols",
        "looking_glass.bird.protocols",
        "节点不支持 BIRD 协议状态查询",
    )


@app.post(f"{LOOKING_GLASS_API_PREFIX}/nodes/{{node_ref_value}}/bird/protocols:lookup-detail", response_model=schemas.LookingGlassQueryRead)
def submit_looking_glass_bird_protocol_detail(
    node_ref_value: str,
    payload: schemas.LookingGlassProtocolDetailRequest,
    response: Response,
    api_key: models.IntegrationApiKey = Depends(require_looking_glass_api_key),
    db: Session = Depends(get_db),
) -> schemas.LookingGlassQueryRead:
    """提交 Looking Glass BIRD 单个协议详情查询任务，返回可轮询的 query_id。"""

    require_looking_glass_scope(api_key, LOOKING_GLASS_BIRD_ROUTE_SCOPE)
    request_payload = {"protocol_name": payload.protocol_name}
    return create_looking_glass_query_task(
        node_ref_value,
        response,
        api_key,
        db,
        "bird.protocol_detail",
        LOOKING_GLASS_BIRD_PROTOCOL_DETAIL_TASK,
        request_payload,
        request_payload,
        payload.protocol_name,
        "looking_glass.bird.protocols",
        "节点不支持 BIRD 协议详情查询",
    )


@app.post(f"{LOOKING_GLASS_API_PREFIX}/nodes/{{node_ref_value}}/ping", response_model=schemas.LookingGlassQueryRead)
def submit_looking_glass_ping(
    node_ref_value: str,
    payload: schemas.LookingGlassPingRequest,
    response: Response,
    api_key: models.IntegrationApiKey = Depends(require_looking_glass_api_key),
    db: Session = Depends(get_db),
) -> schemas.LookingGlassQueryRead:
    """提交 Looking Glass ping 查询任务，返回可轮询的 query_id。"""

    require_looking_glass_scope(api_key, LOOKING_GLASS_BIRD_ROUTE_SCOPE)
    request_payload = {
        "target": payload.target,
        "count": payload.count,
        "per_probe_timeout_seconds": payload.per_probe_timeout_seconds,
    }
    return create_looking_glass_query_task(
        node_ref_value,
        response,
        api_key,
        db,
        "ping",
        LOOKING_GLASS_PING_TASK,
        request_payload,
        request_payload,
        json.dumps(request_payload, ensure_ascii=False, sort_keys=True),
        "looking_glass.ping",
        "节点不支持 ping 查询",
    )


@app.post(f"{LOOKING_GLASS_API_PREFIX}/nodes/{{node_ref_value}}/traceroute", response_model=schemas.LookingGlassQueryRead)
def submit_looking_glass_traceroute(
    node_ref_value: str,
    payload: schemas.LookingGlassTracerouteRequest,
    response: Response,
    api_key: models.IntegrationApiKey = Depends(require_looking_glass_api_key),
    db: Session = Depends(get_db),
) -> schemas.LookingGlassQueryRead:
    """提交 Looking Glass traceroute 查询任务，返回可轮询的 query_id。"""

    require_looking_glass_scope(api_key, LOOKING_GLASS_BIRD_ROUTE_SCOPE)
    request_payload = {
        "target": payload.target,
        "max_hops": payload.max_hops,
        "wait_seconds": payload.wait_seconds,
        "queries": payload.queries,
    }
    return create_looking_glass_query_task(
        node_ref_value,
        response,
        api_key,
        db,
        "traceroute",
        LOOKING_GLASS_TRACEROUTE_TASK,
        request_payload,
        request_payload,
        json.dumps(request_payload, ensure_ascii=False, sort_keys=True),
        "looking_glass.traceroute",
        "节点不支持 traceroute 查询",
    )


@app.get(f"{LOOKING_GLASS_API_PREFIX}/queries/{{query_id}}", response_model=schemas.LookingGlassQueryRead)
def get_looking_glass_query(
    query_id: str,
    api_key: models.IntegrationApiKey = Depends(require_looking_glass_api_key),
    db: Session = Depends(get_db),
) -> schemas.LookingGlassQueryRead:
    """读取 Looking Glass 查询状态和原始结果。"""

    require_looking_glass_scope(api_key, LOOKING_GLASS_BIRD_ROUTE_SCOPE)
    query_record = db.scalar(
        select(models.LookingGlassQuery).where(
            models.LookingGlassQuery.public_id == query_id,
            models.LookingGlassQuery.api_key_id == api_key.id,
        )
    )
    if query_record is None:
        raise api_error(404, "query_not_found", "查询不存在")
    now = datetime.utcnow()
    if query_record.expires_at and query_record.expires_at <= now:
        query_record.status = "expired"
        db.commit()
        raise api_error(410, "result_expired", "查询结果已过期")
    refresh_looking_glass_query_from_task(query_record, now=now)
    db.commit()
    db.refresh(query_record)
    return looking_glass_query_read(query_record)


@app.on_event("startup")
def on_startup() -> None:
    """应用启动时初始化数据库。"""
    logger.info(
        "Link42 主控启动 version=%s database_url=%s config_dir=%s web_dist_dir=%s log_level=%s",
        CONTROLLER_VERSION,
        settings.database_url,
        settings.config_dir,
        settings.web_dist_dir,
        settings.log_level,
    )
    previous_version = controller_version_in_database()
    if previous_version != CONTROLLER_VERSION:
        from .database import backup_sqlite_database_for_upgrade

        backup_path = backup_sqlite_database_for_upgrade()
        if backup_path:
            logger.info(
                "升级前数据库备份完成 path=%s previous_version=%s current_version=%s",
                backup_path,
                previous_version,
                CONTROLLER_VERSION,
            )
    init_db()
    ensure_admin_credentials()
    record_controller_version()
    logger.info("Link42 主控启动完成 version=%s", CONTROLLER_VERSION)


def require_agent(db: Session, node_id: int, token: str) -> models.Node:
    """校验 Agent 身份，并返回对应节点。"""
    node = db.get(models.Node, node_id)
    if node is None or not verify_token(token, node.agent_token_hash):
        logger.warning("Agent 鉴权失败 node_id=%s", node_id)
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


def node_runtime_status(node: models.Node, now: datetime | None = None) -> str:
    """计算节点当前展示状态，不修改数据库对象。"""

    if node.status == "online" and not is_node_online(node, now=now):
        return "offline"
    return node.status


def node_read_with_runtime_status(node: models.Node, now: datetime | None = None) -> schemas.NodeRead:
    """把节点转换为响应模型，并用实时心跳结果覆盖展示状态。"""

    result = schemas.NodeRead.model_validate(node)
    return result.model_copy(update={"status": node_runtime_status(node, now=now)})


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
        if "middleware.mimic" in set(capabilities):
            node.middleware_install_status = "mimic_ready"
    if platform:
        current_platform = dict(platform)
        if "middleware.mimic" in set(node.agent_capabilities or []):
            current_platform.pop("mimic_reboot_required", None)
        elif node.middleware_install_status == "mimic_reboot_required":
            current_platform["mimic_reboot_required"] = True
        platform = current_platform
        node.agent_platform = platform
    if node.agent_update_status in {None, "queued", "staged", "restarting", "healthy", "failed", "rolled_back"}:
        if not previous_version or previous_version != agent_version or node.agent_update_status in {None, "healthy"}:
            node.agent_update_status = "ok"
            node.agent_last_error = None
    if agent_version and previous_version and previous_version != agent_version:
        logger.info("Agent 版本变化 node_id=%s previous=%s current=%s", node.id, previous_version, agent_version)


def agent_satisfies_task(node: models.Node, task_type: str) -> bool:
    """判断节点当前 Agent 是否满足任务要求。"""

    requirement = TASK_REQUIREMENTS.get(task_type)
    if not requirement:
        return True
    if parse_version(node.agent_version) < parse_version(requirement.get("min_agent_version")):
        return False
    capabilities = set(node.agent_capabilities or ["wireguard", "wg_quick_import"])
    return all(capability in capabilities for capability in requirement.get("capabilities", []))


def node_uses_openwrt_uci(node: models.Node | None) -> bool:
    """判断节点是否使用 OpenWrt UCI WireGuard 后端。"""

    if node is None:
        return False
    platform = node.agent_platform or {}
    capabilities = set(node.agent_capabilities or [])
    return platform.get("service_manager") == "openwrt-uci" or "service:openwrt-uci" in capabilities


def require_task_supported(node: models.Node, task_type: str) -> None:
    """创建任务前校验 Agent 版本和能力。"""

    if not agent_satisfies_task(node, task_type):
        logger.warning(
            "Agent 不支持任务 node_id=%s task_type=%s agent_version=%s capabilities=%s",
            node.id,
            task_type,
            node.agent_version,
            node.agent_capabilities,
        )
        raise HTTPException(status_code=409, detail=f"agent does not support task: {task_type}")


def expire_stale_running_agent_tasks(
    db: Session,
    node_id: int | None = None,
    now: datetime | None = None,
) -> int:
    """回收 Agent 拉取后长时间未上报结果的 running 任务。"""

    now = now or datetime.utcnow()
    cutoff = now - AGENT_TASK_RUNNING_TIMEOUT
    query = select(models.AgentTask).where(
        models.AgentTask.status == "running",
        models.AgentTask.started_at.is_not(None),
        models.AgentTask.started_at < cutoff,
    )
    if node_id is not None:
        query = query.where(models.AgentTask.node_id == node_id)
    tasks = list(db.scalars(query.order_by(models.AgentTask.id)))
    for task in tasks:
        task.status = "failed"
        task.finished_at = now
        task.result = {
            "error": f"agent task timed out after {int(AGENT_TASK_RUNNING_TIMEOUT.total_seconds())} seconds",
            "timeout_seconds": int(AGENT_TASK_RUNNING_TIMEOUT.total_seconds()),
        }
    if tasks:
        db.flush()
        logger.warning(
            "回收超时 Agent 任务 node_id=%s count=%d task_ids=%s",
            node_id,
            len(tasks),
            [task.id for task in tasks],
        )
    return len(tasks)


def expire_overdue_pending_agent_tasks(
    db: Session,
    node_id: int | None = None,
    now: datetime | None = None,
) -> int:
    """回收超过 deadline 仍未被 Agent 拉取的 pending 任务。"""

    now = now or datetime.utcnow()
    query = select(models.AgentTask).where(
        models.AgentTask.status == "pending",
        models.AgentTask.deadline_at.is_not(None),
        models.AgentTask.deadline_at <= now,
    )
    if node_id is not None:
        query = query.where(models.AgentTask.node_id == node_id)
    tasks = list(db.scalars(query.order_by(models.AgentTask.id)))
    for task in tasks:
        task.status = "failed"
        task.finished_at = now
        task.result = {
            "error_code": "query_timeout" if task.queue == "query" else "task_timeout",
            "error": "task deadline expired before agent polling",
        }
    if tasks:
        db.flush()
        logger.warning("回收过期待执行任务 node_id=%s count=%d task_ids=%s", node_id, len(tasks), [task.id for task in tasks])
    return len(tasks)


def task_dependency_id(task: models.AgentTask) -> int | None:
    """读取任务 payload 中的依赖任务 ID。"""

    raw_value = (task.payload or {}).get("depends_on_task_id")
    if raw_value in (None, ""):
        return None
    try:
        dependency_id = int(raw_value)
    except (TypeError, ValueError):
        return None
    return dependency_id if dependency_id > 0 else None


def is_task_ready_for_poll(db: Session, task: models.AgentTask, now: datetime) -> bool:
    """判断 pending 任务的依赖是否已满足；依赖失败时同步标记失败。"""

    dependency_id = task_dependency_id(task)
    if dependency_id is None:
        return True
    dependency = db.get(models.AgentTask, dependency_id)
    if dependency is None:
        task.status = "failed"
        task.finished_at = now
        task.result = {
            "error": f"dependency task {dependency_id} was not found",
            "dependency_task_id": dependency_id,
        }
        logger.warning("Agent 任务依赖不存在 task_id=%s dependency_task_id=%s", task.id, dependency_id)
        return False
    if dependency.status == "succeeded":
        return True
    if dependency.status in {"failed", "cancelled"}:
        task.status = "failed"
        task.finished_at = now
        task.result = {
            "error": f"dependency task {dependency_id} ended with status {dependency.status}",
            "dependency_task_id": dependency_id,
            "dependency_status": dependency.status,
            "dependency_result": dependency.result,
        }
        logger.warning(
            "Agent 任务依赖失败 task_id=%s dependency_task_id=%s dependency_status=%s",
            task.id,
            dependency_id,
            dependency.status,
        )
    return False


def command_result_failed(result: object) -> bool:
    """判断 Agent 返回的命令结果是否明确失败。"""

    if not isinstance(result, dict) or "returncode" not in result:
        return False
    try:
        return int(result["returncode"]) != 0
    except (TypeError, ValueError):
        return False


def stop_task_result_failed(result: dict) -> bool:
    """兼容旧 Agent：stop 任务里 wg-quick/ifdown 失败时不应被视为成功。"""

    return command_result_failed(result.get("down")) or command_result_failed(result.get("stop"))


def agent_task_error_summary(result: dict) -> str | None:
    """从 Agent 任务结果中提取适合展示给用户的失败摘要。"""

    for key in ["error", "message", "stderr", "stdout"]:
        value = str(result.get(key) or "").strip()
        if value:
            return value[:500]
    for value in result.values():
        if isinstance(value, dict):
            nested = agent_task_error_summary(value)
            if nested:
                return nested
    return None


def normalize_agent_task_report(
    db: Session,
    task: models.AgentTask,
    status: str,
    result: dict,
) -> tuple[str, dict]:
    """把旧 Agent 的部分宽松结果规整成真实业务状态。"""

    if status != "succeeded":
        return status, result
    interface_id = (task.payload or {}).get("interface_id")
    interface = db.get(models.WireGuardInterface, interface_id) if interface_id else None
    if interface is None:
        return status, result
    driver = connection_driver_for_interface(interface)
    if task.type == driver.tasks.stop and stop_task_result_failed(result):
        return (
            "failed",
            {
                **result,
                "error": "wireguard stop command failed",
            },
        )
    return status, result


def should_clear_previous_interface_name(db: Session, task: models.AgentTask, result: dict) -> bool:
    """确认旧接口清理链路成功后才清除 previous_interface_name 标记。"""

    previous_interface_name = str((task.payload or {}).get("previous_interface_name") or "").strip()
    if not previous_interface_name:
        return True
    dependency_id = task_dependency_id(task)
    if dependency_id is not None:
        dependency = db.get(models.AgentTask, dependency_id)
        return dependency is not None and dependency.status == "succeeded"
    rename_cleanup = result.get("rename_cleanup")
    return isinstance(rename_cleanup, dict) and not rename_cleanup.get("dry_run")


def update_change_plan_task_status(db: Session, plan: models.ChangePlan) -> None:
    """根据计划下所有 Agent 任务聚合 Change Plan 状态。"""

    tasks = list(
        db.scalars(
            select(models.AgentTask)
            .where(models.AgentTask.change_plan_id == plan.id)
            .order_by(models.AgentTask.id)
        )
    )
    if any(task.status in {"failed", "cancelled"} for task in tasks):
        plan.status = "failed"
    elif tasks and all(task.status == "succeeded" for task in tasks):
        plan.status = "succeeded"
    elif plan.status != "failed":
        plan.status = "confirmed"


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

    env_values = {
        "LINK42_AGENT_VERSION": target_version or "latest",
        "LINK42_RES_BASE_URL": settings.agent_res_base_url,
    }
    controller_url = controller_url_for_agent(db)
    if controller_url:
        env_values["LINK42_SERVER_URL"] = controller_url
    env_values["LINK42_NODE_ID"] = str(node.id)
    if node.agent_token_value:
        env_values["LINK42_AGENT_TOKEN"] = node.agent_token_value
    env_parts = [f"{key}={shlex.quote(value)}" for key, value in env_values.items()]
    return f"curl -fsSL {shlex.quote(settings.agent_install_script_url)} | sudo env {' '.join(env_parts)} sh"


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


def require_mimic_ip(value: str, field_name: str) -> str:
    """mimic filter 使用 IP 字面量，IPv6 由 Agent 渲染为方括号格式。"""

    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"{field_name} must be an IP address for mimic") from exc
    return value


def managed_link_middleware(interface: models.WireGuardInterface) -> dict | None:
    """读取受管连接绑定的中间层配置。"""

    middleware = (interface.extras or {}).get("middleware")
    return middleware if isinstance(middleware, dict) and middleware.get("enabled") else None


def require_udp2raw_supported(node: models.Node) -> None:
    """要求节点 Agent 支持 udp2raw 中间层。"""

    for task_type in ["middleware.install", "middleware.udp2raw.apply"]:
        require_task_supported(node, task_type)


def normalize_mimic_config(payload: schemas.MimicMiddlewareConfig | None) -> dict | None:
    """清洗 mimic 插件配置，未启用时返回 None。"""

    if payload is None or not payload.enabled:
        return None
    if not payload.local_bind_interface:
        raise HTTPException(status_code=400, detail="mimic local bind interface is required")
    if not payload.peer_bind_interface:
        raise HTTPException(status_code=400, detail="mimic peer bind interface is required")
    return {
        "type": "mimic",
        "enabled": True,
        "local_bind_interface": payload.local_bind_interface.strip(),
        "peer_bind_interface": payload.peer_bind_interface.strip(),
        "xdp_mode": payload.xdp_mode,
        "link_type": payload.link_type,
        "handshake_interval": payload.handshake_interval,
        "keepalive_interval": payload.keepalive_interval,
        "padding": payload.padding,
    }


def normalize_middleware_config(
    udp2raw_payload: schemas.Udp2RawMiddlewareConfig | None,
    mimic_payload: schemas.MimicMiddlewareConfig | None,
) -> dict | None:
    """统一清洗连接中间层配置；一次只能启用一种中间层。"""

    udp2raw = normalize_udp2raw_config(udp2raw_payload)
    mimic = normalize_mimic_config(mimic_payload)
    if udp2raw and mimic:
        raise HTTPException(status_code=400, detail="only one middleware can be enabled")
    return udp2raw or mimic


def parse_kernel_major_minor(value: object) -> tuple[int, int]:
    """从平台上报的内核版本字符串中解析 major/minor。"""

    match = re.match(r"(\d+)\.(\d+)", str(value or ""))
    if not match:
        return (0, 0)
    return (int(match.group(1)), int(match.group(2)))


def node_supports_mimic_platform(node: models.Node) -> tuple[bool, str | None]:
    """判断节点平台是否满足 mimic 的系统、init 和内核要求。"""

    platform = node.agent_platform or {}
    if platform.get("is_openwrt") or node_uses_openwrt_uci(node):
        return False, "mimic is not supported on OpenWrt nodes"
    if str(platform.get("os") or "linux").lower() != "linux":
        return False, "mimic requires Linux nodes"
    if str(platform.get("service_manager") or "").lower() != "systemd":
        return False, "mimic requires systemd managed Linux nodes"
    kernel = platform.get("kernel_version") or platform.get("kernel")
    if parse_kernel_major_minor(kernel) <= (6, 1):
        return False, "mimic requires Linux kernel newer than 6.1"
    return True, None


def require_mimic_supported(node: models.Node) -> None:
    """要求节点当前版本和平台都支持部署 mimic。"""

    supported, reason = node_supports_mimic_platform(node)
    if not supported:
        raise HTTPException(status_code=409, detail=reason or "node does not support mimic middleware")
    require_task_supported(node, "middleware.mimic.apply")


def require_mimic_install_supported(node: models.Node) -> None:
    """要求节点支持通过 Agent 自动安装 mimic。"""

    supported, reason = node_supports_mimic_platform(node)
    if not supported:
        raise HTTPException(status_code=409, detail=reason or "node does not support installing mimic")
    require_task_supported(node, "middleware.install")
    capabilities = set(node.agent_capabilities or [])
    if "middleware.install.mimic" not in capabilities:
        raise HTTPException(status_code=409, detail="node does not support installing mimic")


def apply_middleware_to_peers(
    middleware: dict | None,
    local_interface: models.WireGuardInterface,
    peer_interface: models.WireGuardInterface,
    local_peer: models.WireGuardPeer,
    peer_peer: models.WireGuardPeer,
    local_endpoint: str | None,
    peer_endpoint: str | None,
    local_endpoint_port: int | None = None,
    peer_endpoint_port: int | None = None,
) -> None:
    """根据中间层类型更新 WireGuard Peer Endpoint。"""

    if middleware and middleware.get("type") == "udp2raw":
        apply_udp2raw_to_peers(
            middleware,
            local_interface,
            peer_interface,
            local_peer,
            peer_peer,
            local_endpoint,
            peer_endpoint,
            local_endpoint_port,
            peer_endpoint_port,
        )
        return
    local_peer.endpoint_host = peer_endpoint
    local_peer.endpoint_port = (peer_endpoint_port or peer_interface.listen_port) if peer_endpoint else None
    peer_peer.endpoint_host = local_endpoint
    peer_peer.endpoint_port = (local_endpoint_port or local_interface.listen_port) if local_endpoint else None


def apply_udp2raw_to_peers(
    middleware: dict | None,
    local_interface: models.WireGuardInterface,
    peer_interface: models.WireGuardInterface,
    local_peer: models.WireGuardPeer,
    peer_peer: models.WireGuardPeer,
    local_endpoint: str | None,
    peer_endpoint: str | None,
    local_endpoint_port: int | None = None,
    peer_endpoint_port: int | None = None,
) -> None:
    """根据单向 udp2raw 配置覆盖 WireGuard Peer Endpoint。"""

    if not middleware:
        local_peer.endpoint_host = peer_endpoint
        local_peer.endpoint_port = (peer_endpoint_port or peer_interface.listen_port) if peer_endpoint else None
        peer_peer.endpoint_host = local_endpoint
        peer_peer.endpoint_port = (local_endpoint_port or local_interface.listen_port) if local_endpoint else None
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
    """根据双端接口 ID 生成稳定的 udp2raw 实例名。"""

    return f"link42-{min(local_interface.id, peer_interface.id)}-{max(local_interface.id, peer_interface.id)}"


def udp2raw_endpoint_payloads(
    middleware: dict | None,
    local_interface: models.WireGuardInterface,
    peer_interface: models.WireGuardInterface,
    local_endpoint: str | None,
    peer_endpoint: str | None,
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
    if not server_public_host and not middleware.get("server_connect_host"):
        raise HTTPException(status_code=400, detail="udp2raw server endpoint address is required")
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
    local_endpoint: str | None,
    peer_endpoint: str | None,
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
        enqueue_interface_task_once(
            db,
            interface,
            task_type,
            payload,
            update_pending_payload=True,
            queue_after_running=True,
        )


def middleware_instance_name(local_interface: models.WireGuardInterface, peer_interface: models.WireGuardInterface) -> str:
    """生成中间层实例名，当前复用 udp2raw 的双端稳定命名规则。"""

    return udp2raw_instance_name(local_interface, peer_interface)


def mimic_endpoint_payloads(
    middleware: dict | None,
    local_interface: models.WireGuardInterface,
    peer_interface: models.WireGuardInterface,
    local_endpoint: str | None,
    peer_endpoint: str | None,
    local_endpoint_port: int | None = None,
    peer_endpoint_port: int | None = None,
) -> list[tuple[models.WireGuardInterface, str, dict]]:
    """生成双方 mimic Agent payload；mimic 透明处理真实 WireGuard Endpoint。"""

    if not middleware or middleware.get("type") != "mimic":
        return []
    if not local_endpoint or not peer_endpoint:
        raise HTTPException(status_code=400, detail="mimic requires endpoint address on both sides")
    if local_interface.listen_port is None or peer_interface.listen_port is None:
        raise HTTPException(status_code=400, detail="mimic requires WireGuard listen port on both sides")
    instance = middleware_instance_name(local_interface, peer_interface)
    common = {
        "plugin": "mimic",
        "instance": instance,
        "xdp_mode": middleware["xdp_mode"],
        "link_type": middleware["link_type"],
        "handshake_interval": middleware.get("handshake_interval"),
        "keepalive_interval": middleware.get("keepalive_interval"),
        "padding": middleware.get("padding"),
    }
    peer_endpoint = require_mimic_ip(peer_endpoint, "mimic peer endpoint")
    local_endpoint = require_mimic_ip(local_endpoint, "mimic local endpoint")
    local_peer_port = peer_endpoint_port or peer_interface.listen_port
    peer_peer_port = local_endpoint_port or local_interface.listen_port
    return [
        (
            local_interface,
            "middleware.mimic.apply",
            {
                **common,
                "bind_interface": middleware["local_bind_interface"],
                "local_host": local_endpoint,
                "local_port": local_interface.listen_port,
                "peer_host": peer_endpoint,
                "peer_port": local_peer_port,
                "filter_origin": "remote",
            },
        ),
        (
            peer_interface,
            "middleware.mimic.apply",
            {
                **common,
                "bind_interface": middleware["peer_bind_interface"],
                "local_host": peer_endpoint,
                "local_port": peer_interface.listen_port,
                "peer_host": local_endpoint,
                "peer_port": peer_peer_port,
                "filter_origin": "remote",
            },
        ),
    ]


def enqueue_mimic_tasks(
    db: Session,
    middleware: dict | None,
    local_interface: models.WireGuardInterface,
    peer_interface: models.WireGuardInterface,
    local_endpoint: str | None,
    peer_endpoint: str | None,
    local_endpoint_port: int | None = None,
    peer_endpoint_port: int | None = None,
) -> None:
    """为启用 mimic 的受管连接下发配置任务。"""

    if not middleware or middleware.get("type") != "mimic":
        return
    for interface in [local_interface, peer_interface]:
        node = db.get(models.Node, interface.node_id)
        if node is not None:
            require_mimic_supported(node)
    for interface, task_type, payload in mimic_endpoint_payloads(
        middleware,
        local_interface,
        peer_interface,
        local_endpoint,
        peer_endpoint,
        local_endpoint_port,
        peer_endpoint_port,
    ):
        enqueue_interface_task_once(db, interface, task_type, payload)


def enqueue_middleware_tasks(
    db: Session,
    middleware: dict | None,
    local_interface: models.WireGuardInterface,
    peer_interface: models.WireGuardInterface,
    local_endpoint: str | None,
    peer_endpoint: str | None,
    local_endpoint_port: int | None = None,
    peer_endpoint_port: int | None = None,
) -> None:
    """按中间层类型下发受管连接两端所需的安装或配置任务。"""

    if not middleware:
        return
    if middleware.get("type") == "udp2raw":
        enqueue_udp2raw_tasks(db, middleware, local_interface, peer_interface, local_endpoint, peer_endpoint)
        return
    if middleware.get("type") == "mimic":
        enqueue_mimic_tasks(
            db,
            middleware,
            local_interface,
            peer_interface,
            local_endpoint,
            peer_endpoint,
            local_endpoint_port,
            peer_endpoint_port,
        )
        return
    raise HTTPException(status_code=400, detail="unsupported middleware type")


def enqueue_middleware_cleanup_tasks(
    db: Session,
    old_middleware: dict | None,
    new_middleware: dict | None,
    local_interface: models.WireGuardInterface,
    peer_interface: models.WireGuardInterface,
) -> None:
    """中间层禁用或切换时，按旧配置清理节点上的服务和配置。"""

    if not old_middleware or old_middleware == new_middleware:
        return
    for action in ["stop", "delete"]:
        for interface, task_type, payload in middleware_task_payloads(
            old_middleware,
            local_interface,
            peer_interface,
            action,
        ):
            enqueue_interface_task_once(db, interface, task_type, payload)


def middleware_task_payloads(
    middleware: dict | None,
    local_interface: models.WireGuardInterface,
    peer_interface: models.WireGuardInterface,
    action: str,
) -> list[tuple[models.WireGuardInterface, str, dict]]:
    """按旧中间层配置生成 stop/delete 等清理任务 payload。"""

    if not middleware:
        return []
    instance = middleware_instance_name(local_interface, peer_interface)
    if middleware.get("type") == "udp2raw":
        server_side = middleware.get("server_side") or "peer"
        local_mode = "server" if server_side == "local" else "client"
        peer_mode = "client" if server_side == "local" else "server"
        return [
            (
                local_interface,
                f"middleware.udp2raw.{action}",
                {"plugin": "udp2raw", "instance": instance, "mode": local_mode},
            ),
            (
                peer_interface,
                f"middleware.udp2raw.{action}",
                {"plugin": "udp2raw", "instance": instance, "mode": peer_mode},
            ),
        ]
    if middleware.get("type") == "mimic":
        return [
            (
                local_interface,
                f"middleware.mimic.{action}",
                {"plugin": "mimic", "instance": instance, "bind_interface": middleware["local_bind_interface"]},
            ),
            (
                peer_interface,
                f"middleware.mimic.{action}",
                {"plugin": "mimic", "instance": instance, "bind_interface": middleware["peer_bind_interface"]},
            ),
        ]
    raise HTTPException(status_code=400, detail="unsupported middleware type")


def require_online_node(db: Session, node_id: int) -> models.Node:
    """读取节点并要求 Agent 当前在线，否则返回可展示的业务错误。"""

    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    if node_runtime_status(node) != "online":
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


def record_interface_rename(interface: models.WireGuardInterface, next_name: str) -> None:
    """记录尚未在节点上清理的旧接口名，供下一次部署时迁移。"""

    if interface.name == next_name:
        return
    previous_name = (interface.extras or {}).get("previous_interface_name")
    if previous_name == next_name:
        set_extra_value(interface, "previous_interface_name", None)
        return
    if not previous_name:
        set_extra_value(interface, "previous_interface_name", interface.name)


def get_wireguard_config_or_404(config_id: int, db: Session) -> models.WireGuardInterface:
    """按配置 ID 读取 WireGuard 配置，不存在时返回 404。"""

    config = db.get(models.WireGuardInterface, config_id)
    if config is None:
        raise HTTPException(status_code=404, detail="wireguard config not found")
    return config


def parse_monitor_window(value: str | None) -> timedelta:
    """解析前端图表窗口参数。"""

    mapping = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "1d": timedelta(days=1),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    key = value or "1h"
    if key not in mapping:
        raise HTTPException(status_code=422, detail="invalid monitor window")
    return mapping[key]


def monitor_status(latency_ms: float | None, packet_loss: float, stability_score: int, sample_count: int) -> str:
    """把监测指标归类为前端颜色状态。"""

    if sample_count == 0:
        return "unknown"
    if packet_loss > 0.05 or stability_score < 70 or (latency_ms is not None and latency_ms > 180):
        return "critical"
    if packet_loss > 0.01 or stability_score < 90 or (latency_ms is not None and latency_ms > 80):
        return "warning"
    return "healthy"


def summarize_monitor(
    db: Session,
    monitor: models.LinkMonitor,
    window: timedelta = MONITOR_SUMMARY_WINDOW,
) -> schemas.LinkMonitorSummary:
    """基于最近窗口样本计算链路摘要。"""

    since = datetime.utcnow() - window
    samples = list(
        db.scalars(
            select(models.LinkMonitorSample)
            .where(models.LinkMonitorSample.monitor_id == monitor.id, models.LinkMonitorSample.checked_at >= since)
            .order_by(models.LinkMonitorSample.checked_at)
        )
    )
    sample_count = len(samples)
    if not samples:
        return schemas.LinkMonitorSummary(
            monitor_id=monitor.id,
            target_host=monitor.target_host,
            packet_loss=0,
            stability_score=0,
            status="unknown",
            sample_count=0,
            last_checked_at=monitor.last_checked_at,
        )
    successes = [sample for sample in samples if sample.success and sample.latency_ms is not None]
    latencies = [float(sample.latency_ms) for sample in successes if sample.latency_ms is not None]
    packet_loss = (sample_count - len(successes)) / sample_count
    avg_latency = sum(latencies) / len(latencies) if latencies else None
    min_latency = min(latencies) if latencies else None
    max_latency = max(latencies) if latencies else None
    jitter = (
        sum(abs(current - previous) for previous, current in zip(latencies, latencies[1:])) / (len(latencies) - 1)
        if len(latencies) > 1
        else 0.0 if latencies else None
    )
    last_sample = samples[-1]
    last_latency = float(last_sample.latency_ms) if last_sample.success and last_sample.latency_ms is not None else None
    latency_penalty = min((avg_latency or 0) / 20, 20)
    jitter_penalty = min((jitter or 0) / 5, 20)
    stability = max(0, min(100, round(100 - packet_loss * 100 - latency_penalty - jitter_penalty)))
    return schemas.LinkMonitorSummary(
        monitor_id=monitor.id,
        target_host=monitor.target_host,
        last_latency_ms=last_latency,
        avg_latency_ms=avg_latency,
        min_latency_ms=min_latency,
        max_latency_ms=max_latency,
        jitter_ms=jitter,
        packet_loss=packet_loss,
        stability_score=stability,
        status=monitor_status(last_latency, packet_loss, stability, sample_count),
        sample_count=sample_count,
        last_checked_at=last_sample.checked_at,
    )


def interface_monitor(db: Session, interface_id: int) -> models.LinkMonitor | None:
    """读取配置绑定的第一个链路监测目标。"""

    return db.scalar(
        select(models.LinkMonitor)
        .where(models.LinkMonitor.interface_id == interface_id)
        .order_by(models.LinkMonitor.id)
        .limit(1)
    )


def interface_read(db: Session, interface: models.WireGuardInterface) -> schemas.InterfaceRead:
    """把 WireGuard 配置转成带监测摘要的响应。"""

    result = schemas.InterfaceRead.model_validate(interface)
    monitor = interface_monitor(db, interface.id)
    result.monitor_summary = summarize_monitor(db, monitor) if monitor else None
    return result


def connection_endpoint_ref(endpoint: models.ConnectionEndpoint) -> str:
    """返回通用连接端点引用。"""

    return f"{endpoint.connection.protocol_type}:{endpoint.id}"


def connection_ref(protocol_type: str, item_id: int) -> str:
    """返回通用连接引用。"""

    return f"{protocol_type}:{item_id}"


def parse_connection_ref(value: str) -> tuple[str, int]:
    """解析通用连接引用，格式为 protocol:id。"""

    protocol_type, separator, raw_id = value.partition(":")
    if separator != ":" or protocol_type not in {CONNECTION_TYPE_WIREGUARD, CONNECTION_TYPE_GRE}:
        raise HTTPException(status_code=404, detail="connection not found")
    try:
        item_id = int(raw_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="connection not found") from exc
    return protocol_type, item_id


def connection_endpoint_monitor(db: Session, endpoint_id: int) -> models.LinkMonitor | None:
    """读取通用连接端点绑定的第一个链路监测目标。"""

    return db.scalar(
        select(models.LinkMonitor)
        .where(models.LinkMonitor.connection_endpoint_id == endpoint_id)
        .order_by(models.LinkMonitor.id)
        .limit(1)
    )


def connection_endpoint_read(db: Session, endpoint: models.ConnectionEndpoint) -> schemas.ConnectionEndpointRead:
    """把数据库连接端点转成通用 API 响应。"""

    monitor = connection_endpoint_monitor(db, endpoint.id)
    extras = endpoint.extras or {}
    return schemas.ConnectionEndpointRead(
        id=endpoint.id,
        endpoint_ref=connection_endpoint_ref(endpoint),
        node_id=endpoint.node_id,
        node_name=endpoint.node.name if endpoint.node else None,
        role=endpoint.role,
        interface_name=endpoint.interface_name,
        tunnel_ips=endpoint.tunnel_ips or [],
        mtu=endpoint.mtu,
        routes=endpoint.routes or [],
        runtime_status=endpoint.runtime_status,
        protocol_config=endpoint.protocol_config or {},
        last_error=str(extras.get("last_error") or "").strip() or None,
        monitor_summary=summarize_monitor(db, monitor) if monitor else None,
    )


def gre_connection_status(connection: models.Connection) -> str:
    """根据两端状态聚合 GRE 连接展示状态。"""

    statuses = [endpoint.runtime_status for endpoint in connection.endpoints]
    if any(status == "failed" for status in statuses):
        return "failed"
    if statuses and all(status == "running" for status in statuses):
        return "running"
    if any(status in {"starting", "stopping"} for status in statuses):
        return "changing"
    return "stopped"


def gre_connection_read(db: Session, connection: models.Connection) -> schemas.ConnectionRead:
    """把 GRE 连接转成通用 API 响应。"""

    endpoints = sorted(connection.endpoints, key=lambda endpoint: 0 if endpoint.role == "local" else 1)
    endpoint_errors = [
        f"{endpoint.node.name if endpoint.node else endpoint.interface_name}: {str((endpoint.extras or {}).get('last_error') or '').strip()}"
        for endpoint in endpoints
        if str((endpoint.extras or {}).get("last_error") or "").strip()
    ]
    return schemas.ConnectionRead(
        id=connection.id,
        connection_ref=connection_ref(CONNECTION_TYPE_GRE, connection.id),
        protocol_type=CONNECTION_TYPE_GRE,
        protocol_label="GRE",
        name=connection.name,
        source=connection.source,
        managed=connection.managed,
        status=gre_connection_status(connection),
        endpoints=[connection_endpoint_read(db, endpoint) for endpoint in endpoints],
        warnings=[
            "GRE 不加密，请勿直接承载敏感流量",
            "GRE 需要中间网络放行 IP protocol 47，普通 NAT 环境通常不可用",
            "OpenWrt 节点创建 GRE 后需要把 GRE 地址接口加入合适的防火墙 zone，否则入向流量可能被防火墙拒绝",
        ] + endpoint_errors,
    )


def wireguard_connection_read(db: Session, interface: models.WireGuardInterface) -> schemas.ConnectionRead:
    """把旧 WireGuard 配置映射成通用连接响应。"""

    peer_interface = None
    local_peer = next(
        (peer for peer in interface.peers if peer.peer_interface_id and peer.source == "managed-node"),
        None,
    )
    if local_peer is not None:
        peer_interface = db.get(models.WireGuardInterface, local_peer.peer_interface_id)
    local_monitor = interface_monitor(db, interface.id)
    endpoints = [
        schemas.ConnectionEndpointRead(
            id=interface.id,
            endpoint_ref=connection_ref(CONNECTION_TYPE_WIREGUARD, interface.id),
            node_id=interface.node_id,
            node_name=interface.node.name if interface.node else None,
            role="local",
            interface_name=interface.name,
            tunnel_ips=interface.tunnel_ips or [],
            mtu=interface.mtu,
            routes=interface.primary_peer_allowed_ips,
            runtime_status=interface.runtime_status,
            protocol_config={"listen_port": interface.listen_port},
            monitor_summary=summarize_monitor(db, local_monitor) if local_monitor else None,
        )
    ]
    if peer_interface is not None:
        peer_monitor = interface_monitor(db, peer_interface.id)
        endpoints.append(
            schemas.ConnectionEndpointRead(
                id=peer_interface.id,
                endpoint_ref=connection_ref(CONNECTION_TYPE_WIREGUARD, peer_interface.id),
                node_id=peer_interface.node_id,
                node_name=peer_interface.node.name if peer_interface.node else None,
                role="peer",
                interface_name=peer_interface.name,
                tunnel_ips=peer_interface.tunnel_ips or [],
                mtu=peer_interface.mtu,
                routes=peer_interface.primary_peer_allowed_ips,
                runtime_status=peer_interface.runtime_status,
                protocol_config={"listen_port": peer_interface.listen_port},
                monitor_summary=summarize_monitor(db, peer_monitor) if peer_monitor else None,
            )
        )
    return schemas.ConnectionRead(
        id=interface.id,
        connection_ref=connection_ref(CONNECTION_TYPE_WIREGUARD, interface.id),
        protocol_type=CONNECTION_TYPE_WIREGUARD,
        protocol_label="WireGuard",
        name=interface.name,
        source=interface.source,
        managed=interface.managed,
        status=interface.runtime_status,
        endpoints=endpoints,
    )


def require_gre_supported(node: models.Node) -> None:
    """要求节点 Agent 支持 GRE 连接任务。"""

    require_task_supported(node, GRE_TASKS.apply_config)


def validate_gre_payload(payload: schemas.GreManagedConnectionCreate | schemas.GreManagedConnectionUpdate) -> None:
    """执行跨字段 GRE 业务校验。"""

    if not payload.risk_accepted:
        raise HTTPException(status_code=400, detail="gre risk must be accepted")
    if payload.local_outer_ip == payload.peer_outer_ip:
        raise HTTPException(status_code=400, detail="gre outer addresses must be different")
    outer = gre_outer_mapping(payload)
    if outer["local_bind_ip"] == outer["local_remote_ip"] or outer["peer_bind_ip"] == outer["peer_remote_ip"]:
        raise HTTPException(status_code=400, detail="gre endpoint local and remote addresses must be different")
    if payload.ttl is not None and not payload.pmtudisc:
        raise HTTPException(status_code=400, detail="gre ttl requires pmtu discovery")


def gre_outer_mapping(payload: schemas.GreManagedConnectionCreate | schemas.GreManagedConnectionUpdate) -> dict[str, str]:
    """把标准两地址和可选 NAT/EIP 覆盖字段合并成两端实际 GRE local/remote。"""

    return {
        "local_bind_ip": payload.local_bind_ip or payload.local_outer_ip,
        "local_remote_ip": payload.local_remote_ip or payload.peer_outer_ip,
        "peer_bind_ip": payload.peer_bind_ip or payload.peer_outer_ip,
        "peer_remote_ip": payload.peer_remote_ip or payload.local_outer_ip,
    }


def gre_protocol_config(local_outer_ip: str, remote_outer_ip: str, payload: schemas.GreManagedConnectionCreate | schemas.GreManagedConnectionUpdate) -> dict:
    """生成单端 GRE 协议配置 JSON。"""

    return {
        "outer_local_ip": local_outer_ip,
        "outer_remote_ip": remote_outer_ip,
        "key": payload.gre_key,
        "ttl": payload.ttl,
        "pmtudisc": payload.pmtudisc,
    }


def gre_task_payload(endpoint: models.ConnectionEndpoint) -> dict[str, Any]:
    """把 GRE 端点转换为 Agent 任务 payload。"""

    previous_interface_name = str((endpoint.extras or {}).get("previous_interface_name") or "").strip()
    payload = {
        "node_id": endpoint.node_id,
        "connection_id": endpoint.connection_id,
        "connection_endpoint_id": endpoint.id,
        "interface_name": endpoint.interface_name,
        "tunnel_ips": endpoint.tunnel_ips or [],
        "routes": endpoint.routes or [],
        "mtu": endpoint.mtu,
        **(endpoint.protocol_config or {}),
    }
    if previous_interface_name and previous_interface_name != endpoint.interface_name:
        payload["previous_interface_name"] = previous_interface_name
    return payload


def create_connection_endpoint_task(
    db: Session,
    endpoint: models.ConnectionEndpoint,
    task_type: str,
    payload_extra: dict | None = None,
) -> models.AgentTask:
    """创建通用连接端点 Agent 任务。"""

    node = db.get(models.Node, endpoint.node_id)
    if node is not None:
        require_task_supported(node, task_type)
    payload = gre_task_payload(endpoint)
    if payload_extra:
        payload.update(payload_extra)
    task = models.AgentTask(node_id=endpoint.node_id, type=task_type, payload=payload)
    db.add(task)
    db.flush()
    logger.info("创建连接端点任务 task=%s", summarize_agent_task(task))
    return task


def enqueue_gre_apply_and_start(db: Session, endpoint: models.ConnectionEndpoint) -> None:
    """为 GRE 端点下发部署并启动任务。"""

    apply_task = create_connection_endpoint_task(db, endpoint, GRE_TASKS.apply_config)
    create_connection_endpoint_task(
        db,
        endpoint,
        GRE_TASKS.start,
        {"depends_on_task_id": apply_task.id},
    )
    endpoint.runtime_status = "starting"


def set_endpoint_extra_value(endpoint: models.ConnectionEndpoint, key: str, value: str | None) -> None:
    """在连接端点 extras 中写入或清理字符串值。"""

    extras = dict(endpoint.extras or {})
    cleaned = value.strip() if value else None
    if cleaned:
        extras[key] = cleaned
    else:
        extras.pop(key, None)
    endpoint.extras = extras


def gre_previous_config_cleanup_confirmed(task: models.AgentTask, result: dict) -> bool:
    """判断 GRE 启动任务是否已经确认清理过旧接口配置。"""

    previous_interface_name = str((task.payload or {}).get("previous_interface_name") or "").strip()
    if not previous_interface_name:
        return True
    cleanup = result.get("previous_config_cleanup")
    if not isinstance(cleanup, dict):
        return False
    return not cleanup.get("dry_run")


def record_endpoint_rename(endpoint: models.ConnectionEndpoint, next_name: str) -> None:
    """记录 GRE 端点改名前的旧接口名，供 Agent 清理旧设备。"""

    if endpoint.interface_name == next_name:
        return
    previous_name = (endpoint.extras or {}).get("previous_interface_name")
    if previous_name == next_name:
        set_endpoint_extra_value(endpoint, "previous_interface_name", None)
        return
    if not previous_name:
        set_endpoint_extra_value(endpoint, "previous_interface_name", endpoint.interface_name)


def build_topology(db: Session) -> schemas.TopologyRead:
    """汇总节点与受管双向链路，供首页拓扑图渲染。"""

    nodes = list(db.scalars(select(models.Node).order_by(models.Node.id)))
    now = datetime.utcnow()

    interfaces = list(
        db.scalars(
            select(models.WireGuardInterface)
            .options(selectinload(models.WireGuardInterface.peers))
            .where(models.WireGuardInterface.source == "managed-node")
            .order_by(models.WireGuardInterface.id)
        )
    )
    interface_by_id = {interface.id: interface for interface in interfaces}
    edges: list[schemas.TopologyEdge] = []
    seen_pairs: set[tuple[int, int]] = set()
    for interface in interfaces:
        local_peer = next(
            (peer for peer in interface.peers if peer.peer_interface_id and peer.source == "managed-node"),
            None,
        )
        if local_peer is None or local_peer.peer_interface_id not in interface_by_id:
            continue
        peer_interface = interface_by_id[local_peer.peer_interface_id]
        peer_peer = next(
            (
                peer
                for peer in peer_interface.peers
                if peer.peer_interface_id == interface.id and peer.source == "managed-node"
            ),
            None,
        )
        if peer_peer is None:
            continue
        pair = tuple(sorted((interface.id, peer_interface.id)))
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        middleware = managed_link_middleware(interface) or managed_link_middleware(peer_interface)
        local_monitor = interface_monitor(db, interface.id)
        peer_monitor = interface_monitor(db, peer_interface.id)
        edges.append(
            schemas.TopologyEdge(
                id=f"wg-{pair[0]}-{pair[1]}",
                connection_ref=connection_ref(CONNECTION_TYPE_WIREGUARD, interface.id),
                protocol_type=CONNECTION_TYPE_WIREGUARD,
                protocol_label="WireGuard",
                local_node_id=interface.node_id,
                peer_node_id=peer_interface.node_id,
                local_interface_id=interface.id,
                peer_interface_id=peer_interface.id,
                local_interface_name=interface.name,
                peer_interface_name=peer_interface.name,
                local_status=interface.runtime_status,
                peer_status=peer_interface.runtime_status,
                middleware_type=middleware.get("type") if middleware else None,
                local_monitor=summarize_monitor(db, local_monitor) if local_monitor else None,
                peer_monitor=summarize_monitor(db, peer_monitor) if peer_monitor else None,
            )
        )

    gre_connections = list(
        db.scalars(
            select(models.Connection)
            .options(
                selectinload(models.Connection.endpoints).selectinload(models.ConnectionEndpoint.node),
            )
            .where(models.Connection.protocol_type == CONNECTION_TYPE_GRE)
            .order_by(models.Connection.id)
        )
    )
    for connection in gre_connections:
        endpoints = sorted(connection.endpoints, key=lambda endpoint: 0 if endpoint.role == "local" else 1)
        if len(endpoints) != 2:
            continue
        local_endpoint, peer_endpoint = endpoints
        local_monitor = connection_endpoint_monitor(db, local_endpoint.id)
        peer_monitor = connection_endpoint_monitor(db, peer_endpoint.id)
        edges.append(
            schemas.TopologyEdge(
                id=f"gre-{connection.id}",
                connection_ref=connection_ref(CONNECTION_TYPE_GRE, connection.id),
                protocol_type=CONNECTION_TYPE_GRE,
                protocol_label="GRE",
                local_node_id=local_endpoint.node_id,
                peer_node_id=peer_endpoint.node_id,
                local_interface_id=local_endpoint.id,
                peer_interface_id=peer_endpoint.id,
                local_interface_name=local_endpoint.interface_name,
                peer_interface_name=peer_endpoint.interface_name,
                local_status=local_endpoint.runtime_status,
                peer_status=peer_endpoint.runtime_status,
                middleware_type=None,
                local_monitor=summarize_monitor(db, local_monitor) if local_monitor else None,
                peer_monitor=summarize_monitor(db, peer_monitor) if peer_monitor else None,
            )
        )

    return schemas.TopologyRead(
        nodes=[
            schemas.TopologyNode(
                id=node.id,
                name=node.name,
                status=node_runtime_status(node, now=now),
                hostname=node.hostname,
                region=node.region,
                endpoint_ips=node.endpoint_ips or [],
                topology_endpoint=node.topology_endpoint,
                agent_version=node.agent_version,
                agent_platform=node.agent_platform or {},
                topology_x=node.topology_x,
                topology_y=node.topology_y,
                topology_locked=bool(node.topology_locked),
            )
            for node in nodes
        ],
        edges=edges,
    )


def monitor_read(db: Session, monitor: models.LinkMonitor, window: timedelta = MONITOR_SUMMARY_WINDOW) -> schemas.LinkMonitorRead:
    """把监测目标转成带摘要的响应。"""

    result = schemas.LinkMonitorRead.model_validate(monitor)
    result.summary = summarize_monitor(db, monitor, window)
    return result


def monitor_read_basic(monitor: models.LinkMonitor) -> schemas.LinkMonitorRead:
    """把监测目标转成基础响应，保存操作不在同步路径里计算历史摘要。"""

    return schemas.LinkMonitorRead.model_validate(monitor)


def suggested_monitor_target(interface: models.WireGuardInterface) -> str:
    """根据对端 AllowedIPs 和隧道地址推断默认监测 IP。"""

    values = []
    for peer in interface.peers or []:
        values.extend(peer.allowed_ips or [])
    values.extend(interface.primary_peer_allowed_ips)
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.num_addresses == 1:
            return str(network.network_address)
        return str(network.network_address + 1)
    return ""


def ensure_unique_interface_name(
    db: Session,
    node_id: int,
    name: str,
    exclude_interface_id: int | None = None,
    exclude_connection_endpoint_id: int | None = None,
) -> None:
    """确保同一节点下本地接口名唯一，避免不同协议生成同名设备。"""

    query = select(models.WireGuardInterface).where(
        models.WireGuardInterface.node_id == node_id,
        models.WireGuardInterface.name == name,
    )
    if exclude_interface_id is not None:
        query = query.where(models.WireGuardInterface.id != exclude_interface_id)
    duplicate = db.scalar(query)
    if duplicate:
        raise HTTPException(status_code=409, detail="interface name already exists on node")
    endpoint_query = select(models.ConnectionEndpoint).where(
        models.ConnectionEndpoint.node_id == node_id,
        models.ConnectionEndpoint.interface_name == name,
    )
    if exclude_connection_endpoint_id is not None:
        endpoint_query = endpoint_query.where(models.ConnectionEndpoint.id != exclude_connection_endpoint_id)
    endpoint_duplicate = db.scalar(endpoint_query)
    if endpoint_duplicate:
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


def get_interface_task(
    db: Session,
    interface_id: int,
    task_type: str,
    statuses: list[str],
) -> models.AgentTask | None:
    """读取某接口指定状态的同类型任务。"""

    return db.scalar(
        select(models.AgentTask).where(
            models.AgentTask.type == task_type,
            models.AgentTask.status.in_(statuses),
            models.AgentTask.payload["interface_id"].as_integer() == interface_id,
        ).order_by(models.AgentTask.id)
    )


def has_active_interface_task(db: Session, interface_id: int, task_type: str) -> bool:
    """判断某接口是否已有同类型待执行任务，保证用户重复点击时幂等。"""

    return get_interface_task(db, interface_id, task_type, ["pending", "running"]) is not None


def enqueue_interface_task_once(
    db: Session,
    interface: models.WireGuardInterface,
    task_type: str,
    payload_extra: dict | None = None,
    update_pending_payload: bool = False,
    queue_after_running: bool = False,
) -> bool:
    """幂等创建接口任务；已存在待执行任务时不重复入队。"""

    changed, _ = enqueue_interface_task_once_with_task(
        db,
        interface,
        task_type,
        payload_extra=payload_extra,
        update_pending_payload=update_pending_payload,
        queue_after_running=queue_after_running,
    )
    return changed


def enqueue_interface_task_once_with_task(
    db: Session,
    interface: models.WireGuardInterface,
    task_type: str,
    payload_extra: dict | None = None,
    update_pending_payload: bool = False,
    queue_after_running: bool = False,
) -> tuple[bool, models.AgentTask | None]:
    """幂等创建接口任务，并返回参与排队的任务对象。"""

    expire_stale_running_agent_tasks(db, node_id=interface.node_id)
    pending_task = get_interface_task(db, interface.id, task_type, ["pending"])
    if pending_task is not None:
        if update_pending_payload:
            pending_task.payload = create_interface_task(interface, task_type, payload_extra=payload_extra).payload
            logger.info("更新待执行接口任务 task=%s", summarize_agent_task(pending_task))
            return True, pending_task
        logger.debug("复用待执行接口任务 task=%s", summarize_agent_task(pending_task))
        return False, pending_task
    running_task = get_interface_task(db, interface.id, task_type, ["running"])
    if not queue_after_running and running_task is not None:
        logger.debug("接口已有运行中任务，跳过重复入队 task=%s", summarize_agent_task(running_task))
        return False, running_task
    node = db.get(models.Node, interface.node_id)
    if node is not None:
        require_task_supported(node, task_type)
    task = create_interface_task(interface, task_type, payload_extra=payload_extra)
    db.add(task)
    db.flush()
    logger.info("创建接口任务 task=%s", summarize_agent_task(task))
    return True, task


def cancel_pending_interface_tasks(
    db: Session,
    interface_id: int,
    task_type: str,
    reason: str,
) -> int:
    """取消指定接口的未执行任务，避免旧 payload 在清理任务之前执行。"""

    now = datetime.utcnow()
    tasks = list(
        db.scalars(
            select(models.AgentTask)
            .where(
                models.AgentTask.type == task_type,
                models.AgentTask.status == "pending",
                models.AgentTask.payload["interface_id"].as_integer() == interface_id,
            )
            .order_by(models.AgentTask.id)
        )
    )
    for task in tasks:
        task.status = "cancelled"
        task.result = {"status": "cancelled", "reason": reason}
        task.finished_at = now
    if tasks:
        logger.info("取消待执行接口任务 interface_id=%s task_type=%s count=%d reason=%s", interface_id, task_type, len(tasks), reason)
    return len(tasks)


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

    driver = connection_driver_for_interface(interface)
    previous_interface_name = str((interface.extras or {}).get("previous_interface_name") or "").strip()
    if previous_interface_name and previous_interface_name != interface.name:
        logger.info(
            "接口改名部署将先清理旧接口 node_id=%s interface_id=%s previous=%s current=%s",
            interface.node_id,
            interface.id,
            previous_interface_name,
            interface.name,
        )
        cancel_pending_interface_tasks(
            db,
            interface.id,
            driver.tasks.apply_config,
            "interface rename cleanup must run before apply_config",
        )
        previous_payload = {"interface_name": previous_interface_name}
        _, stop_task = enqueue_interface_task_once_with_task(
            db,
            interface,
            driver.tasks.stop,
            payload_extra=previous_payload,
            update_pending_payload=True,
        )
        delete_payload = dict(previous_payload)
        if stop_task is not None:
            delete_payload["depends_on_task_id"] = stop_task.id
        _, delete_task = enqueue_interface_task_once_with_task(
            db,
            interface,
            driver.tasks.delete_config,
            payload_extra=delete_payload,
            update_pending_payload=True,
        )
        apply_payload = driver.build_apply_payload(interface, enable_on_boot=enable_on_boot)
        if delete_task is not None:
            apply_payload["depends_on_task_id"] = delete_task.id
        changed, _ = enqueue_interface_task_once_with_task(
            db,
            interface,
            driver.tasks.apply_config,
            payload_extra=apply_payload,
            update_pending_payload=True,
            queue_after_running=True,
        )
        return changed
    return enqueue_interface_task_once(
        db,
        interface,
        driver.tasks.apply_config,
        payload_extra=driver.build_apply_payload(interface, enable_on_boot=enable_on_boot),
        update_pending_payload=True,
        queue_after_running=True,
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

    driver = connection_driver_for_interface(interface)
    enqueue_interface_task_once(db, interface, driver.tasks.stop)
    if should_delete_node_config_file(interface):
        enqueue_interface_task_once(db, interface, driver.tasks.delete_config)
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


def optional_node_endpoint(node: models.Node, host: str | None, detail: str) -> str | None:
    """校验并返回可选入口地址，留空表示该节点不提供可被对端拨入的 Endpoint。"""

    if host is None:
        return None
    cleaned = host.strip()
    if not cleaned:
        return None
    return require_node_endpoint(node, cleaned, detail)


def require_managed_link_endpoints(
    local_node: models.Node,
    peer_node: models.Node,
    local_endpoint_host: str | None,
    peer_endpoint_host: str | None,
) -> tuple[str | None, str | None]:
    """校验受管连接入口地址；至少一端可拨入，另一端可因 NAT 或不对称出入口留空。"""

    local_endpoint = optional_node_endpoint(
        local_node,
        local_endpoint_host,
        "local endpoint address is not registered on node",
    )
    peer_endpoint = optional_node_endpoint(
        peer_node,
        peer_endpoint_host,
        "peer endpoint address is not registered on node",
    )
    if not local_endpoint and not peer_endpoint:
        raise HTTPException(status_code=400, detail="at least one endpoint address is required")
    return local_endpoint, peer_endpoint


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


@app.get("/api/branding", response_model=schemas.BrandingRead)
def get_branding(db: Session = Depends(get_db)) -> schemas.BrandingRead:
    """公开读取站点品牌展示信息，供登录页使用。"""

    return schemas.BrandingRead(
        site_title=get_setting(db, SETTING_SITE_TITLE) or DEFAULT_SITE_TITLE,
        site_logo_url=get_setting(db, SETTING_SITE_LOGO_URL) or DEFAULT_SITE_LOGO_URL,
    )


@app.get("/api/settings", response_model=schemas.ControllerSettingsRead)
def get_controller_settings(db: Session = Depends(get_db)) -> schemas.ControllerSettingsRead:
    """读取主控 Web 设置。"""

    return schemas.ControllerSettingsRead(
        controller_url=get_setting(db, SETTING_CONTROLLER_URL) or "",
        username=admin_username(db),
        site_title=get_setting(db, SETTING_SITE_TITLE) or DEFAULT_SITE_TITLE,
        site_logo_url=get_setting(db, SETTING_SITE_LOGO_URL) or DEFAULT_SITE_LOGO_URL,
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
    set_setting(db, SETTING_SITE_TITLE, payload.site_title.strip() or DEFAULT_SITE_TITLE)
    if payload.site_logo_url is not None:
        set_setting(db, SETTING_SITE_LOGO_URL, payload.site_logo_url.strip() or DEFAULT_SITE_LOGO_URL)
    if payload.new_password:
        set_setting(db, SETTING_ADMIN_PASSWORD_HASH, hash_token(payload.new_password))
        set_setting(db, SETTING_ADMIN_SESSION_HASH, "")
    db.commit()
    return schemas.ControllerSettingsRead(
        controller_url=controller_url,
        username=username,
        site_title=get_setting(db, SETTING_SITE_TITLE) or DEFAULT_SITE_TITLE,
        site_logo_url=get_setting(db, SETTING_SITE_LOGO_URL) or DEFAULT_SITE_LOGO_URL,
    )


@app.post("/api/settings/logo", response_model=schemas.ControllerSettingsRead)
async def upload_site_logo(
    request: Request,
    db: Session = Depends(get_db),
) -> schemas.ControllerSettingsRead:
    """上传站点 Logo 到配置目录，便于 Docker bind mount 持久化。"""

    data = await request.body()
    if not data:
        raise HTTPException(status_code=400, detail="logo file is required")
    if len(data) > BRANDING_LOGO_MAX_BYTES:
        raise HTTPException(status_code=400, detail="logo file must be no larger than 3 MiB")
    suffix = detect_logo_extension(request.headers.get("content-type", ""), data)
    logo_dir = Path(settings.config_dir) / "branding"
    logo_dir.mkdir(parents=True, exist_ok=True)
    for stale_suffix in ["png", "jpg", "webp"]:
        stale_path = logo_dir / f"logo.{stale_suffix}"
        if stale_path.exists():
            stale_path.unlink()
    target = logo_dir / f"logo.{suffix}"
    target.write_bytes(data)
    set_setting(db, SETTING_SITE_LOGO_URL, f"/branding/logo?v={time.time_ns()}")
    db.commit()
    return schemas.ControllerSettingsRead(
        controller_url=get_setting(db, SETTING_CONTROLLER_URL) or "",
        username=admin_username(db),
        site_title=get_setting(db, SETTING_SITE_TITLE) or DEFAULT_SITE_TITLE,
        site_logo_url=get_setting(db, SETTING_SITE_LOGO_URL) or DEFAULT_SITE_LOGO_URL,
    )


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
    plan = build_agent_upgrade_plan(node, db, target_version=payload.target_version, force=payload.force)
    if plan.upgrade_mode != "self_upgrade" or not plan.target_version or not plan.matched_platform or not plan.matched_asset:
        raise HTTPException(status_code=409, detail=plan.reason or "agent self upgrade is not available")
    expire_stale_running_agent_tasks(db, node_id=node_id)
    active = db.scalar(
        select(models.AgentTask).where(
            models.AgentTask.node_id == node_id,
            models.AgentTask.type == "agent.self_upgrade",
            models.AgentTask.status.in_(["pending", "running"]),
        )
    )
    if active:
        logger.info("复用已有 Agent 升级任务 node_id=%s task=%s", node_id, summarize_agent_task(active))
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
    logger.info(
        "创建 Agent 升级任务 node_id=%s target_version=%s platform=%s task=%s",
        node_id,
        plan.target_version,
        plan.matched_platform,
        summarize_agent_task(task),
    )
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
        region=(payload.region or "").strip() or None,
        management_ip=payload.management_ip,
        public_ip=payload.public_ip,
        endpoint_ips=payload.endpoint_ips,
        topology_endpoint=(payload.topology_endpoint or "").strip() or (payload.endpoint_ips[0] if payload.endpoint_ips else None),
        github_proxy_url=payload.github_proxy_url,
        status="offline",
        agent_token_hash=hash_token(token),
        agent_token_value=token,
    )
    db.add(node)
    db.commit()
    db.refresh(node)
    logger.info("创建节点 node_id=%s name=%s region=%s", node.id, node.name, node.region)
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
    node.region = (payload.region or "").strip() or None
    node.management_ip = payload.management_ip
    node.public_ip = payload.public_ip
    node.endpoint_ips = payload.endpoint_ips
    node.topology_endpoint = (payload.topology_endpoint or "").strip() or (payload.endpoint_ips[0] if payload.endpoint_ips else None)
    node.github_proxy_url = payload.github_proxy_url
    db.commit()
    db.refresh(node)
    logger.info("更新节点 node_id=%s name=%s region=%s endpoint_count=%d", node.id, node.name, node.region, len(node.endpoint_ips or []))
    return node


@app.get("/api/nodes", response_model=list[schemas.NodeRead])
def list_nodes(db: Session = Depends(get_db)) -> list[schemas.NodeRead]:
    """列出所有节点。"""

    nodes = list(db.scalars(select(models.Node).order_by(models.Node.id)))
    now = datetime.utcnow()
    return [node_read_with_runtime_status(node, now=now) for node in nodes]


@app.get("/api/topology", response_model=schemas.TopologyRead)
def get_topology(db: Session = Depends(get_db)) -> schemas.TopologyRead:
    """返回首页拓扑图所需的节点和受管链路。"""

    return build_topology(db)


@app.get("/api/protocols", response_model=list[schemas.ConnectionProtocolRead])
def list_protocols() -> list[schemas.ConnectionProtocolRead]:
    """返回当前主控支持创建或展示的连接协议。"""

    return [
        schemas.ConnectionProtocolRead(
            type=CONNECTION_TYPE_WIREGUARD,
            label="WireGuard",
            description="加密的 UDP 点对点隧道，适合大多数跨公网或 NAT 场景。",
            managed=True,
        ),
        schemas.ConnectionProtocolRead(
            type=CONNECTION_TYPE_GRE,
            label="GRE",
            description="IPv4 GRE L3 隧道，不加密，需要中间网络放行 IP protocol 47。",
            managed=True,
            warnings=[
                "GRE 不加密，请勿直接承载敏感流量",
                "GRE 需要协议 47 放行，普通 NAT 环境通常不可用",
                "OpenWrt 节点创建 GRE 后需要把 GRE 地址接口加入合适的防火墙 zone，否则入向流量可能被防火墙拒绝",
            ],
        ),
    ]


def get_gre_connection_or_404(db: Session, connection_id: int) -> models.Connection:
    """读取 GRE 连接及其端点，不存在时返回 404。"""

    connection = db.scalar(
        select(models.Connection)
        .options(
            selectinload(models.Connection.endpoints).selectinload(models.ConnectionEndpoint.node),
        )
        .where(models.Connection.id == connection_id, models.Connection.protocol_type == CONNECTION_TYPE_GRE)
    )
    if connection is None:
        raise HTTPException(status_code=404, detail="connection not found")
    return connection


@app.get("/api/nodes/{node_id}/connections", response_model=list[schemas.ConnectionRead])
def list_node_connections(node_id: int, db: Session = Depends(get_db)) -> list[schemas.ConnectionRead]:
    """列出节点下的通用连接，包含旧 WireGuard 映射和新 GRE 连接。"""

    if db.get(models.Node, node_id) is None:
        raise HTTPException(status_code=404, detail="node not found")
    wireguard_interfaces = list(
        db.scalars(
            select(models.WireGuardInterface)
            .options(
                selectinload(models.WireGuardInterface.node),
                selectinload(models.WireGuardInterface.peers),
            )
            .where(models.WireGuardInterface.node_id == node_id)
            .order_by(models.WireGuardInterface.name)
        )
    )
    gre_connections = list(
        db.scalars(
            select(models.Connection)
            .options(
                selectinload(models.Connection.endpoints).selectinload(models.ConnectionEndpoint.node),
            )
            .join(models.ConnectionEndpoint)
            .where(
                models.Connection.protocol_type == CONNECTION_TYPE_GRE,
                models.ConnectionEndpoint.node_id == node_id,
            )
            .order_by(models.Connection.id)
        )
    )
    connections = [wireguard_connection_read(db, interface) for interface in wireguard_interfaces]
    connections.extend(gre_connection_read(db, connection) for connection in gre_connections)
    return connections


@app.post("/api/nodes/{node_id}/connections/managed", response_model=schemas.ConnectionRead)
def create_managed_connection(
    node_id: int,
    payload: schemas.GreManagedConnectionCreate,
    db: Session = Depends(get_db),
) -> schemas.ConnectionRead:
    """创建受管 GRE 连接，并下发双方部署启动任务。"""

    if node_id == payload.peer_node_id:
        raise HTTPException(status_code=400, detail="peer node must be different")
    validate_gre_payload(payload)
    local_node = require_online_node(db, node_id)
    peer_node = require_online_node(db, payload.peer_node_id)
    require_gre_supported(local_node)
    require_gre_supported(peer_node)
    ensure_unique_interface_name(db, node_id, payload.local_interface_name)
    ensure_unique_interface_name(db, payload.peer_node_id, payload.peer_interface_name)
    outer = gre_outer_mapping(payload)
    connection = models.Connection(
        protocol_type=CONNECTION_TYPE_GRE,
        name=f"{payload.local_interface_name} <-> {payload.peer_interface_name}",
        source="managed-node",
        managed=True,
        status="starting",
    )
    local_endpoint = models.ConnectionEndpoint(
        connection=connection,
        node_id=node_id,
        role="local",
        interface_name=payload.local_interface_name,
        tunnel_ips=payload.local_tunnel_ips,
        mtu=payload.mtu,
        routes=payload.local_routes,
        runtime_status="starting",
        protocol_config=gre_protocol_config(outer["local_bind_ip"], outer["local_remote_ip"], payload),
    )
    peer_endpoint = models.ConnectionEndpoint(
        connection=connection,
        node_id=payload.peer_node_id,
        role="peer",
        interface_name=payload.peer_interface_name,
        tunnel_ips=payload.peer_tunnel_ips,
        mtu=payload.mtu,
        routes=payload.peer_routes,
        runtime_status="starting",
        protocol_config=gre_protocol_config(outer["peer_bind_ip"], outer["peer_remote_ip"], payload),
    )
    db.add_all([connection, local_endpoint, peer_endpoint])
    db.flush()
    enqueue_gre_apply_and_start(db, local_endpoint)
    enqueue_gre_apply_and_start(db, peer_endpoint)
    db.commit()
    db.refresh(connection)
    logger.info(
        "创建 GRE 连接 connection_id=%s local_endpoint_id=%s peer_endpoint_id=%s",
        connection.id,
        local_endpoint.id,
        peer_endpoint.id,
    )
    return gre_connection_read(db, get_gre_connection_or_404(db, connection.id))


@app.get("/api/connections/{raw_connection_ref}", response_model=schemas.ConnectionRead)
def get_connection(raw_connection_ref: str, db: Session = Depends(get_db)) -> schemas.ConnectionRead:
    """读取通用连接详情。"""

    protocol_type, item_id = parse_connection_ref(raw_connection_ref)
    if protocol_type == CONNECTION_TYPE_WIREGUARD:
        interface = get_wireguard_config_or_404(item_id, db)
        return wireguard_connection_read(db, interface)
    return gre_connection_read(db, get_gre_connection_or_404(db, item_id))


@app.patch("/api/connections/{raw_connection_ref}", response_model=schemas.ConnectionRead)
def update_connection(
    raw_connection_ref: str,
    payload: schemas.GreManagedConnectionUpdate,
    db: Session = Depends(get_db),
) -> schemas.ConnectionRead:
    """编辑 GRE 连接并重新下发双方配置。"""

    protocol_type, item_id = parse_connection_ref(raw_connection_ref)
    if protocol_type != CONNECTION_TYPE_GRE:
        raise HTTPException(status_code=400, detail="use wireguard API for WireGuard connections")
    validate_gre_payload(payload)
    connection = get_gre_connection_or_404(db, item_id)
    endpoints = sorted(connection.endpoints, key=lambda endpoint: 0 if endpoint.role == "local" else 1)
    if len(endpoints) != 2:
        raise HTTPException(status_code=400, detail="gre connection endpoints are incomplete")
    local_endpoint, peer_endpoint = endpoints
    local_node = require_online_node(db, local_endpoint.node_id)
    peer_node = require_online_node(db, peer_endpoint.node_id)
    require_gre_supported(local_node)
    require_gre_supported(peer_node)
    ensure_unique_interface_name(
        db,
        local_endpoint.node_id,
        payload.local_interface_name,
        exclude_connection_endpoint_id=local_endpoint.id,
    )
    ensure_unique_interface_name(
        db,
        peer_endpoint.node_id,
        payload.peer_interface_name,
        exclude_connection_endpoint_id=peer_endpoint.id,
    )
    record_endpoint_rename(local_endpoint, payload.local_interface_name)
    record_endpoint_rename(peer_endpoint, payload.peer_interface_name)
    outer = gre_outer_mapping(payload)
    local_endpoint.interface_name = payload.local_interface_name
    local_endpoint.tunnel_ips = payload.local_tunnel_ips
    local_endpoint.mtu = payload.mtu
    local_endpoint.routes = payload.local_routes
    local_endpoint.protocol_config = gre_protocol_config(outer["local_bind_ip"], outer["local_remote_ip"], payload)
    peer_endpoint.interface_name = payload.peer_interface_name
    peer_endpoint.tunnel_ips = payload.peer_tunnel_ips
    peer_endpoint.mtu = payload.mtu
    peer_endpoint.routes = payload.peer_routes
    peer_endpoint.protocol_config = gre_protocol_config(outer["peer_bind_ip"], outer["peer_remote_ip"], payload)
    connection.name = f"{payload.local_interface_name} <-> {payload.peer_interface_name}"
    connection.status = "starting"
    enqueue_gre_apply_and_start(db, local_endpoint)
    enqueue_gre_apply_and_start(db, peer_endpoint)
    db.commit()
    logger.info("更新 GRE 连接 connection_id=%s", connection.id)
    return gre_connection_read(db, get_gre_connection_or_404(db, connection.id))


@app.post("/api/connections/{raw_connection_ref}/start", response_model=schemas.ConnectionRead)
def start_connection(raw_connection_ref: str, db: Session = Depends(get_db)) -> schemas.ConnectionRead:
    """启动 GRE 连接双方端点。"""

    protocol_type, item_id = parse_connection_ref(raw_connection_ref)
    if protocol_type != CONNECTION_TYPE_GRE:
        raise HTTPException(status_code=400, detail="use wireguard API for WireGuard connections")
    connection = get_gre_connection_or_404(db, item_id)
    for endpoint in connection.endpoints:
        require_online_node(db, endpoint.node_id)
        create_connection_endpoint_task(db, endpoint, GRE_TASKS.start)
        endpoint.runtime_status = "starting"
    connection.status = "starting"
    db.commit()
    logger.info("启动 GRE 连接 connection_id=%s", connection.id)
    return gre_connection_read(db, get_gre_connection_or_404(db, connection.id))


@app.post("/api/connections/{raw_connection_ref}/stop", response_model=schemas.ConnectionRead)
def stop_connection(raw_connection_ref: str, db: Session = Depends(get_db)) -> schemas.ConnectionRead:
    """停止 GRE 连接双方端点。"""

    protocol_type, item_id = parse_connection_ref(raw_connection_ref)
    if protocol_type != CONNECTION_TYPE_GRE:
        raise HTTPException(status_code=400, detail="use wireguard API for WireGuard connections")
    connection = get_gre_connection_or_404(db, item_id)
    for endpoint in connection.endpoints:
        require_online_node(db, endpoint.node_id)
        create_connection_endpoint_task(db, endpoint, GRE_TASKS.stop)
        endpoint.runtime_status = "stopping"
    connection.status = "stopping"
    db.commit()
    logger.info("停止 GRE 连接 connection_id=%s", connection.id)
    return gre_connection_read(db, get_gre_connection_or_404(db, connection.id))


@app.post("/api/connections/{raw_connection_ref}/refresh-status", response_model=schemas.ConnectionRead)
def refresh_connection_status(raw_connection_ref: str, db: Session = Depends(get_db)) -> schemas.ConnectionRead:
    """刷新 GRE 连接双方端点运行状态。"""

    protocol_type, item_id = parse_connection_ref(raw_connection_ref)
    if protocol_type != CONNECTION_TYPE_GRE:
        raise HTTPException(status_code=400, detail="use wireguard API for WireGuard connections")
    connection = get_gre_connection_or_404(db, item_id)
    for endpoint in connection.endpoints:
        require_online_node(db, endpoint.node_id)
        create_connection_endpoint_task(db, endpoint, GRE_TASKS.status)
    db.commit()
    logger.info("刷新 GRE 连接状态 connection_id=%s", connection.id)
    return gre_connection_read(db, get_gre_connection_or_404(db, connection.id))


@app.delete("/api/connections/{raw_connection_ref}")
def delete_connection(raw_connection_ref: str, db: Session = Depends(get_db)) -> dict[str, str]:
    """删除 GRE 连接记录，并下发双方清理任务。"""

    protocol_type, item_id = parse_connection_ref(raw_connection_ref)
    if protocol_type != CONNECTION_TYPE_GRE:
        raise HTTPException(status_code=400, detail="use wireguard API for WireGuard connections")
    connection = get_gre_connection_or_404(db, item_id)
    connection_id = connection.id
    for endpoint in list(connection.endpoints):
        require_online_node(db, endpoint.node_id)
        stop_task = create_connection_endpoint_task(db, endpoint, GRE_TASKS.stop)
        create_connection_endpoint_task(db, endpoint, GRE_TASKS.delete_config, {"depends_on_task_id": stop_task.id})
    db.delete(connection)
    db.commit()
    logger.info("删除 GRE 连接 connection_id=%s", connection_id)
    return {"status": "deleted"}


@app.get("/api/nodes/{node_id}", response_model=schemas.NodeRead)
def get_node(node_id: int, db: Session = Depends(get_db)) -> schemas.NodeRead:
    """读取单个节点详情。"""

    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    return node_read_with_runtime_status(node)


@app.get("/api/node-plugins", response_model=list[schemas.NodePluginRead])
def list_node_plugins() -> list[dict[str, object]]:
    """列出主控内置节点插件。"""

    return [plugin.describe() for plugin in NODE_PLUGINS.values()]


@app.get("/api/nodes/{node_id}/plugins", response_model=list[schemas.NodePluginStatusRead])
def list_node_plugins_for_node(node_id: int, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    """列出指定节点可用的插件和能力缺口。"""

    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    context = NodePluginContext(node=node, db=db)
    display_status = node_runtime_status(node)
    return [
        {**plugin.status_for_node(context), "node_status": display_status}
        for plugin in NODE_PLUGINS.values()
    ]


def port_inventory_setting_for_node(node_id: int, db: Session) -> models.PortInventorySetting:
    """读取节点端口台账设置，不存在时创建空设置记录。"""

    setting = db.scalar(select(models.PortInventorySetting).where(models.PortInventorySetting.node_id == node_id))
    if setting is None:
        setting = models.PortInventorySetting(node_id=node_id)
        db.add(setting)
        db.flush()
    return setting


def validate_port_inventory_range(range_start: int | None, range_end: int | None) -> None:
    """校验端口台账范围起止顺序。"""

    if range_start is None or range_end is None:
        return
    if range_start > range_end:
        raise HTTPException(status_code=400, detail="range_start must be less than or equal to range_end")


def validate_port_inventory_entry(node_id: int, protocol: str, port: int, db: Session, exclude_id: int | None = None) -> None:
    """校验端口台账条目是否在范围内且不与现有条目重复。"""

    setting = db.scalar(select(models.PortInventorySetting).where(models.PortInventorySetting.node_id == node_id))
    if setting and setting.range_start is not None and setting.range_end is not None:
        if not setting.range_start <= port <= setting.range_end:
            raise HTTPException(status_code=400, detail="port is outside configured range")
    duplicate_query = select(models.PortInventoryEntry).where(
        models.PortInventoryEntry.node_id == node_id,
        models.PortInventoryEntry.protocol == protocol,
        models.PortInventoryEntry.port == port,
    )
    if exclude_id is not None:
        duplicate_query = duplicate_query.where(models.PortInventoryEntry.id != exclude_id)
    duplicate = db.scalar(duplicate_query)
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="port entry already exists")


@app.get("/api/nodes/{node_id}/port-inventory", response_model=schemas.PortInventoryRead)
def get_port_inventory(node_id: int, q: str | None = None, db: Session = Depends(get_db)) -> schemas.PortInventoryRead:
    """读取节点端口台账。"""

    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    setting = port_inventory_setting_for_node(node_id, db)
    query = select(models.PortInventoryEntry).where(models.PortInventoryEntry.node_id == node_id)
    if q:
        text = f"%{q.strip()}%"
        query = query.where(
            (models.PortInventoryEntry.purpose.like(text))
            | (models.PortInventoryEntry.protocol.like(text))
            | (models.PortInventoryEntry.detected_process.like(text))
            | (models.PortInventoryEntry.detected_source.like(text))
            | (models.PortInventoryEntry.port.cast(String).like(text))
        )
    entries = list(db.scalars(query.order_by(models.PortInventoryEntry.port, models.PortInventoryEntry.protocol)))
    db.commit()
    return schemas.PortInventoryRead(
        setting=schemas.PortInventorySettingRead(range_start=setting.range_start, range_end=setting.range_end),
        entries=entries,
    )


@app.put("/api/nodes/{node_id}/port-inventory/range", response_model=schemas.PortInventorySettingRead)
def update_port_inventory_range(
    node_id: int,
    payload: schemas.PortInventorySettingUpdate,
    db: Session = Depends(get_db),
) -> schemas.PortInventorySettingRead:
    """保存节点端口台账范围。"""

    if db.get(models.Node, node_id) is None:
        raise HTTPException(status_code=404, detail="node not found")
    validate_port_inventory_range(payload.range_start, payload.range_end)
    setting = port_inventory_setting_for_node(node_id, db)
    setting.range_start = payload.range_start
    setting.range_end = payload.range_end
    db.commit()
    return schemas.PortInventorySettingRead(range_start=setting.range_start, range_end=setting.range_end)


@app.post("/api/nodes/{node_id}/port-inventory/entries", response_model=schemas.PortInventoryEntryRead)
def create_port_inventory_entry(
    node_id: int,
    payload: schemas.PortInventoryEntryCreate,
    db: Session = Depends(get_db),
) -> models.PortInventoryEntry:
    """新增端口台账条目。"""

    if db.get(models.Node, node_id) is None:
        raise HTTPException(status_code=404, detail="node not found")
    validate_port_inventory_entry(node_id, payload.protocol, payload.port, db)
    entry = models.PortInventoryEntry(node_id=node_id, **payload.model_dump())
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@app.patch("/api/nodes/{node_id}/port-inventory/entries/{entry_id}", response_model=schemas.PortInventoryEntryRead)
def update_port_inventory_entry(
    node_id: int,
    entry_id: int,
    payload: schemas.PortInventoryEntryUpdate,
    db: Session = Depends(get_db),
) -> models.PortInventoryEntry:
    """修改端口台账条目。"""

    entry = db.get(models.PortInventoryEntry, entry_id)
    if entry is None or entry.node_id != node_id:
        raise HTTPException(status_code=404, detail="port entry not found")
    data = payload.model_dump(exclude_unset=True)
    protocol = data.get("protocol", entry.protocol)
    port = data.get("port", entry.port)
    validate_port_inventory_entry(node_id, protocol, port, db, exclude_id=entry.id)
    for key, value in data.items():
        setattr(entry, key, value)
    db.commit()
    db.refresh(entry)
    return entry


@app.delete("/api/nodes/{node_id}/port-inventory/entries/{entry_id}")
def delete_port_inventory_entry(node_id: int, entry_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    """删除端口台账条目。"""

    entry = db.get(models.PortInventoryEntry, entry_id)
    if entry is None or entry.node_id != node_id:
        raise HTTPException(status_code=404, detail="port entry not found")
    db.delete(entry)
    db.commit()
    return {"status": "deleted"}


@app.post("/api/nodes/{node_id}/plugins/{plugin_type}/{action}", response_model=schemas.NodePluginActionResult)
def request_node_plugin_action(
    node_id: int,
    plugin_type: str,
    action: str,
    payload: schemas.NodePluginActionRequest,
    db: Session = Depends(get_db),
) -> schemas.NodePluginActionResult:
    """创建节点插件任务。"""

    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    plugin = get_node_plugin(plugin_type)
    if plugin is None:
        raise HTTPException(status_code=404, detail="plugin not found")
    if action not in plugin.actions:
        raise HTTPException(status_code=404, detail="plugin action not found")
    if node_runtime_status(node) != "online":
        raise HTTPException(status_code=409, detail="node is offline")
    context = NodePluginContext(node=node, db=db)
    status = plugin.status_for_node(context)
    if not status["version_supported"]:
        raise HTTPException(status_code=409, detail="agent does not support plugin version")
    if status["missing_capabilities"]:
        raise HTTPException(status_code=409, detail="plugin is not supported by this node")
    try:
        cleaned_payload = plugin.validate_payload(action, payload.payload, context)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    task_spec = plugin.build_task(action, cleaned_payload, context)
    require_task_supported(node, task_spec.task_type)
    task = models.AgentTask(node_id=node_id, type=task_spec.task_type, payload=task_spec.payload)
    db.add(task)
    db.commit()
    db.refresh(task)
    logger.info(
        "创建节点插件任务 node_id=%s plugin=%s action=%s task=%s",
        node_id,
        plugin_type,
        action,
        summarize_agent_task(task),
    )
    return schemas.NodePluginActionResult(
        task_id=task.id,
        plugin_type=plugin_type,
        action=action,
        status=task.status,
        message="插件任务已创建",
    )


@app.get("/api/tasks/{task_id}", response_model=schemas.AgentTaskStatusRead)
def get_agent_task_status(task_id: int, db: Session = Depends(get_db)) -> models.AgentTask:
    """读取 Agent 任务状态，供 Web 前端轮询。"""

    task = db.get(models.AgentTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    if task.status == "running":
        expire_stale_running_agent_tasks(db, node_id=task.node_id)
        db.commit()
        db.refresh(task)
    return task


@app.patch("/api/nodes/{node_id}/topology-position", response_model=schemas.NodeRead)
def update_node_topology_position(
    node_id: int,
    payload: schemas.TopologyPositionUpdate,
    db: Session = Depends(get_db),
) -> models.Node:
    """保存用户在拓扑图中拖拽后的节点位置。"""

    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    if (payload.x is None) != (payload.y is None):
        raise HTTPException(status_code=400, detail="topology x and y must be provided together")
    node.topology_x = payload.x
    node.topology_y = payload.y
    node.topology_locked = True if payload.locked is None else payload.locked
    db.commit()
    db.refresh(node)
    return node


@app.post("/api/topology/layout/reset", response_model=schemas.TopologyRead)
def reset_topology_layout(db: Session = Depends(get_db)) -> schemas.TopologyRead:
    """清空所有自定义拓扑坐标，让前端回到自动布局。"""

    nodes = list(db.scalars(select(models.Node)))
    for node in nodes:
        node.topology_x = None
        node.topology_y = None
        node.topology_locked = False
    db.commit()
    return build_topology(db)


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
    node_name = node.name
    for candidate in db.scalars(select(models.ImportCandidate).where(models.ImportCandidate.node_id == node_id)):
        db.delete(candidate)
    for task in db.scalars(select(models.AgentTask).where(models.AgentTask.node_id == node_id)):
        db.delete(task)
    db.delete(node)
    db.commit()
    logger.info("删除节点 node_id=%s name=%s", node_id, node_name)
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
    logger.warning("轮换节点 Agent token node_id=%s name=%s", node.id, node.name)
    return schemas.NodeCreateResult(node=node, agent_token=token)


@app.post("/api/nodes/{node_id}/middleware/{plugin}/install", response_model=schemas.TaskRequestResult)
def install_node_middleware(
    node_id: int,
    plugin: str,
    db: Session = Depends(get_db),
) -> schemas.TaskRequestResult:
    """为节点创建中间层插件安装任务。"""

    node = require_online_node(db, node_id)
    if plugin != "mimic":
        raise HTTPException(status_code=404, detail="middleware plugin not found")
    if "middleware.mimic" in set(node.agent_capabilities or []):
        node.middleware_install_status = "mimic_ready"
        logger.info("mimic 已安装，跳过安装任务 node_id=%s", node.id)
        return schemas.TaskRequestResult(task_id=None, status="succeeded", message="mimic already installed")
    require_mimic_install_supported(node)
    task = models.AgentTask(
        node_id=node.id,
        type="middleware.install",
        status="pending",
        payload={
            "plugin": "mimic",
            "source": "github_latest",
            "repo": "hack3ric/mimic",
            "allow_prerelease": False,
            "github_proxy_url": node.github_proxy_url,
        },
    )
    db.add(task)
    node.middleware_install_status = "mimic_installing"
    db.commit()
    db.refresh(task)
    logger.info("创建中间层安装任务 node_id=%s plugin=%s task=%s", node.id, plugin, summarize_agent_task(task))
    return schemas.TaskRequestResult(task_id=task.id, status=task.status, message="mimic install task queued")


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
    logger.info("创建 WireGuard 配置 node_id=%s interface_id=%s name=%s", node_id, interface.id, interface.name)
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
    middleware = normalize_middleware_config(payload.udp2raw, payload.mimic)
    local_endpoint, peer_endpoint = require_managed_link_endpoints(
        local_node,
        peer_node,
        payload.local_endpoint_host,
        payload.peer_endpoint_host,
    )

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
    set_extra_object(local_interface, "middleware", middleware)
    set_extra_object(peer_interface, "middleware", middleware)
    apply_middleware_to_peers(
        middleware,
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
    enqueue_middleware_tasks(
        db,
        middleware,
        local_interface,
        peer_interface,
        local_endpoint,
        peer_endpoint,
        payload.local_endpoint_port,
        payload.peer_endpoint_port,
    )
    enqueue_apply_config(db, local_interface)
    enqueue_apply_config(db, peer_interface)
    db.commit()
    db.refresh(local_interface)
    db.refresh(peer_interface)
    logger.info(
        "创建受管连接 local_node_id=%s local_interface_id=%s peer_node_id=%s peer_interface_id=%s middleware=%s",
        local_interface.node_id,
        local_interface.id,
        peer_interface.node_id,
        peer_interface.id,
        (middleware or {}).get("type"),
    )
    return schemas.ManagedLinkCreateResult(local_interface=local_interface, peer_interface=peer_interface)


@app.get("/api/nodes/{node_id}/wireguard/interfaces", response_model=list[schemas.InterfaceRead])
@app.get("/api/nodes/{node_id}/wireguard/configs", response_model=list[schemas.InterfaceRead])
def list_interfaces(node_id: int, db: Session = Depends(get_db)) -> list[schemas.InterfaceRead]:
    """列出指定节点上的 WireGuard 点对点配置。"""
    interfaces = list(
        db.scalars(
            select(models.WireGuardInterface)
            .options(selectinload(models.WireGuardInterface.peers))
            .where(models.WireGuardInterface.node_id == node_id)
            .order_by(models.WireGuardInterface.name)
        )
    )
    return [interface_read(db, interface) for interface in interfaces]


@app.get("/api/wireguard/interfaces/{interface_id}", response_model=schemas.InterfaceRead)
@app.get("/api/wireguard/configs/{interface_id}", response_model=schemas.InterfaceRead)
def get_interface(interface_id: int, db: Session = Depends(get_db)) -> schemas.InterfaceRead:
    """读取单个 WireGuard 点对点配置。"""
    interface = db.scalar(
        select(models.WireGuardInterface)
        .options(selectinload(models.WireGuardInterface.peers))
        .where(models.WireGuardInterface.id == interface_id)
    )
    if interface is None:
        raise HTTPException(status_code=404, detail="interface not found")
    return interface_read(db, interface)


@app.get("/api/wireguard/configs/{interface_id}/link-monitor", response_model=schemas.LinkMonitorRead | None)
def get_interface_link_monitor(interface_id: int, db: Session = Depends(get_db)) -> schemas.LinkMonitorRead | None:
    """读取配置绑定的链路监测目标。"""

    get_wireguard_config_or_404(interface_id, db)
    monitor = interface_monitor(db, interface_id)
    return monitor_read(db, monitor) if monitor else None


@app.post("/api/wireguard/configs/{interface_id}/link-monitor", response_model=schemas.LinkMonitorRead)
def upsert_interface_link_monitor(
    interface_id: int,
    payload: schemas.LinkMonitorCreate,
    db: Session = Depends(get_db),
) -> schemas.LinkMonitorRead:
    """创建或覆盖配置的链路监测目标。"""

    interface = db.scalar(
        select(models.WireGuardInterface)
        .options(selectinload(models.WireGuardInterface.peers))
        .where(models.WireGuardInterface.id == interface_id)
    )
    if interface is None:
        raise HTTPException(status_code=404, detail="interface not found")
    require_online_node(db, interface.node_id)
    monitor = interface_monitor(db, interface_id)
    now = datetime.utcnow()
    name = (payload.name or f"{interface.name} latency").strip()
    if monitor is None:
        monitor = models.LinkMonitor(
            node_id=interface.node_id,
            interface_id=interface.id,
            name=name,
            target_host=payload.target_host,
            interval_seconds=payload.interval_seconds,
            retention_days=payload.retention_days,
            enabled=payload.enabled,
            next_due_at=now if payload.enabled else None,
        )
        db.add(monitor)
    else:
        monitor.name = name
        monitor.target_host = payload.target_host
        monitor.interval_seconds = payload.interval_seconds
        monitor.retention_days = payload.retention_days
        monitor.enabled = payload.enabled
        monitor.next_due_at = now if payload.enabled else None
    db.commit()
    db.refresh(monitor)
    return monitor_read_basic(monitor)


@app.get("/api/connection-endpoints/{endpoint_id}/link-monitor", response_model=schemas.LinkMonitorRead | None)
def get_connection_endpoint_link_monitor(endpoint_id: int, db: Session = Depends(get_db)) -> schemas.LinkMonitorRead | None:
    """读取通用连接端点绑定的链路监测目标。"""

    endpoint = db.get(models.ConnectionEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="connection endpoint not found")
    monitor = connection_endpoint_monitor(db, endpoint_id)
    return monitor_read(db, monitor) if monitor else None


@app.post("/api/connection-endpoints/{endpoint_id}/link-monitor", response_model=schemas.LinkMonitorRead)
def upsert_connection_endpoint_link_monitor(
    endpoint_id: int,
    payload: schemas.LinkMonitorCreate,
    db: Session = Depends(get_db),
) -> schemas.LinkMonitorRead:
    """创建或覆盖通用连接端点的链路监测目标。"""

    endpoint = db.get(models.ConnectionEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="connection endpoint not found")
    require_online_node(db, endpoint.node_id)
    monitor = connection_endpoint_monitor(db, endpoint_id)
    now = datetime.utcnow()
    name = (payload.name or f"{endpoint.interface_name} latency").strip()
    if monitor is None:
        monitor = models.LinkMonitor(
            node_id=endpoint.node_id,
            connection_endpoint_id=endpoint.id,
            name=name,
            target_host=payload.target_host,
            interval_seconds=payload.interval_seconds,
            retention_days=payload.retention_days,
            enabled=payload.enabled,
            next_due_at=now if payload.enabled else None,
        )
        db.add(monitor)
    else:
        monitor.name = name
        monitor.target_host = payload.target_host
        monitor.interval_seconds = payload.interval_seconds
        monitor.retention_days = payload.retention_days
        monitor.enabled = payload.enabled
        monitor.next_due_at = now if payload.enabled else None
    db.commit()
    db.refresh(monitor)
    return monitor_read_basic(monitor)


@app.patch("/api/link-monitors/{monitor_id}", response_model=schemas.LinkMonitorRead)
def update_link_monitor(
    monitor_id: int,
    payload: schemas.LinkMonitorUpdate,
    db: Session = Depends(get_db),
) -> schemas.LinkMonitorRead:
    """修改链路监测目标。"""

    monitor = db.get(models.LinkMonitor, monitor_id)
    if monitor is None:
        raise HTTPException(status_code=404, detail="link monitor not found")
    require_online_node(db, monitor.node_id)
    monitor.name = (payload.name or monitor.name).strip()
    monitor.target_host = payload.target_host
    monitor.interval_seconds = payload.interval_seconds
    monitor.retention_days = payload.retention_days
    monitor.enabled = payload.enabled
    monitor.next_due_at = datetime.utcnow() if payload.enabled else None
    db.commit()
    db.refresh(monitor)
    return monitor_read_basic(monitor)


@app.delete("/api/link-monitors/{monitor_id}")
def delete_link_monitor(monitor_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    """删除链路监测目标及历史样本。"""

    monitor = db.get(models.LinkMonitor, monitor_id)
    if monitor is None:
        raise HTTPException(status_code=404, detail="link monitor not found")
    db.delete(monitor)
    db.commit()
    return {"status": "deleted"}


@app.get("/api/link-monitors/{monitor_id}/samples", response_model=schemas.LinkMonitorSamplesResponse)
def get_link_monitor_samples(
    monitor_id: int,
    window: str | None = "1h",
    db: Session = Depends(get_db),
) -> schemas.LinkMonitorSamplesResponse:
    """读取链路监测历史样本，用于前端绘图。"""

    monitor = db.get(models.LinkMonitor, monitor_id)
    if monitor is None:
        raise HTTPException(status_code=404, detail="link monitor not found")
    parsed_window = parse_monitor_window(window)
    since = datetime.utcnow() - parsed_window
    samples = list(
        db.scalars(
            select(models.LinkMonitorSample)
            .where(models.LinkMonitorSample.monitor_id == monitor_id, models.LinkMonitorSample.checked_at >= since)
            .order_by(models.LinkMonitorSample.checked_at)
        )
    )
    summary = summarize_monitor(db, monitor, parsed_window)
    monitor_data = schemas.LinkMonitorRead.model_validate(monitor)
    monitor_data.summary = summary
    return schemas.LinkMonitorSamplesResponse(
        monitor=monitor_data,
        summary=summary,
        samples=[schemas.LinkMonitorSampleRead.model_validate(sample) for sample in samples],
    )


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
    old_middleware = managed_link_middleware(local_interface)
    local_node = require_online_node(db, local_interface.node_id)
    peer_node = require_online_node(db, peer_interface.node_id)
    middleware = normalize_middleware_config(payload.udp2raw, payload.mimic)
    local_endpoint, peer_endpoint = require_managed_link_endpoints(
        local_node,
        peer_node,
        payload.local_endpoint_host,
        payload.peer_endpoint_host,
    )
    ensure_unique_interface_name(db, local_interface.node_id, payload.local_interface_name, local_interface.id)
    ensure_unique_interface_name(db, peer_interface.node_id, payload.peer_interface_name, peer_interface.id)

    record_interface_rename(local_interface, payload.local_interface_name)
    record_interface_rename(peer_interface, payload.peer_interface_name)
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
    set_extra_object(local_interface, "middleware", middleware)
    set_extra_object(peer_interface, "middleware", middleware)
    apply_middleware_to_peers(
        middleware,
        local_interface,
        peer_interface,
        local_peer,
        peer_peer,
        local_endpoint,
        peer_endpoint,
        payload.local_endpoint_port,
        payload.peer_endpoint_port,
    )

    enqueue_middleware_cleanup_tasks(db, old_middleware, middleware, local_interface, peer_interface)
    enqueue_middleware_tasks(
        db,
        middleware,
        local_interface,
        peer_interface,
        local_endpoint,
        peer_endpoint,
        payload.local_endpoint_port,
        payload.peer_endpoint_port,
    )
    if enqueue_apply_config(db, local_interface):
        local_interface.runtime_status = "starting"
    if enqueue_apply_config(db, peer_interface):
        peer_interface.runtime_status = "starting"
    db.commit()
    db.refresh(local_interface)
    db.refresh(peer_interface)
    db.refresh(local_peer)
    db.refresh(peer_peer)
    logger.info(
        "更新受管连接 local_interface_id=%s peer_interface_id=%s middleware=%s",
        local_interface.id,
        peer_interface.id,
        (middleware or {}).get("type"),
    )
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
        for interface, task_type, task_payload in middleware_task_payloads(middleware, local_interface, peer_interface, "start"):
            enqueue_interface_task_once(db, interface, task_type, task_payload)
    for interface in [local_interface, peer_interface]:
        if interface.runtime_status not in ["running", "starting"]:
            driver = connection_driver_for_interface(interface)
            if enqueue_interface_task_once(db, interface, driver.tasks.start):
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
            driver = connection_driver_for_interface(interface)
            if enqueue_interface_task_once(db, interface, driver.tasks.stop):
                interface.runtime_status = "stopping"
    if middleware:
        for interface, task_type, task_payload in middleware_task_payloads(middleware, local_interface, peer_interface, "stop"):
            enqueue_interface_task_once(db, interface, task_type, task_payload)
    db.commit()
    return {
        "local_interface": local_interface,
        "peer_interface": peer_interface,
        "local_peer": local_peer,
        "peer_peer": peer_peer,
        "middleware": middleware,
    }


@app.delete("/api/wireguard/configs/{interface_id}/managed-link")
def delete_managed_link(
    interface_id: int,
    db: Session = Depends(get_db),
    delete_node_config: bool = False,
) -> dict[str, str]:
    """同时删除受管连接双方；必须先断开双方接口。"""

    local_interface, peer_interface, _, _ = get_managed_link_bundle(db, interface_id)
    require_online_node(db, local_interface.node_id)
    require_online_node(db, peer_interface.node_id)
    if any(interface.runtime_status in ["running", "starting", "stopping"] for interface in [local_interface, peer_interface]):
        raise HTTPException(status_code=409, detail="wireguard interface must be stopped before delete")
    middleware = managed_link_middleware(local_interface)
    for interface in [local_interface, peer_interface]:
        if middleware and delete_node_config:
            for target_interface, task_type, task_payload in middleware_task_payloads(middleware, local_interface, peer_interface, "delete"):
                if target_interface.id == interface.id:
                    enqueue_interface_task_once(db, target_interface, task_type, task_payload)
        mark_import_candidate_available_for_interface(db, interface)
        if delete_node_config and should_delete_node_config_file(interface):
            driver = connection_driver_for_interface(interface)
            enqueue_interface_task_once(db, interface, driver.tasks.delete_config)
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

    record_interface_rename(interface, payload.name)
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
    config_diff = build_diff(old_config, new_config, fromfile=f"{interface.name}.current", tofile=f"{interface.name}.link42")
    rename_diff = build_interface_rename_diff(interface)
    diff = config_diff + ("\n" if config_diff and rename_diff else "") + rename_diff
    driver = connection_driver_for_interface(interface)
    plan = models.ChangePlan(
        title=f"Apply WireGuard interface {interface.name}",
        summary=f"Deploy WireGuard config for node {interface.node_id} interface {interface.name}",
        affected_node_ids=[interface.node_id],
        diff=diff,
        payload={"task_type": driver.tasks.apply_config, "task_payload": build_apply_plan(interface)},
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    logger.info(
        "生成部署计划 plan_id=%s node_id=%s interface_id=%s interface_name=%s diff_lines=%d",
        plan.id,
        interface.node_id,
        interface.id,
        interface.name,
        len(diff.splitlines()),
    )
    return plan


@app.post("/api/wireguard/configs/{interface_id}/refresh-deployed", response_model=schemas.InterfaceRead)
def refresh_deployed_config(interface_id: int, db: Session = Depends(get_db)) -> models.WireGuardInterface:
    """请求 Agent 读取节点上的当前配置，供下一次部署计划生成真实 diff。"""

    interface = get_wireguard_config_or_404(interface_id, db)
    require_online_node(db, interface.node_id)
    driver = connection_driver_for_interface(interface)
    enqueue_interface_task_once(db, interface, driver.tasks.read_config)
    db.commit()
    db.refresh(interface)
    return interface


@app.post("/api/wireguard/configs/{interface_id}/refresh-status", response_model=schemas.InterfaceRead)
def refresh_interface_status(interface_id: int, db: Session = Depends(get_db)) -> models.WireGuardInterface:
    """请求 Agent 刷新 WireGuard 接口运行状态。"""

    interface = get_wireguard_config_or_404(interface_id, db)
    require_online_node(db, interface.node_id)
    driver = connection_driver_for_interface(interface)
    enqueue_interface_task_once(db, interface, driver.tasks.status)
    db.commit()
    db.refresh(interface)
    return interface


@app.post("/api/wireguard/configs/{interface_id}/start", response_model=schemas.InterfaceRead)
def start_interface(interface_id: int, db: Session = Depends(get_db)) -> models.WireGuardInterface:
    """创建启动 WireGuard 接口的 Agent 任务。"""

    interface = get_wireguard_config_or_404(interface_id, db)
    node = require_online_node(db, interface.node_id)
    if interface.source == "managed-node":
        raise HTTPException(status_code=400, detail="use managed link operation")
    if not interface.deployed_config and not node_uses_openwrt_uci(node):
        raise HTTPException(status_code=400, detail="wireguard config must be deployed before start")
    if interface.runtime_status in ["running", "starting"]:
        return interface
    driver = connection_driver_for_interface(interface)
    if enqueue_interface_task_once(db, interface, driver.tasks.start):
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
    driver = connection_driver_for_interface(interface)
    if enqueue_interface_task_once(db, interface, driver.tasks.stop):
        interface.runtime_status = "stopping"
    db.commit()
    db.refresh(interface)
    return interface


@app.delete("/api/wireguard/configs/{interface_id}")
def delete_interface(
    interface_id: int,
    db: Session = Depends(get_db),
    delete_node_config: bool = False,
) -> dict[str, str]:
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
    if delete_node_config and should_delete_node_config_file(interface):
        driver = connection_driver_for_interface(interface)
        enqueue_interface_task_once(db, interface, driver.tasks.delete_config)
    db.delete(interface)
    db.commit()
    return {"status": "deleted"}


def create_change_plan_agent_tasks(
    db: Session,
    plan: models.ChangePlan,
    task_type: str,
    task_payload: dict,
) -> list[models.AgentTask]:
    """按计划 payload 创建 Agent 任务；接口改名时附加受依赖保护的清理任务。"""

    interface_id = task_payload.get("interface_id")
    interface = db.get(models.WireGuardInterface, interface_id) if interface_id else None
    previous_interface_name = str(task_payload.get("previous_interface_name") or "").strip()
    if interface is not None and previous_interface_name and previous_interface_name != task_payload.get("interface_name"):
        driver = connection_driver_for_interface(interface)
        if task_type == driver.tasks.apply_config:
            node = db.get(models.Node, task_payload["node_id"])
            if node is not None:
                require_task_supported(node, driver.tasks.stop)
                require_task_supported(node, driver.tasks.delete_config)
            previous_payload = {
                "node_id": task_payload["node_id"],
                "interface_id": interface.id,
                "interface_name": previous_interface_name,
            }
            stop_task = models.AgentTask(
                node_id=task_payload["node_id"],
                change_plan_id=plan.id,
                type=driver.tasks.stop,
                payload=previous_payload,
            )
            db.add(stop_task)
            db.flush()
            delete_task = models.AgentTask(
                node_id=task_payload["node_id"],
                change_plan_id=plan.id,
                type=driver.tasks.delete_config,
                payload={**previous_payload, "depends_on_task_id": stop_task.id},
            )
            db.add(delete_task)
            db.flush()
            apply_task = models.AgentTask(
                node_id=task_payload["node_id"],
                change_plan_id=plan.id,
                type=task_type,
                payload={**task_payload, "depends_on_task_id": delete_task.id},
            )
            db.add(apply_task)
            return [stop_task, delete_task, apply_task]

    task = models.AgentTask(
        node_id=task_payload["node_id"],
        change_plan_id=plan.id,
        type=task_type,
        payload=task_payload,
    )
    db.add(task)
    return [task]


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
    created_tasks = create_change_plan_agent_tasks(db, plan, task_type, task_payload)
    db.flush()
    logger.info(
        "确认部署计划 plan_id=%s node_id=%s task_type=%s tasks=%s",
        plan.id,
        task_payload["node_id"],
        task_type,
        [summarize_agent_task(task) for task in created_tasks],
    )
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

    node = require_online_node(db, node_id)
    if node_uses_openwrt_uci(node):
        raise HTTPException(status_code=409, detail="OpenWrt UCI nodes do not support wg-quick import scan")
    require_task_supported(node, WIREGUARD_TASKS.import_scan)
    expire_stale_running_agent_tasks(db, node_id=node_id)

    existing = db.scalar(
        select(models.AgentTask).where(
            models.AgentTask.node_id == node_id,
            models.AgentTask.type == WIREGUARD_TASKS.import_scan,
            models.AgentTask.status.in_(["pending", "running"]),
        )
    )
    if existing is not None:
        logger.info("复用已有导入扫描任务 node_id=%s task=%s", node_id, summarize_agent_task(existing))
        return schemas.TaskRequestResult(
            task_id=existing.id,
            status=existing.status,
            message="scan task already queued",
        )

    task = models.AgentTask(
        node_id=node_id,
        type=WIREGUARD_TASKS.import_scan,
        payload={"node_id": node_id},
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    logger.info("创建导入扫描任务 node_id=%s task=%s", node_id, summarize_agent_task(task))
    return schemas.TaskRequestResult(
        task_id=task.id,
        status=task.status,
        message="scan task queued",
    )


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
    driver = connection_driver_for_interface(interface)
    plan = models.ChangePlan(
        title=f"Take over WireGuard interface {interface.name}",
        summary=f"Back up and replace imported config for node {interface.node_id} interface {interface.name}",
        affected_node_ids=[interface.node_id],
        diff=diff,
        payload={
            "task_type": driver.tasks.apply_config,
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
    previous_status = node.status
    previous_version = node.agent_version
    previous_capabilities = sorted(node.agent_capabilities or [])
    node.hostname = payload.hostname or node.hostname
    node.management_ip = payload.management_ip or node.management_ip
    node.public_ip = payload.public_ip or node.public_ip
    update_agent_metadata(node, payload.agent_version, payload.protocol_version, payload.capabilities, payload.platform)
    node.status = "online"
    node.last_seen_at = datetime.utcnow()
    db.commit()
    current_capabilities = sorted(node.agent_capabilities or [])
    if previous_status != "online" or previous_version != node.agent_version or previous_capabilities != current_capabilities:
        logger.info(
            "Agent 注册 node_id=%s hostname=%s version=%s protocol=%s service=%s capabilities=%s",
            node.id,
            node.hostname,
            node.agent_version,
            node.agent_protocol_version,
            (node.agent_platform or {}).get("service_manager"),
            current_capabilities,
        )
    else:
        logger.debug("Agent 注册刷新 node_id=%s hostname=%s version=%s", node.id, node.hostname, node.agent_version)
    return {"status": "registered"}


@app.post("/api/agent/heartbeat")
def agent_heartbeat(payload: schemas.AgentHeartbeatRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    """Agent 心跳，用于更新节点在线状态。"""
    node = require_agent(db, payload.node_id, payload.token)
    was_online = is_node_online(node)
    update_agent_metadata(node, payload.agent_version, payload.protocol_version, payload.capabilities, payload.platform)
    node.status = "online"
    node.last_seen_at = datetime.utcnow()
    db.commit()
    if not was_online:
        logger.info("Agent 心跳恢复在线 node_id=%s hostname=%s version=%s", node.id, node.hostname, node.agent_version)
    else:
        logger.debug("Agent 心跳 node_id=%s version=%s", node.id, node.agent_version)
    return {"status": "ok"}


@app.post("/api/agent/tasks/poll", response_model=schemas.AgentPollResponse)
def agent_poll(payload: schemas.AgentPollRequest, db: Session = Depends(get_db)) -> schemas.AgentPollResponse:
    """Agent 轮询待执行任务，并把任务标记为 running。"""
    node = require_agent(db, payload.node_id, payload.token)
    update_agent_metadata(node, payload.agent_version, payload.protocol_version, payload.capabilities, payload.platform)
    now = datetime.utcnow()
    expired_count = expire_stale_running_agent_tasks(db, node_id=payload.node_id, now=now)
    expired_pending_count = expire_overdue_pending_agent_tasks(db, node_id=payload.node_id, now=now)
    candidate_tasks = list(
        db.scalars(
            select(models.AgentTask)
            .where(models.AgentTask.node_id == payload.node_id, models.AgentTask.status == "pending")
            .order_by(models.AgentTask.queue == "query", models.AgentTask.priority, models.AgentTask.id)
            .limit(AGENT_TASK_POLL_SCAN_LIMIT)
        )
    )
    tasks = []
    for task in candidate_tasks:
        if not agent_satisfies_task(node, task.type):
            continue
        if not is_task_ready_for_poll(db, task, now):
            continue
        tasks.append(task)
        if len(tasks) >= AGENT_TASK_POLL_BATCH_SIZE:
            break
    for task in tasks:
        task.status = "running"
        task.started_at = now
    db.commit()
    if tasks:
        logger.info(
            "Agent 拉取任务 node_id=%s count=%d expired_running=%d tasks=%s",
            payload.node_id,
            len(tasks),
            expired_count + expired_pending_count,
            [summarize_agent_task(task) for task in tasks],
        )
    elif expired_count or expired_pending_count:
        logger.info(
            "Agent 本轮未拉取新任务 node_id=%s expired_running=%d expired_pending=%d",
            payload.node_id,
            expired_count,
            expired_pending_count,
        )
    else:
        logger.debug("Agent 本轮无任务 node_id=%s", payload.node_id)
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

    reported_status, reported_result = normalize_agent_task_report(db, task, payload.status, payload.result)
    task.status = reported_status
    task.result = reported_result
    task.finished_at = datetime.utcnow()
    node = db.get(models.Node, payload.node_id)
    log_message = "Agent 上报任务结果 task=%s result=%s"
    log_args = (summarize_agent_task(task), summarize_task_result(reported_result))
    if reported_status == "succeeded":
        logger.info(log_message, *log_args)
    else:
        logger.warning(log_message, *log_args)

    if task.type == "agent.self_upgrade" and node is not None:
        upgrade_status = str(reported_result.get("status") or reported_status)
        node.agent_update_status = upgrade_status
        if reported_status == "failed" or upgrade_status in {"failed", "rolled_back"}:
            node.agent_last_error = str(reported_result.get("error") or reported_result)
        else:
            node.agent_last_error = None

    if task.type == "middleware.install" and node is not None and (task.payload or {}).get("plugin") == "mimic":
        if reported_status == "succeeded":
            if reported_result.get("reboot_required"):
                node.middleware_install_status = "mimic_reboot_required"
                platform = dict(node.agent_platform or {})
                platform["mimic_reboot_required"] = True
                node.agent_platform = platform
            else:
                node.middleware_install_status = "mimic_ready"
                platform = dict(node.agent_platform or {})
                platform.pop("mimic_reboot_required", None)
                node.agent_platform = platform
        elif reported_status == "failed":
            node.middleware_install_status = "mimic_failed"

    if task.change_plan_id:
        plan = db.get(models.ChangePlan, task.change_plan_id)
        if plan is not None:
            previous_plan_status = plan.status
            update_change_plan_task_status(db, plan)
            if previous_plan_status != plan.status:
                logger.info(
                    "部署计划状态变化 plan_id=%s previous=%s current=%s task_id=%s",
                    plan.id,
                    previous_plan_status,
                    plan.status,
                    task.id,
                )

    # import_scan 的结果由 Agent 返回候选配置，API 在这里转存为 ImportCandidate。
    if task.type == WIREGUARD_TASKS.import_scan and reported_status == "succeeded":
        candidates = reported_result.get("candidates", [])
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
    if interface_id and reported_status == "succeeded":
        interface = db.get(models.WireGuardInterface, interface_id)
        if interface is not None:
            driver = connection_driver_for_interface(interface)
            if task.type == driver.tasks.apply_config:
                # 部署成功后记录节点上的已部署配置，后续 Change Plan diff 才能对比真实基线。
                interface.deployed_config = task.payload.get("config")
                interface.runtime_status = "running"
                if should_clear_previous_interface_name(db, task, reported_result):
                    set_extra_value(interface, "previous_interface_name", None)
            elif task.type == driver.tasks.read_config:
                if not (
                    reported_result.get("config_backend") == "openwrt-uci"
                    and reported_result.get("exists") is False
                    and not reported_result.get("config")
                ):
                    interface.deployed_config = reported_result.get("config") or ""
            elif task.type == driver.tasks.start:
                interface.runtime_status = "running"
            elif task.type == driver.tasks.stop:
                interface.runtime_status = "stopped"
            elif task.type == driver.tasks.status:
                interface.runtime_status = reported_result.get("runtime_status") or interface.runtime_status

    connection_endpoint_id = task.payload.get("connection_endpoint_id")
    if connection_endpoint_id and reported_status == "failed":
        endpoint = db.get(models.ConnectionEndpoint, connection_endpoint_id)
        if endpoint is not None and endpoint.connection.protocol_type == CONNECTION_TYPE_GRE:
            endpoint.runtime_status = "failed"
            set_endpoint_extra_value(endpoint, "last_error", agent_task_error_summary(reported_result) or "Agent 任务执行失败")
            endpoint.connection.status = gre_connection_status(endpoint.connection)
    if connection_endpoint_id and reported_status == "succeeded":
        endpoint = db.get(models.ConnectionEndpoint, connection_endpoint_id)
        if endpoint is not None and endpoint.connection.protocol_type == CONNECTION_TYPE_GRE:
            if task.type == GRE_TASKS.apply_config:
                endpoint.deployed_config = json.dumps(gre_task_payload(endpoint), ensure_ascii=False, sort_keys=True)
            elif task.type == GRE_TASKS.start:
                endpoint.runtime_status = "running"
                set_endpoint_extra_value(endpoint, "last_error", None)
                if gre_previous_config_cleanup_confirmed(task, reported_result):
                    set_endpoint_extra_value(endpoint, "previous_interface_name", None)
            elif task.type == GRE_TASKS.stop:
                endpoint.runtime_status = "stopped"
                set_endpoint_extra_value(endpoint, "last_error", None)
            elif task.type == GRE_TASKS.status:
                endpoint.runtime_status = reported_result.get("runtime_status") or endpoint.runtime_status
            elif task.type == GRE_TASKS.read_config:
                endpoint.deployed_config = json.dumps(reported_result.get("config") or {}, ensure_ascii=False, sort_keys=True)
            endpoint.connection.status = gre_connection_status(endpoint.connection)

    looking_glass_query = db.scalar(
        select(models.LookingGlassQuery).where(models.LookingGlassQuery.agent_task_id == task.id)
    )
    if looking_glass_query is not None:
        refresh_looking_glass_query_from_task(looking_glass_query)

    db.commit()
    return {"status": "recorded"}


@app.post("/api/agent/link-monitors/poll", response_model=schemas.AgentLinkMonitorPollResponse)
def agent_link_monitor_poll(
    payload: schemas.AgentPollRequest,
    db: Session = Depends(get_db),
) -> schemas.AgentLinkMonitorPollResponse:
    """Agent 拉取当前到期的链路监测目标。"""

    node = require_agent(db, payload.node_id, payload.token)
    update_agent_metadata(node, payload.agent_version, payload.protocol_version, payload.capabilities, payload.platform)
    now = datetime.utcnow()
    monitors = list(
        db.scalars(
            select(models.LinkMonitor)
            .where(
                models.LinkMonitor.node_id == payload.node_id,
                models.LinkMonitor.enabled.is_(True),
                or_(models.LinkMonitor.next_due_at.is_(None), models.LinkMonitor.next_due_at <= now),
            )
            .order_by(models.LinkMonitor.id)
            .limit(10)
        )
    )
    for monitor in monitors:
        monitor.next_due_at = now + timedelta(seconds=monitor.interval_seconds)
    node.status = "online"
    node.last_seen_at = now
    db.commit()
    if monitors:
        logger.info(
            "Agent 拉取链路监测目标 node_id=%s count=%d monitor_ids=%s",
            payload.node_id,
            len(monitors),
            [monitor.id for monitor in monitors],
        )
    else:
        logger.debug("Agent 本轮无链路监测目标 node_id=%s", payload.node_id)
    return schemas.AgentLinkMonitorPollResponse(
        monitors=[
            schemas.AgentLinkMonitorRead(
                id=monitor.id,
                target_host=monitor.target_host,
                timeout_seconds=max(1.0, min(3.0, float(monitor.interval_seconds) * 0.8)),
            )
            for monitor in monitors
        ]
    )


@app.post("/api/agent/link-monitors/result")
def agent_link_monitor_result(
    payload: schemas.AgentLinkMonitorResultRequest,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Agent 上报链路监测结果。"""

    require_agent(db, payload.node_id, payload.token)
    now = datetime.utcnow()
    recorded_count = 0
    failed_count = 0
    cleanup_cutoffs: dict[int, datetime] = {}
    last_checked_by_monitor: dict[int, datetime] = {}
    for item in payload.results:
        monitor = db.get(models.LinkMonitor, item.monitor_id)
        if monitor is None or monitor.node_id != payload.node_id:
            logger.warning("忽略未知链路监测结果 node_id=%s monitor_id=%s", payload.node_id, item.monitor_id)
            continue
        checked_at = item.checked_at or now
        db.add(
            models.LinkMonitorSample(
                monitor_id=monitor.id,
                checked_at=checked_at,
                success=item.success,
                latency_ms=item.latency_ms if item.success else None,
                error=item.error,
            )
        )
        last_checked_by_monitor[monitor.id] = checked_at
        cleanup_cutoffs[monitor.id] = now - timedelta(days=monitor.retention_days)
        recorded_count += 1
        if not item.success:
            failed_count += 1
    for monitor_id, checked_at in last_checked_by_monitor.items():
        monitor = db.get(models.LinkMonitor, monitor_id)
        if monitor is not None:
            monitor.last_checked_at = checked_at
    for monitor_id, cutoff in cleanup_cutoffs.items():
        db.execute(
            delete(models.LinkMonitorSample).where(
                models.LinkMonitorSample.monitor_id == monitor_id,
                models.LinkMonitorSample.checked_at < cutoff,
            )
        )
    db.commit()
    if failed_count:
        logger.warning(
            "链路监测结果已记录 node_id=%s count=%d failed=%d",
            payload.node_id,
            recorded_count,
            failed_count,
        )
    else:
        logger.info("链路监测结果已记录 node_id=%s count=%d failed=0", payload.node_id, recorded_count)
    return {"status": "recorded"}


mount_web_panel()
