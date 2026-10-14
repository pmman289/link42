from __future__ import annotations

import json
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import fcntl
import ipaddress
import logging
import math
import os
import re
from pathlib import Path
import secrets
import stat
import shlex
import subprocess
import sys
import threading
import time
import tempfile
from typing import Any
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from pydantic import ValidationError
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
from sqlalchemy import String, delete, func, or_, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from link42_common.security import (
    generate_token,
    hash_password,
    hash_token,
    password_hash_needs_update,
    verify_password,
    verify_token,
)
from link42_common.version import AGENT_VERSION, CONTROLLER_VERSION

from . import models, schemas, ipam
from .ipam_api import router as ipam_router
from .config import settings
from .connection_drivers import connection_driver_for_interface
from .database import (
    get_db,
    init_db,
    protect_sensitive_database_values,
    protect_sqlite_sensitive_values,
    sqlite_database_path,
)
from .http_security import RequestBodyLimitMiddleware
from .node_plugins import NODE_PLUGINS, get_node_plugin
from .node_plugins.base import NodePluginContext
from .secret_store import load_master_key
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


def json_object(value: Any) -> dict[str, Any]:
    """将旧库/外部 JSON 字段安全规整为对象。"""

    return value if isinstance(value, dict) else {}


def commit_unique_or_conflict(db: Session, detail: str) -> None:
    """把数据库唯一约束竞态转换成稳定的业务冲突响应。"""

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=detail) from exc


def flush_unique_or_conflict(db: Session, detail: str) -> None:
    """把 flush 阶段的唯一约束竞态转换成稳定冲突响应。"""

    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=detail) from exc


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


def validate_wireguard_ipv6_mtu(mtu: int | None, *tunnel_ip_groups: list[str]) -> None:
    """拒绝会让 Linux 注销接口 IPv6 能力的过小 WireGuard MTU。"""

    if mtu is None or mtu >= 1280:
        return
    for tunnel_ips in tunnel_ip_groups:
        if any(ipaddress.ip_interface(value).version == 6 for value in tunnel_ips):
            raise HTTPException(status_code=400, detail="IPv6 WireGuard MTU must be at least 1280")


def summarize_task_payload(payload: dict | None) -> dict[str, object]:
    """生成可安全写入日志的任务 payload 摘要。"""

    # 历史数据库可能包含合法 JSON 但根类型不是对象；日志路径也不能因此
    # 触发 TypeError，进而掩盖真正的任务状态。
    if not isinstance(payload, dict):
        return {}
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
app.add_middleware(RequestBodyLimitMiddleware)
cors_origins = [item.strip() for item in settings.cors_allowed_origins.split(",") if item.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=bool(cors_origins),
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
    # 默认错误包含原始 input；它可能携带密钥、极深 JSON 或 NaN，
    # 既会泄露输入，也可能让错误响应本身序列化失败。前端只需要这三个字段。
    details = [{key: error[key] for key in ("loc", "msg", "type") if key in error} for error in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": details})

DEFAULT_ADMIN_USERNAME = "pmman"
ADMIN_USERNAME = DEFAULT_ADMIN_USERNAME
SETTING_ADMIN_USERNAME = "admin_username"
SETTING_ADMIN_PASSWORD_HASH = "admin_password_hash"
SETTING_ADMIN_SESSION_HASH = "admin_session_hash"
SETTING_ADMIN_SESSION_ISSUED_AT = "admin_session_issued_at"
SETTING_ADMIN_SESSION_LAST_USED_AT = "admin_session_last_used_at"
SETTING_ADMIN_INITIAL_PASSWORD_PENDING = "admin_initial_password_pending"
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
MAX_AGENT_TASK_DEPENDENCY_DEPTH = 64
MAX_AGENT_TASK_PAYLOAD_BYTES = 2 * 1024 * 1024
LOOKING_GLASS_QUEUE_TIMEOUT = timedelta(seconds=30)
LOOKING_GLASS_COMMAND_TIMEOUT_SECONDS = 15
LOOKING_GLASS_TOTAL_DEADLINE = timedelta(seconds=60)
LOOKING_GLASS_RESULT_RETENTION = timedelta(minutes=10)
LOOKING_GLASS_CACHE_WINDOW = timedelta(seconds=5)
LOOKING_GLASS_OUTPUT_LIMIT_BYTES = 256 * 1024
LINK_MONITOR_SAMPLE_LIMIT = 20_000
AGENT_RELEASE_MANIFEST_MAX_BYTES = 2 * 1024 * 1024
WEB_SESSION_COOKIE = "link42_session"
WEB_CSRF_HEADER = "x-link42-csrf"
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW_SECONDS = 5 * 60
LOGIN_FAILURES: dict[tuple[str, str], deque[float]] = defaultdict(deque)
LOGIN_FAILURES_LOCK = threading.Lock()
LOGIN_CONCURRENCY = threading.BoundedSemaphore(settings.login_concurrency)


def reject_symlink_components(path: Path) -> None:
    """拒绝受管路径中已存在的符号链接组件。"""

    current = Path(path.anchor or "/")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    if not path.is_absolute():
        current = Path()
    for part in parts:
        current /= part
        try:
            if current.is_symlink():
                raise HTTPException(status_code=404, detail="managed path is invalid")
        except OSError as exc:
            raise HTTPException(status_code=404, detail="managed path is invalid") from exc


def uploaded_logo_path() -> Path | None:
    """返回当前上传 Logo 文件路径。"""

    logo_dir = Path(settings.config_dir) / "branding"
    reject_symlink_components(logo_dir)
    for suffix in ["png", "jpg", "webp"]:
        path = logo_dir / f"logo.{suffix}"
        if path.is_file() and not path.is_symlink():
            return path
    return None


@contextmanager
def branding_logo_lock(logo_dir: Path, *, shared: bool = False):
    """用持久锁文件协调线程及不同主控 worker 的 Logo 读写。"""

    reject_symlink_components(logo_dir)
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        descriptor = os.open(logo_dir / ".logo.lock", flags, 0o600)
    except OSError as exc:
        raise HTTPException(status_code=404, detail="managed path is invalid") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise HTTPException(status_code=404, detail="managed path is invalid")
        fcntl.flock(descriptor, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def read_uploaded_logo(path: Path) -> tuple[bytes, str]:
    """以不可跟随最终符号链接的方式读取 Logo。"""

    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > BRANDING_LOGO_MAX_BYTES:
                raise OSError("invalid logo file")
            data = source.read(BRANDING_LOGO_MAX_BYTES + 1)
        if len(data) > BRANDING_LOGO_MAX_BYTES:
            raise OSError("logo is too large")
    except (OSError, ValueError):
        raise HTTPException(status_code=404, detail="logo not uploaded") from None
    media_type = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".webp": "image/webp",
    }.get(path.suffix.lower(), "application/octet-stream")
    return data, media_type


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


@app.get("/branding/logo", include_in_schema=False)
def serve_uploaded_logo() -> Response:
    """返回用户上传并保存在配置目录中的 Logo。"""

    logo_dir = Path(settings.config_dir) / "branding"
    if not logo_dir.exists():
        raise HTTPException(status_code=404, detail="logo not uploaded")
    with branding_logo_lock(logo_dir, shared=True):
        path = uploaded_logo_path()
        if not path:
            raise HTTPException(status_code=404, detail="logo not uploaded")
        data, media_type = read_uploaded_logo(path)
    return Response(content=data, media_type=media_type)

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
    """首次启动时生成管理员密码，并写入权限受限的引导文件。"""

    db = next(get_db())
    password: str | None = None
    try:
        if get_setting(db, SETTING_ADMIN_PASSWORD_HASH):
            if not get_setting(db, SETTING_ADMIN_USERNAME):
                set_setting(db, SETTING_ADMIN_USERNAME, DEFAULT_ADMIN_USERNAME)
                db.commit()
            return
        password = secrets.token_urlsafe(18)
        # 多 worker 同时启动时，只有成功插入密码行的 worker 能发布引导文件；
        # 其它 worker 看到主键冲突后直接读取已提交凭据，避免文件与数据库不匹配。
        try:
            with db.begin_nested():
                db.add(models.SystemSetting(key=SETTING_ADMIN_PASSWORD_HASH, value=hash_password(password)))
                db.flush()
        except IntegrityError:
            db.expire_all()
            password = None
            return
        set_setting(db, SETTING_ADMIN_USERNAME, DEFAULT_ADMIN_USERNAME)
        set_setting(db, SETTING_ADMIN_INITIAL_PASSWORD_PENDING, "1")
        set_setting(db, SETTING_CONTROLLER_URL, get_setting(db, SETTING_CONTROLLER_URL) or "")
        set_setting(db, SETTING_SITE_TITLE, get_setting(db, SETTING_SITE_TITLE) or DEFAULT_SITE_TITLE)
        set_setting(db, SETTING_SITE_LOGO_URL, get_setting(db, SETTING_SITE_LOGO_URL) or DEFAULT_SITE_LOGO_URL)
        db.commit()
    finally:
        db.close()
    if password is None:
        return
    password_path = Path(settings.config_dir) / "initial-admin-password"
    reject_symlink_components(password_path.parent)
    if password_path.is_symlink():
        raise RuntimeError("initial admin password path must not be a symbolic link")
    password_path.parent.mkdir(parents=True, exist_ok=True)
    reject_symlink_components(password_path.parent)
    temporary_path = password_path.with_name(f".{password_path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(f"username={DEFAULT_ADMIN_USERNAME}\npassword={password}\n".encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
        temporary_path.replace(password_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    password_path.chmod(0o600)
    logger.warning(
        "Link42 初始登录信息已写入受限文件 username=%s path=%s",
        DEFAULT_ADMIN_USERNAME,
        password_path,
    )


def remove_initial_password_file() -> None:
    """管理员修改密码后删除不再有效的初始密码文件。"""

    path = Path(settings.config_dir) / "initial-admin-password"
    if path.exists() and not path.is_symlink() and path.is_file():
        path.unlink()


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


def database_target_for_log() -> str:
    """返回不含用户名和密码的数据库类型及目标摘要。"""

    url = make_url(settings.database_url)
    if url.get_backend_name() == "sqlite":
        return f"sqlite:{url.database or ':memory:'}"
    host = url.host or "local"
    port = f":{url.port}" if url.port else ""
    database = f"/{url.database}" if url.database else ""
    return f"{url.get_backend_name()}://{host}{port}{database}"


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


def web_session_token_from_request(request: Request) -> tuple[str | None, str | None]:
    """优先读取 Bearer 会话，并兼容浏览器使用的 HttpOnly Cookie。"""

    bearer = bearer_token_from_request(request)
    if bearer:
        return bearer, "bearer"
    cookie = request.cookies.get(WEB_SESSION_COOKIE, "").strip()
    return (cookie, "cookie") if cookie else (None, None)


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
    """校验 Web 管理端会话 token、空闲有效期和绝对有效期。"""

    token, _source = web_session_token_from_request(request)
    session_hash = get_setting(db, SETTING_ADMIN_SESSION_HASH)
    if not token or not session_hash or not verify_token(token, session_hash):
        raise HTTPException(status_code=401, detail="not authenticated")
    now = time.time()
    try:
        issued_at = float(get_setting(db, SETTING_ADMIN_SESSION_ISSUED_AT) or now)
        last_used_at = float(get_setting(db, SETTING_ADMIN_SESSION_LAST_USED_AT) or issued_at)
    except ValueError:
        issued_at = now
        last_used_at = now
    if (
        now - issued_at > settings.web_session_absolute_seconds
        or now - last_used_at > settings.web_session_idle_seconds
    ):
        clear_web_session(db)
        db.commit()
        raise HTTPException(status_code=401, detail="session expired")
    if now - last_used_at >= 60 or not get_setting(db, SETTING_ADMIN_SESSION_ISSUED_AT):
        set_setting(db, SETTING_ADMIN_SESSION_ISSUED_AT, str(issued_at))
        set_setting(db, SETTING_ADMIN_SESSION_LAST_USED_AT, str(now))
        db.commit()


def clear_web_session(db: Session) -> None:
    """清除服务端保存的单用户 Web 会话。"""

    set_setting(db, SETTING_ADMIN_SESSION_HASH, "")
    set_setting(db, SETTING_ADMIN_SESSION_ISSUED_AT, "")
    set_setting(db, SETTING_ADMIN_SESSION_LAST_USED_AT, "")


def request_uses_cookie_session(request: Request) -> bool:
    """判断当前 Web 请求是否依赖 Cookie 而非显式 Bearer Token。"""

    return not bearer_token_from_request(request) and bool(request.cookies.get(WEB_SESSION_COOKIE))


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


def request_direct_peer_is_trusted(request: Request) -> bool:
    """判断 TCP 直连来源是否属于管理员配置的可信反向代理网段。"""

    direct_ip = normalized_header_ip(request.client.host) if request.client else None
    if not direct_ip:
        return False
    address = ipaddress.ip_address(direct_ip)
    for value in settings.trusted_proxy_cidrs.split(","):
        value = value.strip()
        if not value:
            continue
        try:
            if address in ipaddress.ip_network(value, strict=False):
                return True
        except ValueError:
            logger.warning("忽略无效可信代理 CIDR value=%s", value)
    return False


def request_source_ip(request: Request) -> str | None:
    """获取来源 IP，仅对显式配置的可信代理接受转发头。"""

    direct_ip = normalized_header_ip(request.client.host) if request.client else None
    if request_direct_peer_is_trusted(request):
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
    return direct_ip or (request.client.host if request.client else None)


def login_rate_key(request: Request, username: str) -> tuple[str, str]:
    """生成登录限流键，同时约束来源和账号两个维度。"""

    return request_source_ip(request) or "unknown", username.strip().casefold()[:80]


def login_retry_after(key: tuple[str, str], now: float | None = None) -> int:
    """返回登录失败窗口内需要等待的秒数，未受限时返回零。"""

    current = time.monotonic() if now is None else now
    rate_keys = [key, (key[0], "*"), ("*", key[1])]
    with LOGIN_FAILURES_LOCK:
        retry_after = 0
        for rate_key in rate_keys:
            failures = LOGIN_FAILURES[rate_key]
            while failures and current - failures[0] >= LOGIN_FAILURE_WINDOW_SECONDS:
                failures.popleft()
            if not failures:
                LOGIN_FAILURES.pop(rate_key, None)
            elif len(failures) >= LOGIN_FAILURE_LIMIT:
                retry_after = max(
                    retry_after,
                    max(1, int(LOGIN_FAILURE_WINDOW_SECONDS - (current - failures[0]))),
                )
        return retry_after


def record_login_failure(key: tuple[str, str]) -> None:
    """记录一次失败登录，并保持内存表大小有界。"""

    current = time.monotonic()
    with LOGIN_FAILURES_LOCK:
        for rate_key in [key, (key[0], "*"), ("*", key[1])]:
            failures = LOGIN_FAILURES[rate_key]
            while failures and current - failures[0] >= LOGIN_FAILURE_WINDOW_SECONDS:
                failures.popleft()
            failures.append(current)
        if len(LOGIN_FAILURES) > 4096:
            for stale_key in list(LOGIN_FAILURES)[:1024]:
                if stale_key != key:
                    LOGIN_FAILURES.pop(stale_key, None)


def clear_login_failures(key: tuple[str, str]) -> None:
    """成功登录后清除对应来源和账号的失败记录。"""

    with LOGIN_FAILURES_LOCK:
        for rate_key in [key, (key[0], "*"), ("*", key[1])]:
            LOGIN_FAILURES.pop(rate_key, None)


def cookie_should_be_secure(request: Request) -> bool:
    """按显式配置或请求协议决定会话 Cookie 是否仅通过 HTTPS 发送。"""

    configured = settings.web_cookie_secure.strip().lower()
    if configured in {"1", "true", "yes", "on"}:
        return True
    if configured in {"0", "false", "no", "off"}:
        return False
    forwarded_https = (
        request_direct_peer_is_trusted(request)
        and request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https"
    )
    return request.url.scheme == "https" or forwarded_https


def set_web_session_cookie(response: Response, request: Request, token: str) -> None:
    """写入 HttpOnly、SameSite=Strict 的 Web 会话 Cookie。"""

    response.set_cookie(
        WEB_SESSION_COOKIE,
        token,
        max_age=settings.web_session_absolute_seconds,
        httponly=True,
        secure=cookie_should_be_secure(request),
        samesite="strict",
        path="/",
    )


def clear_web_session_cookie(response: Response) -> None:
    """让浏览器立即删除 Web 会话 Cookie。"""

    response.delete_cookie(WEB_SESSION_COOKIE, path="/", httponly=True, samesite="strict")


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
        task_result = task.result if isinstance(task.result, dict) else {}
        query.result = task_result
        if task_result.get("error_code"):
            query.status = "failed"
            query.error_code = str(task_result.get("error_code"))
            query.error_message = str(task_result.get("error") or "查询执行失败")[:500]
        else:
            query.status = "succeeded"
            query.error_code = None
            query.error_message = None
    elif task.status in {"failed", "cancelled"}:
        result = task.result if isinstance(task.result, dict) else {}
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
        if (
            request.method not in {"GET", "HEAD", "OPTIONS"}
            and request_uses_cookie_session(request)
            and request.headers.get(WEB_CSRF_HEADER) != "1"
        ):
            response = JSONResponse(status_code=403, content={"detail": "CSRF validation failed"})
            return add_security_headers(request, response)
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
            response = JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
            return add_security_headers(request, response)
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
    return add_security_headers(request, response)


def add_security_headers(request: Request, response: Response) -> Response:
    """为浏览器响应增加 CSP 和常用纵深防御响应头。"""

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
        "script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: http: https:; "
        "font-src 'self' data:; connect-src 'self'",
    )
    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    if request.url.path.startswith(("/api/", LOOKING_GLASS_API_PREFIX)):
        response.headers.setdefault("Cache-Control", "no-store")
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
    now = datetime.utcnow()
    # `online` is derived from the heartbeat timestamp and cannot be expressed
    # reliably as a simple SQL predicate. Scan ordered batches until we have
    # enough matching rows; limiting before filtering would make a sparse
    # region/status page appear empty even when later nodes match.
    filtered_nodes: list[models.Node] = []
    scan_cursor = cursor_id
    batch_size = min(500, max(limit + 1, 100))
    while len(filtered_nodes) <= limit:
        query = (
            select(models.Node)
            .where(models.Node.id > scan_cursor)
            .order_by(models.Node.id)
            .limit(batch_size)
        )
        if region is not None:
            query = query.where(models.Node.region == region)
        batch = list(db.scalars(query))
        if not batch:
            break
        scan_cursor = batch[-1].id
        for node in batch:
            node_online = is_node_online(node, now=now)
            if online is not None and node_online != online:
                continue
            filtered_nodes.append(node)
            if len(filtered_nodes) > limit:
                break
        if len(batch) < batch_size:
            break
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
    # Serialize admission for this node before checking the queue length.  A
    # plain count followed by an insert lets concurrent workers all observe
    # the same free slots and exceed LOOKING_GLASS_QUERY_QUEUE_LIMIT.  The
    # no-op update takes a row/write lock (including SQLite's writer lock)
    # for the rest of this transaction, so the next admission sees the task
    # committed by the previous worker.
    db.execute(
        update(models.Node)
        .where(models.Node.id == node_id)
        .values(updated_at=models.Node.updated_at)
    )
    fingerprint = looking_glass_request_fingerprint(api_key.id, node_id, operation, fingerprint_value)
    reusable_query = db.scalar(
        select(models.LookingGlassQuery)
        .where(
            models.LookingGlassQuery.api_key_id == api_key.id,
            models.LookingGlassQuery.node_id == node_id,
            models.LookingGlassQuery.request_fingerprint == fingerprint,
            or_(
                models.LookingGlassQuery.status.in_(["queued", "running"]),
                (models.LookingGlassQuery.status == "succeeded")
                & (models.LookingGlassQuery.created_at >= now - LOOKING_GLASS_CACHE_WINDOW),
            ),
        )
        .order_by(models.LookingGlassQuery.id.desc())
    )
    if reusable_query is not None:
        refresh_looking_glass_query_from_task(reusable_query, now=now)
        if reusable_query.status in {"queued", "running"} or (
            reusable_query.status == "succeeded"
            and reusable_query.created_at >= now - LOOKING_GLASS_CACHE_WINDOW
        ):
            db.commit()
            response.status_code = 202
            response.headers["Location"] = f"{LOOKING_GLASS_API_PREFIX}/queries/{reusable_query.public_id}"
            response.headers["Retry-After"] = "1"
            return looking_glass_query_read(reusable_query)
        db.flush()
    expire_overdue_pending_agent_tasks(db, node_id=node_id, now=now)
    expire_stale_running_agent_tasks(db, node_id=node_id, now=now)
    queued_count = db.scalar(
        select(func.count(models.AgentTask.id)).where(
            models.AgentTask.node_id == node_id,
            models.AgentTask.queue == "query",
            models.AgentTask.status.in_(["pending", "running"]),
        )
    )
    if int(queued_count or 0) >= LOOKING_GLASS_QUERY_QUEUE_LIMIT:
        raise api_error(429, "query_queue_full", "节点查询队列已满，请稍后重试")
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
    query_record = models.LookingGlassQuery(
        public_id=looking_glass_query_public_id(),
        api_key_id=api_key.id,
        node_id=node_id,
        operation=operation,
        request=request_payload,
        request_fingerprint=fingerprint,
        status="queued",
        deadline_at=deadline_at,
        expires_at=expires_at,
    )
    try:
        # 查询记录的部分唯一索引负责跨进程仲裁相同请求；任务和查询必须在
        # 同一个 savepoint 中写入，避免唯一键冲突后留下孤儿 AgentTask。
        with db.begin_nested():
            db.add(task)
            db.flush()
            query_record.agent_task_id = task.id
            db.add(query_record)
            db.flush()
    except IntegrityError:
        reusable_query = db.scalar(
            select(models.LookingGlassQuery)
            .where(
                models.LookingGlassQuery.api_key_id == api_key.id,
                models.LookingGlassQuery.node_id == node_id,
                models.LookingGlassQuery.request_fingerprint == fingerprint,
                or_(
                    models.LookingGlassQuery.status.in_(["queued", "running"]),
                    (models.LookingGlassQuery.status == "succeeded")
                    & (models.LookingGlassQuery.created_at >= now - LOOKING_GLASS_CACHE_WINDOW),
                ),
            )
            .order_by(models.LookingGlassQuery.id.desc())
        )
        if reusable_query is None:
            raise
        refresh_looking_glass_query_from_task(reusable_query, now=now)
        db.commit()
        response.status_code = 202
        response.headers["Location"] = f"{LOOKING_GLASS_API_PREFIX}/queries/{reusable_query.public_id}"
        response.headers["Retry-After"] = "1"
        return looking_glass_query_read(reusable_query)
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
        "Link42 主控启动 version=%s database=%s config_dir=%s web_dist_dir=%s log_level=%s",
        CONTROLLER_VERSION,
        database_target_for_log(),
        settings.config_dir,
        settings.web_dist_dir,
        settings.log_level,
    )
    sqlite_path = sqlite_database_path()
    database_existed = sqlite_path is None or sqlite_path.exists()
    previous_version = controller_version_in_database() if database_existed else None
    backup_path = None
    load_master_key()
    if database_existed and previous_version != CONTROLLER_VERSION:
        from .database import backup_sqlite_database_for_upgrade

        backup_path = backup_sqlite_database_for_upgrade()
        if backup_path:
            protected_backup_count = protect_sqlite_sensitive_values(backup_path)
            logger.info(
                "升级前数据库备份完成 path=%s previous_version=%s current_version=%s protected=%s",
                backup_path,
                previous_version,
                CONTROLLER_VERSION,
                protected_backup_count,
            )
    init_db()
    protected_count = protect_sensitive_database_values()
    if protected_count:
        logger.warning("敏感数据库字段迁移完成 count=%s", protected_count)
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


def touch_node_heartbeat(node: models.Node, now: datetime | None = None) -> datetime:
    """统一更新 Agent 入口的在线状态和最近上报时间。"""

    current_time = now or datetime.utcnow()
    node.status = "online"
    node.last_seen_at = current_time
    return current_time


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
    # Agent 每次注册/心跳都会完整上报能力列表；空列表也必须覆盖旧值，
    # 否则 Agent 降级或插件卸载后主控仍会把任务派给已不存在的能力。
    if capabilities is not None:
        node.agent_capabilities = sorted(set(capabilities))
        if "middleware.mimic" in set(capabilities):
            node.middleware_install_status = "mimic_ready"
        elif node.middleware_install_status == "mimic_ready":
            node.middleware_install_status = None
    if platform is not None:
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
    capabilities = set(node.agent_capabilities or [])
    # 尚未注册过的旧节点没有能力快照，保留第一版 WireGuard 兼容默认值；
    # 已注册 Agent 即使上报空列表也必须按空列表处理。
    if node.agent_version is None:
        capabilities.update({"wireguard", "wg_quick_import"})
    return all(capability in capabilities for capability in requirement.get("capabilities", []))


def node_uses_openwrt_uci(node: models.Node | None) -> bool:
    """判断节点是否使用 OpenWrt UCI WireGuard 后端。"""

    if node is None:
        return False
    platform = json_object(node.agent_platform)
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
    candidates = list(db.scalars(query.order_by(models.AgentTask.id)))
    expired = 0
    affected_plan_ids: set[int] = set()
    for task in candidates:
        updated = db.execute(
            update(models.AgentTask)
            .where(models.AgentTask.id == task.id, models.AgentTask.status == "running")
            .values(status="failed", finished_at=now, result={
                "error": f"agent task timed out after {int(AGENT_TASK_RUNNING_TIMEOUT.total_seconds())} seconds",
                "timeout_seconds": int(AGENT_TASK_RUNNING_TIMEOUT.total_seconds()),
            })
            .execution_options(synchronize_session="fetch")
        )
        if updated.rowcount:
            expired += int(updated.rowcount)
            if task.change_plan_id is not None:
                affected_plan_ids.add(task.change_plan_id)
    for plan_id in affected_plan_ids:
        plan = db.get(models.ChangePlan, plan_id)
        if plan is not None:
            update_change_plan_task_status(db, plan)
    if expired:
        logger.warning(
            "回收超时 Agent 任务 node_id=%s count=%d",
            node_id,
            expired,
        )
    return expired


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
    expired_ids: list[int] = []
    affected_plan_ids: set[int] = set()
    for task in tasks:
        updated = db.execute(
            update(models.AgentTask)
            .where(models.AgentTask.id == task.id, models.AgentTask.status == "pending", models.AgentTask.deadline_at <= now)
            .values(status="failed", finished_at=now, result={
                "error_code": "query_timeout" if task.queue == "query" else "task_timeout",
                "error": "task deadline expired before agent polling",
            })
            .execution_options(synchronize_session="fetch")
        )
        if updated.rowcount == 1:
            expired_ids.append(task.id)
            if task.change_plan_id is not None:
                affected_plan_ids.add(task.change_plan_id)
    for plan_id in affected_plan_ids:
        plan = db.get(models.ChangePlan, plan_id)
        if plan is not None:
            update_change_plan_task_status(db, plan)
    if expired_ids:
        logger.warning("回收过期待执行任务 node_id=%s count=%d task_ids=%s", node_id, len(expired_ids), expired_ids)
    return len(expired_ids)


def task_dependency_id(task: models.AgentTask) -> int | None:
    """读取任务 payload 中的依赖任务 ID。"""

    task_payload = task.payload if isinstance(task.payload, dict) else {}
    raw_value = task_payload.get("depends_on_task_id")
    if raw_value in (None, ""):
        return None
    try:
        dependency_id = int(raw_value)
    except (TypeError, ValueError):
        return None
    return dependency_id if dependency_id > 0 else None


def is_task_ready_for_poll(db: Session, task: models.AgentTask, now: datetime) -> bool:
    """判断 pending 任务的依赖是否已满足；依赖失败时同步标记失败。"""

    def fail_dependency(result: dict[str, Any]) -> bool:
        """持久化依赖失败，并立即同步部署计划聚合状态。"""

        task.status = "failed"
        task.finished_at = now
        task.result = result
        db.flush()
        if task.change_plan_id is not None:
            plan = db.get(models.ChangePlan, task.change_plan_id)
            if plan is not None:
                update_change_plan_task_status(db, plan)
        return False

    dependency_id = task_dependency_id(task)
    if dependency_id is None:
        return True
    dependency = db.get(models.AgentTask, dependency_id)
    if dependency is None:
        result = {
            "error": f"dependency task {dependency_id} was not found",
            "dependency_task_id": dependency_id,
        }
        logger.warning("Agent 任务依赖不存在 task_id=%s dependency_task_id=%s", task.id, dependency_id)
        return fail_dependency(result)
    if dependency.node_id != task.node_id:
        result = {
            "error": f"dependency task {dependency_id} belongs to another node",
            "dependency_task_id": dependency_id,
        }
        logger.warning("Agent 任务依赖跨节点 task_id=%s dependency_task_id=%s", task.id, dependency_id)
        return fail_dependency(result)
    # 依赖来自内部任务编排，但旧库或手工修复可能留下环。沿链检查有限深度，
    # 发现环或异常深链立即失败，避免 Agent 永久看不到这些任务。
    seen = {task.id}
    cursor = dependency
    for _ in range(MAX_AGENT_TASK_DEPENDENCY_DEPTH):
        if cursor.id in seen:
            result = {
                "error": "agent task dependency cycle detected",
                "dependency_task_id": dependency_id,
            }
            logger.warning("Agent 任务依赖形成环 task_id=%s dependency_task_id=%s", task.id, dependency_id)
            return fail_dependency(result)
        seen.add(cursor.id)
        next_id = task_dependency_id(cursor)
        if next_id is None:
            break
        cursor = db.get(models.AgentTask, next_id)
        if cursor is None:
            result = {
                "error": f"dependency task {next_id} was not found",
                "dependency_task_id": dependency_id,
            }
            logger.warning("Agent 任务依赖链断裂 task_id=%s dependency_task_id=%s", task.id, dependency_id)
            return fail_dependency(result)
        if cursor.node_id != task.node_id:
            result = {
                "error": f"dependency task {next_id} belongs to another node",
                "dependency_task_id": dependency_id,
            }
            logger.warning("Agent 任务依赖链跨节点 task_id=%s dependency_task_id=%s", task.id, dependency_id)
            return fail_dependency(result)
    else:
        result = {
            "error": "agent task dependency chain is too deep",
            "dependency_task_id": dependency_id,
        }
        logger.warning("Agent 任务依赖链过深 task_id=%s dependency_task_id=%s", task.id, dependency_id)
        return fail_dependency(result)
    # 停止任务只需等待前序部署结束；即使启动失败，也必须允许清理
    # 可能已部分创建的设备。普通 apply/start/delete 仍要求依赖成功。
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    continue_after_failure = (
        task.type in {
            WIREGUARD_TASKS.stop,
            GRE_TASKS.stop,
            "middleware.udp2raw.delete",
            "middleware.mimic.delete",
        }
        and task_payload.get("continue_after_dependency_failure") is True
    )
    if dependency.status == "succeeded" or (
        continue_after_failure and dependency.status in {"failed", "cancelled"}
    ):
        return True
    if dependency.status in {"failed", "cancelled"}:
        result = {
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
        return fail_dependency(result)
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


def agent_task_error_summary(result: dict, _depth: int = 0) -> str | None:
    """从 Agent 任务结果中提取适合展示给用户的失败摘要。"""

    for key in ["error", "message", "stderr", "stdout"]:
        value = str(result.get(key) or "").strip()
        if value:
            return value[:500]
    if _depth >= 12:
        return None
    for value in result.values():
        if isinstance(value, dict):
            nested = agent_task_error_summary(value, _depth=_depth + 1)
            if nested:
                return nested
    return None


def validate_agent_result_json(value: Any, *, _depth: int = 0, _budget: list[int] | None = None) -> None:
    """限制 Agent 结果 JSON 的深度和节点数，避免异常结果耗尽解析/序列化资源。"""

    budget = _budget if _budget is not None else [10000]
    budget[0] -= 1
    if budget[0] < 0 or _depth > 16:
        raise ValueError("agent task result is too deeply nested or too large")
    if isinstance(value, dict):
        if len(value) > 2000:
            raise ValueError("agent task result object has too many fields")
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 256 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in key):
                raise ValueError("agent task result field name is invalid")
            validate_agent_result_json(child, _depth=_depth + 1, _budget=budget)
        return
    if isinstance(value, list):
        if len(value) > 2000:
            raise ValueError("agent task result array has too many items")
        for child in value:
            validate_agent_result_json(child, _depth=_depth + 1, _budget=budget)
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > 1024 * 1024:
            raise ValueError("agent task result string is too large")
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if len(str(abs(value))) > 128:
            raise ValueError("agent task result integer is too large")
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("agent task result contains a non-finite number")
    if value is None or isinstance(value, (bool, int, float)):
        return
    raise ValueError("agent task result contains an unsupported value")


def normalize_agent_task_report(
    db: Session,
    task: models.AgentTask,
    status: str,
    result: dict,
) -> tuple[str, dict]:
    """把旧 Agent 的部分宽松结果规整成真实业务状态。"""

    if status != "succeeded":
        return status, result
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    interface_id = task_payload.get("interface_id")
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


def has_newer_interface_state_task(
    db: Session,
    interface_id: int,
    task_id: int,
    driver: Any,
) -> bool:
    """判断状态查询之后是否已有更新的接口状态任务。"""

    return db.scalar(
        select(models.AgentTask.id).where(
            models.AgentTask.id > task_id,
            models.AgentTask.payload["interface_id"].as_integer() == interface_id,
            models.AgentTask.type.in_([driver.tasks.apply_config, driver.tasks.start, driver.tasks.stop]),
            models.AgentTask.status != "cancelled",
        ).limit(1)
    ) is not None


def has_newer_endpoint_state_task(
    db: Session,
    endpoint_id: int,
    task_id: int,
) -> bool:
    """判断 GRE 状态查询之后是否已有更新的配置任务。"""

    return db.scalar(
        select(models.AgentTask.id).where(
            models.AgentTask.id > task_id,
            models.AgentTask.payload["connection_endpoint_id"].as_integer() == endpoint_id,
            models.AgentTask.type.in_([GRE_TASKS.apply_config, GRE_TASKS.start, GRE_TASKS.stop]),
            models.AgentTask.status != "cancelled",
        ).limit(1)
    ) is not None


def should_clear_previous_interface_name(db: Session, task: models.AgentTask, result: dict) -> bool:
    """确认旧接口清理链路成功后才清除 previous_interface_name 标记。"""

    task_payload = task.payload if isinstance(task.payload, dict) else {}
    previous_interface_name = str(task_payload.get("previous_interface_name") or "").strip()
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

    release_root = agent_release_dir()
    try:
        reject_symlink_components(release_root)
    except HTTPException:
        raise
    manifest_path = release_root / "manifest.json"
    if not manifest_path.exists():
        return {"latest": None, "minimum_supported": None, "releases": {}}
    try:
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise HTTPException(status_code=500, detail="invalid agent release manifest")
        if manifest_path.stat().st_size > AGENT_RELEASE_MANIFEST_MAX_BYTES:
            raise HTTPException(status_code=500, detail="agent release manifest is too large")
    except OSError as exc:
        raise HTTPException(status_code=500, detail="invalid agent release manifest") from exc
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="invalid agent release manifest") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail="invalid agent release manifest")
    try:
        # 在所有使用方之前统一校验路径、摘要、大小和安装模式，避免
        # download/upgrade-plan 对同一份损坏 manifest 产生不一致行为。
        return schemas.AgentReleaseManifest.model_validate(data).model_dump(mode="python")
    except ValidationError as exc:
        raise HTTPException(status_code=500, detail="invalid agent release manifest") from exc


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

    platform = json_object(node.agent_platform)
    os_name = str(platform.get("os") or "linux").lower()
    arch = normalize_agent_arch(str(platform.get("arch") or "")) or "x64"
    glibc = platform.get("glibc")
    service_manager = str(platform.get("service_manager") or "").lower()
    candidates: list[str] = []
    if service_manager == "openwrt-uci":
        candidates.append("openwrt-source")
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


def resolve_agent_release_asset_path(asset: dict, *, missing_status: int = 404) -> Path:
    """解析并检查 release 资产路径，禁止逃逸和符号链接组件。"""

    release_root = agent_release_dir()
    reject_symlink_components(release_root)
    relative_path = Path(str(asset.get("path") or ""))
    path = release_root / relative_path
    try:
        path.resolve().relative_to(release_root.resolve())
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="invalid agent release asset path") from exc
    try:
        reject_symlink_components(path.parent)
        if path.is_symlink() or not path.exists() or not path.is_file():
            raise HTTPException(status_code=missing_status, detail="agent release asset file not found")
    except OSError as exc:
        raise HTTPException(status_code=missing_status, detail="agent release asset file not found") from exc
    return path


def controller_url_for_agent(db: Session) -> str:
    """返回 Agent 访问主控时应使用的 URL。"""

    return (get_setting(db, SETTING_CONTROLLER_URL) or "").rstrip("/")


def build_agent_manual_upgrade_command(node: models.Node, target_version: str | None, db: Session) -> str:
    """生成旧 Agent 可执行的覆盖安装命令。"""

    env_values = {
        "LINK42_AGENT_VERSION": target_version or "latest",
        "LINK42_RES_BASE_URL": settings.agent_res_base_url,
    }
    env_parts = [f"{key}={shlex.quote(value)}" for key, value in env_values.items()]
    privilege_prefix = "" if str(json_object(node.agent_platform).get("service_manager") or "") == "openwrt-uci" else "sudo "
    return f"curl -fsSL {shlex.quote(settings.agent_install_script_url)} | {privilege_prefix}env {' '.join(env_parts)} sh"


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
    expected_install_mode = "source" if node_uses_openwrt_uci(node) else "binary"
    if str(asset.get("install_mode") or "binary") != expected_install_mode:
        return schemas.AgentUpgradePlan(
            node_id=node.id,
            current_version=node.agent_version,
            target_version=selected_version,
            upgrade_mode="manual",
            reason="主控发布资产与节点服务后端不匹配",
            manual_command=manual_command,
            status=node.agent_update_status,
        )
    try:
        resolve_agent_release_asset_path(asset)
    except HTTPException:
        return schemas.AgentUpgradePlan(
            node_id=node.id,
            current_version=node.agent_version,
            target_version=selected_version,
            upgrade_mode="manual",
            reason="主控缺少目标版本 Agent 资产文件",
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
        "auth_mode": payload.auth_mode,
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

    middleware = json_object(interface.extras).get("middleware")
    return middleware if isinstance(middleware, dict) and middleware.get("enabled") else None


def require_udp2raw_supported(node: models.Node) -> None:
    """要求节点 Agent 支持 udp2raw 中间层。"""

    for task_type in ["middleware.install", "middleware.udp2raw.apply"]:
        require_task_supported(node, task_type)


def require_udp2raw_mode_supported(node: models.Node, raw_mode: str) -> None:
    """要求节点 Agent 支持所选 udp2raw 传输模式。"""

    require_udp2raw_supported(node)
    if raw_mode == "icmp" and "middleware.udp2raw.icmp" not in set(node.agent_capabilities or []):
        raise HTTPException(status_code=409, detail="agent does not support udp2raw ICMP mode")


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


def validate_udp2raw_port_conflicts(
    middleware: dict | None,
    local_listen_port: int | None,
    peer_listen_port: int | None,
) -> None:
    """校验 udp2raw 与同机 WireGuard 不会占用冲突的 UDP 端口。"""

    if not middleware or middleware.get("type") != "udp2raw":
        return
    server_side = str(middleware.get("server_side") or "peer")
    server_wireguard_port = local_listen_port if server_side == "local" else peer_listen_port
    client_wireguard_port = peer_listen_port if server_side == "local" else local_listen_port
    if server_wireguard_port is None:
        raise HTTPException(status_code=400, detail="udp2raw server side requires WireGuard listen port")
    if client_wireguard_port == middleware.get("client_listen_port"):
        raise HTTPException(
            status_code=400,
            detail="udp2raw client listen port conflicts with WireGuard listen port on the same node",
        )
    if middleware.get("raw_mode") == "udp" and server_wireguard_port == middleware.get("server_listen_port"):
        raise HTTPException(
            status_code=400,
            detail="udp2raw UDP server port conflicts with WireGuard listen port on the same node",
        )


def parse_kernel_major_minor(value: object) -> tuple[int, int]:
    """从平台上报的内核版本字符串中解析 major/minor。"""

    match = re.match(r"(\d+)\.(\d+)", str(value or ""))
    if not match:
        return (0, 0)
    return (int(match.group(1)), int(match.group(2)))


def node_supports_mimic_platform(node: models.Node) -> tuple[bool, str | None]:
    """判断节点平台是否满足 mimic 的系统、init 和内核要求。"""

    platform = json_object(node.agent_platform)
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
    outer_ip_version = ipaddress.ip_address(server_connect_host).version
    server_listen_host = require_udp2raw_ip(
        middleware.get("server_listen_host") or ("::" if outer_ip_version == 6 else "0.0.0.0"),
        "udp2raw server listen host",
    )
    listen_ip = ipaddress.ip_address(server_listen_host)
    if listen_ip.is_unspecified:
        server_listen_host = server_connect_host if middleware.get("raw_mode") == "icmp" else (
            "::" if outer_ip_version == 6 else "0.0.0.0"
        )
    elif listen_ip.version != outer_ip_version:
        raise HTTPException(status_code=400, detail="udp2raw server listen address must match outer IP version")
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
        "auth_mode": middleware.get("auth_mode") or "md5",
        "password": middleware["password"],
        "auto_rule": middleware["auto_rule"],
    }
    server_payload = {
        **common,
        "mode": "server",
        "listen_host": server_listen_host,
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
            require_udp2raw_mode_supported(node, str(middleware.get("raw_mode") or "faketcp"))
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
    stop_tasks: dict[int, models.AgentTask] = {}
    for interface, task_type, payload in middleware_task_payloads(
        old_middleware,
        local_interface,
        peer_interface,
        "stop",
    ):
        _, stop_task = enqueue_interface_task_once_with_task(
            db,
            interface,
            task_type,
            payload,
            update_pending_payload=True,
        )
        if stop_task is not None:
            stop_tasks[interface.id] = stop_task
    for interface, task_type, payload in middleware_task_payloads(
        old_middleware,
        local_interface,
        peer_interface,
        "delete",
    ):
        dependency = stop_tasks.get(interface.id)
        delete_payload = {**payload}
        if dependency is not None:
            delete_payload["depends_on_task_id"] = dependency.id
            delete_payload["continue_after_dependency_failure"] = True
        enqueue_interface_task_once(
            db,
            interface,
            task_type,
            delete_payload,
            update_pending_payload=True,
        )


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

    extras = json_object(model.extras).copy()
    cleaned = value.strip() if value else None
    if cleaned:
        extras[key] = cleaned
    else:
        extras.pop(key, None)
    model.extras = extras


def set_extra_object(model: models.WireGuardInterface | models.WireGuardPeer, key: str, value: dict | None) -> None:
    """在 JSON extras 中保存对象扩展字段。"""

    extras = json_object(model.extras).copy()
    if value:
        extras[key] = value
    else:
        extras.pop(key, None)
    model.extras = extras


def record_interface_rename(interface: models.WireGuardInterface, next_name: str) -> None:
    """记录尚未在节点上清理的旧接口名，供下一次部署时迁移。"""

    if interface.name == next_name:
        return
    previous_name = json_object(interface.extras).get("previous_interface_name")
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


def delete_link_monitors_where(db: Session, *criteria: Any) -> tuple[int, int]:
    """按条件集合删除链路监测及历史样本，避免 ORM 逐条加载大量样本。"""

    if not criteria:
        raise ValueError("link monitor deletion criteria must not be empty")
    monitor_ids = select(models.LinkMonitor.id).where(*criteria)
    sample_result = db.execute(
        delete(models.LinkMonitorSample).where(models.LinkMonitorSample.monitor_id.in_(monitor_ids)),
        execution_options={"synchronize_session": False},
    )
    monitor_result = db.execute(
        delete(models.LinkMonitor).where(*criteria),
        execution_options={"synchronize_session": False},
    )
    sample_count = max(sample_result.rowcount or 0, 0)
    monitor_count = max(monitor_result.rowcount or 0, 0)
    if monitor_count or sample_count:
        logger.info("批量删除链路监测 monitor_count=%d sample_count=%d", monitor_count, sample_count)
    return monitor_count, sample_count


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
            .order_by(models.LinkMonitorSample.checked_at.desc())
            .limit(LINK_MONITOR_SAMPLE_LIMIT)
        )
    )
    samples.sort(key=lambda sample: sample.checked_at)
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
    extras = json_object(endpoint.extras)
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
        protocol_config=json_object(endpoint.protocol_config),
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
    manual_connection = len(endpoints) == 1
    endpoint_errors = [
        f"{endpoint.node.name if endpoint.node else endpoint.interface_name}: {str(json_object(endpoint.extras).get('last_error') or '').strip()}"
        for endpoint in endpoints
        if str(json_object(endpoint.extras).get("last_error") or "").strip()
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
        warnings=(["此 GRE 连接仅管理当前节点，对端配置需要在外部设备上自行维护"] if manual_connection else []) + [
            "GRE 不加密，请勿直接承载敏感流量",
            "GRE 需要底层网络放行 GRE（协议/下一头部 47）；普通 IPv4 NAT 通常不可用，IPv6 需要端到端可达",
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


def require_gre_supported(node: models.Node, outer_ip_version: int = 4) -> None:
    """要求节点 Agent 支持指定外层地址族的 GRE 连接任务。"""

    require_task_supported(node, GRE_TASKS.apply_config)
    if outer_ip_version == 6 and "gre.ipv6.encaplimit" not in (node.agent_capabilities or []):
        raise HTTPException(status_code=409, detail="agent does not support GRE over IPv6 encaplimit control")


def gre_outer_ip_version(values: list[str | None]) -> int:
    """校验 GRE 外层地址全部同族并返回地址版本。"""

    versions = {ipaddress.ip_address(value).version for value in values if value}
    if len(versions) != 1:
        raise HTTPException(status_code=400, detail="gre outer addresses must use the same IP version")
    return versions.pop()


def gre_effective_mtu(mtu: int | None, outer_ip_version: int) -> int:
    """返回 GRE 显式 MTU，未填写时按外层地址族使用推荐值。"""

    return mtu if mtu is not None else (1456 if outer_ip_version == 6 else 1476)


def validate_gre_payload(payload: schemas.GreManagedConnectionCreate | schemas.GreManagedConnectionUpdate) -> None:
    """执行跨字段 GRE 业务校验。"""

    if not payload.risk_accepted:
        raise HTTPException(status_code=400, detail="gre risk must be accepted")
    if payload.local_outer_ip == payload.peer_outer_ip:
        raise HTTPException(status_code=400, detail="gre outer addresses must be different")
    outer = gre_outer_mapping(payload)
    outer_version = gre_outer_ip_version(list(outer.values()))
    if outer["local_bind_ip"] == outer["local_remote_ip"] or outer["peer_bind_ip"] == outer["peer_remote_ip"]:
        raise HTTPException(status_code=400, detail="gre endpoint local and remote addresses must be different")
    if outer_version == 4 and payload.ttl is not None and not payload.pmtudisc:
        raise HTTPException(status_code=400, detail="gre ttl requires pmtu discovery")
    if outer_version == 4 and payload.encaplimit is not None:
        raise HTTPException(status_code=400, detail="encaplimit is only supported by GRE over IPv6")


def validate_manual_gre_payload(
    payload: schemas.GreManualConnectionCreate | schemas.GreManualConnectionUpdate,
) -> None:
    """执行手动单端 GRE 的跨字段业务校验。"""

    if not payload.risk_accepted:
        raise HTTPException(status_code=400, detail="gre risk must be accepted")
    if payload.outer_local_ip == payload.outer_remote_ip:
        raise HTTPException(status_code=400, detail="gre endpoint local and remote addresses must be different")
    outer_version = gre_outer_ip_version([payload.outer_local_ip, payload.outer_remote_ip])
    if outer_version == 4 and payload.ttl is not None and not payload.pmtudisc:
        raise HTTPException(status_code=400, detail="gre ttl requires pmtu discovery")
    if outer_version == 4 and payload.encaplimit is not None:
        raise HTTPException(status_code=400, detail="encaplimit is only supported by GRE over IPv6")


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
        "encaplimit": payload.encaplimit,
    }


def manual_gre_protocol_config(
    payload: schemas.GreManualConnectionCreate | schemas.GreManualConnectionUpdate,
) -> dict[str, Any]:
    """生成手动单端 GRE 的协议配置和外部对端备注。"""

    return {
        "outer_local_ip": payload.outer_local_ip,
        "outer_remote_ip": payload.outer_remote_ip,
        "key": payload.gre_key,
        "ttl": payload.ttl,
        "pmtudisc": payload.pmtudisc,
        "encaplimit": payload.encaplimit,
        "peer_interface_name": payload.peer_interface_name,
        "peer_tunnel_ips": payload.peer_tunnel_ips,
    }


def gre_task_payload(endpoint: models.ConnectionEndpoint) -> dict[str, Any]:
    """把 GRE 端点转换为 Agent 任务 payload。"""

    previous_interface_name = str(json_object(endpoint.extras).get("previous_interface_name") or "").strip()
    payload = {
        "node_id": endpoint.node_id,
        "connection_id": endpoint.connection_id,
        "connection_endpoint_id": endpoint.id,
        "interface_name": endpoint.interface_name,
        "tunnel_ips": endpoint.tunnel_ips or [],
        "routes": endpoint.routes or [],
        "mtu": endpoint.mtu,
        **json_object(endpoint.protocol_config),
    }
    if previous_interface_name and previous_interface_name != endpoint.interface_name:
        payload["previous_interface_name"] = previous_interface_name
    payload["ipam_owner"] = ipam.config_owner(endpoint)
    return payload


def create_connection_endpoint_task(
    db: Session,
    endpoint: models.ConnectionEndpoint,
    task_type: str,
    payload_extra: dict | None = None,
    *,
    update_pending_payload: bool = False,
    queue_after_running: bool = False,
) -> models.AgentTask:
    """创建通用连接端点 Agent 任务。"""

    node = db.get(models.Node, endpoint.node_id)
    if node is not None:
        require_task_supported(node, task_type)
    payload = gre_task_payload(endpoint)
    if payload_extra:
        payload.update(payload_extra)
    existing = db.scalar(
        select(models.AgentTask)
        .where(
            models.AgentTask.type == task_type,
            models.AgentTask.status == "pending",
            models.AgentTask.payload["connection_endpoint_id"].as_integer() == endpoint.id,
        )
        .order_by(models.AgentTask.id)
    )
    if existing is not None:
        if not update_pending_payload:
            return existing
        refreshed = db.execute(
            update(models.AgentTask)
            .where(models.AgentTask.id == existing.id, models.AgentTask.status == "pending")
            .values(payload=payload)
            .execution_options(synchronize_session="fetch")
        )
        if refreshed.rowcount == 1:
            return existing
        db.refresh(existing)
    running = db.scalar(
        select(models.AgentTask)
        .where(
            models.AgentTask.type == task_type,
            models.AgentTask.status == "running",
            models.AgentTask.payload["connection_endpoint_id"].as_integer() == endpoint.id,
        )
        .order_by(models.AgentTask.id.desc())
    )
    if running is not None:
        if not queue_after_running:
            return running
        payload.setdefault("depends_on_task_id", running.id)
    task = models.AgentTask(node_id=endpoint.node_id, type=task_type, payload=payload)
    task.dedup_key = f"endpoint:{endpoint.id}:{task_type}"
    try:
        with db.begin_nested():
            db.add(task)
            db.flush()
    except IntegrityError:
        existing = db.scalar(
            select(models.AgentTask)
            .where(
                models.AgentTask.dedup_key == f"endpoint:{endpoint.id}:{task_type}",
                models.AgentTask.status == "pending",
            )
            .order_by(models.AgentTask.id)
        )
        if existing is None:
            raise
        if update_pending_payload:
            db.execute(
                update(models.AgentTask)
                .where(models.AgentTask.id == existing.id, models.AgentTask.status == "pending")
                .values(payload=payload)
                .execution_options(synchronize_session="fetch")
            )
        return existing
    logger.info("创建连接端点任务 task=%s", summarize_agent_task(task))
    return task


def enqueue_gre_apply_and_start(db: Session, endpoint: models.ConnectionEndpoint) -> None:
    """为 GRE 端点下发部署并启动任务。"""

    # 已领取任务的 payload 是执行快照；编辑时更新待执行任务或在其后排队，
    # 不能复用旧 apply/start 后仅保存数据库期望状态。
    running = db.scalar(
        select(models.AgentTask)
        .where(
            models.AgentTask.payload["connection_endpoint_id"].as_integer() == endpoint.id,
            models.AgentTask.status == "running",
            models.AgentTask.type.in_([GRE_TASKS.apply_config, GRE_TASKS.start, GRE_TASKS.stop]),
        )
        .order_by(models.AgentTask.id.desc())
    )
    apply_task = create_connection_endpoint_task(
        db, endpoint, GRE_TASKS.apply_config,
        {"depends_on_task_id": running.id} if running is not None else None,
        update_pending_payload=True, queue_after_running=True,
    )
    create_connection_endpoint_task(
        db,
        endpoint,
        GRE_TASKS.start,
        {"depends_on_task_id": apply_task.id},
        update_pending_payload=True, queue_after_running=True,
    )
    endpoint.runtime_status = "starting"


def cancel_pending_gre_deployment_tasks(db: Session, endpoint_id: int) -> int:
    """停止或删除时取消尚未领取的 GRE 部署链，避免旧任务重新拉起接口。"""

    tasks = list(
        db.scalars(
            select(models.AgentTask).where(
                models.AgentTask.payload["connection_endpoint_id"].as_integer() == endpoint_id,
                models.AgentTask.type.in_([GRE_TASKS.apply_config, GRE_TASKS.start]),
                models.AgentTask.status == "pending",
            )
        )
    )
    affected_plan_ids = {task.change_plan_id for task in tasks if task.change_plan_id is not None}
    cancelled = db.execute(
        update(models.AgentTask)
        .where(
            models.AgentTask.payload["connection_endpoint_id"].as_integer() == endpoint_id,
            models.AgentTask.type.in_([GRE_TASKS.apply_config, GRE_TASKS.start]),
            models.AgentTask.status == "pending",
        )
        .values(
            status="cancelled",
            finished_at=datetime.utcnow(),
            result={"reason": "GRE deployment superseded by stop or delete"},
        )
        .execution_options(synchronize_session="fetch")
    )
    for plan_id in affected_plan_ids:
        plan = db.get(models.ChangePlan, plan_id)
        if plan is not None:
            update_change_plan_task_status(db, plan)
    return cancelled.rowcount


def running_gre_deployment_task_id(db: Session, endpoint_id: int) -> int | None:
    """返回端点当前正在执行的部署或启动任务，供停止任务建立顺序依赖。"""

    task = db.scalar(
        select(models.AgentTask)
        .where(
            models.AgentTask.payload["connection_endpoint_id"].as_integer() == endpoint_id,
            models.AgentTask.type.in_([GRE_TASKS.apply_config, GRE_TASKS.start]),
            models.AgentTask.status == "running",
        )
        .order_by(models.AgentTask.id.desc())
    )
    return task.id if task is not None else None


def set_endpoint_extra_value(endpoint: models.ConnectionEndpoint, key: str, value: str | None) -> None:
    """在连接端点 extras 中写入或清理字符串值。"""

    extras = json_object(endpoint.extras).copy()
    cleaned = value.strip() if value else None
    if cleaned:
        extras[key] = cleaned
    else:
        extras.pop(key, None)
    endpoint.extras = extras


def gre_previous_config_cleanup_confirmed(task: models.AgentTask, result: dict) -> bool:
    """判断 GRE 启动任务是否已经确认清理过旧接口配置。"""

    task_payload = task.payload if isinstance(task.payload, dict) else {}
    previous_interface_name = str(task_payload.get("previous_interface_name") or "").strip()
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
    previous_name = json_object(endpoint.extras).get("previous_interface_name")
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
                agent_platform=json_object(node.agent_platform),
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
        if payload.preshared_key:
            existing_peer.preshared_key_ref = "local-db"
            existing_peer.preshared_key_value = payload.preshared_key
        elif payload.clear_preshared_key:
            existing_peer.preshared_key_ref = None
            existing_peer.preshared_key_value = None
        existing_peer.endpoint_host = payload.endpoint_host
        existing_peer.endpoint_port = payload.endpoint_port
        existing_peer.allowed_ips = payload.allowed_ips
        existing_peer.persistent_keepalive = payload.persistent_keepalive
        existing_peer.enabled = True
        set_extra_value(existing_peer, "custom_config", payload.peer_custom_config)
        for extra_peer in existing_peers[1:]:
            db.delete(extra_peer)
        commit_unique_or_conflict(db, "wireguard peer already exists")
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
    commit_unique_or_conflict(db, "wireguard peer already exists")
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
    payload["ipam_owner"] = ipam.config_owner(interface)
    return models.AgentTask(
        node_id=interface.node_id,
        change_plan_id=change_plan_id,
        type=task_type,
        payload=payload,
    )


def interface_task_dedup_key(interface_id: int, task_type: str) -> str:
    """返回接口任务的数据库级幂等键。"""

    return f"interface:{interface_id}:{task_type}"


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
    # 查询后再插入无法阻止并发请求同时看到空结果；数据库部分唯一索引负责最终仲裁。
    # 索引仅约束 pending；queue_after_running 允许跟在运行中任务后再排队一次。
    task.dedup_key = interface_task_dedup_key(interface.id, task_type)
    try:
        with db.begin_nested():
            db.add(task)
            db.flush()
    except IntegrityError:
        # 只有幂等键冲突才应走这里；其它约束错误继续抛出，避免吞掉真实数据错误。
        if not task.dedup_key:
            raise
        existing = get_interface_task(db, interface.id, task_type, ["pending", "running"])
        if existing is None:
            raise
        if update_pending_payload and existing.status == "pending":
            existing.payload = task.payload
            return True, existing
        logger.debug("并发请求复用已创建接口任务 task=%s", summarize_agent_task(existing))
        return False, existing
    logger.info("创建接口任务 task=%s", summarize_agent_task(task))
    return True, task


def cancel_pending_interface_deployment_tasks(db: Session, interface: models.WireGuardInterface) -> int:
    """停止或删除时取消接口尚未领取的 apply/start 任务。"""

    cancelled = 0
    driver = connection_driver_for_interface(interface)
    for task_type in [driver.tasks.apply_config, driver.tasks.start]:
        cancelled += cancel_pending_interface_tasks(
            db,
            interface.id,
            task_type,
            "interface deployment superseded by stop or delete",
        )
    return cancelled


def running_interface_deployment_task_id(db: Session, interface: models.WireGuardInterface) -> int | None:
    """返回接口当前运行中的 apply/start 任务，供停止任务建立依赖。"""

    driver = connection_driver_for_interface(interface)
    task = db.scalar(
        select(models.AgentTask)
        .where(
            models.AgentTask.node_id == interface.node_id,
            models.AgentTask.type.in_([driver.tasks.apply_config, driver.tasks.start]),
            models.AgentTask.status == "running",
            models.AgentTask.payload["interface_id"].as_integer() == interface.id,
        )
        .order_by(models.AgentTask.id.desc())
    )
    return task.id if task is not None else None


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
    cancelled = 0
    affected_plan_ids: set[int] = set()
    for task in tasks:
        updated = db.execute(
            update(models.AgentTask)
            .where(models.AgentTask.id == task.id, models.AgentTask.status == "pending")
            .values(status="cancelled", result={"status": "cancelled", "reason": reason}, finished_at=now)
            .execution_options(synchronize_session="fetch")
        )
        if updated.rowcount:
            cancelled += int(updated.rowcount)
            if task.change_plan_id is not None:
                affected_plan_ids.add(task.change_plan_id)
    for plan_id in affected_plan_ids:
        plan = db.get(models.ChangePlan, plan_id)
        if plan is not None:
            update_change_plan_task_status(db, plan)
    if cancelled:
        logger.info("取消待执行接口任务 interface_id=%s task_type=%s count=%d reason=%s", interface_id, task_type, cancelled, reason)
    return cancelled


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


def cancel_draft_interface_change_plans(db: Session, interface_id: int) -> None:
    """删除接口时作废草稿，避免 SQLite 复用 ID 后旧计划误关联新接口。"""

    db.execute(
        update(models.ChangePlan)
        .where(
            models.ChangePlan.status == "draft",
            models.ChangePlan.payload["task_payload"]["interface_id"].as_integer() == interface_id,
        )
        .values(status="cancelled")
        .execution_options(synchronize_session="fetch")
    )


def existing_interface_names(db: Session, node_id: int) -> set[str]:
    """返回节点下已存在的 WireGuard 接口名，用于排除重复导入候选。"""

    return set(
        db.scalars(
            select(models.WireGuardInterface.name).where(models.WireGuardInterface.node_id == node_id)
        )
    )


def normalize_import_candidate_parsed(value: Any) -> dict[str, Any] | None:
    """验证并限制 Agent 返回的导入候选结构。

    Agent 结果经过 token 鉴权仍属于外部输入；导入接口不能假设其中的
    ``peers``、地址列表或整数始终符合解析器输出，否则一个损坏结果就能
    让候选导入路径抛出 500 或写入不可渲染的数据。
    """

    if not isinstance(value, dict):
        return None
    try:
        if not isinstance(value.get("name"), str):
            return None
        name = schemas._validate_linux_interface_name(value["name"])
        private_key = value.get("private_key")
        if private_key is not None:
            private_key = schemas._validate_wireguard_key(private_key, "WireGuard private key")

        def text_list(key: str, max_items: int = 128, max_length: int = 4096) -> list[str]:
            items = value.get(key, [])
            if not isinstance(items, list) or len(items) > max_items:
                raise ValueError(f"invalid import candidate {key}")
            normalized: list[str] = []
            for item in items:
                if not isinstance(item, str) or len(item) > max_length or any(ord(char) < 0x20 or ord(char) == 0x7F for char in item):
                    raise ValueError(f"invalid import candidate {key}")
                normalized.append(item)
            return normalized

        addresses = schemas._validate_cidrs(text_list("addresses", max_length=128))
        dns = text_list("dns", max_length=255)
        pre_up = text_list("pre_up")
        post_up = text_list("post_up")
        pre_down = text_list("pre_down")
        post_down = text_list("post_down")

        def optional_int(key: str, minimum: int, maximum: int) -> int | None:
            raw = value.get(key)
            if raw is None:
                return None
            if isinstance(raw, bool) or not isinstance(raw, int) or not minimum <= raw <= maximum:
                raise ValueError(f"invalid import candidate {key}")
            return raw

        listen_port = optional_int("listen_port", 1, 65535)
        mtu = optional_int("mtu", 576, 9000)
        table = value.get("table")
        fwmark = value.get("fwmark")
        if table is not None and (not isinstance(table, str) or len(table) > 64 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in table)):
            raise ValueError("invalid import candidate table")
        if fwmark is not None and (not isinstance(fwmark, str) or len(fwmark) > 64 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in fwmark)):
            raise ValueError("invalid import candidate fwmark")

        peers_value = value.get("peers", [])
        if not isinstance(peers_value, list) or len(peers_value) > 128:
            raise ValueError("invalid import candidate peers")
        peers: list[dict[str, Any]] = []
        for peer in peers_value:
            if not isinstance(peer, dict):
                raise ValueError("invalid import candidate peer")
            public_key = peer.get("public_key")
            if public_key is not None:
                public_key = schemas._validate_wireguard_key(public_key, "WireGuard public key")
            preshared_key = peer.get("preshared_key")
            if preshared_key is not None:
                preshared_key = schemas._validate_wireguard_key(preshared_key, "WireGuard preshared key")
            allowed_ips_value = peer.get("allowed_ips", [])
            if not isinstance(allowed_ips_value, list) or len(allowed_ips_value) > 256:
                raise ValueError("invalid import candidate allowed_ips")
            if any(not isinstance(item, str) for item in allowed_ips_value):
                raise ValueError("invalid import candidate allowed_ips")
            allowed_ips = schemas._validate_cidrs(allowed_ips_value)
            endpoint = peer.get("endpoint")
            if endpoint is not None:
                if not isinstance(endpoint, str) or len(endpoint) > 255 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in endpoint):
                    raise ValueError("invalid import candidate endpoint")
                host, port = split_endpoint(endpoint)
                if host is not None:
                    schemas._validate_endpoint_host(host)
                if port is not None and not 1 <= port <= 65535:
                    raise ValueError("invalid import candidate endpoint port")
            else:
                host, port = None, None
            keepalive = peer.get("persistent_keepalive")
            if keepalive is not None and (isinstance(keepalive, bool) or not isinstance(keepalive, int) or not 0 <= keepalive <= 65535):
                raise ValueError("invalid import candidate keepalive")
            peer_warnings = peer.get("warnings", [])
            if not isinstance(peer_warnings, list) or any(not isinstance(item, str) or len(item) > 500 for item in peer_warnings[:100]):
                raise ValueError("invalid import candidate warnings")
            peers.append({
                "public_key": public_key,
                "preshared_key": preshared_key,
                "allowed_ips": allowed_ips,
                "endpoint": endpoint,
                "persistent_keepalive": keepalive,
                "extras": peer.get("extras") if isinstance(peer.get("extras"), dict) else {},
                "warnings": peer_warnings[:100],
            })
        warnings = value.get("warnings", [])
        if not isinstance(warnings, list) or any(not isinstance(item, str) or len(item) > 500 for item in warnings[:100]):
            raise ValueError("invalid import candidate warnings")
        extras = value.get("extras") if isinstance(value.get("extras"), dict) else {}
        return {
            "name": name,
            "private_key": private_key,
            "addresses": addresses,
            "listen_port": listen_port,
            "dns": dns,
            "mtu": mtu,
            "table": table,
            "fwmark": fwmark,
            "pre_up": pre_up,
            "post_up": post_up,
            "pre_down": pre_down,
            "post_down": post_down,
            "extras": extras,
            "warnings": warnings[:100],
            "peers": peers,
        }
    except (TypeError, ValueError):
        return None


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
    previous_interface_name = str(json_object(interface.extras).get("previous_interface_name") or "").strip()
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
    cancel_pending_interface_deployment_tasks(db, interface)
    running_id = running_interface_deployment_task_id(db, interface)
    stop_payload = (
        {"depends_on_task_id": running_id, "continue_after_dependency_failure": True}
        if running_id is not None
        else None
    )
    _, stop_task = enqueue_interface_task_once_with_task(
        db,
        interface,
        driver.tasks.stop,
        payload_extra=stop_payload,
        update_pending_payload=True,
    )
    # Replacement explicitly takes ownership; cleanup must precede the new
    # deployment even when the old interface was observation-only.
    delete_payload = {"depends_on_task_id": stop_task.id} if stop_task is not None else None
    enqueue_interface_task_once(
        db,
        interface,
        driver.tasks.delete_config,
        payload_extra=delete_payload,
        update_pending_payload=True,
    )
    mark_import_candidate_available_for_interface(db, interface)
    delete_link_monitors_where(db, models.LinkMonitor.interface_id == interface.id)
    cancel_draft_interface_change_plans(db, interface.id)
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
            timeout=10,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail="wireguard tool is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=500, detail="wireguard tool timed out") from exc
    if completed.returncode != 0:
        raise HTTPException(status_code=500, detail="wireguard tool failed")
    output = completed.stdout or ""
    if len(output.encode("utf-8", errors="replace")) > 4096:
        raise HTTPException(status_code=500, detail="wireguard tool returned too much output")
    return output.strip()


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


def login(payload: schemas.LoginRequest, db: Session = Depends(get_db)) -> schemas.LoginResult:
    """验证单用户凭据、迁移旧密码哈希并签发新会话。"""

    password_hash = get_setting(db, SETTING_ADMIN_PASSWORD_HASH)
    username = admin_username(db)
    if payload.username != username or not password_hash or not verify_password(payload.password, password_hash):
        raise HTTPException(status_code=401, detail="invalid username or password")
    if password_hash_needs_update(password_hash):
        set_setting(db, SETTING_ADMIN_PASSWORD_HASH, hash_password(payload.password))
    token = generate_token("l42web")
    now = time.time()
    set_setting(db, SETTING_ADMIN_SESSION_HASH, hash_token(token))
    set_setting(db, SETTING_ADMIN_SESSION_ISSUED_AT, str(now))
    set_setting(db, SETTING_ADMIN_SESSION_LAST_USED_AT, str(now))
    db.commit()
    return schemas.LoginResult(token=token, username=username)


@app.post("/api/auth/login", response_model=schemas.LoginResult)
def login_endpoint(
    payload: schemas.LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> schemas.LoginResult:
    """对登录请求执行来源限流，并把会话写入安全 Cookie。"""

    key = login_rate_key(request, payload.username)
    retry_after = login_retry_after(key)
    if retry_after:
        raise HTTPException(
            status_code=429,
            detail="too many login attempts",
            headers={"Retry-After": str(retry_after)},
        )
    if not LOGIN_CONCURRENCY.acquire(blocking=False):
        raise HTTPException(
            status_code=429,
            detail="too many concurrent login attempts",
            headers={"Retry-After": "1"},
        )
    try:
        try:
            result = login(payload, db)
        except HTTPException:
            record_login_failure(key)
            raise
    finally:
        LOGIN_CONCURRENCY.release()
    clear_login_failures(key)
    set_web_session_cookie(response, request, result.token)
    return result


@app.post("/api/auth/logout")
def logout(response: Response, db: Session = Depends(get_db)) -> dict[str, str]:
    """退出当前 Web 管理端会话。"""

    clear_web_session(db)
    db.commit()
    clear_web_session_cookie(response)
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
        set_setting(db, SETTING_ADMIN_PASSWORD_HASH, hash_password(payload.new_password))
        set_setting(db, SETTING_ADMIN_INITIAL_PASSWORD_PENDING, "")
        clear_web_session(db)
    db.commit()
    if payload.new_password:
        remove_initial_password_file()
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

    data_buffer = bytearray()
    async for chunk in request.stream():
        if len(data_buffer) + len(chunk) > BRANDING_LOGO_MAX_BYTES:
            raise HTTPException(status_code=413, detail="logo file must be no larger than 3 MiB")
        data_buffer.extend(chunk)
    data = bytes(data_buffer)
    if not data:
        raise HTTPException(status_code=400, detail="logo file is required")
    suffix = detect_logo_extension(request.headers.get("content-type", ""), data)
    # 等待其他 worker 的文件锁或数据库提交时不占住事件循环。
    return await run_in_threadpool(store_site_logo, data, suffix, db)


def store_site_logo(data: bytes, suffix: str, db: Session) -> schemas.ControllerSettingsRead:
    """原子替换 Logo，并在同一跨进程临界区提交品牌 URL。"""

    logo_dir = Path(settings.config_dir) / "branding"
    reject_symlink_components(logo_dir)
    logo_dir.mkdir(parents=True, exist_ok=True)
    reject_symlink_components(logo_dir)
    with branding_logo_lock(logo_dir):
        target = logo_dir / f"logo.{suffix}"
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=f".{target.name}.", suffix=".tmp", dir=logo_dir, delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(data)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, target)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
        for stale_suffix in ["png", "jpg", "webp"]:
            if stale_suffix != suffix:
                (logo_dir / f"logo.{stale_suffix}").unlink(missing_ok=True)
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
    path = resolve_agent_release_asset_path(asset)
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
    # hash 接口与下载接口必须针对同一份实际存在的普通文件作答，避免
    # manifest 指向丢失/链接文件时返回看似可信但不可下载的摘要。
    resolve_agent_release_asset_path(asset)
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
        dedup_key=f"node:{node_id}:agent.self_upgrade",
        payload={
            "target_version": plan.target_version,
            "download_url": (
                f"{controller_url}/api/agent/releases/{plan.target_version}/download"
                f"?platform={plan.matched_platform}"
            ),
            "sha256": asset.sha256,
            "size": asset.size,
            "upgrade_mode": asset.install_mode,
            "binary_args": ["--version"],
            "install_path": "/usr/local/bin/link42-agent",
            "rollback": True,
        },
    )
    try:
        with db.begin_nested():
            db.add(task)
            db.flush()
    except IntegrityError:
        active = db.scalar(
            select(models.AgentTask).where(
                models.AgentTask.node_id == node_id,
                models.AgentTask.type == "agent.self_upgrade",
                models.AgentTask.status.in_(["pending", "running"]),
            )
        )
        if active is None:
            raise
        logger.info("并发请求复用 Agent 升级任务 node_id=%s task=%s", node_id, summarize_agent_task(active))
        return schemas.TaskRequestResult(task_id=active.id, status=active.status, message="升级任务已存在")
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
@ipam.transaction
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
    )
    node.internal_ipv4s = payload.internal_ipv4s
    db.add(node)
    commit_unique_or_conflict(db, "node name already exists")
    db.refresh(node)
    logger.info("创建节点 node_id=%s name=%s region=%s", node.id, node.name, node.region)
    return schemas.NodeCreateResult(node=node, agent_token=token)


@app.patch("/api/nodes/{node_id}", response_model=schemas.NodeRead)
@ipam.transaction
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
    if "internal_ipv4s" in payload.model_fields_set:
        node.internal_ipv4s = payload.internal_ipv4s
    commit_unique_or_conflict(db, "node name already exists")
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
            description="GRE L3 隧道，支持 IPv4 或 IPv6 外层，不加密，需要中间网络放行 GRE。",
            managed=True,
            warnings=[
                "GRE 不加密，请勿直接承载敏感流量",
                "GRE over IPv4 需要协议 47 放行，普通 NAT 环境通常不可用；GRE over IPv6 需要端到端 IPv6 可达",
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
@ipam.transaction
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
    outer = gre_outer_mapping(payload)
    outer_ip_version = gre_outer_ip_version(list(outer.values()))
    mtu = gre_effective_mtu(payload.mtu, outer_ip_version)
    require_gre_supported(local_node, outer_ip_version)
    require_gre_supported(peer_node, outer_ip_version)
    ensure_unique_interface_name(db, node_id, payload.local_interface_name)
    ensure_unique_interface_name(db, payload.peer_node_id, payload.peer_interface_name)
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
        mtu=mtu,
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
        mtu=mtu,
        routes=payload.peer_routes,
        runtime_status="starting",
        protocol_config=gre_protocol_config(outer["peer_bind_ip"], outer["peer_remote_ip"], payload),
    )
    db.add_all([connection, local_endpoint, peer_endpoint])
    flush_unique_or_conflict(db, "interface name already exists on node")
    enqueue_gre_apply_and_start(db, local_endpoint)
    enqueue_gre_apply_and_start(db, peer_endpoint)
    commit_unique_or_conflict(db, "interface name already exists on node")
    db.refresh(connection)
    logger.info(
        "创建 GRE 连接 connection_id=%s local_endpoint_id=%s peer_endpoint_id=%s",
        connection.id,
        local_endpoint.id,
        peer_endpoint.id,
    )
    return gre_connection_read(db, get_gre_connection_or_404(db, connection.id))


@app.post("/api/nodes/{node_id}/connections/manual", response_model=schemas.ConnectionRead)
@ipam.transaction
def create_manual_connection(
    node_id: int,
    payload: schemas.GreManualConnectionCreate,
    db: Session = Depends(get_db),
) -> schemas.ConnectionRead:
    """创建仅由当前节点 Agent 管理的单端 GRE 连接。"""

    validate_manual_gre_payload(payload)
    node = require_online_node(db, node_id)
    outer_ip_version = gre_outer_ip_version([payload.outer_local_ip, payload.outer_remote_ip])
    require_gre_supported(node, outer_ip_version)
    ensure_unique_interface_name(db, node_id, payload.interface_name)
    connection_name = payload.interface_name
    if payload.peer_interface_name:
        connection_name = f"{payload.interface_name} -> {payload.peer_interface_name}"
    connection = models.Connection(
        protocol_type=CONNECTION_TYPE_GRE,
        name=connection_name,
        source="created",
        managed=True,
        status="starting",
    )
    endpoint = models.ConnectionEndpoint(
        connection=connection,
        node_id=node_id,
        role="local",
        interface_name=payload.interface_name,
        tunnel_ips=payload.tunnel_ips,
        mtu=gre_effective_mtu(payload.mtu, outer_ip_version),
        routes=payload.routes,
        runtime_status="starting",
        protocol_config=manual_gre_protocol_config(payload),
    )
    db.add_all([connection, endpoint])
    flush_unique_or_conflict(db, "interface name already exists on node")
    enqueue_gre_apply_and_start(db, endpoint)
    commit_unique_or_conflict(db, "interface name already exists on node")
    logger.info("创建手动 GRE 连接 connection_id=%s endpoint_id=%s node_id=%s", connection.id, endpoint.id, node_id)
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
@ipam.transaction
def update_connection(
    raw_connection_ref: str,
    payload: schemas.GreManagedConnectionUpdate,
    db: Session = Depends(get_db),
) -> schemas.ConnectionRead:
    """编辑双端受管 GRE 连接并重新下发双方配置。"""

    protocol_type, item_id = parse_connection_ref(raw_connection_ref)
    if protocol_type != CONNECTION_TYPE_GRE:
        raise HTTPException(status_code=400, detail="use wireguard API for WireGuard connections")
    validate_gre_payload(payload)
    connection = get_gre_connection_or_404(db, item_id)
    endpoints = sorted(connection.endpoints, key=lambda endpoint: 0 if endpoint.role == "local" else 1)
    if len(endpoints) != 2:
        raise HTTPException(status_code=400, detail="use manual GRE API for single-endpoint connections")
    local_endpoint, peer_endpoint = endpoints
    local_node = require_online_node(db, local_endpoint.node_id)
    peer_node = require_online_node(db, peer_endpoint.node_id)
    outer = gre_outer_mapping(payload)
    outer_ip_version = gre_outer_ip_version(list(outer.values()))
    mtu = gre_effective_mtu(payload.mtu, outer_ip_version)
    require_gre_supported(local_node, outer_ip_version)
    require_gre_supported(peer_node, outer_ip_version)
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
    local_endpoint.interface_name = payload.local_interface_name
    local_endpoint.tunnel_ips = payload.local_tunnel_ips
    local_endpoint.mtu = mtu
    local_endpoint.routes = payload.local_routes
    local_endpoint.protocol_config = gre_protocol_config(outer["local_bind_ip"], outer["local_remote_ip"], payload)
    peer_endpoint.interface_name = payload.peer_interface_name
    peer_endpoint.tunnel_ips = payload.peer_tunnel_ips
    peer_endpoint.mtu = mtu
    peer_endpoint.routes = payload.peer_routes
    peer_endpoint.protocol_config = gre_protocol_config(outer["peer_bind_ip"], outer["peer_remote_ip"], payload)
    connection.name = f"{payload.local_interface_name} <-> {payload.peer_interface_name}"
    connection.status = "starting"
    enqueue_gre_apply_and_start(db, local_endpoint)
    enqueue_gre_apply_and_start(db, peer_endpoint)
    commit_unique_or_conflict(db, "interface name already exists on node")
    logger.info("更新 GRE 连接 connection_id=%s", connection.id)
    return gre_connection_read(db, get_gre_connection_or_404(db, connection.id))


@app.patch("/api/connections/{raw_connection_ref}/manual", response_model=schemas.ConnectionRead)
@ipam.transaction
def update_manual_connection(
    raw_connection_ref: str,
    payload: schemas.GreManualConnectionUpdate,
    db: Session = Depends(get_db),
) -> schemas.ConnectionRead:
    """编辑单端手动 GRE 连接并重新下发当前节点配置。"""

    protocol_type, item_id = parse_connection_ref(raw_connection_ref)
    if protocol_type != CONNECTION_TYPE_GRE:
        raise HTTPException(status_code=400, detail="use wireguard API for WireGuard connections")
    validate_manual_gre_payload(payload)
    connection = get_gre_connection_or_404(db, item_id)
    endpoints = list(connection.endpoints)
    if len(endpoints) != 1 or connection.source != "created":
        raise HTTPException(status_code=400, detail="connection is not a manual GRE connection")
    endpoint = endpoints[0]
    node = require_online_node(db, endpoint.node_id)
    outer_ip_version = gre_outer_ip_version([payload.outer_local_ip, payload.outer_remote_ip])
    require_gre_supported(node, outer_ip_version)
    ensure_unique_interface_name(
        db,
        endpoint.node_id,
        payload.interface_name,
        exclude_connection_endpoint_id=endpoint.id,
    )
    record_endpoint_rename(endpoint, payload.interface_name)
    endpoint.interface_name = payload.interface_name
    endpoint.tunnel_ips = payload.tunnel_ips
    endpoint.mtu = gre_effective_mtu(payload.mtu, outer_ip_version)
    endpoint.routes = payload.routes
    endpoint.protocol_config = manual_gre_protocol_config(payload)
    connection.name = payload.interface_name
    if payload.peer_interface_name:
        connection.name = f"{payload.interface_name} -> {payload.peer_interface_name}"
    connection.status = "starting"
    enqueue_gre_apply_and_start(db, endpoint)
    commit_unique_or_conflict(db, "interface name already exists on node")
    logger.info("更新手动 GRE 连接 connection_id=%s endpoint_id=%s", connection.id, endpoint.id)
    return gre_connection_read(db, get_gre_connection_or_404(db, connection.id))


@app.post("/api/connections/{raw_connection_ref}/start", response_model=schemas.ConnectionRead)
@ipam.transaction
def start_connection(raw_connection_ref: str, db: Session = Depends(get_db)) -> schemas.ConnectionRead:
    """启动 GRE 连接的全部受管端点。"""

    protocol_type, item_id = parse_connection_ref(raw_connection_ref)
    if protocol_type != CONNECTION_TYPE_GRE:
        raise HTTPException(status_code=400, detail="use wireguard API for WireGuard connections")
    connection = get_gre_connection_or_404(db, item_id)
    for endpoint in connection.endpoints:
        node = require_online_node(db, endpoint.node_id)
        outer_local_ip = str(json_object(endpoint.protocol_config).get("outer_local_ip") or "").strip()
        outer_ip_version = ipaddress.ip_address(outer_local_ip).version if outer_local_ip else 4
        require_gre_supported(node, outer_ip_version)
        create_connection_endpoint_task(db, endpoint, GRE_TASKS.start)
        endpoint.runtime_status = "starting"
    connection.status = "starting"
    db.commit()
    logger.info("启动 GRE 连接 connection_id=%s", connection.id)
    return gre_connection_read(db, get_gre_connection_or_404(db, connection.id))


@app.post("/api/connections/{raw_connection_ref}/stop", response_model=schemas.ConnectionRead)
def stop_connection(raw_connection_ref: str, db: Session = Depends(get_db)) -> schemas.ConnectionRead:
    """停止 GRE 连接的全部受管端点。"""

    protocol_type, item_id = parse_connection_ref(raw_connection_ref)
    if protocol_type != CONNECTION_TYPE_GRE:
        raise HTTPException(status_code=400, detail="use wireguard API for WireGuard connections")
    connection = get_gre_connection_or_404(db, item_id)
    for endpoint in connection.endpoints:
        require_online_node(db, endpoint.node_id)
        cancel_pending_gre_deployment_tasks(db, endpoint.id)
        running_id = running_gre_deployment_task_id(db, endpoint.id)
        create_connection_endpoint_task(
            db,
            endpoint,
            GRE_TASKS.stop,
            {"depends_on_task_id": running_id, "continue_after_dependency_failure": True} if running_id is not None else None,
            update_pending_payload=True,
        )
        endpoint.runtime_status = "stopping"
    connection.status = "stopping"
    db.commit()
    logger.info("停止 GRE 连接 connection_id=%s", connection.id)
    return gre_connection_read(db, get_gre_connection_or_404(db, connection.id))


@app.post("/api/connections/{raw_connection_ref}/refresh-status", response_model=schemas.ConnectionRead)
def refresh_connection_status(raw_connection_ref: str, db: Session = Depends(get_db)) -> schemas.ConnectionRead:
    """刷新 GRE 连接全部受管端点的运行状态。"""

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
@ipam.transaction
def delete_connection(raw_connection_ref: str, db: Session = Depends(get_db)) -> dict[str, str]:
    """删除 GRE 连接记录，并向全部受管端点下发清理任务。"""

    protocol_type, item_id = parse_connection_ref(raw_connection_ref)
    if protocol_type != CONNECTION_TYPE_GRE:
        raise HTTPException(status_code=400, detail="use wireguard API for WireGuard connections")
    connection = get_gre_connection_or_404(db, item_id)
    connection_id = connection.id
    endpoints = list(connection.endpoints)
    for endpoint in endpoints:
        require_online_node(db, endpoint.node_id)
        cancel_pending_gre_deployment_tasks(db, endpoint.id)
        running_id = running_gre_deployment_task_id(db, endpoint.id)
        stop_task = create_connection_endpoint_task(
            db,
            endpoint,
            GRE_TASKS.stop,
            {"depends_on_task_id": running_id, "continue_after_dependency_failure": True} if running_id is not None else None,
            update_pending_payload=True,
        )
        create_connection_endpoint_task(db, endpoint, GRE_TASKS.delete_config, {"depends_on_task_id": stop_task.id})
    delete_link_monitors_where(
        db,
        models.LinkMonitor.connection_endpoint_id.in_([endpoint.id for endpoint in endpoints]),
    )
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
        flush_unique_or_conflict(db, "port inventory setting already exists")
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
    commit_unique_or_conflict(db, "port inventory entry already exists")
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
    commit_unique_or_conflict(db, "port inventory entry already exists")
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
    # 页面重复点击或自动重试不应无限堆积完全相同的只读/插件任务。
    # 运行中的任务仍允许在需要时再次排队；数据库唯一索引只约束 pending。
    payload_fingerprint = hashlib.sha256(
        json.dumps(task_spec.payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    dedup_key = f"plugin:{node_id}:{task_spec.task_type}:{payload_fingerprint}"
    task = models.AgentTask(
        node_id=node_id,
        type=task_spec.task_type,
        payload=task_spec.payload,
        dedup_key=dedup_key,
    )
    try:
        with db.begin_nested():
            db.add(task)
            db.flush()
    except IntegrityError:
        existing = db.scalar(
            select(models.AgentTask).where(
                models.AgentTask.dedup_key == dedup_key,
                models.AgentTask.status == "pending",
            )
        )
        if existing is None:
            raise
        task = existing
        logger.info(
            "复用已有节点插件任务 node_id=%s plugin=%s action=%s task=%s",
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
            message="插件任务已存在",
        )
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
@ipam.transaction
def delete_node(node_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    """删除空节点及其历史数据；仍参与连接的节点必须先清空连接。"""

    node = db.get(models.Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    wireguard_interface = db.scalar(
        select(models.WireGuardInterface).where(models.WireGuardInterface.node_id == node_id).limit(1)
    )
    connection_endpoint = db.scalar(
        select(models.ConnectionEndpoint).where(models.ConnectionEndpoint.node_id == node_id).limit(1)
    )
    peer_reference = db.scalar(
        select(models.WireGuardPeer).where(models.WireGuardPeer.peer_node_id == node_id).limit(1)
    )
    if wireguard_interface is not None or connection_endpoint is not None or peer_reference is not None:
        raise HTTPException(status_code=409, detail="node has connections")
    node_name = node.name

    delete_link_monitors_where(db, models.LinkMonitor.node_id == node_id)
    db.execute(
        delete(models.LookingGlassQuery).where(models.LookingGlassQuery.node_id == node_id),
        execution_options={"synchronize_session": False},
    )
    for model in [
        models.IPAMNodeAddress,
        models.ImportCandidate,
        models.PortInventoryEntry,
        models.PortInventorySetting,
        models.AgentTask,
    ]:
        db.execute(
            delete(model).where(model.node_id == node_id),
            execution_options={"synchronize_session": False},
        )
    # 不使用 ORM 的 delete-orphan 级联：检查完成后新建的配置不能被
    # 悄悄级联删除。让数据库外键在最终 DELETE 时拒绝仍有关联的节点。
    try:
        # 把“仍无连接”的条件放进最终 DELETE，避免旧数据库缺少外键时，
        # 检查之后新建的连接被错误删除。该条件也与启用外键的数据库一致。
        deleted = db.execute(
            delete(models.Node).where(
                models.Node.id == node_id,
                ~select(models.WireGuardInterface.id)
                .where(models.WireGuardInterface.node_id == node_id)
                .exists(),
                ~select(models.ConnectionEndpoint.id)
                .where(models.ConnectionEndpoint.node_id == node_id)
                .exists(),
                ~select(models.WireGuardPeer.id)
                .where(models.WireGuardPeer.peer_node_id == node_id)
                .exists(),
            )
        )
        if deleted.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="node has connections")
        db.commit()
    except IntegrityError as exc:
        # 前面的关联检查与最终删除之间可能有其他请求创建连接；外键约束
        # 会拒绝删除节点，统一转成可重试的业务冲突而不是 500。
        db.rollback()
        raise HTTPException(status_code=409, detail="node has connections") from exc
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
        dedup_key=f"node:{node.id}:middleware.install:mimic",
        payload={
            "plugin": "mimic",
            "source": "github_latest",
            "repo": "hack3ric/mimic",
            "allow_prerelease": False,
            "github_proxy_url": node.github_proxy_url,
        },
    )
    try:
        with db.begin_nested():
            db.add(task)
            db.flush()
    except IntegrityError:
        active = db.scalar(
            select(models.AgentTask).where(
                models.AgentTask.node_id == node.id,
                models.AgentTask.type == "middleware.install",
                models.AgentTask.status.in_(["pending", "running"]),
            )
        )
        if active is None:
            raise
        return schemas.TaskRequestResult(task_id=active.id, status=active.status, message="middleware install task already queued")
    node.middleware_install_status = "mimic_installing"
    db.commit()
    db.refresh(task)
    logger.info("创建中间层安装任务 node_id=%s plugin=%s task=%s", node.id, plugin, summarize_agent_task(task))
    return schemas.TaskRequestResult(task_id=task.id, status=task.status, message="mimic install task queued")


@app.post("/api/nodes/{node_id}/wireguard/interfaces", response_model=schemas.InterfaceRead)
@app.post("/api/nodes/{node_id}/wireguard/configs", response_model=schemas.InterfaceRead)
@ipam.transaction
def create_interface(
    node_id: int,
    payload: schemas.InterfaceCreate,
    db: Session = Depends(get_db),
) -> models.WireGuardInterface:
    """在指定节点上创建 WireGuard 点对点配置期望状态。"""
    validate_wireguard_ipv6_mtu(payload.mtu, payload.tunnel_ips)
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
    commit_unique_or_conflict(db, "interface name already exists on node")
    db.refresh(interface)
    logger.info("创建 WireGuard 配置 node_id=%s interface_id=%s name=%s", node_id, interface.id, interface.name)
    return interface


@app.post("/api/nodes/{node_id}/wireguard/managed-links", response_model=schemas.ManagedLinkCreateResult)
@ipam.transaction
def create_managed_link(
    node_id: int,
    payload: schemas.ManagedLinkCreate,
    db: Session = Depends(get_db),
) -> schemas.ManagedLinkCreateResult:
    """在两个受管节点之间创建点对点 WireGuard 连接期望状态。"""

    if node_id == payload.peer_node_id:
        raise HTTPException(status_code=400, detail="peer node must be different")
    validate_wireguard_ipv6_mtu(payload.mtu, payload.local_tunnel_ips, payload.peer_tunnel_ips)

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
    validate_udp2raw_port_conflicts(middleware, payload.local_listen_port, payload.peer_listen_port)
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

    # Remove the old records before inserting same-name replacements. Their
    # addresses remain held by IPAM until the cleanup tasks finish.
    cleanup_by_node: dict[int, int] = {}
    for replaced in [replace_local, replace_peer]:
        if replaced is not None:
            replaced_node_id, replaced_id = replaced.node_id, replaced.id
            queue_replace_interface(db, replaced)
            cleanup_task = get_interface_task(db, replaced_id, WIREGUARD_TASKS.delete_config, ["pending", "running"])
            if cleanup_task is not None:
                cleanup_by_node[replaced_node_id] = cleanup_task.id
    if replace_local or replace_peer:
        db.flush()

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
    flush_unique_or_conflict(db, "interface name already exists on node")
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
    flush_unique_or_conflict(db, "wireguard peer already exists")
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
    for target in [local_interface, peer_interface]:
        enqueue_apply_config(db, target)
        cleanup_id = cleanup_by_node.get(target.node_id)
        if cleanup_id:
            apply_task = get_interface_task(db, target.id, WIREGUARD_TASKS.apply_config, ["pending"])
            if apply_task is not None:
                apply_task.payload = {**json_object(apply_task.payload), "depends_on_task_id": cleanup_id}
    commit_unique_or_conflict(db, "interface name already exists on node")
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
    if db.get(models.Node, node_id) is None:
        raise HTTPException(status_code=404, detail="node not found")
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
    commit_unique_or_conflict(db, "link monitor already exists for this interface")
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
    commit_unique_or_conflict(db, "link monitor already exists for this endpoint")
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
    delete_link_monitors_where(db, models.LinkMonitor.id == monitor_id)
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
            .order_by(models.LinkMonitorSample.checked_at.desc())
            .limit(LINK_MONITOR_SAMPLE_LIMIT)
        )
    )
    samples.sort(key=lambda sample: sample.checked_at)
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
@ipam.transaction
def update_managed_link(
    interface_id: int,
    payload: schemas.ManagedLinkUpdate,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """编辑受管节点连接，并直接下发双方配置。"""

    validate_wireguard_ipv6_mtu(payload.mtu, payload.local_tunnel_ips, payload.peer_tunnel_ips)
    local_interface, peer_interface, local_peer, peer_peer = get_managed_link_bundle(db, interface_id)
    old_middleware = managed_link_middleware(local_interface)
    local_node = require_online_node(db, local_interface.node_id)
    peer_node = require_online_node(db, peer_interface.node_id)
    middleware = normalize_middleware_config(payload.udp2raw, payload.mimic)
    validate_udp2raw_port_conflicts(middleware, payload.local_listen_port, payload.peer_listen_port)
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
    commit_unique_or_conflict(db, "interface name already exists on node")
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
@ipam.transaction
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
            cancel_pending_interface_deployment_tasks(db, interface)
            running_id = running_interface_deployment_task_id(db, interface)
            changed, _ = enqueue_interface_task_once_with_task(
                db,
                interface,
                driver.tasks.stop,
                payload_extra={"depends_on_task_id": running_id, "continue_after_dependency_failure": True} if running_id is not None else None,
                update_pending_payload=True,
            )
            if changed:
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
@ipam.transaction
def delete_managed_link(
    interface_id: int,
    db: Session = Depends(get_db),
    delete_node_config: bool = False,
) -> dict[str, str]:
    """同时删除受管连接双方；必须先断开双方接口。"""

    local_interface, peer_interface, local_peer, peer_peer = get_managed_link_bundle(db, interface_id)
    require_online_node(db, local_interface.node_id)
    require_online_node(db, peer_interface.node_id)
    if any(interface.runtime_status in ["running", "starting", "stopping"] for interface in [local_interface, peer_interface]):
        raise HTTPException(status_code=409, detail="wireguard interface must be stopped before delete")
    middleware = managed_link_middleware(local_interface)
    if middleware and delete_node_config:
        middleware_stop_tasks: dict[int, models.AgentTask] = {}
        for target_interface, stop_type, stop_payload in middleware_task_payloads(
            middleware,
            local_interface,
            peer_interface,
            "stop",
        ):
            _, stop_task = enqueue_interface_task_once_with_task(
                db,
                target_interface,
                stop_type,
                stop_payload,
                update_pending_payload=True,
            )
            if stop_task is not None:
                middleware_stop_tasks[target_interface.id] = stop_task
        for target_interface, task_type, task_payload in middleware_task_payloads(
            middleware,
            local_interface,
            peer_interface,
            "delete",
        ):
            dependency = middleware_stop_tasks.get(target_interface.id)
            payload = {**task_payload}
            if dependency is not None:
                payload["depends_on_task_id"] = dependency.id
                payload["continue_after_dependency_failure"] = True
            enqueue_interface_task_once(
                db,
                target_interface,
                task_type,
                payload,
                update_pending_payload=True,
            )
    for interface in [local_interface, peer_interface]:
        cancel_pending_interface_deployment_tasks(db, interface)
        mark_import_candidate_available_for_interface(db, interface)
        if delete_node_config and should_delete_node_config_file(interface):
            driver = connection_driver_for_interface(interface)
            enqueue_interface_task_once(db, interface, driver.tasks.delete_config)

    delete_link_monitors_where(
        db,
        models.LinkMonitor.interface_id.in_([local_interface.id, peer_interface.id]),
    )

    # 双向 Peer 通过 peer_interface_id 交叉引用双方接口。先删除并 flush Peer，
    # 避免删除首个接口后，加载第二个接口的监测关系触发自动 flush 和外键失败。
    local_interface.peers.remove(local_peer)
    peer_interface.peers.remove(peer_peer)
    db.flush()
    for interface in [local_interface, peer_interface]:
        cancel_draft_interface_change_plans(db, interface.id)
        db.delete(interface)
    db.commit()
    return {"status": "deleted"}


@app.patch("/api/wireguard/interfaces/{interface_id}", response_model=schemas.InterfaceRead)
@app.patch("/api/wireguard/configs/{interface_id}", response_model=schemas.InterfaceRead)
@ipam.transaction
def update_interface(
    interface_id: int,
    payload: schemas.InterfaceUpdate,
    db: Session = Depends(get_db),
) -> models.WireGuardInterface:
    """修改已有 WireGuard 点对点配置的期望状态。"""

    validate_wireguard_ipv6_mtu(payload.mtu, payload.tunnel_ips)
    interface = db.get(models.WireGuardInterface, interface_id)
    if interface is None:
        raise HTTPException(status_code=404, detail="interface not found")
    require_online_node(db, interface.node_id)
    ensure_unique_interface_name(db, interface.node_id, payload.name, exclude_interface_id=interface.id)

    record_interface_rename(interface, payload.name)
    interface.name = payload.name
    interface.tunnel_ips = payload.tunnel_ips
    interface.listen_port = payload.listen_port
    if payload.private_key:
        interface.private_key_ref = "local-db"
        interface.private_key_value = payload.private_key
    elif payload.clear_private_key:
        interface.private_key_ref = None
        interface.private_key_value = None
    interface.public_key = payload.public_key
    interface.mtu = payload.mtu
    interface.table_name = payload.table_name
    interface.dns = payload.dns
    set_extra_value(interface, "custom_config", payload.interface_custom_config)
    commit_unique_or_conflict(db, "interface name already exists on node")
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
@ipam.transaction
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
    cancel_pending_interface_deployment_tasks(db, interface)
    running_id = running_interface_deployment_task_id(db, interface)
    changed, _ = enqueue_interface_task_once_with_task(
        db,
        interface,
        driver.tasks.stop,
        payload_extra={"depends_on_task_id": running_id, "continue_after_dependency_failure": True} if running_id is not None else None,
        update_pending_payload=True,
    )
    if changed:
        interface.runtime_status = "stopping"
    db.commit()
    db.refresh(interface)
    return interface


@app.delete("/api/wireguard/configs/{interface_id}")
@ipam.transaction
def delete_interface(
    interface_id: int,
    db: Session = Depends(get_db),
    delete_node_config: bool = False,
) -> dict[str, str]:
    """删除 WireGuard 配置；运行中的配置必须先关闭。"""

    interface = get_wireguard_config_or_404(interface_id, db)
    if interface.source == "imported" and not interface.managed:
        mark_import_candidate_available_for_interface(db, interface)
        delete_link_monitors_where(db, models.LinkMonitor.interface_id == interface.id)
        cancel_draft_interface_change_plans(db, interface.id)
        db.delete(interface)
        db.commit()
        return {"status": "deleted"}

    require_online_node(db, interface.node_id)
    if interface.runtime_status in ["running", "starting", "stopping"]:
        raise HTTPException(status_code=409, detail="wireguard interface must be stopped before delete")
    cancel_pending_interface_deployment_tasks(db, interface)
    mark_import_candidate_available_for_interface(db, interface)
    if delete_node_config and should_delete_node_config_file(interface):
        driver = connection_driver_for_interface(interface)
        enqueue_interface_task_once(db, interface, driver.tasks.delete_config)
    delete_link_monitors_where(db, models.LinkMonitor.interface_id == interface.id)
    cancel_draft_interface_change_plans(db, interface.id)
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
    if interface is not None:
        task_payload = {**task_payload, "ipam_owner": ipam.config_owner(interface)}
    else:
        task_payload = {key: value for key, value in task_payload.items() if key != "ipam_owner"}
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
                "ipam_owner": ipam.config_owner(interface),
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
@ipam.transaction
def confirm_change_plan(plan_id: int, db: Session = Depends(get_db)) -> models.ChangePlan:
    """确认部署计划，并创建等待 Agent 拉取的任务。"""
    plan = db.get(models.ChangePlan, plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="change plan not found")
    if plan.status != "draft":
        raise HTTPException(status_code=409, detail="change plan is not draft")
    if not plan.diff.strip():
        raise HTTPException(status_code=400, detail="change plan has no diff")

    plan_payload = plan.payload if isinstance(plan.payload, dict) else {}
    task_payload = plan_payload.get("task_payload")
    task_type = plan_payload.get("task_type")
    if not isinstance(task_payload, dict) or not task_payload or not isinstance(task_type, str) or not task_type:
        raise HTTPException(status_code=400, detail="change plan has no task payload")
    if not isinstance(task_payload.get("node_id"), int) or isinstance(task_payload.get("node_id"), bool):
        raise HTTPException(status_code=400, detail="change plan task payload has invalid node id")
    node = require_online_node(db, task_payload["node_id"])
    require_task_supported(node, task_type)
    if "interface_id" in task_payload:
        interface_id = task_payload["interface_id"]
        if not isinstance(interface_id, int) or isinstance(interface_id, bool):
            raise HTTPException(status_code=400, detail="change plan task payload has invalid interface id")
        interface = db.get(models.WireGuardInterface, interface_id)
        if (
            interface is None
            or interface.node_id != task_payload["node_id"]
            or interface.name != task_payload.get("interface_name")
        ):
            raise HTTPException(status_code=409, detail="change plan interface has changed or been deleted; generate a new plan")

    confirmed_at = datetime.utcnow()
    claimed_plan = db.execute(
        update(models.ChangePlan)
        .where(models.ChangePlan.id == plan.id, models.ChangePlan.status == "draft")
        .values(status="confirmed", confirmed_at=confirmed_at)
        .execution_options(synchronize_session="fetch")
    )
    if claimed_plan.rowcount != 1:
        db.refresh(plan)
        raise HTTPException(status_code=409, detail="change plan is no longer draft")
    db.refresh(plan)
    post_confirm = plan_payload.get("post_confirm")
    if not isinstance(post_confirm, dict):
        post_confirm = {}
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
        dedup_key=f"node:{node_id}:{WIREGUARD_TASKS.import_scan}",
        payload={"node_id": node_id},
    )
    try:
        with db.begin_nested():
            db.add(task)
            db.flush()
    except IntegrityError:
        existing = db.scalar(
            select(models.AgentTask).where(
                models.AgentTask.node_id == node_id,
                models.AgentTask.type == WIREGUARD_TASKS.import_scan,
                models.AgentTask.status.in_(["pending", "running"]),
            )
        )
        if existing is None:
            raise
        return schemas.TaskRequestResult(
            task_id=existing.id,
            status=existing.status,
            message="scan task already queued",
        )
    db.commit()
    db.refresh(task)
    logger.info("创建导入扫描任务 node_id=%s task=%s", node_id, summarize_agent_task(task))
    return schemas.TaskRequestResult(
        task_id=task.id,
        status=task.status,
        message="scan task queued",
    )


@app.get("/api/agent/plugins/udp2raw/assets/{asset_name}")
def get_udp2raw_asset(
    asset_name: str,
    request: Request,
    db: Session = Depends(get_db),
) -> FileResponse:
    """为已鉴权 Agent 提供主控内置的 udp2raw 二进制资产。"""

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
    try:
        node_id = int(request.headers.get("X-Link42-Node-ID", ""))
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid agent credentials") from exc
    token = request.headers.get("X-Link42-Agent-Token", "")
    require_agent(db, node_id, token)
    roots = [
        Path("/opt/link42/plugins/udp2raw/assets"),
        Path(__file__).resolve().parents[3] / "plugins" / "udp2raw" / "assets",
        Path(__file__).resolve().parents[3] / "udp2raw_sh" / "udp2raw_bin",
    ]
    for root in roots:
        path = root / asset_name
        try:
            reject_symlink_components(root)
            if path.is_symlink() or not path.exists() or not path.is_file():
                continue
        except OSError:
            continue
        try:
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            return FileResponse(path, headers={"X-Link42-Asset-SHA256": digest.hexdigest()})
        except OSError:
            continue
    raise HTTPException(status_code=404, detail="udp2raw asset not found")


@app.get("/api/nodes/{node_id}/wireguard/import-candidates", response_model=list[schemas.ImportCandidateRead])
def list_import_candidates(node_id: int, db: Session = Depends(get_db)) -> list[models.ImportCandidate]:
    """列出 Agent 扫描回来的 wg-quick 导入候选。"""
    if db.get(models.Node, node_id) is None:
        raise HTTPException(status_code=404, detail="node not found")
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
@ipam.transaction(observe=True)
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

    parsed = normalize_import_candidate_parsed(candidate.parsed)
    if parsed is None:
        raise HTTPException(status_code=409, detail="import candidate data is invalid")
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

    # 先用条件更新原子认领候选，避免两个并发请求都通过上面的快照检查，
    # 随后各自创建出一份相同的接口。后续任意异常都会回滚这次认领。
    claimed = db.execute(
        update(models.ImportCandidate)
        .where(
            models.ImportCandidate.id == candidate.id,
            models.ImportCandidate.node_id == node_id,
            models.ImportCandidate.imported.is_(False),
        )
        .values(imported=True)
        .execution_options(synchronize_session="fetch")
    )
    if claimed.rowcount != 1:
        raise HTTPException(status_code=409, detail="candidate already imported")
    candidate.imported = True

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
    touch_node_heartbeat(node)
    db.commit()
    current_capabilities = sorted(node.agent_capabilities or [])
    if previous_status != "online" or previous_version != node.agent_version or previous_capabilities != current_capabilities:
        logger.info(
            "Agent 注册 node_id=%s hostname=%s version=%s protocol=%s service=%s capabilities=%s",
            node.id,
            node.hostname,
            node.agent_version,
            node.agent_protocol_version,
            json_object(node.agent_platform).get("service_manager"),
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
    previous_seen = node.last_seen_at
    update_agent_metadata(node, payload.agent_version, payload.protocol_version, payload.capabilities, payload.platform)
    now = touch_node_heartbeat(node)
    db.commit()
    if not was_online:
        gap_seconds = (now - previous_seen).total_seconds() if previous_seen else None
        logger.info(
            "Agent 心跳恢复在线 node_id=%s hostname=%s version=%s gap_seconds=%s",
            node.id,
            node.hostname,
            node.agent_version,
            round(gap_seconds, 3) if gap_seconds is not None else None,
        )
    else:
        logger.debug("Agent 心跳 node_id=%s version=%s", node.id, node.agent_version)
    return {"status": "ok"}


@app.post("/api/agent/tasks/poll", response_model=schemas.AgentPollResponse)
def agent_poll(payload: schemas.AgentPollRequest, db: Session = Depends(get_db)) -> schemas.AgentPollResponse:
    """Agent 轮询待执行任务，并把任务标记为 running。"""
    node = require_agent(db, payload.node_id, payload.token)
    update_agent_metadata(node, payload.agent_version, payload.protocol_version, payload.capabilities, payload.platform)
    now = datetime.utcnow()
    touch_node_heartbeat(node, now)
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
    failed_plan_ids: set[int] = set()
    for task in candidate_tasks:
        if not agent_satisfies_task(node, task.type):
            continue
        if not isinstance(task.payload, dict):
            task.status = "failed"
            task.finished_at = now
            task.result = {"error": "agent task payload must be an object"}
            if task.change_plan_id is not None:
                failed_plan_ids.add(task.change_plan_id)
            logger.warning("Agent 任务 payload 类型异常 task_id=%s", task.id)
            continue
        if not is_task_ready_for_poll(db, task, now):
            continue
        try:
            payload_size = len(json.dumps(task.payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError, OverflowError, RecursionError):
            payload_size = MAX_AGENT_TASK_PAYLOAD_BYTES + 1
        if payload_size > MAX_AGENT_TASK_PAYLOAD_BYTES:
            task.status = "failed"
            task.finished_at = now
            task.result = {
                "error": "agent task payload exceeds response size limit",
                "max_bytes": MAX_AGENT_TASK_PAYLOAD_BYTES,
            }
            if task.change_plan_id is not None:
                failed_plan_ids.add(task.change_plan_id)
            logger.warning("Agent 任务 payload 过大 task_id=%s bytes=%s", task.id, payload_size)
            continue
        # The SELECT may be shared by concurrent polls. Claim only rows that
        # are still pending at the database write, so exactly one poll owns
        # each task (including across controller worker processes).
        db.flush()
        claimed = db.execute(
            update(models.AgentTask)
            .where(models.AgentTask.id == task.id, models.AgentTask.status == "pending")
            .values(status="running", started_at=now)
            .execution_options(synchronize_session="fetch")
        )
        if claimed.rowcount != 1:
            continue
        tasks.append(task)
        if len(tasks) >= AGENT_TASK_POLL_BATCH_SIZE:
            break
    if failed_plan_ids:
        db.flush()
        for plan_id in failed_plan_ids:
            plan = db.get(models.ChangePlan, plan_id)
            if plan is not None:
                update_change_plan_task_status(db, plan)
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
@ipam.transaction(observe=True, authorize=lambda params: require_agent(params["db"], params["payload"].node_id, params["payload"].token))
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
    try:
        validate_agent_result_json(payload.result)
    except ValueError as exc:
        # 结果已经无法被安全持久化；若任务仍在执行，立即收敛为失败，
        # 否则 Agent 会因持续重试同一无效结果而让任务长期保持 running。
        if task.status == "running":
            recorded = db.execute(
                update(models.AgentTask)
                .where(models.AgentTask.id == task.id, models.AgentTask.status == "running")
                .values(status="failed", finished_at=datetime.utcnow(), result={"error": str(exc)})
                .execution_options(synchronize_session="fetch")
            )
            if recorded.rowcount == 1 and task.change_plan_id is not None:
                plan = db.get(models.ChangePlan, task.change_plan_id)
                if plan is not None:
                    update_change_plan_task_status(db, plan)
            db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # 旧库可能保存合法 JSON 数组/字符串作为任务 payload。结果上报仍应
    # 幂等完成并返回稳定错误，而不是在业务分支中因 `.get()`/`.items()` 触发 500。
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    if task.payload is not None and not isinstance(task.payload, dict):
        logger.warning("Agent 任务 payload 类型异常 task_id=%s type=%s", task.id, type(task.payload).__name__)
    reported_status, reported_result = normalize_agent_task_report(db, task, payload.status, payload.result)
    # 任务只能由实际领取它的 Agent 完成；过期任务的迟到结果不能覆盖
    # 主控已经记录的失败状态。相同终态的重试保持幂等，避免网络重传造成 409。
    if task.status != "running":
        if task.status == reported_status and task.status in {"succeeded", "failed", "cancelled"}:
            return {"status": "recorded"}
        raise HTTPException(status_code=409, detail=f"task is not running: {task.status}")

    recorded = db.execute(
        update(models.AgentTask)
        .where(models.AgentTask.id == task.id, models.AgentTask.status == "running")
        .values(status=reported_status, result=reported_result, finished_at=datetime.utcnow())
        .execution_options(synchronize_session="fetch")
    )
    if recorded.rowcount != 1:
        # 并发重传只能有一次写入和一次业务副作用；其余请求读取已提交终态。
        db.refresh(task)
        if task.status == reported_status:
            return {"status": "recorded"}
        raise HTTPException(status_code=409, detail=f"task is not running: {task.status}")
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

    if task.type == "middleware.install" and node is not None and task_payload.get("plugin") == "mimic":
        if reported_status == "succeeded":
            if reported_result.get("reboot_required"):
                node.middleware_install_status = "mimic_reboot_required"
                platform = json_object(node.agent_platform).copy()
                platform["mimic_reboot_required"] = True
                node.agent_platform = platform
            else:
                node.middleware_install_status = "mimic_ready"
                platform = json_object(node.agent_platform).copy()
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
        raw_candidates = reported_result.get("candidates", [])
        candidates = raw_candidates if isinstance(raw_candidates, list) else []
        # Agent results are authenticated but still treated as untrusted input:
        # a corrupt or outdated agent must not turn a result upload into a 500
        # or create an import candidate that the later import endpoint cannot
        # safely consume.
        valid_candidates: list[dict[str, Any]] = []
        for candidate in candidates[:1000]:
            if not isinstance(candidate, dict):
                continue
            path = candidate.get("path")
            parsed = candidate.get("parsed")
            normalized_parsed = normalize_import_candidate_parsed(parsed)
            interface_name = normalized_parsed.get("name") if normalized_parsed else None
            content = candidate.get("content")
            if (
                not isinstance(path, str)
                or not path
                or len(path) > 512
                or not isinstance(content, str)
                or len(content.encode("utf-8")) > 512 * 1024
                or normalized_parsed is None
                or not isinstance(interface_name, str)
            ):
                continue
            valid_candidates.append({**candidate, "parsed": normalized_parsed, "content": content, "warnings": normalized_parsed["warnings"]})
        candidates = valid_candidates
        scanned_paths = {candidate["path"] for candidate in candidates}
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
            if not isinstance(parsed, dict) or not candidate.get("path"):
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

    interface_id = task_payload.get("interface_id")
    if interface_id and reported_status == "succeeded":
        interface = db.get(models.WireGuardInterface, interface_id)
        if ipam.task_targets(task, interface):
            driver = connection_driver_for_interface(interface)
            if task.type == driver.tasks.apply_config:
                # 部署成功后记录节点上的已部署配置，后续 Change Plan diff 才能对比真实基线。
                interface.deployed_config = task_payload.get("config")
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
                # status 查询可能在 start/stop 前已被领取；迟到结果不能覆盖
                # 后面已经排队或完成的真实状态变更。
                if not has_newer_interface_state_task(db, interface.id, task.id, driver):
                    interface.runtime_status = reported_result.get("runtime_status") or interface.runtime_status

    connection_endpoint_id = task_payload.get("connection_endpoint_id")
    if connection_endpoint_id and reported_status == "failed":
        endpoint = db.get(models.ConnectionEndpoint, connection_endpoint_id)
        if ipam.task_targets(task, endpoint) and endpoint.connection.protocol_type == CONNECTION_TYPE_GRE:
            endpoint.runtime_status = "failed"
            set_endpoint_extra_value(endpoint, "last_error", agent_task_error_summary(reported_result) or "Agent 任务执行失败")
            endpoint.connection.status = gre_connection_status(endpoint.connection)
    if connection_endpoint_id and reported_status == "succeeded":
        endpoint = db.get(models.ConnectionEndpoint, connection_endpoint_id)
        if ipam.task_targets(task, endpoint) and endpoint.connection.protocol_type == CONNECTION_TYPE_GRE:
            if task.type == GRE_TASKS.apply_config:
                # 部署基线来自实际执行的任务快照，而非任务执行期间可能被编辑的端点。
                deployed_payload = {key: value for key, value in task_payload.items() if key != "depends_on_task_id"}
                endpoint.deployed_config = json.dumps(deployed_payload, ensure_ascii=False, sort_keys=True)
            elif task.type == GRE_TASKS.start:
                endpoint.runtime_status = "running"
                set_endpoint_extra_value(endpoint, "last_error", None)
                if (
                    task_payload.get("interface_name") == endpoint.interface_name
                    and task_payload.get("previous_interface_name") == json_object(endpoint.extras).get("previous_interface_name")
                    and gre_previous_config_cleanup_confirmed(task, reported_result)
                ):
                    set_endpoint_extra_value(endpoint, "previous_interface_name", None)
            elif task.type == GRE_TASKS.stop:
                endpoint.runtime_status = "stopped"
                set_endpoint_extra_value(endpoint, "last_error", None)
            elif task.type == GRE_TASKS.status:
                if not has_newer_endpoint_state_task(db, endpoint.id, task.id):
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
    touch_node_heartbeat(node, now)
    candidates = list(
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
    monitors: list[models.LinkMonitor] = []
    for monitor in candidates:
        next_due = now + timedelta(seconds=monitor.interval_seconds)
        claimed = db.execute(
            update(models.LinkMonitor)
            .where(
                models.LinkMonitor.id == monitor.id,
                models.LinkMonitor.enabled.is_(True),
                or_(models.LinkMonitor.next_due_at.is_(None), models.LinkMonitor.next_due_at <= now),
            )
            .values(next_due_at=next_due)
            .execution_options(synchronize_session="fetch")
        )
        if claimed.rowcount == 1:
            monitors.append(monitor)
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
    seen_checked_samples: set[tuple[int, datetime]] = set()
    generated_sequence = 0
    generated_base = now - timedelta(microseconds=len(payload.results) + 1)
    for item in payload.results:
        monitor = db.get(models.LinkMonitor, item.monitor_id)
        if monitor is None or monitor.node_id != payload.node_id:
            logger.warning("忽略未知链路监测结果 node_id=%s monitor_id=%s", payload.node_id, item.monitor_id)
            continue
        # Agent clocks can drift, but a future timestamp must not move the
        # dashboard's last-check time or keep a sample in every summary window.
        checked_at = item.checked_at or now
        if checked_at.tzinfo is not None:
            checked_at = checked_at.astimezone(timezone.utc).replace(tzinfo=None)
        if checked_at > now:
            checked_at = now
        if item.checked_at is None:
            # Agent 可能一次上报多个未带时间戳的结果；预留一个小的过去
            # 时间段并按输入顺序递增，让批次内的最后结果保持稳定顺序，
            # 也不会把 dashboard 的 last_checked_at 推到未来。
            checked_at = generated_base + timedelta(microseconds=generated_sequence)
            generated_sequence += 1
        if item.checked_at is not None:
            sample_key = (monitor.id, checked_at)
            if sample_key in seen_checked_samples:
                continue
            duplicate = db.scalar(
                select(models.LinkMonitorSample.id).where(
                    models.LinkMonitorSample.monitor_id == monitor.id,
                    models.LinkMonitorSample.checked_at == checked_at,
                )
            )
            if duplicate is not None:
                continue
            seen_checked_samples.add(sample_key)
        db.add(
            models.LinkMonitorSample(
                monitor_id=monitor.id,
                checked_at=checked_at,
                success=item.success,
                latency_ms=item.latency_ms if item.success else None,
                error=item.error,
            )
        )
        previous_checked_at = last_checked_by_monitor.get(monitor.id)
        if previous_checked_at is None or checked_at > previous_checked_at:
            last_checked_by_monitor[monitor.id] = checked_at
        cleanup_cutoffs[monitor.id] = now - timedelta(days=monitor.retention_days)
        recorded_count += 1
        if not item.success:
            failed_count += 1
    for monitor_id, checked_at in last_checked_by_monitor.items():
        monitor = db.get(models.LinkMonitor, monitor_id)
        if monitor is not None:
            if monitor.last_checked_at is None or checked_at > monitor.last_checked_at:
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


app.include_router(ipam_router)
mount_web_panel()
