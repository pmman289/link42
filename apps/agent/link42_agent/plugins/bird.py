from __future__ import annotations

from datetime import datetime
import hashlib
import os
import shutil
import secrets
import stat as stat_module
from pathlib import Path
from typing import Any

from ..system import run_command
from ..validation import atomic_write_bytes, ensure_managed_directory, read_existing_bytes
from .base import AgentNodePlugin, AgentPluginContext


BIRD_ROOT = Path("/etc/bird")
BIRD_LEGACY_MAIN = Path("/etc/bird.conf")
BIRD_DEFAULT_MAIN = BIRD_ROOT / "bird.conf"
BIRD_BACKUP_DIR = Path("/var/lib/link42/backups/bird")
BIRD_MAX_FILE_BYTES = 512 * 1024


def write_existing_file(path: Path, content: bytes) -> None:
    """写入既有 BIRD 文件且拒绝在检查后跟随被替换的符号链接。"""

    flags = os.O_WRONLY | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        if not stat_module.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("BIRD resource must be a regular file")
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class BirdAgentPlugin(AgentNodePlugin):
    """在节点本机编辑、校验并应用 BIRD 配置文件的插件。"""

    type = "bird"
    capabilities = [
        "node_plugin",
        "node_plugin.bird",
        "node_plugin.bird.list",
        "node_plugin.bird.read",
        "node_plugin.bird.validate",
        "node_plugin.bird.apply",
        "node_plugin.bird.apply_many",
        "node_plugin.bird.status",
    ]
    actions = {"list", "read", "validate", "apply", "apply_many", "status"}

    def detect(self, context: AgentPluginContext) -> dict[str, Any]:
        """检测 BIRD 和 birdc 命令是否存在。"""

        return bird_detect()

    def execute(self, action: str, payload: dict[str, Any], context: AgentPluginContext) -> dict[str, Any]:
        """根据 action 执行 BIRD 配置列表、读取、校验或应用。"""

        if action == "list":
            return list_bird_resources()
        if action == "read":
            return read_bird_resource(str(payload.get("resource_key") or ""))
        if action == "validate":
            return validate_bird_resource(
                str(payload.get("resource_key") or ""),
                str(payload.get("content") or ""),
                dry_run=context.config.dry_run,
            )
        if action == "apply":
            return apply_bird_resource(
                str(payload.get("resource_key") or ""),
                str(payload.get("content") or ""),
                str(payload.get("base_sha256") or "") or None,
                reload=bool(payload.get("reload", True)),
                dry_run=context.config.dry_run,
            )
        if action == "apply_many":
            return apply_bird_resources(
                payload.get("files") if isinstance(payload.get("files"), list) else [],
                reload=bool(payload.get("reload", True)),
                dry_run=context.config.dry_run,
            )
        if action == "status":
            return bird_status()
        raise ValueError(f"unsupported bird action: {action}")


def bird_roots() -> list[Path]:
    """返回 Link42 允许浏览和编辑的 BIRD 配置根路径。"""

    return [BIRD_LEGACY_MAIN, BIRD_ROOT]


def default_main_config() -> Path | None:
    """按常见发行版路径选择默认 BIRD 主配置文件。"""

    if BIRD_DEFAULT_MAIN.exists():
        return BIRD_DEFAULT_MAIN
    if BIRD_LEGACY_MAIN.exists():
        return BIRD_LEGACY_MAIN
    return BIRD_DEFAULT_MAIN if BIRD_ROOT.exists() else None


def bird_detect() -> dict[str, Any]:
    """返回节点上的 BIRD 插件可用性和配置根信息。"""

    bird_binary = shutil.which("bird")
    return {
        "plugin_type": "bird",
        "available": bool(bird_binary),
        "bird_binary": bird_binary,
        "birdc_binary": shutil.which("birdc"),
        "main_config": str(default_main_config()) if default_main_config() else None,
        "roots": [str(path) for path in bird_roots() if path.exists()],
    }


def resolve_bird_resource(resource_key: str) -> Path:
    """校验并解析前端传入的 BIRD 配置资源路径。"""

    if not resource_key:
        raise ValueError("resource_key is required")
    path = Path(resource_key)
    if not path.is_absolute():
        raise ValueError("resource_key must be an absolute path")
    root = BIRD_ROOT.resolve()
    # /etc/bird.conf is a supported legacy location, and some distributions
    # make it a symlink into /etc/bird.  Do not let an arbitrary symlink at
    # that location turn the legacy exception into access to /etc/shadow or
    # another unrelated file.
    if path == BIRD_LEGACY_MAIN:
        resolved = path.resolve()
        if path.is_symlink() and resolved != root and root not in resolved.parents:
            raise ValueError("legacy BIRD resource must resolve inside BIRD configuration roots")
        return resolved
    resolved = path.resolve()
    if resolved == root or root not in resolved.parents:
        raise ValueError("resource is outside BIRD configuration roots")
    if not is_bird_config_file(resolved):
        raise ValueError("resource is not a BIRD configuration file")
    return resolved


def is_bird_config_file(path: Path) -> bool:
    """判断路径是否属于可编辑的 BIRD 配置文件。"""

    try:
        resolved = path.resolve()
    except FileNotFoundError:
        resolved = path
    if path == BIRD_LEGACY_MAIN:
        return True
    if resolved == BIRD_DEFAULT_MAIN.resolve():
        return True
    return resolved.suffix == ".conf"


def file_sha256(path: Path) -> str:
    """计算配置文件当前 sha256，用于并发修改检测。"""

    ensure_bird_file_size(path)
    content = read_existing_bytes(path)
    if len(content) > BIRD_MAX_FILE_BYTES:
        raise ValueError("BIRD config file is too large")
    return hashlib.sha256(content).hexdigest()


def read_text_limited(path: Path) -> str:
    """读取文本配置并限制最大文件大小。"""

    ensure_bird_file_size(path)
    content = read_existing_bytes(path)
    return content.decode("utf-8", errors="replace")


def ensure_bird_file_size(path: Path) -> None:
    """限制需要完整读入内存的 BIRD 文件大小。"""

    metadata = path.stat()
    if not stat_module.S_ISREG(metadata.st_mode):
        raise ValueError("BIRD resource must be a regular file")
    if metadata.st_size > BIRD_MAX_FILE_BYTES:
        raise ValueError("BIRD config file is too large")


def bird_resource(path: Path) -> dict[str, Any]:
    """把单个 BIRD 配置文件转换为前端文件树需要的资源描述。"""

    stat = path.stat()
    return {
        "resource_key": str(path),
        "path": str(path),
        "name": path.name,
        "size": stat.st_size,
        "sha256": file_sha256(path),
        "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "editable": path.is_file(),
        "is_main": default_main_config() == path,
    }


def list_bird_resources() -> dict[str, Any]:
    """递归列出允许编辑的 BIRD 配置文件。"""

    files: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for root in bird_roots():
        if root.is_file():
            resolved = root.resolve()
            if resolved not in seen:
                files.append(bird_resource(resolved))
                seen.add(resolved)
        elif root.is_dir():
            for path in sorted(item for item in root.rglob("*") if item.is_file()):
                resolved = path.resolve()
                if resolved in seen:
                    continue
                if not is_bird_config_file(resolved):
                    continue
                resolve_bird_resource(str(resolved))
                files.append(bird_resource(resolved))
                seen.add(resolved)
    return {
        "plugin_type": "bird",
        "main_config": str(default_main_config()) if default_main_config() else None,
        "roots": [str(path) for path in bird_roots() if path.exists()],
        "files": files,
    }


def read_bird_resource(resource_key: str) -> dict[str, Any]:
    """读取单个 BIRD 配置文件内容和元数据。"""

    path = resolve_bird_resource(resource_key)
    if not path.is_file():
        raise ValueError("BIRD resource is not a file")
    return {
        **bird_resource(path),
        "content": read_text_limited(path),
    }


def run_bird_config_check(main_config: Path | None = None) -> dict[str, Any]:
    """调用 bird -p 校验当前主配置和 include 文件。"""

    main = main_config or default_main_config()
    if main is None:
        raise ValueError("BIRD main config was not found")
    return run_command(["bird", "-p", "-c", str(main)], allow_failure=True)


def run_bird_configure() -> dict[str, Any]:
    """调用 birdc configure 让运行中的 BIRD 重新加载配置。"""

    if not shutil.which("birdc"):
        return {
            "command": ["birdc", "configure"],
            "returncode": 127,
            "stdout": "",
            "stderr": "birdc was not found",
        }
    return run_command(["birdc", "configure"], allow_failure=True)


def validate_bird_resource(resource_key: str, content: str, dry_run: bool = False) -> dict[str, Any]:
    """临时写入指定文件内容并校验完整 BIRD 配置，随后恢复原文件元数据。"""

    path = resolve_bird_resource(resource_key)
    if len(content.encode("utf-8")) > BIRD_MAX_FILE_BYTES:
        raise ValueError("BIRD config content is too large")
    if dry_run:
        return {"valid": True, "dry_run": True, "resource_key": str(path)}
    if not path.exists():
        raise ValueError("BIRD resource does not exist")
    ensure_bird_file_size(path)
    original_stat = path.stat()
    original = read_existing_bytes(path)
    try:
        write_existing_file(path, content.encode("utf-8"))
        result = run_bird_config_check()
    finally:
        write_existing_file(path, original)
        os.chown(path, original_stat.st_uid, original_stat.st_gid)
        os.chmod(path, original_stat.st_mode)
        os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    return {
        "valid": result["returncode"] == 0,
        "resource_key": str(path),
        "check": result,
    }


def bird_backup_path(path: Path) -> Path:
    """生成当前配置文件的带时间戳备份路径。"""

    ensure_managed_directory(BIRD_BACKUP_DIR, mode=0o700)
    os.chmod(BIRD_BACKUP_DIR, 0o700)
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    safe_name = str(path).strip("/").replace("/", "__")
    return BIRD_BACKUP_DIR / f"{safe_name}.{stamp}.{secrets.token_hex(8)}.bak"


def apply_bird_resource(
    resource_key: str,
    content: str,
    base_sha256: str | None,
    *,
    reload: bool,
    dry_run: bool,
) -> dict[str, Any]:
    """应用单个 BIRD 配置文件，校验或 reload 失败时恢复备份。"""

    path = resolve_bird_resource(resource_key)
    if len(content.encode("utf-8")) > BIRD_MAX_FILE_BYTES:
        raise ValueError("BIRD config content is too large")
    if not path.exists() or not path.is_file():
        raise ValueError("BIRD resource does not exist")
    ensure_bird_file_size(path)
    current_sha = file_sha256(path)
    if base_sha256 and current_sha != base_sha256:
        raise ValueError("BIRD resource changed on node, please read it again")
    if dry_run:
        return {
            "applied": False,
            "dry_run": True,
            "resource_key": str(path),
            "sha256": current_sha,
        }

    backup = bird_backup_path(path)
    atomic_write_bytes(backup, read_existing_bytes(path), mode=0o600)
    try:
        write_existing_file(path, content.encode("utf-8"))
        check = run_bird_config_check()
        if check["returncode"] != 0:
            write_existing_file(path, read_existing_bytes(backup))
            return {
                "applied": False,
                "valid": False,
                "resource_key": str(path),
                "backup_ref": str(backup),
                "check": check,
                "restored": True,
            }
        reload_result = None
        if reload:
            reload_result = run_bird_configure()
            if reload_result["returncode"] != 0:
                write_existing_file(path, read_existing_bytes(backup))
                return {
                    "applied": False,
                    "valid": True,
                    "resource_key": str(path),
                    "backup_ref": str(backup),
                    "check": check,
                    "reload": reload_result,
                    "restored": True,
                }
        return {
            "applied": True,
            "valid": True,
            "resource_key": str(path),
            "sha256": file_sha256(path),
            "backup_ref": str(backup),
            "check": check,
            "reload": reload_result,
        }
    except Exception:
        if backup.exists():
            write_existing_file(path, read_existing_bytes(backup))
        raise


def apply_bird_resources(files: list[Any], *, reload: bool, dry_run: bool) -> dict[str, Any]:
    """一次性应用多个 BIRD 配置文件，并在整体校验失败时全部回滚。"""

    if not files:
        raise ValueError("BIRD resources are required")
    changes: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("BIRD resource entry must be an object")
        path = resolve_bird_resource(str(item.get("resource_key") or ""))
        if path in seen:
            raise ValueError(f"duplicate BIRD resource: {path}")
        seen.add(path)
        if not path.exists() or not path.is_file():
            raise ValueError(f"BIRD resource does not exist: {path}")
        ensure_bird_file_size(path)
        current_sha = file_sha256(path)
        base_sha = str(item.get("base_sha256") or "") or None
        if base_sha and current_sha != base_sha:
            raise ValueError(f"BIRD resource changed on node: {path}")
        content = item.get("content")
        if not isinstance(content, str):
            raise ValueError("BIRD resource content must be a string")
        if len(content.encode("utf-8")) > BIRD_MAX_FILE_BYTES:
            raise ValueError("BIRD config content is too large")
        changes.append({
            "path": path,
            "content": content,
            "sha256": current_sha,
        })
    if dry_run:
        return {
            "applied": False,
            "dry_run": True,
            "files": [{"resource_key": str(change["path"]), "sha256": change["sha256"]} for change in changes],
        }

    backups: dict[Path, Path] = {}
    try:
        for change in changes:
            path = change["path"]
            backup = bird_backup_path(path)
            atomic_write_bytes(backup, read_existing_bytes(path), mode=0o600)
            backups[path] = backup
            write_existing_file(path, change["content"].encode("utf-8"))
        check = run_bird_config_check()
        if check["returncode"] != 0:
            for path, backup in backups.items():
                write_existing_file(path, read_existing_bytes(backup))
            return {
                "applied": False,
                "valid": False,
                "files": [{"resource_key": str(change["path"])} for change in changes],
                "backups": {str(path): str(backup) for path, backup in backups.items()},
                "check": check,
                "restored": True,
            }
        reload_result = None
        if reload:
            reload_result = run_bird_configure()
            if reload_result["returncode"] != 0:
                for path, backup in backups.items():
                    write_existing_file(path, read_existing_bytes(backup))
                return {
                    "applied": False,
                    "valid": True,
                    "files": [{"resource_key": str(change["path"])} for change in changes],
                    "backups": {str(path): str(backup) for path, backup in backups.items()},
                    "check": check,
                    "reload": reload_result,
                    "restored": True,
                }
        return {
            "applied": True,
            "valid": True,
            "files": [
                {
                    "resource_key": str(change["path"]),
                    "sha256": file_sha256(change["path"]),
                    "backup_ref": str(backups[change["path"]]),
                }
                for change in changes
            ],
            "check": check,
            "reload": reload_result,
        }
    except Exception:
        for path, backup in backups.items():
            if backup.exists():
                write_existing_file(path, read_existing_bytes(backup))
        raise


def bird_status() -> dict[str, Any]:
    """返回 BIRD 插件检测结果和 birdc show status 输出。"""

    status_result = run_command(["birdc", "show", "status"], allow_failure=True) if shutil.which("birdc") else None
    return {
        "plugin_type": "bird",
        "detect": bird_detect(),
        "status": status_result,
    }
