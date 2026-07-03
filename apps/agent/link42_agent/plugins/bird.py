from __future__ import annotations

from datetime import datetime
import hashlib
import os
import shutil
from pathlib import Path
from typing import Any

from ..system import run_command
from .base import AgentNodePlugin, AgentPluginContext


BIRD_ROOT = Path("/etc/bird")
BIRD_LEGACY_MAIN = Path("/etc/bird.conf")
BIRD_DEFAULT_MAIN = BIRD_ROOT / "bird.conf"
BIRD_BACKUP_DIR = Path("/var/lib/link42/backups/bird")
BIRD_MAX_FILE_BYTES = 512 * 1024


class BirdAgentPlugin(AgentNodePlugin):
    """Edit and validate BIRD configuration files on a node."""

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
        return bird_detect()

    def execute(self, action: str, payload: dict[str, Any], context: AgentPluginContext) -> dict[str, Any]:
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
    return [BIRD_LEGACY_MAIN, BIRD_ROOT]


def default_main_config() -> Path | None:
    if BIRD_DEFAULT_MAIN.exists():
        return BIRD_DEFAULT_MAIN
    if BIRD_LEGACY_MAIN.exists():
        return BIRD_LEGACY_MAIN
    return BIRD_DEFAULT_MAIN if BIRD_ROOT.exists() else None


def bird_detect() -> dict[str, Any]:
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
    if not resource_key:
        raise ValueError("resource_key is required")
    path = Path(resource_key)
    if not path.is_absolute():
        raise ValueError("resource_key must be an absolute path")
    resolved = path.resolve()
    if resolved == BIRD_LEGACY_MAIN.resolve():
        return resolved
    root = BIRD_ROOT.resolve()
    if resolved == root or root not in resolved.parents:
        raise ValueError("resource is outside BIRD configuration roots")
    if not is_bird_config_file(resolved):
        raise ValueError("resource is not a BIRD configuration file")
    return resolved


def is_bird_config_file(path: Path) -> bool:
    """Return whether a path is an editable BIRD config file."""

    try:
        resolved = path.resolve()
    except FileNotFoundError:
        resolved = path
    if resolved == BIRD_LEGACY_MAIN.resolve() or resolved == BIRD_DEFAULT_MAIN.resolve():
        return True
    return resolved.suffix == ".conf"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_text_limited(path: Path) -> str:
    if path.stat().st_size > BIRD_MAX_FILE_BYTES:
        raise ValueError("BIRD config file is too large")
    return path.read_text(encoding="utf-8", errors="replace")


def bird_resource(path: Path) -> dict[str, Any]:
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
    path = resolve_bird_resource(resource_key)
    if not path.is_file():
        raise ValueError("BIRD resource is not a file")
    return {
        **bird_resource(path),
        "content": read_text_limited(path),
    }


def run_bird_config_check(main_config: Path | None = None) -> dict[str, Any]:
    main = main_config or default_main_config()
    if main is None:
        raise ValueError("BIRD main config was not found")
    return run_command(["bird", "-p", "-c", str(main)], allow_failure=True)


def run_bird_configure() -> dict[str, Any]:
    if not shutil.which("birdc"):
        return {
            "command": ["birdc", "configure"],
            "returncode": 127,
            "stdout": "",
            "stderr": "birdc was not found",
        }
    return run_command(["birdc", "configure"], allow_failure=True)


def validate_bird_resource(resource_key: str, content: str, dry_run: bool = False) -> dict[str, Any]:
    path = resolve_bird_resource(resource_key)
    if dry_run:
        return {"valid": True, "dry_run": True, "resource_key": str(path)}
    if not path.exists():
        raise ValueError("BIRD resource does not exist")
    original_stat = path.stat()
    original = path.read_bytes()
    try:
        path.write_text(content, encoding="utf-8")
        result = run_bird_config_check()
    finally:
        path.write_bytes(original)
        os.chown(path, original_stat.st_uid, original_stat.st_gid)
        os.chmod(path, original_stat.st_mode)
        os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    return {
        "valid": result["returncode"] == 0,
        "resource_key": str(path),
        "check": result,
    }


def bird_backup_path(path: Path) -> Path:
    BIRD_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    safe_name = str(path).strip("/").replace("/", "__")
    return BIRD_BACKUP_DIR / f"{safe_name}.{stamp}.bak"


def apply_bird_resource(
    resource_key: str,
    content: str,
    base_sha256: str | None,
    *,
    reload: bool,
    dry_run: bool,
) -> dict[str, Any]:
    path = resolve_bird_resource(resource_key)
    if not path.exists() or not path.is_file():
        raise ValueError("BIRD resource does not exist")
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
    shutil.copy2(path, backup)
    path.write_text(content, encoding="utf-8")
    check = run_bird_config_check()
    if check["returncode"] != 0:
        shutil.copy2(backup, path)
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
            shutil.copy2(backup, path)
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


def apply_bird_resources(files: list[Any], *, reload: bool, dry_run: bool) -> dict[str, Any]:
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
        current_sha = file_sha256(path)
        base_sha = str(item.get("base_sha256") or "") or None
        if base_sha and current_sha != base_sha:
            raise ValueError(f"BIRD resource changed on node: {path}")
        content = item.get("content")
        if not isinstance(content, str):
            raise ValueError("BIRD resource content must be a string")
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
            shutil.copy2(path, backup)
            backups[path] = backup
            path.write_text(change["content"], encoding="utf-8")
        check = run_bird_config_check()
        if check["returncode"] != 0:
            for path, backup in backups.items():
                shutil.copy2(backup, path)
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
                    shutil.copy2(backup, path)
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
                shutil.copy2(backup, path)
        raise


def bird_status() -> dict[str, Any]:
    status_result = run_command(["birdc", "show", "status"], allow_failure=True) if shutil.which("birdc") else None
    return {
        "plugin_type": "bird",
        "detect": bird_detect(),
        "status": status_result,
    }
