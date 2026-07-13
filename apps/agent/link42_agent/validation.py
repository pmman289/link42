from __future__ import annotations

from pathlib import Path
import os
import re


INTERFACE_NAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,15}", flags=re.ASCII)
INSTANCE_NAME_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,63}", flags=re.ASCII)


def validate_interface_name(value: object, label: str = "interface name") -> str:
    """校验 Linux 接口名，阻止路径分隔符、Unicode 混淆和超长名称。"""

    name = str(value or "").strip()
    if name in {".", ".."} or not INTERFACE_NAME_PATTERN.fullmatch(name):
        raise ValueError(f"{label} contains unsupported characters or exceeds 15 characters")
    return name


def validate_instance_name(value: object, label: str = "instance name") -> str:
    """校验中间层实例名，确保其可安全用于配置键和服务单元名。"""

    name = str(value or "").strip()
    if name in {".", ".."} or not INSTANCE_NAME_PATTERN.fullmatch(name):
        raise ValueError(f"{label} contains unsupported characters or exceeds 63 characters")
    return name


def managed_child_path(root: str | Path, *parts: str) -> Path:
    """返回受管目录内的路径，并拒绝父目录或目标符号链接逃逸。"""

    root_path = Path(root)
    resolved_root = root_path.resolve(strict=False)
    candidate = root_path.joinpath(*parts)
    resolved_candidate = candidate.resolve(strict=False)
    if resolved_candidate == resolved_root or not resolved_candidate.is_relative_to(resolved_root):
        raise ValueError("managed path escapes configured directory")
    if candidate.is_symlink():
        raise ValueError("managed path must not be a symbolic link")
    current = root_path
    for part in parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise ValueError("managed path parent must not be a symbolic link")
    return candidate


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    """在目标目录内原子写入文本，避免跟随目标符号链接或留下半文件。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content.encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
