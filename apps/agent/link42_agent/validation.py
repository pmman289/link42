from __future__ import annotations

from pathlib import Path
import os
import re
import stat
import tempfile


INTERFACE_NAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,15}", flags=re.ASCII)
INSTANCE_NAME_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,63}", flags=re.ASCII)
MAX_EXISTING_FILE_BYTES = 4 * 1024 * 1024


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
    _reject_symlink_components(root_path)
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


def _reject_symlink_components(path: Path) -> None:
    """拒绝路径中已经存在的符号链接，避免受管根目录被替换后逃逸。"""

    current = Path(path.anchor or "/")
    relative_parts = path.parts[1:] if path.is_absolute() else path.parts
    if not path.is_absolute():
        current = Path()
        relative_parts = path.parts
    for part in relative_parts:
        current = current / part
        try:
            if current.is_symlink():
                raise ValueError("managed path must not contain symbolic links")
        except OSError as exc:
            raise ValueError("cannot inspect managed path") from exc


def ensure_managed_directory(path: str | Path, mode: int = 0o700) -> Path:
    """创建受管目录并在创建前后拒绝符号链接组件。"""

    directory = Path(path)
    _reject_symlink_components(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=mode)
    _reject_symlink_components(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("managed directory is invalid")
    return directory


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    """在目标目录内原子写入文本，避免跟随目标符号链接或留下半文件。"""

    _reject_symlink_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(content.encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_bytes(path: Path, content: bytes, mode: int = 0o600) -> None:
    """在目标目录内原子写入字节，避免跟随目标符号链接或留下半文件。"""

    _reject_symlink_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def read_existing_bytes(path: Path) -> bytes:
    """读取受管现有文件，并拒绝特殊文件、符号链接和超大内容。"""

    _reject_symlink_components(path.parent)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    # 非阻塞打开让 FIFO 等特殊文件可以被安全识别，而不会在 Agent 线程中永久等待。
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("managed file must be a regular file")
        if metadata.st_size > MAX_EXISTING_FILE_BYTES:
            raise ValueError("managed file is too large")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            content = source.read(MAX_EXISTING_FILE_BYTES + 1)
        if len(content) > MAX_EXISTING_FILE_BYTES:
            raise ValueError("managed file is too large")
        return content
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_existing_text(path: Path, encoding: str = "utf-8") -> str:
    """以不可跟随符号链接的方式读取受管文本文件。"""

    return read_existing_bytes(path).decode(encoding)
