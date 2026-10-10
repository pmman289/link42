from __future__ import annotations

import base64
from functools import lru_cache
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.types import JSON, Text, TypeDecorator

from .config import settings


ENCRYPTED_PREFIX = "l42enc:v1:"
ASSOCIATED_DATA = b"link42-controller-secret:v1"
MAX_MASTER_KEY_FILE_BYTES = 4096


def decode_master_key(value: str) -> bytes:
    """解析 URL-safe base64 主密钥并要求其恰好为 256 位。"""

    try:
        key = base64.b64decode(value.strip().encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError("LINK42_MASTER_KEY must be URL-safe base64") from exc
    if len(key) != 32:
        raise RuntimeError("LINK42_MASTER_KEY must decode to exactly 32 bytes")
    return key


def master_key_path() -> Path:
    """返回独立于数据库目录的主密钥文件路径。"""

    configured = os.getenv("LINK42_MASTER_KEY_FILE", "").strip()
    return Path(configured) if configured else Path(settings.config_dir) / "master.key"


def _reject_symlink_components(path: Path) -> None:
    """拒绝主密钥路径中的符号链接组件，避免密钥被写到目录外。"""

    current = Path(path.anchor or "/")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    if not path.is_absolute():
        current = Path()
    for part in parts:
        current /= part
        if current.is_symlink():
            raise RuntimeError("Link42 master key path must not contain symbolic links")


def create_master_key_file(path: Path) -> bytes:
    """原子发布完整主密钥，并发启动时读取首先成功发布的密钥。"""

    key = secrets.token_bytes(32)
    encoded = base64.urlsafe_b64encode(key) + b"\n"
    _reject_symlink_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".master-key-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        # link() is exclusive and atomic: no worker can observe an empty or
        # partially written final key, and no existing key is ever replaced.
        try:
            os.link(temporary, path)
        except FileExistsError:
            return read_master_key_file(path)
    finally:
        temporary.unlink(missing_ok=True)
    return key


def read_master_key_file(path: Path) -> bytes:
    """有界读取普通密钥文件，FIFO 等特殊文件不得阻塞主控启动。"""

    _reject_symlink_components(path.parent)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("Link42 master key path must be a regular file") from exc
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("Link42 master key path must be a regular file")
        if metadata.st_size > MAX_MASTER_KEY_FILE_BYTES:
            raise RuntimeError("Link42 master key file is too large")
        os.fchmod(source.fileno(), 0o600)
        encoded_value = source.read(MAX_MASTER_KEY_FILE_BYTES + 1)
    if len(encoded_value) > MAX_MASTER_KEY_FILE_BYTES:
        raise RuntimeError("Link42 master key file is too large")
    try:
        return decode_master_key(encoded_value.decode("ascii"))
    except UnicodeDecodeError as exc:
        raise RuntimeError("Link42 master key file must be ASCII base64") from exc


@lru_cache(maxsize=1)
def load_master_key() -> bytes:
    """从环境变量或权限受限文件加载主密钥，缺失时安全生成。"""

    configured = os.getenv("LINK42_MASTER_KEY", "").strip()
    if configured:
        return decode_master_key(configured)
    path = master_key_path()
    _reject_symlink_components(path.parent)
    if not path.exists():
        return create_master_key_file(path)
    return read_master_key_file(path)


def encrypt_text(value: str) -> str:
    """使用 AES-256-GCM 加密文本并返回带版本前缀的存储值。"""

    if value.startswith(ENCRYPTED_PREFIX):
        return value
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(load_master_key()).encrypt(nonce, value.encode("utf-8"), ASSOCIATED_DATA)
    payload = base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")
    return f"{ENCRYPTED_PREFIX}{payload}"


def decrypt_text(value: str) -> str:
    """解密带版本前缀的文本；认证失败时拒绝返回任何内容。"""

    if not value.startswith(ENCRYPTED_PREFIX):
        return value
    try:
        payload = base64.urlsafe_b64decode(value.removeprefix(ENCRYPTED_PREFIX).encode("ascii"))
        return AESGCM(load_master_key()).decrypt(payload[:12], payload[12:], ASSOCIATED_DATA).decode("utf-8")
    except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError("encrypted database value authentication failed") from exc


class EncryptedText(TypeDecorator[str]):
    """在数据库边界透明加解密字符串的 SQLAlchemy 类型。"""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect) -> str | None:
        """写库前加密非空字符串。"""

        return encrypt_text(value) if value is not None else None

    def process_result_value(self, value: str | None, dialect) -> str | None:
        """读库后解密密文，并兼容启动迁移前的旧明文。"""

        return decrypt_text(value) if value is not None else None


class EncryptedJSON(TypeDecorator[Any]):
    """保留 JSON 结构并递归加密字符串，兼容数据库中的数字字段查询。"""

    impl = JSON
    cache_ok = True

    def process_bind_param(self, value: Any, dialect) -> Any:
        """写库前递归加密 JSON 中的字符串。"""

        return protect_json_value(value)

    def process_result_value(self, value: Any, dialect) -> Any:
        """读库后递归解密 JSON，并兼容早期整列密文。"""

        if isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX):
            decrypted = decrypt_text(value)
            # 早期版本对根节点字符串直接加密了原文，而对象/数组则
            # 保存为 JSON 文档。先按文档解析，失败时保留原始字符串，
            # 避免读取合法但非对象的历史 payload 触发 500。
            try:
                return json.loads(decrypted)
            except json.JSONDecodeError:
                return decrypted
        return reveal_json_value(value)


def protect_json_value(value: Any) -> Any:
    """递归加密 JSON 的字符串值，同时保留数字和布尔值供数据库查询。"""

    if isinstance(value, str):
        return encrypt_text(value)
    if isinstance(value, list):
        return [protect_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): protect_json_value(item) for key, item in value.items()}
    return value


def reveal_json_value(value: Any) -> Any:
    """递归解密 JSON 中由 Link42 保存的密文字符串。"""

    if isinstance(value, str):
        return decrypt_text(value)
    if isinstance(value, list):
        return [reveal_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: reveal_json_value(item) for key, item in value.items()}
    return value
