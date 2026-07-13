from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


PASSWORD_HASHER = PasswordHasher()


def generate_token(prefix: str = "l42") -> str:
    """生成带前缀的随机 token，便于区分用途。"""
    # token 只在创建时明文返回给用户，服务端落库时必须存 hash。
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def hash_token(token: str) -> str:
    """对 token 做不可逆 hash，避免服务端保存明文凭据。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(token: str, token_hash: str) -> bool:
    """使用恒定时间比较验证 token，降低时序侧信道风险。"""
    return hmac.compare_digest(hash_token(token), token_hash)


def hash_password(password: str) -> str:
    """使用带随机盐的 Argon2id 保存管理员密码。"""

    return PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """验证管理员密码，并兼容升级前的 SHA-256 哈希。"""

    if password_hash.startswith("$argon2"):
        try:
            return PASSWORD_HASHER.verify(password_hash, password)
        except (InvalidHashError, VerificationError, VerifyMismatchError):
            return False
    if len(password_hash) == 64 and all(character in "0123456789abcdef" for character in password_hash.lower()):
        return verify_token(password, password_hash)
    return False


def password_hash_needs_update(password_hash: str) -> bool:
    """判断密码哈希是否需要从旧算法或旧参数迁移。"""

    if not password_hash.startswith("$argon2"):
        return True
    try:
        return PASSWORD_HASHER.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True
