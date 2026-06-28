from __future__ import annotations

import hashlib
import hmac
import secrets


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
