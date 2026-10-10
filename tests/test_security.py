from __future__ import annotations

import sqlite3
import time
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
import threading

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from link42_agent import gre, middleware, system
from link42_agent.validation import managed_child_path
from link42_api import models
from link42_api.database import Base, protect_sqlite_sensitive_values
from link42_api.http_security import RequestBodyLimitMiddleware
from link42_api.main import (
    LOGIN_FAILURES,
    SETTING_ADMIN_PASSWORD_HASH,
    SETTING_ADMIN_SESSION_HASH,
    SETTING_ADMIN_SESSION_ISSUED_AT,
    SETTING_ADMIN_SESSION_LAST_USED_AT,
    get_setting,
    login,
    login_rate_key,
    login_retry_after,
    record_login_failure,
    request_source_ip,
    require_web_session,
    set_setting,
)
from link42_api.secret_store import create_master_key_file, decrypt_text, encrypt_text, load_master_key


@pytest.mark.parametrize("operation", ["load_master_key", "create_master_key_file"])
def test_master_key_fifo_is_rejected_without_blocking(tmp_path, operation):
    path = tmp_path / "master.key"
    os.mkfifo(path)
    child_env = os.environ.copy()
    child_env.pop("LINK42_MASTER_KEY", None)
    child_env["LINK42_MASTER_KEY_FILE"] = str(path)
    child_env["PYTHONPATH"] = os.pathsep.join(sys.path)
    script = '''
from pathlib import Path
import sys
from link42_api import secret_store
try:
    if sys.argv[1] == "load_master_key":
        secret_store.load_master_key()
    else:
        secret_store.create_master_key_file(Path(sys.argv[2]))
except RuntimeError as exc:
    assert "regular file" in str(exc)
else:
    raise AssertionError("FIFO accepted")
'''
    result = subprocess.run([sys.executable, "-c", script, operation, str(path)],
                            env=child_env, capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr


def test_master_key_creation_publishes_only_complete_key(tmp_path, monkeypatch):
    from link42_api import secret_store

    path = tmp_path / "master.key"
    creator_paused = threading.Event()
    creator_resume = threading.Event()
    actual_fsync = secret_store.os.fsync

    def pause_first_writer(descriptor):
        actual_fsync(descriptor)
        if threading.current_thread().name.startswith("key-creator"):
            creator_paused.set()
            assert creator_resume.wait(3)

    monkeypatch.setattr(secret_store.os, "fsync", pause_first_writer)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="key-creator") as executor:
        pending = executor.submit(create_master_key_file, path)
        try:
            assert creator_paused.wait(3)
            assert not path.exists(), "incomplete key was published"
            winner = create_master_key_file(path)
        finally:
            creator_resume.set()
        assert pending.result(timeout=3) == winner
    assert path.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.iterdir()) == [path]
from link42_api.schemas import AgentTaskStatusRead, ChangePlanRead, LoginRequest
from link42_common.security import hash_password, hash_token, verify_password


def request_with_cookie(token: str) -> Request:
    """构造带 Web 会话 Cookie 的最小测试请求。"""

    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/auth/me",
            "headers": [(b"cookie", f"link42_session={token}".encode("ascii"))],
            "client": ("127.0.0.1", 12345),
            "scheme": "http",
            "server": ("testserver", 80),
        }
    )


def request_from(client_ip: str, headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    """构造指定直连来源和请求头的测试请求。"""

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/auth/login",
            "headers": headers or [],
            "client": (client_ip, 12345),
            "scheme": "http",
            "server": ("testserver", 80),
        }
    )


def test_password_hash_uses_salted_argon2id() -> None:
    """验证相同密码生成不同的 Argon2id 哈希并可正常校验。"""

    first = hash_password("correct horse battery staple")
    second = hash_password("correct horse battery staple")

    assert first.startswith("$argon2id$")
    assert second.startswith("$argon2id$")
    assert first != second
    assert verify_password("correct horse battery staple", first)
    assert not verify_password("wrong", first)


def test_successful_login_migrates_legacy_password_hash() -> None:
    """验证旧 SHA-256 密码在成功登录时无感迁移到 Argon2id。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        set_setting(session, SETTING_ADMIN_PASSWORD_HASH, hash_token("legacy-password"))
        session.commit()
        login(LoginRequest(username="pmman", password="legacy-password"), session)
        migrated = get_setting(session, SETTING_ADMIN_PASSWORD_HASH)

    assert migrated is not None
    assert migrated.startswith("$argon2id$")


def test_expired_web_session_is_revoked(monkeypatch) -> None:
    """验证超过绝对有效期的正确 Token 也会被服务端拒绝并吊销。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main.settings, "web_session_absolute_seconds", 60)
    monkeypatch.setattr(api_main.settings, "web_session_idle_seconds", 60)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    token = "l42web_test_session"
    with Session(engine) as session:
        set_setting(session, SETTING_ADMIN_SESSION_HASH, hash_token(token))
        set_setting(session, SETTING_ADMIN_SESSION_ISSUED_AT, str(time.time() - 120))
        set_setting(session, SETTING_ADMIN_SESSION_LAST_USED_AT, str(time.time()))
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            require_web_session(request_with_cookie(token), session)

        assert exc_info.value.status_code == 401
        assert get_setting(session, SETTING_ADMIN_SESSION_HASH) == ""


def test_request_body_limit_rejects_before_endpoint_reads_body() -> None:
    """验证登录接口超大请求体由 ASGI 层直接返回 413。"""

    limited_app = FastAPI()
    limited_app.add_middleware(RequestBodyLimitMiddleware)

    @limited_app.post("/api/auth/login")
    async def consume(request: Request) -> dict[str, int]:
        """返回已读取大小，正常请求用于确认中间件可回放请求体。"""

        return {"size": len(await request.body())}

    client = TestClient(limited_app)
    assert client.post("/api/auth/login", content=b"x" * 1024).json() == {"size": 1024}
    assert client.post("/api/auth/login", content=b"x" * (16 * 1024 + 1)).status_code == 413


def test_login_failures_are_rate_limited() -> None:
    """验证同一来源和账号连续失败达到阈值后进入限流窗口。"""

    LOGIN_FAILURES.clear()
    key = login_rate_key(request_from("198.51.100.10"), "pmman")
    for _ in range(5):
        record_login_failure(key)

    assert login_retry_after(key) > 0
    LOGIN_FAILURES.clear()


def test_untrusted_client_cannot_spoof_forwarded_source(monkeypatch) -> None:
    """验证直连请求伪造 X-Forwarded-For 时仍使用 TCP 来源地址。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main.settings, "trusted_proxy_cidrs", "10.0.0.0/8")
    request = request_from("198.51.100.20", [(b"x-forwarded-for", b"203.0.113.9")])

    assert request_source_ip(request) == "198.51.100.20"


def test_database_sensitive_values_are_not_plaintext(tmp_path) -> None:
    """验证 WireGuard 密钥、配置和任务字符串在原始 SQLite 中均为认证密文。"""

    database_path = tmp_path / "encrypted.db"
    engine = create_engine(f"sqlite:///{database_path}")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="agent-hash")
        interface = models.WireGuardInterface(
            node=node,
            name="wg0",
            private_key_value="private-secret",
            deployed_config="PrivateKey = private-secret\n",
        )
        task = models.AgentTask(
            node=node,
            type="wireguard.apply_config",
            payload={"interface_id": 7, "config": "PrivateKey = task-secret"},
            result={"stdout": "result-secret"},
        )
        session.add_all([node, interface, task])
        session.commit()

    with sqlite3.connect(database_path) as connection:
        interface_row = connection.execute(
            "SELECT private_key_value, deployed_config FROM wg_interfaces"
        ).fetchone()
        task_row = connection.execute("SELECT payload, result FROM agent_tasks").fetchone()

    raw = " ".join(str(value) for value in (*interface_row, *task_row))
    assert "private-secret" not in raw
    assert "task-secret" not in raw
    assert "result-secret" not in raw
    assert "l42enc:v1:" in raw
    assert '"interface_id": 7' in task_row[0]


def test_encrypted_value_fails_closed_with_wrong_master_key(monkeypatch) -> None:
    """验证主密钥不匹配时认证解密失败，不返回伪造或空白内容。"""

    original = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
    monkeypatch.setenv("LINK42_MASTER_KEY", original)
    load_master_key.cache_clear()

    encrypted = encrypt_text("secret")
    monkeypatch.setenv("LINK42_MASTER_KEY", "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=")
    load_master_key.cache_clear()
    with pytest.raises(RuntimeError, match="authentication failed"):
        decrypt_text(encrypted)
    monkeypatch.setenv("LINK42_MASTER_KEY", original)
    load_master_key.cache_clear()


def test_master_key_file_has_bounded_size(tmp_path, monkeypatch) -> None:
    """异常大的主密钥文件不能被一次性读入内存。"""

    path = tmp_path / "master.key"
    path.write_bytes(b"A" * 5000)
    monkeypatch.delenv("LINK42_MASTER_KEY", raising=False)
    monkeypatch.setenv("LINK42_MASTER_KEY_FILE", str(path))
    load_master_key.cache_clear()
    with pytest.raises(RuntimeError, match="too large"):
        load_master_key()
    load_master_key.cache_clear()


def test_legacy_database_token_is_cleared_and_secret_is_encrypted(tmp_path) -> None:
    """验证旧数据库迁移会清除 Agent 明文 Token 并加密 WireGuard 私钥。"""

    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE nodes (id INTEGER PRIMARY KEY, agent_token_value TEXT)")
        connection.execute("CREATE TABLE wg_interfaces (id INTEGER PRIMARY KEY, private_key_value TEXT)")
        connection.execute("INSERT INTO nodes VALUES (1, 'l42agent_legacy_secret_value')")
        connection.execute("INSERT INTO wg_interfaces VALUES (1, 'legacy-private-key')")
        connection.commit()

    protect_sqlite_sensitive_values(path)

    with sqlite3.connect(path) as connection:
        token = connection.execute("SELECT agent_token_value FROM nodes").fetchone()[0]
        private_key = connection.execute("SELECT private_key_value FROM wg_interfaces").fetchone()[0]
    assert token is None
    assert private_key.startswith("l42enc:v1:")
    assert "legacy-private-key" not in private_key


def test_web_response_models_redact_wireguard_secrets() -> None:
    """验证部署计划和任务状态响应不会返回 WireGuard 密钥正文。"""

    plan = ChangePlanRead(
        id=1,
        title="test",
        status="draft",
        summary="test",
        affected_node_ids=[1],
        diff="+PrivateKey = private-secret\n+PresharedKey = psk-secret\n",
        confirmed_at=None,
        task_result={"config": "PrivateKey = result-secret\n"},
    )
    task = AgentTaskStatusRead(
        id=1,
        node_id=1,
        type="wireguard.read_config",
        status="succeeded",
        result={"private_key": "field-secret", "config": "PresharedKey = config-secret\n"},
    )

    serialized = f"{plan.model_dump_json()} {task.model_dump_json()}"
    assert "private-secret" not in serialized
    assert "psk-secret" not in serialized
    assert "result-secret" not in serialized
    assert "field-secret" not in serialized
    assert "config-secret" not in serialized
    assert "<REDACTED>" in serialized


@pytest.mark.parametrize("name", ["../outside", "/absolute", ".", "..", "a" * 16, "接口"])
def test_agent_handlers_reject_unsafe_interface_names(name, tmp_path) -> None:
    """验证绕过主控直接调用 Agent handler 时仍会拒绝不安全接口名。"""

    with pytest.raises(ValueError):
        system.read_wireguard_config({"interface_name": name}, str(tmp_path / "wireguard"))
    with pytest.raises(ValueError):
        gre.write_gre_config({"interface_name": name}, str(tmp_path / "gre"))
    assert not (tmp_path / "outside.conf").exists()


def test_agent_rejects_symlink_escape(tmp_path) -> None:
    """验证受管目录中的符号链接不能把文件操作引向目录外部。"""

    root = tmp_path / "managed"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "nested").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="managed path"):
        managed_child_path(root, "nested", "config.conf")


def test_master_key_rejects_symlinked_parent(tmp_path) -> None:
    """主密钥生成不能跟随配置目录中的符号链接。"""

    outside = tmp_path / "outside"
    outside.mkdir()
    config = tmp_path / "config"
    config.mkdir()
    (config / "keys").symlink_to(outside, target_is_directory=True)
    with pytest.raises(RuntimeError, match="symbolic links"):
        create_master_key_file(config / "keys" / "master.key")
    assert not (outside / "master.key").exists()


def test_udp2raw_handler_rejects_unsafe_instance_name() -> None:
    """验证 udp2raw 删除入口不会接受可注入服务名或配置行的实例名。"""

    with pytest.raises(ValueError):
        middleware.delete_udp2raw({"instance": "../bad", "mode": "client"}, dry_run=True)
