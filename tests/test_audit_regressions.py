"""Regression coverage for issues reproduced during the project audit."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import threading

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from link42_api import main, models, schemas
from link42_api.database import Base
from link42_api.wireguard_service import split_endpoint
from link42_agent import middleware
from link42_agent.validation import MAX_EXISTING_FILE_BYTES, atomic_write_text, read_existing_bytes


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        yield db
    engine.dispose()


@pytest.mark.parametrize("database_relative_path", ["data/link42.db", "custom/nested/controller.db"])
def test_fresh_startup_creates_database_directory_in_empty_runtime(tmp_path, database_relative_path):
    """模拟空宿主机目录覆盖镜像 /link42 后，完整首次启动及重启都应成功。"""

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    path = runtime / database_relative_path
    config = runtime / "config"
    env = {key: value for key, value in os.environ.items() if not key.startswith("LINK42_")}
    project = Path(__file__).resolve().parents[1]
    env.update({
        "PYTHONPATH": os.pathsep.join(str(project / directory) for directory in ["apps/api", "apps/agent", "packages"]),
        "LINK42_DATABASE_URL": f"sqlite:///{path}",
        "LINK42_CONFIG_DIR": str(config),
        "LINK42_AGENT_RELEASE_DIR": str(tmp_path / "no-releases"),
    })
    script = """
from link42_api.main import on_startup, SETTING_CONTROLLER_VERSION, get_setting
from link42_api.database import SessionLocal
from link42_common.version import CONTROLLER_VERSION
on_startup()
with SessionLocal() as db:
    assert get_setting(db, SETTING_CONTROLLER_VERSION) == CONTROLLER_VERSION
"""
    assert list(runtime.iterdir()) == []
    result = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert path.is_file()
    assert (config / "master.key").is_file()
    credentials = (config / "initial-admin-password").read_bytes()
    master_key = (config / "master.key").read_bytes()
    restarted = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=15)
    assert restarted.returncode == 0, restarted.stderr
    assert (config / "master.key").read_bytes() == master_key
    assert (config / "initial-admin-password").read_bytes() == credentials


def test_startup_upgrades_existing_looking_glass_and_connection_tables(monkeypatch):
    """已存在的新协议/插件表也需要补列，且升级不能丢失已有记录。"""

    from link42_api import database

    engine = create_engine("sqlite:///:memory:")
    monkeypatch.setattr(database, "engine", engine)
    Base.metadata.create_all(engine)
    removed_columns = {
        "integration_api_keys": ["allowed_node_ids", "last_used_ip", "revoked_at"],
        "looking_glass_queries": ["error_code", "error_message", "deadline_at", "expires_at"],
        "connections": ["source", "managed", "extras"],
        "connection_endpoints": ["routes", "deployed_config", "protocol_config", "extras"],
        "link_monitors": ["retention_days", "last_checked_at"],
        "port_inventory_entries": ["detected_process", "detected_pid", "detected_source"],
    }
    with engine.begin() as connection:
        for table, columns in removed_columns.items():
            for column in columns:
                connection.execute(text(f"ALTER TABLE {table} DROP COLUMN {column}"))
        connection.execute(text("INSERT INTO connections (id, protocol_type, name, status) VALUES (1, 'gre', 'legacy', 'stopped')"))

    database.init_db()
    database.init_db()

    with Session(engine) as db:
        assert db.get(models.Connection, 1).name == "legacy"
        assert db.get(models.Connection, 1).source == "managed-node"
        assert db.get(models.Connection, 1).extras == {}
        for model in [models.IntegrationApiKey, models.LookingGlassQuery, models.ConnectionEndpoint,
                      models.LinkMonitor, models.PortInventoryEntry]:
            # ORM 会读取全部模型字段，比仅检查 PRAGMA 列名更接近真实启动后的请求。
            list(db.scalars(select(model)))
    engine.dispose()


def test_list_interfaces_rejects_unknown_node(session):
    """节点级资源不存在时应返回 404，而不是把拼写错误伪装成空列表。"""

    with pytest.raises(HTTPException) as exc_info:
        main.list_interfaces(404, session)

    assert exc_info.value.status_code == 404


def test_list_import_candidates_rejects_unknown_node(session):
    """导入候选列表同样必须区分不存在节点和没有候选。"""

    with pytest.raises(HTTPException) as exc_info:
        main.list_import_candidates(404, session)

    assert exc_info.value.status_code == 404


def test_startup_migration_removes_duplicate_connection_endpoint_monitors(monkeypatch):
    """旧库重复 GRE 端点带监测记录时，迁移应清理依赖后继续启动。"""

    from link42_api import database

    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE nodes (id INTEGER PRIMARY KEY, name VARCHAR(80), agent_token_hash VARCHAR(128))"
        ))
        connection.execute(text(
            "CREATE TABLE connections (id INTEGER PRIMARY KEY, protocol_type VARCHAR(32), name VARCHAR(120))"
        ))
        # 模拟早期没有唯一索引的 connection_endpoints 表。
        connection.execute(text(
            "CREATE TABLE connection_endpoints ("
            "id INTEGER PRIMARY KEY, connection_id INTEGER NOT NULL, node_id INTEGER NOT NULL, "
            "role VARCHAR(32) NOT NULL, interface_name VARCHAR(32) NOT NULL, "
            "tunnel_ips JSON, mtu INTEGER, routes JSON, runtime_status VARCHAR(32), "
            "deployed_config TEXT, protocol_config JSON, extras JSON, created_at DATETIME, updated_at DATETIME)"
        ))
        connection.execute(text(
            "CREATE TABLE link_monitors ("
            "id INTEGER PRIMARY KEY, node_id INTEGER NOT NULL, interface_id INTEGER, "
            "connection_endpoint_id INTEGER, name VARCHAR(80), target_host VARCHAR(255), "
            "interval_seconds INTEGER, retention_days INTEGER, enabled BOOLEAN, next_due_at DATETIME, "
            "last_checked_at DATETIME, created_at DATETIME, updated_at DATETIME)"
        ))
        connection.execute(text(
            "CREATE TABLE link_monitor_samples ("
            "id INTEGER PRIMARY KEY, monitor_id INTEGER NOT NULL, checked_at DATETIME NOT NULL, "
            "success BOOLEAN NOT NULL, latency_ms FLOAT, error TEXT)"
        ))
        connection.execute(text("INSERT INTO nodes (id, name, agent_token_hash) VALUES (1, 'legacy-node', 'hash')"))
        connection.execute(text(
            "INSERT INTO connections (id, protocol_type, name) VALUES (1, 'gre', 'legacy')"
        ))
        connection.execute(text(
            "INSERT INTO connection_endpoints "
            "(id, connection_id, node_id, role, interface_name) "
            "VALUES (1, 1, 1, 'local', 'gre0'), (2, 1, 1, 'peer', 'gre0')"
        ))
        connection.execute(text(
            "INSERT INTO link_monitors "
            "(id, node_id, connection_endpoint_id, name, target_host) "
            "VALUES (1, 1, 2, 'legacy-monitor', '198.51.100.2')"
        ))
        connection.execute(text(
            "INSERT INTO link_monitor_samples "
            "(id, monitor_id, checked_at, success) "
            "VALUES (1, 1, '2026-01-01 00:00:00', 1)"
        ))

    monkeypatch.setattr(database, "engine", engine)
    database.ensure_sqlite_point_to_point_constraints()

    with engine.connect() as connection:
        endpoints = connection.execute(text(
            "SELECT id FROM connection_endpoints ORDER BY id"
        )).fetchall()
        monitors = connection.execute(text("SELECT id FROM link_monitors")).fetchall()
        samples = connection.execute(text("SELECT id FROM link_monitor_samples")).fetchall()
        connection.execute(text(
            "INSERT INTO connection_endpoints "
            "(connection_id, node_id, role, interface_name) VALUES (1, 1, 'peer', 'gre1')"
        ))

    assert endpoints == [(1,)]
    assert monitors == []
    assert samples == []


def test_agent_reports_large_task_errors_within_controller_limits(monkeypatch):
    """异常文本必须可上报，否则 API 拒绝结果会让任务一直保持 running。"""

    from link42_agent import main as agent_main

    reports = []
    snapshot = agent_main.AgentSnapshot([], {})

    class FakeClient:
        def heartbeat(self, **kwargs):
            return None

        def poll_tasks(self, **kwargs):
            return [{"id": 1, "type": "test.failure", "payload": {}}]

        def report_task(self, task_id, status, result):
            main.validate_agent_result_json(result)
            reports.append((task_id, status, result))

    def fail_task(task, config):
        raise RuntimeError("异常" * (1024 * 1024))

    monkeypatch.setattr(agent_main, "execute_task", fail_task)
    monkeypatch.setattr(agent_main.logger, "exception", lambda *args, **kwargs: None)
    agent_main.run_once(FakeClient(), "/tmp", snapshot)

    assert len(reports) == 1
    task_id, status, result = reports[0]
    assert (task_id, status) == (1, "failed")
    assert "异常" in result["error"]
    assert "RuntimeError" in result["traceback"]
    assert len(result["error"].encode("utf-8")) <= 64 * 1024
    assert len(result["traceback"].encode("utf-8")) <= 64 * 1024


def test_agent_empty_capability_heartbeat_clears_stale_snapshot(session):
    """Agent 卸载能力后上报空列表时，主控不能继续沿用旧能力。"""

    node = models.Node(
        name="capability-refresh",
        agent_token_hash="hash",
        agent_version="0.6.0",
        agent_capabilities=["wireguard", "middleware.mimic"],
        agent_platform={"service_manager": "systemd"},
        middleware_install_status="mimic_ready",
    )
    session.add(node)
    session.flush()

    main.update_agent_metadata(node, "0.6.1", 1, [], {})

    assert node.agent_capabilities == []
    assert node.agent_platform == {}
    assert node.middleware_install_status is None


def test_legacy_json_read_models_are_safe_for_dashboard_responses(session):
    """旧库 JSON 列损坏时，节点/配置/计划响应仍应可序列化。"""

    node = models.Node(
        name="legacy-json-read",
        agent_token_hash="hash",
        endpoint_ips="10.0.0.1",
        agent_capabilities={"wireguard": True},
        agent_platform=["legacy"],
    )
    session.add(node)
    session.flush()
    interface = models.WireGuardInterface(
        node_id=node.id,
        name="wg0",
        tunnel_ips="10.0.0.1/24",
        dns={"server": "1.1.1.1"},
        warnings=42,
    )
    session.add(interface)
    session.flush()

    node_read = main.node_read_with_runtime_status(node)
    interface_read = schemas.InterfaceRead.model_validate(interface)
    plan_read = schemas.ChangePlanRead.model_validate({
        "id": 1,
        "title": "legacy",
        "status": "draft",
        "summary": "legacy",
        "affected_node_ids": "1",
        "diff": "",
        "confirmed_at": None,
        "task_result": ["legacy"],
    })

    assert node_read.endpoint_ips == []
    assert node_read.agent_capabilities == []
    assert node_read.agent_platform == {}
    assert interface_read.tunnel_ips == []
    assert interface_read.dns == []
    assert interface_read.warnings == []
    assert plan_read.affected_node_ids == []
    assert plan_read.task_result == {}


@pytest.mark.parametrize("legacy_value", [["legacy"], "legacy", 42])
def test_legacy_task_and_looking_glass_results_are_safe_for_responses(legacy_value):
    """旧库 JSON 根类型异常时，任务和 Looking Glass 响应仍保持对象契约。"""

    task = schemas.AgentTaskStatusRead(
        id=1,
        node_id=1,
        type="legacy.task",
        status="failed",
        result=legacy_value,
    )
    query = schemas.LookingGlassQueryRead(
        query_id="q1",
        status="succeeded",
        node_ref="node-1",
        operation="ping",
        request=legacy_value,
        created_at=datetime.utcnow(),
        result=legacy_value,
    )

    assert task.result == {}
    assert query.request == {}
    assert query.result == {}


def test_node_plugin_payload_has_recursive_and_total_size_limits():
    """插件请求不能借由深层 JSON 或多份配置绕过 HTTP body 限制。"""

    with pytest.raises(ValidationError):
        schemas.NodePluginActionRequest(payload={"files": [{"content": "x" * (512 * 1024 + 1)}]})
    with pytest.raises(ValidationError):
        schemas.NodePluginActionRequest(payload={"files": [{"content": "x" * (512 * 1024)} for _ in range(7)]})
    nested: object = "value"
    for _ in range(10):
        nested = {"next": nested}
    with pytest.raises(ValidationError):
        schemas.NodePluginActionRequest(payload={"nested": nested})


def test_proxy_path_prefix_is_preserved_by_api_and_agent():
    proxy = "https://proxy.example/download/"
    node = schemas.NodeCreate(name="proxy", endpoint_ips=["192.0.2.1"], github_proxy_url=proxy)
    update = schemas.NodeUpdate(name="proxy", endpoint_ips=["192.0.2.1"], github_proxy_url=proxy)
    assert node.github_proxy_url == update.github_proxy_url == proxy
    assert middleware.proxied_url("https://github.com/org/repo/file", middleware.validate_proxy_url(proxy)) == (
        "https://proxy.example/download/https://github.com/org/repo/file"
    )
    with pytest.raises(ValidationError):
        schemas.ControllerSettingsUpdate(controller_url=proxy, username="admin")


@pytest.mark.parametrize("proxy", [
    "https://:8000", "https://user:password@proxy.example/download/",
    "https://proxy.example:70000/", "https://proxy.example:abc/",
    "https://proxy.example/?url=", "https://proxy.example/#download",
    "https://proxy.example/\x00", "https://proxy.example\\evil/",
])
def test_invalid_proxy_prefix_is_rejected_on_both_sides(proxy):
    with pytest.raises(ValidationError):
        schemas.NodeCreate(name="proxy", endpoint_ips=["192.0.2.1"], github_proxy_url=proxy)
    with pytest.raises(ValueError):
        middleware.validate_proxy_url(proxy)


def test_managed_link_optional_peer_name_accepts_explicit_null():
    result = schemas.ManagedLinkCreate(
        peer_node_id=2, local_interface_name="wg0", peer_interface_name=None,
        local_tunnel_ips=["10.0.0.1/32"], peer_tunnel_ips=["10.0.0.2/32"],
    )
    assert result.peer_interface_name is None


@pytest.mark.parametrize("field", ["protocol", "port", "purpose", "source"])
def test_inventory_patch_rejects_null_required_columns(field):
    with pytest.raises(ValidationError):
        schemas.PortInventoryEntryUpdate(**{field: None})


def test_inventory_patch_can_omit_required_fields_and_clear_optional_fields():
    result = schemas.PortInventoryEntryUpdate(detected_process=None)
    assert result.model_dump(exclude_unset=True) == {"detected_process": None}


def test_gre_edit_does_not_reuse_running_apply_snapshot(session):
    """GRE 编辑期间已有任务运行时，新的配置必须排在旧任务之后。"""

    node = models.Node(
        name="gre-running", agent_token_hash="hash", status="online",
        agent_version="0.6.0", agent_capabilities=["gre"], last_seen_at=datetime.utcnow(),
    )
    session.add(node)
    session.commit()
    created = main.create_manual_connection(
        node.id,
        schemas.GreManualConnectionCreate(
            interface_name="gre_old", outer_local_ip="203.0.113.10", outer_remote_ip="198.51.100.20",
            tunnel_ips=["10.42.9.1/30"], risk_accepted=True,
        ),
        session,
    )
    tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.id)))
    tasks[0].status = "running"
    tasks[0].started_at = datetime.utcnow()
    session.commit()

    main.update_manual_connection(
        created.connection_ref,
        schemas.GreManualConnectionUpdate(
            interface_name="gre_new", peer_interface_name="gre_peer",
            outer_local_ip="203.0.113.10", outer_remote_ip="198.51.100.21",
            tunnel_ips=["10.42.10.1/30"], peer_tunnel_ips=["10.42.10.2/30"], risk_accepted=True,
        ),
        session,
    )
    updated_tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.id)))
    pending_apply = [task for task in updated_tasks if task.type == main.GRE_TASKS.apply_config and task.status == "pending"]
    pending_start = [task for task in updated_tasks if task.type == main.GRE_TASKS.start and task.status == "pending"]

    assert len(pending_apply) == 1
    assert pending_apply[0].payload["interface_name"] == "gre_new"
    assert pending_apply[0].payload["depends_on_task_id"] == tasks[0].id
    assert len(pending_start) == 1
    assert pending_start[0].payload["depends_on_task_id"] == pending_apply[0].id


@pytest.mark.parametrize("action", ["stop", "delete"])
@pytest.mark.parametrize("running_status", ["succeeded", "failed", "cancelled"])
def test_gre_stop_cancels_stale_deployments_and_waits_for_running_apply(session, monkeypatch, action, running_status):
    """停止 GRE 时不能让旧启动链在停止之后再次执行。"""

    node = models.Node(
        name="gre-stop", agent_token_hash="hash", status="online",
        agent_version="0.6.0", agent_capabilities=["gre"], last_seen_at=datetime.utcnow(),
    )
    connection = models.Connection(
        protocol_type=main.CONNECTION_TYPE_GRE, name="gre0", source="created", managed=True, status="starting",
    )
    endpoint = models.ConnectionEndpoint(
        connection=connection, node=node, role="local", interface_name="gre0",
        tunnel_ips=["10.42.20.1/30"], mtu=1476, routes=[], runtime_status="starting",
        protocol_config={"outer_local_ip": "203.0.113.10", "outer_remote_ip": "198.51.100.20"},
    )
    session.add_all([node, connection, endpoint])
    session.flush()
    running_apply = models.AgentTask(
        node_id=node.id, type=main.GRE_TASKS.apply_config, status="running",
        started_at=datetime.utcnow(), payload={"connection_endpoint_id": endpoint.id},
    )
    pending_start = models.AgentTask(
        node_id=node.id, type=main.GRE_TASKS.start, status="pending",
        payload={"connection_endpoint_id": endpoint.id},
    )
    pending_apply = models.AgentTask(
        node_id=node.id, type=main.GRE_TASKS.apply_config, status="pending",
        payload={"connection_endpoint_id": endpoint.id},
    )
    session.add_all([running_apply, pending_start, pending_apply])
    session.commit()

    connection_ref = f"gre:{connection.id}"
    endpoint_id = endpoint.id
    if action == "stop":
        main.stop_connection(connection_ref, session)
    else:
        main.delete_connection(connection_ref, session)
    session.refresh(pending_start)
    session.refresh(pending_apply)
    stop_task = session.scalar(
        select(models.AgentTask).where(
            models.AgentTask.payload["connection_endpoint_id"].as_integer() == endpoint_id,
            models.AgentTask.type == main.GRE_TASKS.stop,
        )
    )

    assert pending_start.status == "cancelled"
    assert pending_apply.status == "cancelled"
    assert stop_task is not None
    assert stop_task.status == "pending"
    assert stop_task.payload["depends_on_task_id"] == running_apply.id
    monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
    poll = schemas.AgentPollRequest(node_id=node.id, token="token", agent_version="0.6.0", capabilities=["gre"])
    assert main.agent_poll(poll, session).tasks == []
    running_apply.status = running_status
    session.commit()
    assert [task.id for task in main.agent_poll(poll, session).tasks] == [stop_task.id]


@pytest.mark.parametrize("request_model", [schemas.AgentRegisterRequest, schemas.AgentHeartbeatRequest, schemas.AgentPollRequest])
@pytest.mark.parametrize("invalid_platform", [
    {"x": float("nan")}, {"x": float("inf")}, {"x": "a" * 8193},
    {"x": "log\nline"}, {"x": list(range(257))}, {"x" * 129: "value"},
])
def test_agent_platform_metadata_rejects_unserializable_or_excessive_values(request_model, invalid_platform):
    """异常 Agent 元数据必须在写库及响应序列化之前被拒绝。"""

    with pytest.raises(ValidationError):
        request_model(node_id=1, token="token", platform=invalid_platform)


@pytest.mark.parametrize("request_model", [schemas.AgentRegisterRequest, schemas.AgentHeartbeatRequest, schemas.AgentPollRequest])
def test_agent_metadata_depth_and_capability_limits(request_model):
    """平台嵌套和能力标识也必须受限，同时接受正常 Linux 平台快照。"""

    nested = {"x": "leaf"}
    for _ in range(9):
        nested = {"x": nested}
    with pytest.raises(ValidationError):
        request_model(node_id=1, token="token", platform=nested)
    for capability in ["", "x" * 129, "gre\nlog", "wire guard"]:
        with pytest.raises(ValidationError):
            request_model(node_id=1, token="token", capabilities=[capability])
    normal = request_model(
        node_id=1, token="token", capabilities=[" gre ", "gre"],
        platform={"service_manager": "systemd", "network_interfaces": ["eth0"], "kernel_major": 6, "has_mimic": False},
    )
    assert normal.capabilities == ["gre"]


@pytest.mark.parametrize("running_status", ["succeeded", "failed"])
def test_wireguard_stop_cancels_pending_apply_and_start(session, monkeypatch, running_status):
    """WireGuard 停止也必须取消旧部署链，并等待已领取部署完成后执行。"""

    node = models.Node(
        name="wg-stop", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow(),
        agent_version="0.6.0", agent_capabilities=["wireguard"],
    )
    interface = models.WireGuardInterface(node=node, name="wg0", source="created", managed=True, runtime_status="starting")
    session.add_all([node, interface])
    session.flush()
    running_apply = models.AgentTask(
        node_id=node.id, type=main.WIREGUARD_TASKS.apply_config, status="running",
        started_at=datetime.utcnow(), payload={"interface_id": interface.id, "interface_name": "wg0"},
    )
    stale_tasks = [models.AgentTask(
        node_id=node.id, type=task_type, payload={"interface_id": interface.id, "interface_name": "wg0"},
    ) for task_type in [main.WIREGUARD_TASKS.apply_config, main.WIREGUARD_TASKS.start]]
    session.add_all([running_apply, *stale_tasks])
    session.commit()

    main.stop_interface(interface.id, session)
    for task in stale_tasks:
        session.refresh(task)
        assert task.status == "cancelled"
    monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
    poll = schemas.AgentPollRequest(node_id=node.id, token="token", agent_version="0.6.0", capabilities=["wireguard"])
    assert main.agent_poll(poll, session).tasks == []
    running_apply.status = running_status
    session.commit()
    ready = main.agent_poll(poll, session).tasks
    assert len(ready) == 1
    assert ready[0].type == main.WIREGUARD_TASKS.stop


def test_invalid_platform_http_response_does_not_echo_secrets_or_nan():
    """元数据校验错误必须能序列化为 422，且不回显原请求中的认证信息。"""

    app = FastAPI()
    app.add_exception_handler(RequestValidationError, main.looking_glass_validation_error_handler)

    @app.post("/api/agent/tasks/poll")
    def receive(payload: schemas.AgentPollRequest):
        """仅校验 Agent 请求，避免测试访问运行数据库。"""

        return {"accepted": True}

    client = TestClient(app)
    response = client.post(
        "/api/agent/tasks/poll",
        content='{"node_id":1,"token":"secret-token","platform":{"value":NaN,"private_key":"secret-key"}}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "platform"]
    assert "secret-token" not in response.text
    assert "secret-key" not in response.text
    assert "NaN" not in response.text


@pytest.mark.parametrize("online", [True, False])
def test_node_pagination_scans_past_nonmatching_batches(session, online):
    now = datetime.utcnow()
    for index in range(105):
        matches = index >= 101
        session.add(models.Node(
            name=f"node-{index}", agent_token_hash="hash", region="test",
            status="online" if matches == online else "offline", last_seen_at=now,
        ))
    session.commit()
    api_key = models.IntegrationApiKey(scopes=[main.LOOKING_GLASS_NODE_READ_SCOPE])
    first = main.list_looking_glass_nodes(region="test", online=online, limit=2, api_key=api_key, db=session)
    assert [item.node_ref for item in first.items] == ["node_102", "node_103"]
    assert first.next_cursor == "103"
    second = main.list_looking_glass_nodes(
        region="test", online=online, limit=2, cursor=first.next_cursor, api_key=api_key, db=session,
    )
    assert [item.node_ref for item in second.items] == ["node_104", "node_105"]
    assert second.next_cursor is None


def logo_request(data):
    async def receive():
        return {"type": "http.request", "body": data, "more_body": False}
    return Request({"type": "http", "method": "POST", "path": "/api/settings/logo", "headers": []}, receive)


@pytest.mark.parametrize("old_suffix", ["png", "jpg"])
def test_logo_replace_failure_preserves_old_file(monkeypatch, tmp_path, session, old_suffix):
    monkeypatch.setattr(main.settings, "config_dir", str(tmp_path))
    directory = tmp_path / "branding"
    directory.mkdir()
    old_file = directory / f"logo.{old_suffix}"
    old_file.write_bytes(b"old-logo")
    main.set_setting(session, main.SETTING_SITE_LOGO_URL, "/branding/logo?v=old")
    session.commit()
    def fail_replace(source, target):
        raise OSError("disk error")
    monkeypatch.setattr(main.os, "replace", fail_replace)
    with pytest.raises(OSError, match="disk error"):
        asyncio.run(main.upload_site_logo(logo_request(b"\x89PNG\r\n\x1a\nnew"), session))
    assert old_file.read_bytes() == b"old-logo"
    assert main.get_setting(session, main.SETTING_SITE_LOGO_URL) == "/branding/logo?v=old"
    assert sorted(path.name for path in directory.iterdir()) == [".logo.lock", old_file.name]


def test_logo_upload_switches_formats(monkeypatch, tmp_path, session):
    monkeypatch.setattr(main.settings, "config_dir", str(tmp_path))
    directory = tmp_path / "branding"
    directory.mkdir()
    (directory / "logo.jpg").write_bytes(b"old-logo")
    data = b"\x89PNG\r\n\x1a\nnew"
    result = asyncio.run(main.upload_site_logo(logo_request(data), session))
    assert (directory / "logo.png").read_bytes() == data
    assert not (directory / "logo.jpg").exists()
    assert result.site_logo_url.startswith("/branding/logo?v=")


def test_logo_upload_rejects_symlinked_branding_directory(monkeypatch, tmp_path, session):
    """Logo 上传不能跟随被替换的 branding 父目录写到配置目录外。"""

    monkeypatch.setattr(main.settings, "config_dir", str(tmp_path / "config"))
    outside = tmp_path / "outside"
    outside.mkdir()
    config = tmp_path / "config"
    config.mkdir()
    (config / "branding").symlink_to(outside, target_is_directory=True)
    with pytest.raises(HTTPException, match="managed path"):
        asyncio.run(main.upload_site_logo(logo_request(b"\x89PNG\r\n\x1a\nnew"), session))
    assert not (outside / "logo.png").exists()


@pytest.mark.skipif("fork" not in multiprocessing.get_all_start_methods(), reason="requires POSIX workers")
def test_logo_uploads_in_separate_workers_do_not_delete_active_file(monkeypatch, tmp_path):
    """不同 worker 必须串行完成替换、清理和提交，不能互删正在使用的 Logo。"""

    monkeypatch.setattr(main.settings, "config_dir", str(tmp_path))
    database_url = f"sqlite:///{tmp_path / 'logo.db'}"
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        main.set_setting(db, main.SETTING_SITE_LOGO_URL, "/branding/logo?v=old")
        db.commit()
    engine.dispose()
    context = multiprocessing.get_context("fork")
    first_replaced = context.Event()
    release_first = context.Event()
    second_started = context.Event()
    second_replaced = context.Event()
    replace = main.os.replace

    def pause_replace(source, target):
        replace(source, target)
        if target.name == "logo.png":
            first_replaced.set()
            if not release_first.wait(10):
                raise RuntimeError("first worker was not released")
        else:
            second_replaced.set()

    monkeypatch.setattr(main.os, "replace", pause_replace)

    def upload(data, started=None):
        worker_engine = create_engine(database_url, connect_args={"check_same_thread": False})
        try:
            with Session(worker_engine) as db:
                if started is not None:
                    started.set()
                asyncio.run(main.upload_site_logo(logo_request(data), db))
        finally:
            worker_engine.dispose()

    first = context.Process(target=upload, args=(b"\x89PNG\r\n\x1a\nfirst",))
    second = context.Process(target=upload, args=(b"\xff\xd8\xffsecond", second_started))
    try:
        first.start()
        assert first_replaced.wait(5)
        second.start()
        assert second_started.wait(5)
        assert not second_replaced.wait(0.2)
        release_first.set()
        first.join(5)
        second.join(5)
        assert first.exitcode == second.exitcode == 0
        path = main.uploaded_logo_path()
        assert path is not None
        assert main.read_uploaded_logo(path) == (b"\xff\xd8\xffsecond", "image/jpeg")
    finally:
        release_first.set()
        for worker in (first, second):
            if worker.pid is not None:
                if worker.is_alive():
                    worker.terminate()
                worker.join(5)


def test_logo_upload_rejects_symlinked_lock(monkeypatch, tmp_path, session):
    monkeypatch.setattr(main.settings, "config_dir", str(tmp_path))
    directory = tmp_path / "branding"
    directory.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"unchanged")
    (directory / ".logo.lock").symlink_to(outside)
    with pytest.raises(HTTPException, match="managed path"):
        asyncio.run(main.upload_site_logo(logo_request(b"\x89PNG\r\n\x1a\nnew"), session))
    assert outside.read_bytes() == b"unchanged"
    assert main.uploaded_logo_path() is None


def test_missing_logo_returns_not_found(tmp_path):
    with pytest.raises(HTTPException) as error:
        main.read_uploaded_logo(tmp_path / "logo.png")
    assert error.value.status_code == 404


def test_branding_logo_route_is_registered_without_web_static_directory():
    """开发模式未挂载 Web 静态目录时，上传 Logo 的公开读取路由仍存在。"""

    assert any(route.path == "/branding/logo" for route in main.app.routes)


@pytest.mark.parametrize(
    ("statuses", "expected_index"),
    [(["failed", "cancelled", "pending"], 0), (["succeeded", "failed", "cancelled"], 1),
     (["succeeded", "running", "pending"], 1), (["succeeded", "pending"], 1),
     (["cancelled", "succeeded"], 0), (["succeeded", "succeeded"], 1)],
)
def test_change_plan_exposes_failure_or_active_task_instead_of_last_task(session, statuses, expected_index):
    node = models.Node(name="plan-node", agent_token_hash="hash")
    plan = models.ChangePlan(title="rename", summary="rename", diff="change")
    session.add_all([node, plan])
    session.flush()
    for index, status in enumerate(statuses):
        session.add(models.AgentTask(
            node_id=node.id, change_plan_id=plan.id, type="wireguard.apply_config",
            status=status, result={"error": f"task-{index}"},
        ))
    session.commit()
    main.update_change_plan_task_status(session, plan)
    response = schemas.ChangePlanRead.model_validate(plan)
    assert response.task_status == statuses[expected_index]
    assert response.task_result == {"error": f"task-{expected_index}"}


def test_expiring_running_task_marks_change_plan_failed(session):
    """超时回收任务时，关联部署计划不能永久停留在 confirmed。"""

    node = models.Node(name="timeout-node", agent_token_hash="hash", status="online")
    plan = models.ChangePlan(title="deploy", summary="deploy", diff="changed", status="confirmed")
    session.add_all([node, plan])
    session.flush()
    task = models.AgentTask(
        node_id=node.id,
        change_plan_id=plan.id,
        type="wireguard.apply_config",
        status="running",
        payload={"node_id": node.id},
        started_at=datetime.utcnow() - timedelta(hours=3),
    )
    session.add(task)
    session.commit()

    assert main.expire_stale_running_agent_tasks(session, node_id=node.id) == 1
    session.commit()
    session.refresh(plan)
    assert plan.status == "failed"


def test_dependency_failure_marks_change_plan_failed_without_agent_result(session):
    """依赖失败而未返回给 Agent 的任务也必须结束其部署计划。"""

    node = models.Node(name="dependency-node", agent_token_hash="hash", status="online")
    plan = models.ChangePlan(title="rename", summary="rename", diff="changed", status="confirmed")
    session.add_all([node, plan])
    session.flush()
    dependency = models.AgentTask(
        node_id=node.id, change_plan_id=plan.id, type="wireguard.stop_interface",
        status="failed", result={"error": "stop failed"},
    )
    session.add(dependency)
    session.flush()
    dependent = models.AgentTask(
        node_id=node.id, change_plan_id=plan.id, type="wireguard.delete_config",
        status="pending", payload={"depends_on_task_id": dependency.id},
    )
    session.add(dependent)
    session.commit()

    assert main.is_task_ready_for_poll(session, dependent, datetime.utcnow()) is False
    session.commit()
    session.refresh(plan)
    assert dependent.status == "failed"
    assert plan.status == "failed"


@pytest.mark.parametrize("protocol", ["wireguard", "gre"])
@pytest.mark.parametrize("foreign_keys", [True, False])
def test_node_delete_preserves_connection_created_after_empty_check(monkeypatch, tmp_path, protocol, foreign_keys):
    """空节点检查后创建的连接必须阻止节点删除，不能被 ORM cascade 顺带清理。"""

    engine = create_engine(f"sqlite:///{tmp_path / 'delete-race.db'}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record):
        connection.execute(f"PRAGMA foreign_keys={'ON' if foreign_keys else 'OFF'}")

    Base.metadata.create_all(engine)
    with Session(engine) as db:
        node = models.Node(name="node", agent_token_hash="hash")
        db.add(node)
        db.commit()
        node_id = node.id
    cleanup = main.delete_link_monitors_where
    created_ids = []

    def create_connection_before_cleanup(db, predicate):
        with Session(engine) as writer:
            if protocol == "wireguard":
                child = models.WireGuardInterface(node_id=node_id, name="wg0")
            else:
                connection = models.Connection(protocol_type="gre", name="gre0")
                writer.add(connection)
                writer.flush()
                child = models.ConnectionEndpoint(
                    node_id=node_id, connection_id=connection.id, role="local", interface_name="gre0",
                )
            writer.add(child)
            writer.commit()
            created_ids.append(child.id)
        return cleanup(db, predicate)

    monkeypatch.setattr(main, "delete_link_monitors_where", create_connection_before_cleanup)
    try:
        with Session(engine) as db:
            with pytest.raises(HTTPException) as error:
                # Exercise the final conditional DELETE independently: the IPAM
                # wrapper now prevents this injected writer from entering at all.
                main.delete_node.__wrapped__(node_id, db)
            assert error.value.status_code == 409
        with Session(engine) as db:
            assert db.get(models.Node, node_id) is not None
            child_model = models.WireGuardInterface if protocol == "wireguard" else models.ConnectionEndpoint
            assert db.get(child_model, created_ids[0]) is not None
    finally:
        engine.dispose()


def test_port_inventory_migration_normalizes_protocol_before_enforcing_uniqueness(monkeypatch):
    """旧协议大小写变体不能在迁移后绕过端口唯一约束，也不能让启动失败。"""

    from link42_api import database

    engine = create_engine("sqlite:///:memory:")
    monkeypatch.setattr(database, "engine", engine)
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            node = models.Node(name="legacy", agent_token_hash="hash")
            db.add(node)
            db.flush()
            db.add_all([
                models.PortInventoryEntry(node_id=node.id, protocol="tcp", port=42, purpose="old"),
                models.PortInventoryEntry(node_id=node.id, protocol="TCP", port=42, purpose="duplicate"),
                models.PortInventoryEntry(node_id=node.id, protocol="udp", port=42),
            ])
            db.commit()
            node_id = node.id
        database.init_db()
        database.init_db()
        with Session(engine) as db:
            entries = list(db.scalars(select(models.PortInventoryEntry).order_by(models.PortInventoryEntry.id)))
            assert [(entry.protocol, entry.port) for entry in entries] == [("TCP", 42), ("UDP", 42)]
            assert entries[0].purpose == "old"
            with pytest.raises(HTTPException) as error:
                main.create_port_inventory_entry(node_id, schemas.PortInventoryEntryCreate(protocol="TCP", port=42), db)
            assert error.value.status_code == 409
    finally:
        engine.dispose()


def test_read_existing_bytes_rejects_special_and_oversized_files(tmp_path):
    """读取备份或配置时不能阻塞在 FIFO，也不能无界读取恶意大文件。"""

    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular file"):
        read_existing_bytes(fifo)

    oversized = tmp_path / "oversized"
    oversized.write_bytes(b"x" * (MAX_EXISTING_FILE_BYTES + 1))
    with pytest.raises(ValueError, match="too large"):
        read_existing_bytes(oversized)


def test_command_timeout_rejects_non_finite_environment_value(monkeypatch):
    """无穷或 NaN 的命令超时配置必须回退到安全的有限默认值。"""

    from link42_agent import system

    for value in ["inf", "-inf", "nan", "0"]:
        monkeypatch.setenv("LINK42_COMMAND_TIMEOUT", value)
        assert system.command_timeout_seconds() == system.DEFAULT_COMMAND_TIMEOUT_SECONDS


def test_looking_glass_token_expiry_is_normalized_to_utc_naive():
    """带时区的 Token 过期时间写库前必须与 SQLite/PostgreSQL DateTime 一致。"""

    value = schemas.IntegrationApiTokenCreate(
        name="expiry",
        scopes=["looking_glass.nodes.read"],
        expires_at="2026-10-10T12:00:00+08:00",
    ).expires_at
    assert value == datetime(2026, 10, 10, 4, 0, 0)
    assert value.tzinfo is None


def test_cancelling_pending_interface_task_updates_change_plan(session):
    """停止流程取消待执行任务后，部署计划不能继续显示 confirmed。"""

    node = models.Node(name="cancel-plan", agent_token_hash="hash")
    session.add(node)
    session.flush()
    interface = models.WireGuardInterface(node_id=node.id, name="wg0")
    session.add(interface)
    session.flush()
    plan = models.ChangePlan(
        title="apply",
        summary="apply",
        status="confirmed",
        payload={"task_payload": {"interface_id": interface.id}},
    )
    session.add(plan)
    session.flush()
    task = models.AgentTask(
        node_id=node.id,
        change_plan_id=plan.id,
        type=main.WIREGUARD_TASKS.apply_config,
        payload={"interface_id": interface.id},
        status="pending",
    )
    session.add(task)
    session.commit()

    assert main.cancel_pending_interface_tasks(
        session,
        interface.id,
        main.WIREGUARD_TASKS.apply_config,
        "superseded",
    ) == 1
    session.commit()
    session.refresh(plan)
    assert task.status == "cancelled"
    assert plan.status == "failed"


def test_csp_allows_supported_external_logo_urls():
    response = main.add_security_headers(logo_request(b""), Response())
    directives = response.headers["content-security-policy"].split(";")
    images = next(item.strip() for item in directives if item.strip().startswith("img-src "))
    assert "https:" in images.split()
    assert "http:" in images.split()
    assert "script-src 'self'" in response.headers["content-security-policy"]


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        ("[2001:db8::1]:51820", ("2001:db8::1", 51820)),
        ("2001:db8::1", ("2001:db8::1", None)),
        ("198.51.100.10:51820", ("198.51.100.10", 51820)),
        ("hostname.example", ("hostname.example", None)),
    ],
)
def test_split_endpoint_handles_bracketed_ipv6(endpoint, expected):
    assert split_endpoint(endpoint) == expected


@pytest.mark.parametrize("name", ["../escape", "/absolute", "wg-name-that-is-too-long", "接口"])
def test_wireguard_schemas_reject_unsafe_or_unusable_interface_names(name):
    with pytest.raises(ValidationError):
        main.schemas.InterfaceCreate(name=name)


def test_wireguard_endpoint_host_rejects_config_line_injection():
    with pytest.raises(ValidationError):
        main.schemas.PeerCreate(
            public_key="peer",
            endpoint_host="example.com\nAllowedIPs = 0.0.0.0/0",
        )


def test_node_endpoint_addresses_are_trimmed_and_nonempty():
    node = main.schemas.NodeCreate(name="node", endpoint_ips=[" example.com "])
    assert node.endpoint_ips == ["example.com"]
    with pytest.raises(ValidationError):
        main.schemas.NodeCreate(name="node", endpoint_ips=["bad host"])
    with pytest.raises(ValidationError):
        main.schemas.NodeCreate(name="   ", endpoint_ips=["example.com"])


@pytest.mark.parametrize("field", ["name", "hostname", "region", "management_ip", "public_ip", "topology_endpoint"])
def test_node_display_fields_reject_control_characters(field):
    values = {"name": "node", "endpoint_ips": ["example.com"]}
    values[field] = "value\nforged-log-line"
    with pytest.raises(ValidationError):
        schemas.NodeCreate(**values)


@pytest.mark.parametrize("field", ["username", "site_title"])
def test_controller_settings_display_fields_reject_control_characters(field):
    values = {"controller_url": "http://controller.example", "username": "admin", "site_title": "Link42"}
    values[field] = "operator\nforged-log-line"
    with pytest.raises(ValidationError):
        schemas.ControllerSettingsUpdate(**values)


def test_agent_registration_metadata_rejects_control_characters():
    with pytest.raises(ValidationError):
        schemas.AgentRegisterRequest(node_id=1, token="token", hostname="node\nforged")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0, 3_600_001.0])
def test_monitor_result_rejects_invalid_latency(value):
    with pytest.raises(ValidationError):
        schemas.AgentLinkMonitorResultItem(monitor_id=1, success=True, latency_ms=value)


def test_monitor_result_clamps_future_timestamp(session, monkeypatch):
    monkeypatch.setattr(main, "require_agent", lambda db, node_id, token: db.get(models.Node, node_id))
    node = models.Node(name="monitor-node", agent_token_hash="hash")
    session.add(node)
    session.flush()
    monitor = models.LinkMonitor(node_id=node.id, name="m", target_host="192.0.2.1", retention_days=7)
    session.add(monitor)
    session.commit()
    future = (datetime.now(timezone.utc) + timedelta(days=365))
    main.agent_link_monitor_result(
        schemas.AgentLinkMonitorResultRequest(
            node_id=node.id,
            token="token",
            results=[schemas.AgentLinkMonitorResultItem(monitor_id=monitor.id, checked_at=future, success=True, latency_ms=1)],
        ),
        session,
    )
    sample = session.scalar(select(models.LinkMonitorSample))
    assert sample.checked_at <= datetime.utcnow()


def test_monitor_result_replay_is_idempotent(session, monkeypatch):
    monkeypatch.setattr(main, "require_agent", lambda db, node_id, token: db.get(models.Node, node_id))
    node = models.Node(name="monitor-replay", agent_token_hash="hash")
    session.add(node)
    session.flush()
    monitor = models.LinkMonitor(node_id=node.id, name="m", target_host="192.0.2.1", retention_days=7)
    session.add(monitor)
    session.commit()
    checked_at = datetime.utcnow()
    request = schemas.AgentLinkMonitorResultRequest(
        node_id=node.id,
        token="token",
        results=[schemas.AgentLinkMonitorResultItem(monitor_id=monitor.id, checked_at=checked_at, success=True, latency_ms=1)],
    )
    main.agent_link_monitor_result(request, session)
    main.agent_link_monitor_result(request, session)
    assert session.scalar(select(func.count(models.LinkMonitorSample.id))) == 1


def test_monitor_result_duplicate_timestamp_within_batch_is_idempotent(session, monkeypatch):
    """同一批次重复结果不能绕过禁用 autoflush 的重放去重。"""

    session.autoflush = False
    monkeypatch.setattr(main, "require_agent", lambda db, node_id, token: db.get(models.Node, node_id))
    node = models.Node(name="monitor-batch-replay", agent_token_hash="hash")
    session.add(node)
    session.flush()
    monitor = models.LinkMonitor(node_id=node.id, name="m", target_host="192.0.2.1", retention_days=7)
    session.add(monitor)
    session.commit()
    checked_at = datetime.utcnow()
    main.agent_link_monitor_result(
        schemas.AgentLinkMonitorResultRequest(
            node_id=node.id,
            token="token",
            results=[
                schemas.AgentLinkMonitorResultItem(monitor_id=monitor.id, checked_at=checked_at, success=True, latency_ms=1),
                schemas.AgentLinkMonitorResultItem(monitor_id=monitor.id, checked_at=checked_at, success=True, latency_ms=2),
            ],
        ),
        session,
    )
    samples = list(session.scalars(select(models.LinkMonitorSample)))
    assert len(samples) == 1
    assert samples[0].latency_ms == 1


def test_malformed_import_scan_result_is_ignored_instead_of_crashing(session, monkeypatch):
    monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
    node = models.Node(name="scan-node", agent_token_hash="hash", endpoint_ips=["10.0.0.1"])
    session.add(node)
    session.flush()
    task = models.AgentTask(node_id=node.id, type="wireguard.import_scan", status="running", payload={})
    session.add(task)
    session.commit()

    result = main.agent_task_result(
        task.id,
        schemas.AgentTaskResultRequest(
            node_id=node.id,
            token="token",
            status="succeeded",
            result={"candidates": [None, {"path": "/tmp/bad.conf", "parsed": {}}, "bad"]},
        ),
        session,
    )

    assert result == {"status": "recorded"}
    assert session.scalars(select(models.ImportCandidate)).all() == []


def test_deep_agent_task_result_is_rejected_before_persistence(session, monkeypatch):
    """拒绝持久化异常深度 JSON，并用安全错误结束任务。"""

    monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
    node = models.Node(name="deep-result", agent_token_hash="hash")
    session.add(node)
    session.flush()
    task = models.AgentTask(node_id=node.id, type="node_plugin.port_inventory.scan", status="running", payload={})
    session.add(task)
    session.commit()

    value: dict[str, object] = {}
    nested = value
    for _ in range(18):
        child: dict[str, object] = {}
        nested["nested"] = child
        nested = child
    with pytest.raises(HTTPException) as caught:
        main.agent_task_result(
            task.id,
            schemas.AgentTaskResultRequest(node_id=node.id, token="token", status="failed", result=value),
            session,
        )

    assert caught.value.status_code == 400
    session.refresh(task)
    assert task.status == "failed"
    assert task.finished_at is not None
    assert task.result == {"error": "agent task result is too deeply nested or too large"}


def test_invalid_agent_result_cannot_overwrite_concurrently_completed_task(session, monkeypatch):
    """结果校验期间的有效终态不得被随后无效请求的失败写入覆盖。"""

    monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
    node = models.Node(name="result-race", agent_token_hash="hash")
    session.add(node)
    session.flush()
    task = models.AgentTask(node_id=node.id, type="wireguard.apply_config", status="running", payload={})
    session.add(task)
    session.commit()
    task_id = task.id

    def complete_then_reject(_value):
        with Session(session.get_bind()) as winner:
            completed = winner.get(models.AgentTask, task_id)
            completed.status = "succeeded"
            completed.result = {"applied": True}
            winner.commit()
        raise ValueError("invalid result")

    monkeypatch.setattr(main, "validate_agent_result_json", complete_then_reject)
    with pytest.raises(HTTPException) as caught:
        main.agent_task_result(task_id, schemas.AgentTaskResultRequest(
            node_id=node.id, token="token", status="succeeded", result={},
        ), session)
    assert caught.value.status_code == 400
    session.refresh(task)
    assert task.status == "succeeded"
    assert task.result == {"applied": True}


@pytest.mark.parametrize("malformed_payload", [["legacy"], "legacy", 42])
def test_agent_result_handles_non_object_legacy_task_payload(session, monkeypatch, malformed_payload):
    """旧库中 payload 根类型异常时，迟到结果仍应稳定落库而非触发 500。"""

    monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
    node = models.Node(name="legacy-payload", agent_token_hash="hash")
    session.add(node)
    session.flush()
    task = models.AgentTask(
        node_id=node.id,
        type="legacy.task",
        status="running",
        payload=malformed_payload,
    )
    session.add(task)
    session.commit()

    assert main.agent_task_result(
        task.id,
        schemas.AgentTaskResultRequest(
            node_id=node.id,
            token="token",
            status="succeeded",
            result={"message": "done"},
        ),
        session,
    ) == {"status": "recorded"}
    session.refresh(task)
    assert task.status == "succeeded"


@pytest.mark.parametrize(
    "manifest",
    [
        {
            "latest": "1.0.0",
            "releases": {
                "1.0.0": {
                    "assets": {
                        "linux-x64": {
                            "path": "../outside",
                            "sha256": "0" * 64,
                        }
                    }
                }
            },
        },
        {"latest": "1.0.0", "releases": {"1.0.0": {"assets": {"linux-x64": {"path": "agent", "sha256": "bad"}}}}},
    ],
)
def test_release_manifest_rejects_unsafe_assets(monkeypatch, tmp_path, manifest):
    """损坏或越界的 release 清单必须在所有 API 使用前被拒绝。"""

    monkeypatch.setattr(main.settings, "agent_release_dir", str(tmp_path))
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(HTTPException) as caught:
        main.load_agent_release_manifest()
    assert caught.value.status_code == 500


def test_release_manifest_size_is_bounded(monkeypatch, tmp_path):
    """release manifest 不能通过无限文件读取耗尽主控内存。"""

    monkeypatch.setattr(main.settings, "agent_release_dir", str(tmp_path))
    (tmp_path / "manifest.json").write_bytes(b"{" + b" " * (main.AGENT_RELEASE_MANIFEST_MAX_BYTES + 1))
    with pytest.raises(HTTPException) as caught:
        main.load_agent_release_manifest()
    assert caught.value.status_code == 500


def test_confirm_change_plan_rejects_non_object_legacy_payload(session):
    """旧库中的损坏计划 payload 应返回可理解的 400，而不是未处理异常。"""

    plan = models.ChangePlan(
        title="legacy-plan",
        summary="legacy",
        diff="change",
        status="draft",
        payload=["legacy"],
    )
    session.add(plan)
    session.commit()
    with pytest.raises(HTTPException) as caught:
        main.confirm_change_plan(plan.id, session)
    assert caught.value.status_code == 400


@pytest.mark.parametrize("change", ["delete", "rename", "move"])
def test_confirm_change_plan_rejects_missing_or_reassigned_interface(session, monkeypatch, change):
    """草稿计划不能在目标已删除、改名或转移后重建旧配置。"""

    node = models.Node(name="stale-plan-node", agent_token_hash="hash", status="online",
                       last_seen_at=datetime.utcnow())
    other_node = models.Node(name="other-plan-node", agent_token_hash="hash")
    session.add_all([node, other_node])
    session.flush()
    interface = models.WireGuardInterface(node_id=node.id, name="wg0", managed=True)
    session.add(interface)
    session.flush()
    plan = models.ChangePlan(title="deploy", summary="deploy", diff="changed", payload={
        "task_type": "wireguard.apply_config",
        "task_payload": {"node_id": node.id, "interface_id": interface.id,
                         "interface_name": "wg0", "config": "old config"},
    })
    session.add(plan)
    session.commit()
    if change == "delete":
        main.delete_interface(interface.id, session)
    elif change == "rename":
        interface.name = "wg1"
        session.commit()
    else:
        interface.node_id = other_node.id
        session.commit()
    monkeypatch.setattr(main, "require_task_supported", lambda *_: None)
    with pytest.raises(HTTPException) as caught:
        main.confirm_change_plan(plan.id, session)
    assert caught.value.status_code == 409
    assert session.scalar(select(func.count(models.AgentTask.id))) == 0
    assert session.get(models.ChangePlan, plan.id).status == ("cancelled" if change == "delete" else "draft")


@pytest.mark.parametrize("imported", [False, True])
def test_deleted_interface_draft_cannot_apply_to_reused_id(session, monkeypatch, imported):
    node = models.Node(name="reused-plan-node", agent_token_hash="hash", status="online",
                       last_seen_at=datetime.utcnow())
    session.add(node)
    session.flush()
    interface = models.WireGuardInterface(node_id=node.id, name="wg0", managed=not imported,
                                         source="imported" if imported else "created")
    session.add(interface)
    session.flush()
    interface_id = interface.id
    plan = models.ChangePlan(title="deploy", summary="deploy", diff="changed", payload={
        "task_type": "wireguard.apply_config",
        "task_payload": {"node_id": node.id, "interface_id": interface_id,
                         "interface_name": "wg0", "config": "old config"},
    })
    session.add(plan)
    session.commit()
    main.delete_interface(interface_id, session)
    replacement = models.WireGuardInterface(node_id=node.id, name="wg0", managed=True)
    session.add(replacement)
    session.commit()
    assert replacement.id == interface_id
    monkeypatch.setattr(main, "require_task_supported", lambda *_: None)
    with pytest.raises(HTTPException) as caught:
        main.confirm_change_plan(plan.id, session)
    assert caught.value.status_code == 409
    assert session.scalar(select(func.count(models.AgentTask.id))) == 0
    assert session.get(models.ChangePlan, plan.id).status == "cancelled"


@pytest.mark.parametrize("bad_fields", [
    {"peers": None}, {"peers": [None]}, {"peers": [{"endpoint": []}]},
    {"peers": [{"allowed_ips": [None]}]}, {"warnings": None},
    {"addresses": "10.0.0.1/32"}, {"listen_port": {}}, {"private_key": 42},
    {"name": 42}, {"post_up": ["echo foo\nbar"]},
])
def test_deep_malformed_import_candidate_is_rejected(session, bad_fields):
    node = models.Node(name="bad-import", agent_token_hash="hash")
    session.add(node)
    session.flush()
    candidate = models.ImportCandidate(
        node_id=node.id, path="/etc/wireguard/wg0.conf", interface_name="wg0",
        parsed={"name": "wg0", **bad_fields}, warnings=[],
    )
    session.add(candidate)
    session.commit()
    with pytest.raises(HTTPException) as exc:
        main.import_candidate(node.id, schemas.ImportRequest(candidate_id=candidate.id), session)
    assert exc.value.status_code == 409
    assert session.scalar(select(func.count(models.WireGuardInterface.id))) == 0


def make_query_node_and_key(db):
    node = models.Node(
        name="query-node", agent_token_hash="hash", status="online",
        last_seen_at=datetime.utcnow(), agent_version="0.6.16", agent_capabilities=["looking_glass.ping"],
    )
    key = models.IntegrationApiKey(
        name="lg", token_prefix="l42lg_test", token_hash="hash", token_hint="hint",
        scopes=[main.LOOKING_GLASS_BIRD_ROUTE_SCOPE],
    )
    db.add_all([node, key])
    db.commit()
    return node.id, key.id


def submit_ping(db, node_id, key_id):
    return main.submit_looking_glass_ping(
        f"node_{node_id}", schemas.LookingGlassPingRequest(target="192.0.2.1"), Response(),
        db.get(models.IntegrationApiKey, key_id), db,
    )


def test_created_looking_glass_query_follows_agent_result(session, monkeypatch):
    node_id, key_id = make_query_node_and_key(session)
    result = submit_ping(session, node_id, key_id)
    query = session.scalar(select(models.LookingGlassQuery))
    task = session.scalar(select(models.AgentTask))
    assert query.agent_task_id == task.id
    task.status = "running"
    session.commit()
    monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
    main.agent_task_result(task.id, schemas.AgentTaskResultRequest(
        node_id=node_id, token="token", status="succeeded", result={"stdout": "ping success"},
    ), session)
    read = main.get_looking_glass_query(result.query_id, session.get(models.IntegrationApiKey, key_id), session)
    assert read.status == "succeeded"
    assert read.result == {"stdout": "ping success"}


def test_full_query_queue_still_reuses_identical_query(session, monkeypatch):
    node_id, key_id = make_query_node_and_key(session)
    first = submit_ping(session, node_id, key_id)
    monkeypatch.setattr(main, "LOOKING_GLASS_QUERY_QUEUE_LIMIT", 1)
    second = submit_ping(session, node_id, key_id)
    assert first.query_id == second.query_id
    assert session.scalar(select(func.count(models.AgentTask.id))) == 1


def test_stale_active_query_releases_unique_key_and_creates_new_query(session):
    node_id, key_id = make_query_node_and_key(session)
    first = submit_ping(session, node_id, key_id)
    query = session.scalar(select(models.LookingGlassQuery))
    query.created_at = datetime.utcnow() - timedelta(hours=1)
    query.deadline_at = datetime.utcnow() - timedelta(minutes=1)
    query.agent_task.deadline_at = query.deadline_at
    session.commit()
    second = submit_ping(session, node_id, key_id)
    assert second.query_id != first.query_id
    assert query.status == "failed"


def test_concurrent_plan_confirm_creates_tasks_only_once(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'confirm.db'}", connect_args={"timeout": 10})
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        node = models.Node(name="plan-node", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        db.add(node)
        db.flush()
        plan = models.ChangePlan(title="deploy", summary="deploy", diff="changed", payload={
            "task_type": "wireguard.apply_config", "task_payload": {"node_id": node.id, "interface_name": "wg0", "config": "config"},
        })
        db.add(plan)
        db.commit()
        plan_id = plan.id
    barrier = threading.Barrier(2)
    monkeypatch.setattr(main, "require_task_supported", lambda *_: None)
    def confirm():
        with Session(engine, autoflush=False) as db:
            # Race before acquisition of the database allocation lock. Waiting
            # inside validation would deadlock the deliberately serialized API.
            barrier.wait(timeout=10)
            try:
                main.confirm_change_plan(plan_id, db)
                return 200
            except HTTPException as exc:
                return exc.status_code
    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: confirm(), range(2)))
        assert sorted(results) == [200, 409]
        with Session(engine) as db:
            assert db.scalar(select(func.count(models.AgentTask.id))) == 1
            assert db.get(models.ChangePlan, plan_id).status == "confirmed"
    finally:
        engine.dispose()


@pytest.mark.parametrize("schema,values", [
    (schemas.InterfaceCreate, {"name": "wg0", "private_key": "key\nPostUp = touch /tmp/injected"}),
    (schemas.InterfaceUpdate, {"name": "wg0", "public_key": "key\x00"}),
    (schemas.PeerCreate, {"public_key": "key\n[Interface]"}),
    (schemas.PeerCreate, {"public_key": "peer", "preshared_key": "key\nPostUp = injected"}),
])
def test_wireguard_keys_reject_config_control_characters(schema, values):
    with pytest.raises(ValidationError):
        schema(**values)


@pytest.mark.parametrize("value", ["fe80::1%$(id)", "fe80::1%eth0\nfilter = injected", "fe80::1%eth0;id"])
def test_udp2raw_api_rejects_unsafe_ipv6_zone(value):
    with pytest.raises(ValidationError):
        schemas.Udp2RawMiddlewareConfig(server_listen_host=value)


def test_udp2raw_api_accepts_safe_ipv6_zone():
    assert schemas.Udp2RawMiddlewareConfig(server_listen_host="fe80::1%eth0").server_listen_host == "fe80::1%eth0"


def test_cidr_validation_does_not_discard_injected_ipv6_zone():
    with pytest.raises(ValidationError):
        schemas.InterfaceCreate(name="wg0", tunnel_ips=["fe80::1%eth0\nPostUp = id/64"])


@pytest.mark.parametrize("queue_after_running", [False, True])
def test_concurrent_interface_enqueue_preserves_transaction(monkeypatch, tmp_path, queue_after_running):
    engine = create_engine(f"sqlite:///{tmp_path / 'enqueue.db'}", connect_args={"timeout": 10})
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        node = models.Node(name="enqueue-node", agent_token_hash="hash")
        db.add(node)
        db.flush()
        interface = models.WireGuardInterface(node_id=node.id, name="wg0", tunnel_ips=[])
        db.add(interface)
        db.commit()
        interface_id = interface.id

    selected = threading.Barrier(2)
    original_get = main.get_interface_task

    def synchronize_pending_reads(db, interface_id, task_type, statuses):
        task = original_get(db, interface_id, task_type, statuses)
        if statuses == ["pending"]:
            selected.wait(timeout=10)
        return task

    monkeypatch.setattr(main, "get_interface_task", synchronize_pending_reads)

    def enqueue():
        with Session(engine, autoflush=False) as db:
            interface = db.get(models.WireGuardInterface, interface_id)
            changed, task = main.enqueue_interface_task_once_with_task(
                db, interface, "wireguard.start", queue_after_running=queue_after_running,
            )
            db.commit()  # A constraint race must not poison the caller's transaction.
            return changed, task.id

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: enqueue(), range(2)))
    assert sorted(changed for changed, _ in results) == [False, True]
    assert results[0][1] == results[1][1]
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(models.AgentTask)) == 1
    engine.dispose()


def test_concurrent_agent_polls_claim_each_task_once(monkeypatch, tmp_path):
    """两个会话读到同一 pending 快照时，仅一个请求能领取任务。"""

    engine = create_engine(f"sqlite:///{tmp_path / 'poll.db'}", connect_args={"timeout": 10})
    Base.metadata.create_all(engine)
    monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
    with Session(engine) as db:
        node = models.Node(name="poll-node", agent_token_hash="hash")
        db.add(node)
        db.flush()
        node_id = node.id
        db.add(models.AgentTask(node_id=node_id, type="wireguard.apply_config", payload={}))
        db.commit()

    selected = threading.Barrier(2)
    original_scalars = Session.scalars

    def synchronize_candidate_reads(db, statement, *args, **kwargs):
        rows = original_scalars(db, statement, *args, **kwargs)
        if "ORDER BY agent_tasks.queue =" in str(statement):
            # Materialize before waiting: both polls must hold the pending
            # snapshot, rather than merely execute one after the other.
            rows = list(rows)
            selected.wait(timeout=10)
        return rows

    monkeypatch.setattr(Session, "scalars", synchronize_candidate_reads)

    def poll():
        with Session(engine, autoflush=False) as db:
            return main.agent_poll(schemas.AgentPollRequest(node_id=node_id, token="token"), db)

    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: poll(), range(2)))
        assert sorted(len(result.tasks) for result in results) == [0, 1]
        with Session(engine) as db:
            task = db.query(models.AgentTask).one()
            assert task.status == "running"
            assert task.started_at is not None
    finally:
        engine.dispose()


def test_agent_task_dependency_cycle_is_failed_instead_of_stuck(session):
    """异常旧数据中的循环依赖必须收敛为失败状态。"""

    node = models.Node(name="cycle-node", agent_token_hash="hash", agent_version="0.6.0", agent_capabilities=["wireguard"])
    session.add(node)
    session.flush()
    first = models.AgentTask(node_id=node.id, type="wireguard.apply_config", payload={})
    second = models.AgentTask(node_id=node.id, type="wireguard.apply_config", payload={})
    session.add_all([first, second])
    session.flush()
    first.payload = {"depends_on_task_id": second.id}
    second.payload = {"depends_on_task_id": first.id}
    session.commit()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
    try:
        result = main.agent_poll(schemas.AgentPollRequest(node_id=node.id, token="token", agent_version="0.6.0", capabilities=["wireguard"]), session)
    finally:
        monkeypatch.undo()
    assert result.tasks == []
    session.refresh(first)
    session.refresh(second)
    assert first.status == "failed"
    assert second.status == "failed"
    assert "cycle" in (first.result or {}).get("error", "") or "cycle" in (second.result or {}).get("error", "")


def test_agent_poll_rejects_oversized_legacy_payload(session):
    """旧库中异常大的任务 payload 不得进入 Agent 轮询响应。"""

    node = models.Node(name="large-task-node", agent_token_hash="hash", agent_version="0.6.0", agent_capabilities=["wireguard"])
    session.add(node)
    session.flush()
    plan = models.ChangePlan(title="large", summary="large", status="confirmed")
    task = models.AgentTask(node_id=node.id, change_plan=plan, type="wireguard.apply_config", payload={"config": "x" * (2 * 1024 * 1024)})
    session.add_all([plan, task])
    session.commit()
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
    try:
        result = main.agent_poll(schemas.AgentPollRequest(node_id=node.id, token="token", agent_version="0.6.0", capabilities=["wireguard"]), session)
    finally:
        monkeypatch.undo()
    assert result.tasks == []
    session.refresh(task)
    session.refresh(plan)
    assert task.status == "failed"
    assert "payload" in (task.result or {}).get("error", "")
    assert plan.status == "failed"


def test_agent_poll_refreshes_node_heartbeat(session):
    """没有任务和链路监测时，tasks/poll 也必须维持节点在线。"""

    old_seen = datetime.utcnow() - timedelta(seconds=120)
    node = models.Node(
        name="poll-heartbeat-node",
        agent_token_hash="hash",
        status="offline",
        last_seen_at=old_seen,
        agent_version="0.6.0",
        agent_capabilities=["wireguard"],
    )
    session.add(node)
    session.commit()
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
        result = main.agent_poll(
            schemas.AgentPollRequest(node_id=node.id, token="token", agent_version="0.6.0", capabilities=["wireguard"]),
            session,
        )
    assert result.tasks == []
    session.refresh(node)
    assert node.status == "online"
    assert node.last_seen_at is not None and node.last_seen_at > old_seen


def test_agent_poll_rejects_non_object_legacy_payload_and_updates_plan(session):
    """旧任务 payload 不是对象时也必须结束关联部署计划。"""

    node = models.Node(name="invalid-task-node", agent_token_hash="hash", agent_version="0.6.0", agent_capabilities=["wireguard"])
    plan = models.ChangePlan(title="invalid", summary="invalid", status="confirmed")
    session.add_all([node, plan])
    session.flush()
    task = models.AgentTask(node_id=node.id, change_plan_id=plan.id, type="wireguard.apply_config", payload=["invalid"])
    session.add(task)
    session.commit()
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
    try:
        result = main.agent_poll(schemas.AgentPollRequest(node_id=node.id, token="token", agent_version="0.6.0", capabilities=["wireguard"]), session)
    finally:
        monkeypatch.undo()
    assert result.tasks == []
    session.refresh(task)
    session.refresh(plan)
    assert task.status == "failed"
    assert plan.status == "failed"


@pytest.mark.parametrize("reported_status", ["succeeded", "failed"])
def test_invalid_agent_result_ends_running_task_and_plan(session, monkeypatch, reported_status):
    """无法接受的 Agent 结果不能让 running 任务等到超时才失败。"""

    node = models.Node(name="invalid-result-node", agent_token_hash="hash")
    plan = models.ChangePlan(title="invalid-result", summary="invalid-result", status="confirmed")
    session.add_all([node, plan])
    session.flush()
    task = models.AgentTask(
        node_id=node.id,
        change_plan_id=plan.id,
        type="wireguard.apply_config",
        status="running",
        payload={},
    )
    session.add(task)
    session.commit()
    monkeypatch.setattr(main, "verify_token", lambda token, token_hash: token == "token")
    request = schemas.AgentTaskResultRequest(
        node_id=node.id,
        token="token",
        status=reported_status,
        result={"output": "x" * (1024 * 1024 + 1)},
    )
    with pytest.raises(HTTPException) as error:
        main.agent_task_result(task.id, request, session)
    assert error.value.status_code == 400
    session.refresh(task)
    session.refresh(plan)
    assert task.status == "failed"
    assert plan.status == "failed"


def test_atomic_write_rejects_symlinked_parent(tmp_path):
    """原子写入不能跟随被替换的受管父目录符号链接。"""

    outside = tmp_path / "outside"
    outside.mkdir()
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "nested").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        atomic_write_text(managed / "nested" / "config", "secret")
    assert not (outside / "config").exists()
