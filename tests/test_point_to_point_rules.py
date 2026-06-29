from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from link42_api.database import Base
from link42_api import models
from link42_api.main import (
    ADMIN_USERNAME,
    SETTING_ADMIN_PASSWORD_HASH,
    SETTING_ADMIN_SESSION_HASH,
    SETTING_ADMIN_USERNAME,
    SETTING_CONTROLLER_URL,
    create_managed_link,
    create_node,
    confirm_change_plan,
    delete_interface,
    delete_node,
    agent_poll,
    agent_register,
    agent_task_result,
    enqueue_interface_task_once,
    ensure_unique_interface_name,
    get_controller_settings,
    get_setting,
    mark_import_candidate_available_for_interface,
    is_node_online,
    is_api_auth_exempt,
    list_import_candidates,
    login,
    require_node_endpoint,
    require_online_node,
    set_setting,
    set_unique_peer,
    should_delete_node_config_file,
    stop_managed_link,
    update_controller_settings,
)
from link42_api.schemas import (
    AgentTaskResultRequest,
    ControllerSettingsUpdate,
    InterfaceCreate,
    InterfaceRead,
    LoginRequest,
    ManagedLinkCreate,
    NodeCreate,
    PeerCreate,
    AgentPollRequest,
    AgentRegisterRequest,
    Udp2RawMiddlewareConfig,
)
from link42_common.security import hash_token, verify_token
from link42_api.wireguard_service import build_diff, count_enabled_peers, render_interface_config
from link42_api.database import ensure_sqlite_point_to_point_constraints


def test_count_enabled_peers_ignores_disabled_peer() -> None:
    """验证点对点规则只统计启用的对端。"""

    interface = models.WireGuardInterface(name="wg0", node_id=1)
    interface.peers = [
        models.WireGuardPeer(interface_id=1, public_key="enabled", enabled=True),
        models.WireGuardPeer(interface_id=1, public_key="disabled", enabled=False),
    ]

    assert count_enabled_peers(interface) == 1


def test_render_still_outputs_single_peer_config() -> None:
    """验证单对端配置会被渲染成一个 Peer 区块。"""

    interface = models.WireGuardInterface(
        name="wg0",
        node_id=1,
        tunnel_ips=["10.42.0.1/30"],
        private_key_value="private",
    )
    interface.peers = [
        models.WireGuardPeer(
            interface_id=1,
            public_key="peer-public",
            allowed_ips=["10.42.0.2/32"],
            enabled=True,
        )
    ]

    rendered = render_interface_config(interface)

    assert rendered.count("[Peer]") == 1
    assert "PublicKey = peer-public" in rendered


def test_diff_uses_deployed_config_as_baseline() -> None:
    """验证已部署配置会作为下一次部署计划的 diff 基线。"""

    deployed = "[Interface]\nAddress = 10.42.0.1/30\n"
    desired = "[Interface]\nAddress = 10.42.0.1/30\nListenPort = 51820\n"

    diff = build_diff(deployed, desired, fromfile="wg0.current", tofile="wg0.link42")

    assert "@@ -1,2 +1,3 @@" in diff
    assert "+ListenPort = 51820" in diff
    assert "@@ -0,0" not in diff


def test_imported_config_inherits_secrets_from_deployed_config() -> None:
    """验证导入配置会保留并渲染真实密钥，方便可信面板自动配置。"""

    deployed = """[Interface]
PrivateKey = local-private
Address = 10.42.42.42/32
ListenPort = 11453

[Peer]
PublicKey = peer-public
PresharedKey = peer-psk
AllowedIPs = 192.168.110.1/32
Endpoint = 192.168.120.1:11451
PersistentKeepalive = 30
"""
    interface = models.WireGuardInterface(
        name="testn",
        node_id=1,
        tunnel_ips=["10.42.42.42/32"],
        listen_port=11453,
        private_key_ref="imported-local-db",
        private_key_value="local-private",
        source="imported",
        managed=True,
        deployed_config=deployed,
    )
    peer = models.WireGuardPeer(
        interface=interface,
        public_key="peer-public",
        preshared_key_ref="imported-local-db",
        preshared_key_value="peer-psk",
        allowed_ips=["192.168.110.1/32"],
        endpoint_host="192.168.120.1",
        endpoint_port=11451,
        persistent_keepalive=30,
        enabled=True,
    )
    interface.peers = [peer]

    rendered = render_interface_config(interface)

    assert "PrivateKey = local-private" in rendered
    assert "PresharedKey = peer-psk" in rendered


def test_interface_read_exposes_primary_peer_endpoint() -> None:
    """验证配置摘要会带出原始 Peer Endpoint，供受管导入时优先预填。"""

    interface = models.WireGuardInterface(
        id=1,
        name="wg0",
        node_id=1,
        tunnel_ips=[],
        dns=[],
        source="imported",
        managed=False,
        enabled=True,
        runtime_status="unknown",
        warnings=[],
    )
    interface.peers = [
        models.WireGuardPeer(
            interface_id=1,
            public_key="peer-public",
            endpoint_host="127.0.0.1",
            endpoint_port=40000,
            allowed_ips=["10.99.0.0/24"],
        )
    ]

    data = InterfaceRead.model_validate(interface)

    assert data.primary_peer_endpoint_host == "127.0.0.1"
    assert data.primary_peer_endpoint_port == 40000
    assert data.primary_peer_allowed_ips == ["10.99.0.0/24"]


def test_require_node_endpoint_allows_original_or_manual_host() -> None:
    """验证受管连接允许使用原始导入 Endpoint 或手填地址，不要求预先登记到节点。"""

    node = models.Node(name="node-a", endpoint_ips=["198.51.100.10"])

    assert require_node_endpoint(node, "127.0.0.1", "missing") == "127.0.0.1"
    assert require_node_endpoint(node, " vpn.example.com ", "missing") == "vpn.example.com"


def test_managed_link_schema_allows_passive_listen_ports() -> None:
    """验证受管连接监听端口可留空，以支持 WireGuard 被动模式。"""

    payload = ManagedLinkCreate(
        peer_node_id=2,
        local_interface_name="wg-a",
        peer_interface_name="wg-b",
        local_tunnel_ips=["10.42.0.1/32"],
        peer_tunnel_ips=["10.42.0.2/32"],
        local_endpoint_host="198.51.100.10",
        peer_endpoint_host="198.51.100.20",
        local_listen_port=None,
        peer_listen_port=None,
    )

    assert payload.local_listen_port is None
    assert payload.peer_listen_port is None


def test_web_login_rotates_session_token() -> None:
    """验证 Web 单用户登录成功后会写入新的会话 token hash。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        set_setting(session, SETTING_ADMIN_PASSWORD_HASH, hash_token("secret-pass"))
        session.commit()

        result = login(LoginRequest(username=ADMIN_USERNAME, password="secret-pass"), session)
        session_hash = get_setting(session, SETTING_ADMIN_SESSION_HASH)

    assert result.username == ADMIN_USERNAME
    assert result.token.startswith("l42web_")
    assert session_hash is not None
    assert verify_token(result.token, session_hash)


def test_web_login_rejects_wrong_password() -> None:
    """验证错误密码不会通过 Web 登录。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        set_setting(session, SETTING_ADMIN_PASSWORD_HASH, hash_token("secret-pass"))
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            login(LoginRequest(username=ADMIN_USERNAME, password="bad-pass"), session)

    assert exc_info.value.status_code == 401


def test_controller_settings_round_trip() -> None:
    """验证设置页保存的主控访问地址和用户名会进入系统设置。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        updated = update_controller_settings(
            ControllerSettingsUpdate(controller_url=" http://10.0.0.1:8000 ", username="admin"),
            session,
        )
        loaded = get_controller_settings(session)
        stored = get_setting(session, SETTING_CONTROLLER_URL)
        username = get_setting(session, SETTING_ADMIN_USERNAME)

    assert updated.controller_url == "http://10.0.0.1:8000"
    assert updated.username == "admin"
    assert loaded.controller_url == "http://10.0.0.1:8000"
    assert loaded.username == "admin"
    assert stored == "http://10.0.0.1:8000"
    assert username == "admin"


def test_controller_settings_can_change_username_and_password() -> None:
    """验证设置页可修改用户名和密码，并使旧会话失效。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        set_setting(session, SETTING_ADMIN_USERNAME, ADMIN_USERNAME)
        set_setting(session, SETTING_ADMIN_PASSWORD_HASH, hash_token("old-pass"))
        set_setting(session, SETTING_ADMIN_SESSION_HASH, hash_token("old-session"))
        session.commit()

        update_controller_settings(
            ControllerSettingsUpdate(
                controller_url="http://10.0.0.1:8000",
                username="new-admin",
                new_password="new-pass",
            ),
            session,
        )
        result = login(LoginRequest(username="new-admin", password="new-pass"), session)
        old_session_hash = get_setting(session, SETTING_ADMIN_SESSION_HASH)

    assert result.username == "new-admin"
    assert old_session_hash is not None
    assert not verify_token("old-session", old_session_hash)


def test_api_auth_exemptions_only_cover_login_and_agent() -> None:
    """验证 API 鉴权白名单只覆盖登录和 Agent token 接口。"""

    assert is_api_auth_exempt("/api/auth/login")
    assert is_api_auth_exempt("/api/agent/heartbeat")
    assert not is_api_auth_exempt("/api/health")
    assert not is_api_auth_exempt("/api/nodes")
    assert not is_api_auth_exempt("/api/settings")


def test_set_unique_peer_replaces_existing_duplicates() -> None:
    """验证保存唯一对端时会更新已有 Peer。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        session.add(node)
        session.flush()
        interface = models.WireGuardInterface(name="wg0", node_id=node.id)
        session.add(interface)
        session.flush()
        session.add(models.WireGuardPeer(interface_id=interface.id, public_key="old-a"))
        session.commit()

        peer = set_unique_peer(
            interface.id,
            PeerCreate(public_key="new-key", allowed_ips=["10.42.0.2/32"]),
            session,
        )
        peers = list(session.query(models.WireGuardPeer).all())

    assert peer.public_key == "new-key"
    assert len(peers) == 1
    assert peers[0].allowed_ips == ["10.42.0.2/32"]


def test_node_online_requires_recent_heartbeat() -> None:
    """验证节点在线状态必须有近期 Agent 心跳支撑。"""

    fresh_node = models.Node(
        name="fresh",
        agent_token_hash="hash",
        status="online",
        last_seen_at=datetime.utcnow(),
    )
    stale_node = models.Node(
        name="stale",
        agent_token_hash="hash",
        status="online",
        last_seen_at=datetime.utcnow() - timedelta(seconds=120),
    )

    assert is_node_online(fresh_node)
    assert not is_node_online(stale_node)


def test_require_online_node_rejects_offline_node() -> None:
    """验证离线节点在提交部署相关操作时会返回明确错误。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="offline")
        session.add(node)
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            require_online_node(session, node.id)

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "agent is offline"


def test_interface_name_unique_check_can_exclude_current_interface() -> None:
    """验证修改配置时允许保留原名称，但拒绝改成同节点其他配置名。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        session.add(node)
        session.flush()
        first = models.WireGuardInterface(name="wg0", node_id=node.id)
        second = models.WireGuardInterface(name="wg1", node_id=node.id)
        session.add_all([first, second])
        session.commit()

        ensure_unique_interface_name(session, node.id, "wg0", exclude_interface_id=first.id)
        with pytest.raises(HTTPException) as exc_info:
            ensure_unique_interface_name(session, node.id, "wg1", exclude_interface_id=first.id)

    assert exc_info.value.status_code == 409


def test_enqueue_interface_task_once_is_idempotent() -> None:
    """验证同一接口的同类未完成任务不会重复入队。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        session.add(node)
        session.flush()
        interface = models.WireGuardInterface(name="wg0", node_id=node.id)
        session.add(interface)
        session.flush()

        first = enqueue_interface_task_once(session, interface, "wireguard.status")
        second = enqueue_interface_task_once(session, interface, "wireguard.status")
        session.commit()
        tasks = list(session.query(models.AgentTask).all())

    assert first is True
    assert second is False
    assert len(tasks) == 1


def test_deleting_imported_config_makes_candidate_importable_again() -> None:
    """验证删除导入配置后，对应导入候选会恢复为可导入状态。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        session.add(node)
        session.flush()
        candidate = models.ImportCandidate(
            node_id=node.id,
            path="/etc/wireguard/wg0.conf",
            interface_name="wg0",
            parsed={"name": "wg0"},
            imported=True,
        )
        interface = models.WireGuardInterface(
            name="wg0",
            node_id=node.id,
            source="imported",
            import_path="/etc/wireguard/wg0.conf",
        )
        session.add_all([candidate, interface])
        session.flush()

        changed = mark_import_candidate_available_for_interface(session, interface)
        session.commit()
        session.refresh(candidate)

    assert changed is True
    assert candidate.imported is False


def test_deleting_created_config_does_not_reset_import_candidate() -> None:
    """验证删除非导入配置不会误改扫描候选状态。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        session.add(node)
        session.flush()
        candidate = models.ImportCandidate(
            node_id=node.id,
            path="/etc/wireguard/wg0.conf",
            interface_name="wg0",
            parsed={"name": "wg0"},
            imported=True,
        )
        interface = models.WireGuardInterface(
            name="wg0",
            node_id=node.id,
            source="created",
            import_path="/etc/wireguard/wg0.conf",
        )
        session.add_all([candidate, interface])
        session.flush()

        changed = mark_import_candidate_available_for_interface(session, interface)
        session.commit()
        session.refresh(candidate)

    assert changed is False
    assert candidate.imported is True


def test_delete_node_requires_all_wireguard_configs_removed() -> None:
    """验证节点下仍有 WireGuard 配置时不能删除节点。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="offline", endpoint_ips=["10.0.0.1"])
        session.add(node)
        session.commit()
        interface = models.WireGuardInterface(node_id=node.id, name="wg0")
        session.add(interface)
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            delete_node(node.id, session)

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "node has wireguard configs"


def test_delete_node_removes_empty_node_related_tasks_and_candidates() -> None:
    """验证空节点可删除，并清理历史任务和扫描候选。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="offline", endpoint_ips=["10.0.0.1"])
        session.add(node)
        session.commit()
        node_id = node.id
        session.add(models.AgentTask(node_id=node_id, type="wireguard.import_scan", payload={}))
        session.add(
            models.ImportCandidate(
                node_id=node_id,
                path="/etc/wireguard/wg0.conf",
                interface_name="wg0",
                parsed={"name": "wg0"},
            )
        )
        session.commit()

        result = delete_node(node_id, session)
        node_count = session.scalar(select(models.Node).where(models.Node.id == node_id))
        task_count = session.scalar(select(models.AgentTask).where(models.AgentTask.node_id == node_id))
        candidate_count = session.scalar(select(models.ImportCandidate).where(models.ImportCandidate.node_id == node_id))

    assert result == {"status": "deleted"}
    assert node_count is None
    assert task_count is None
    assert candidate_count is None


def test_import_scan_result_removes_stale_unimported_candidates(monkeypatch) -> None:
    """验证重新扫描会按当前磁盘文件集合清理旧的未导入候选。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "verify_token", lambda token, token_hash: token == "token")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", endpoint_ips=["10.0.0.1"])
        session.add(node)
        session.commit()
        node_id = node.id
        stale = models.ImportCandidate(
            node_id=node_id,
            path="/etc/wireguard/old.conf",
            interface_name="old",
            parsed={"name": "old"},
            imported=False,
        )
        current = models.ImportCandidate(
            node_id=node_id,
            path="/etc/wireguard/current.conf",
            interface_name="current",
            parsed={"name": "current"},
            imported=False,
        )
        imported = models.ImportCandidate(
            node_id=node_id,
            path="/etc/wireguard/imported.conf",
            interface_name="imported",
            parsed={"name": "imported"},
            imported=True,
        )
        task = models.AgentTask(node_id=node_id, type="wireguard.import_scan", status="running", payload={})
        session.add_all([stale, current, imported, task])
        session.commit()

        agent_task_result(
            task.id,
            AgentTaskResultRequest(
                node_id=node_id,
                token="token",
                status="succeeded",
                result={
                    "candidates": [
                        {
                            "path": "/etc/wireguard/current.conf",
                            "content": "[Interface]\nPrivateKey = private\n",
                            "parsed": {"name": "current-new", "warnings": []},
                            "warnings": [],
                        }
                    ]
                },
            ),
            session,
        )
        candidates = list(session.scalars(select(models.ImportCandidate).order_by(models.ImportCandidate.path)))

    assert [candidate.path for candidate in candidates] == [
        "/etc/wireguard/current.conf",
        "/etc/wireguard/imported.conf",
    ]
    assert candidates[0].interface_name == "current-new"
    assert candidates[0].parsed["raw_config"] == "[Interface]\nPrivateKey = private\n"
    assert candidates[1].imported is True


def test_import_scan_does_not_reoffer_already_imported_path(monkeypatch) -> None:
    """验证已导入的 wg-quick 路径重新扫描后不会再次出现在可导入候选中。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "verify_token", lambda token, token_hash: token == "token")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", endpoint_ips=["10.0.0.1"])
        session.add(node)
        session.commit()
        imported = models.ImportCandidate(
            node_id=node.id,
            path="/etc/wireguard/imported.conf",
            interface_name="imported",
            parsed={"name": "imported"},
            imported=True,
        )
        task = models.AgentTask(node_id=node.id, type="wireguard.import_scan", status="running", payload={})
        session.add_all([imported, task])
        session.commit()

        agent_task_result(
            task.id,
            AgentTaskResultRequest(
                node_id=node.id,
                token="token",
                status="succeeded",
                result={
                    "candidates": [
                        {
                            "path": "/etc/wireguard/imported.conf",
                            "content": "[Interface]\nPrivateKey = new\n",
                            "parsed": {"name": "imported-new", "warnings": []},
                            "warnings": [],
                        }
                    ]
                },
            ),
            session,
        )
        all_candidates = list(session.scalars(select(models.ImportCandidate)))
        visible_candidates = list_import_candidates(node.id, session)

    assert len(all_candidates) == 1
    assert all_candidates[0].imported is True
    assert all_candidates[0].interface_name == "imported"
    assert visible_candidates == []


def test_import_scan_does_not_offer_existing_interface_name(monkeypatch) -> None:
    """验证节点已有同名接口时，不再按 wg-quick 文件名重复提供导入。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "verify_token", lambda token, token_hash: token == "token")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", endpoint_ips=["10.0.0.1"])
        session.add(node)
        session.flush()
        session.add(models.WireGuardInterface(node_id=node.id, name="wg-a", source="managed-node", managed=True))
        task = models.AgentTask(node_id=node.id, type="wireguard.import_scan", status="running", payload={})
        session.add(task)
        session.commit()

        agent_task_result(
            task.id,
            AgentTaskResultRequest(
                node_id=node.id,
                token="token",
                status="succeeded",
                result={
                    "candidates": [
                        {
                            "path": "/etc/wireguard/wg-a.conf",
                            "content": "[Interface]\nPrivateKey = new\n",
                            "parsed": {"name": "wg-a", "warnings": []},
                            "warnings": [],
                        }
                    ]
                },
            ),
            session,
        )
        all_candidates = list(session.scalars(select(models.ImportCandidate)))
        visible_candidates = list_import_candidates(node.id, session)

    assert all_candidates == []
    assert visible_candidates == []


def test_unmanaged_imported_config_delete_keeps_node_file() -> None:
    """验证未接管导入配置删除时不应删除节点原始 wg-quick 文件。"""

    interface = models.WireGuardInterface(
        name="wg0",
        node_id=1,
        source="imported",
        managed=False,
        import_path="/etc/wireguard/wg0.conf",
    )

    assert should_delete_node_config_file(interface) is False


def test_delete_unmanaged_imported_observation_without_agent() -> None:
    """验证删除未接管导入记录只移除观察记录，不要求 Agent 在线或接口停止。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="offline")
        session.add(node)
        session.flush()
        candidate = models.ImportCandidate(
            node_id=node.id,
            path="/etc/wireguard/wg0.conf",
            interface_name="wg0",
            parsed={"name": "wg0"},
            imported=True,
        )
        interface = models.WireGuardInterface(
            name="wg0",
            node_id=node.id,
            source="imported",
            managed=False,
            import_path="/etc/wireguard/wg0.conf",
            runtime_status="running",
        )
        session.add_all([candidate, interface])
        session.commit()
        interface_id = interface.id
        candidate_id = candidate.id

        result = delete_interface(interface_id, session)
        remaining_interface = session.get(models.WireGuardInterface, interface_id)
        refreshed_candidate = session.get(models.ImportCandidate, candidate_id)
        tasks = list(session.scalars(select(models.AgentTask)))

    assert result == {"status": "deleted"}
    assert remaining_interface is None
    assert refreshed_candidate is not None
    assert refreshed_candidate.imported is False
    assert tasks == []


def test_managed_imported_config_delete_removes_node_file() -> None:
    """验证已接管导入配置删除时才应删除节点上的受管文件。"""

    interface = models.WireGuardInterface(
        name="wg0",
        node_id=1,
        source="imported",
        managed=True,
        import_path="/etc/wireguard/wg0.conf",
    )

    assert should_delete_node_config_file(interface) is True


def test_schema_rejects_invalid_ports_and_cidrs() -> None:
    """验证 API schema 会拒绝明显错误的配置输入。"""

    with pytest.raises(ValueError):
        InterfaceCreate(name="wg0", tunnel_ips=["10.42.0.1"], listen_port=51820)

    with pytest.raises(ValueError):
        InterfaceCreate(name="wg0", tunnel_ips=["10.42.0.1/24"], listen_port=70000)

    with pytest.raises(ValueError):
        PeerCreate(public_key="peer", allowed_ips=["10.42.0.2/32"], endpoint_port=70000)


def test_confirm_change_plan_rejects_empty_diff() -> None:
    """验证没有 diff 的部署计划不能被确认下发。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        session.add(node)
        session.flush()
        plan = models.ChangePlan(
            title="Noop",
            summary="No changes",
            affected_node_ids=[node.id],
            diff="",
            payload={"task_type": "wireguard.apply_config", "task_payload": {"node_id": node.id}},
        )
        session.add(plan)
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            confirm_change_plan(plan.id, session)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "change plan has no diff"


def test_create_node_stores_viewable_agent_token() -> None:
    """验证可信面板可再次查看新创建节点的 Agent token。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        result = create_node(NodeCreate(name="node-a", endpoint_ips=["198.51.100.10"]), session)
        node = session.get(models.Node, result.node.id)

    assert result.agent_token.startswith("l42agent_")
    assert node is not None
    assert node.agent_token_value == result.agent_token


def test_create_managed_link_creates_both_sides_with_generated_keys(monkeypatch) -> None:
    """验证受管节点互联会一次创建双方配置和互指 peer。"""

    private_keys = iter(["local-private", "peer-private"])
    public_keys = iter(["local-public", "peer-public"])

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "generate_wireguard_keypair", lambda: (next(private_keys), next(public_keys)))
    monkeypatch.setattr(api_main, "generate_preshared_key", lambda: "shared-key")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node_a = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.10", "10.0.0.10"],
            last_seen_at=datetime.utcnow(),
        )
        node_b = models.Node(
            name="node-b",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.20", "10.0.0.20"],
            last_seen_at=datetime.utcnow(),
        )
        session.add_all([node_a, node_b])
        session.commit()
        node_ids = {node_a.id, node_b.id}

        result = create_managed_link(
            node_a.id,
            ManagedLinkCreate(
                peer_node_id=node_b.id,
                local_interface_name="wg-a",
                peer_interface_name="wg-b",
                local_tunnel_ips=["10.42.0.1/32"],
                peer_tunnel_ips=["10.42.0.2/32"],
                local_allowed_ips=["10.88.0.0/24"],
                peer_allowed_ips=["10.99.0.0/24"],
                local_endpoint_host="10.0.0.10",
                peer_endpoint_host="10.0.0.20",
                local_listen_port=51820,
                peer_listen_port=51821,
                mtu=1420,
                table_name="off",
                local_interface_custom_config="PostUp = ip route add 10.1.0.0/16 dev wg-a",
                local_peer_custom_config="PersistentKeepalive = 24",
                peer_interface_custom_config="PostUp = ip route add 10.2.0.0/16 dev wg-b",
                peer_peer_custom_config="PersistentKeepalive = 25",
            ),
            session,
        )
        local_peer = session.scalar(
            select(models.WireGuardPeer).where(models.WireGuardPeer.interface_id == result.local_interface.id)
        )
        remote_peer = session.scalar(
            select(models.WireGuardPeer).where(models.WireGuardPeer.interface_id == result.peer_interface.id)
        )
        tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.node_id)))

    assert result.local_interface.private_key_value == "local-private"
    assert result.local_interface.public_key == "local-public"
    assert result.peer_interface.private_key_value == "peer-private"
    assert result.peer_interface.public_key == "peer-public"
    assert result.local_interface.runtime_status == "starting"
    assert result.peer_interface.runtime_status == "starting"
    assert local_peer is not None
    assert local_peer.public_key == "peer-public"
    assert local_peer.preshared_key_value == "shared-key"
    assert local_peer.endpoint_host == "10.0.0.20"
    assert local_peer.endpoint_port == 51821
    assert local_peer.allowed_ips == ["10.88.0.0/24"]
    assert remote_peer is not None
    assert remote_peer.public_key == "local-public"
    assert remote_peer.endpoint_host == "10.0.0.10"
    assert remote_peer.endpoint_port == 51820
    assert remote_peer.allowed_ips == ["10.99.0.0/24"]
    assert len(tasks) == 2
    assert {task.node_id for task in tasks} == {result.local_interface.node_id, result.peer_interface.node_id}
    assert {task.payload["interface_id"] for task in tasks} == {result.local_interface.id, result.peer_interface.id}
    assert all(task.type == "wireguard.apply_config" for task in tasks)
    assert all(task.payload["enable_on_boot"] is True for task in tasks)
    assert all(task.payload["auto_start"] is True for task in tasks)
    assert all("[Peer]" in task.payload["config"] for task in tasks)
    assert all("MTU = 1420" in task.payload["config"] for task in tasks)
    assert all("Table = off" in task.payload["config"] for task in tasks)
    assert any("AllowedIPs = 10.88.0.0/24" in task.payload["config"] for task in tasks)
    assert any("AllowedIPs = 10.99.0.0/24" in task.payload["config"] for task in tasks)
    assert any("PublicKey = peer-public" in task.payload["config"] for task in tasks)
    assert any("PublicKey = local-public" in task.payload["config"] for task in tasks)
    assert any("PostUp = ip route add 10.1.0.0/16 dev wg-a" in task.payload["config"] for task in tasks)
    assert any("PostUp = ip route add 10.2.0.0/16 dev wg-b" in task.payload["config"] for task in tasks)


def test_agent_register_saves_version_and_poll_filters_unsupported_tasks(monkeypatch) -> None:
    """验证主控保存 Agent 版本能力，并不会把不支持的任务交给旧 Agent。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "verify_token", lambda token, token_hash: token == "token")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="offline")
        session.add(node)
        session.commit()
        node_id = node.id
        session.add_all(
            [
                models.AgentTask(node_id=node_id, type="middleware.udp2raw.apply", payload={"node_id": node_id}),
                models.AgentTask(node_id=node_id, type="wireguard.import_scan", payload={"node_id": node_id}),
            ]
        )
        session.commit()

        agent_register(
            AgentRegisterRequest(
                node_id=node_id,
                token="token",
                hostname="host-a",
                agent_version="0.1.0",
                protocol_version=1,
                capabilities=["wireguard", "wg_quick_import", "service:systemd"],
                platform={"service_manager": "systemd"},
            ),
            session,
        )
        response = agent_poll(
            AgentPollRequest(
                node_id=node_id,
                token="token",
                agent_version="0.1.0",
                protocol_version=1,
                capabilities=["wireguard", "wg_quick_import", "service:systemd"],
            ),
            session,
        )
        node = session.get(models.Node, node_id)

    assert node is not None
    assert node.agent_version == "0.1.0"
    assert node.agent_capabilities == ["service:systemd", "wg_quick_import", "wireguard"]
    assert [task.type for task in response.tasks] == ["wireguard.import_scan"]


def test_create_managed_link_with_udp2raw_uses_single_direction(monkeypatch) -> None:
    """验证 udp2raw 中间层只要求服务端 WireGuard ListenPort，并接管客户端 Endpoint。"""

    private_keys = iter(["local-private", "peer-private"])
    public_keys = iter(["local-public", "peer-public"])

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "generate_wireguard_keypair", lambda: (next(private_keys), next(public_keys)))
    monkeypatch.setattr(api_main, "generate_preshared_key", lambda: "shared-key")
    monkeypatch.setattr(api_main, "generate_token", lambda prefix: f"{prefix}_secret")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    capabilities = [
        "wireguard",
        "wg_quick_import",
        "service:systemd",
        "middleware",
        "middleware.install",
        "middleware.udp2raw",
    ]
    with Session(engine) as session:
        node_a = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.10"],
            agent_version="0.2.0",
            agent_capabilities=capabilities,
            last_seen_at=datetime.utcnow(),
        )
        node_b = models.Node(
            name="node-b",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.20"],
            agent_version="0.2.0",
            agent_capabilities=capabilities,
            last_seen_at=datetime.utcnow(),
        )
        session.add_all([node_a, node_b])
        session.commit()

        result = create_managed_link(
            node_a.id,
            ManagedLinkCreate(
                peer_node_id=node_b.id,
                local_interface_name="wg-a",
                peer_interface_name="wg-b",
                local_tunnel_ips=["10.42.0.1/32"],
                peer_tunnel_ips=["10.42.0.2/32"],
                local_endpoint_host="198.51.100.10",
                peer_endpoint_host="198.51.100.20",
                local_listen_port=None,
                peer_listen_port=51821,
                udp2raw=Udp2RawMiddlewareConfig(
                    enabled=True,
                    server_side="peer",
                    server_listen_port=23002,
                    client_listen_port=12312,
                ),
            ),
            session,
        )
        local_peer = session.scalar(
            select(models.WireGuardPeer).where(models.WireGuardPeer.interface_id == result.local_interface.id)
        )
        remote_peer = session.scalar(
            select(models.WireGuardPeer).where(models.WireGuardPeer.interface_id == result.peer_interface.id)
        )
        tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.id)))

    assert local_peer is not None
    assert local_peer.endpoint_host == "127.0.0.1"
    assert local_peer.endpoint_port == 12312
    assert remote_peer is not None
    assert remote_peer.endpoint_host is None
    assert remote_peer.endpoint_port is None
    assert [task.type for task in tasks] == [
        "middleware.install",
        "middleware.install",
        "middleware.udp2raw.apply",
        "middleware.udp2raw.apply",
        "wireguard.apply_config",
        "wireguard.apply_config",
    ]
    assert tasks[2].payload["mode"] == "server"
    assert tasks[2].payload["remote_port"] == 51821
    assert tasks[3].payload["mode"] == "client"
    assert tasks[3].payload["remote_host"] == "198.51.100.20"


def test_stop_managed_link_queues_both_sides(monkeypatch) -> None:
    """验证受管连接断开操作会同时作用于双方节点。"""

    private_keys = iter(["local-private", "peer-private"])
    public_keys = iter(["local-public", "peer-public"])

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "generate_wireguard_keypair", lambda: (next(private_keys), next(public_keys)))
    monkeypatch.setattr(api_main, "generate_preshared_key", lambda: "shared-key")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node_a = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.10"],
            last_seen_at=datetime.utcnow(),
        )
        node_b = models.Node(
            name="node-b",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.20"],
            last_seen_at=datetime.utcnow(),
        )
        session.add_all([node_a, node_b])
        session.commit()
        node_ids = {node_a.id, node_b.id}

        result = create_managed_link(
            node_a.id,
            ManagedLinkCreate(
                peer_node_id=node_b.id,
                local_interface_name="wg-a",
                peer_interface_name="wg-b",
                local_tunnel_ips=["10.42.0.1/32", "fd42::1/64"],
                peer_tunnel_ips=["10.42.0.2/32", "fd42::2/64"],
                local_endpoint_host="198.51.100.10",
                peer_endpoint_host="198.51.100.20",
                local_listen_port=51820,
                peer_listen_port=51821,
                table_name="off",
            ),
            session,
        )
        session.query(models.AgentTask).delete()
        result.local_interface.runtime_status = "running"
        result.peer_interface.runtime_status = "running"
        session.commit()

        stop_managed_link(result.local_interface.id, session)
        tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.node_id)))

    assert len(tasks) == 2
    assert {task.node_id for task in tasks} == node_ids
    assert all(task.type == "wireguard.stop_interface" for task in tasks)


def test_sqlite_point_to_point_repair_can_create_unique_index(monkeypatch) -> None:
    """验证旧 SQLite 库启动修复会删除重复对端并创建唯一索引。"""

    import link42_api.database as database

    engine = create_engine("sqlite:///:memory:")
    monkeypatch.setattr(database, "engine", engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE wg_peers (id INTEGER PRIMARY KEY, interface_id INTEGER NOT NULL)"))
        connection.execute(text("CREATE TABLE wg_interfaces (id INTEGER PRIMARY KEY, name VARCHAR(32) NOT NULL)"))
        connection.execute(text("CREATE TABLE nodes (id INTEGER PRIMARY KEY, name VARCHAR(80) NOT NULL)"))
        connection.execute(
            text(
                """
                INSERT INTO wg_peers (id, interface_id)
                VALUES
                    (1, 1),
                    (2, 1)
                """
            )
        )

    ensure_sqlite_point_to_point_constraints()

    with engine.connect() as connection:
        peer_count = connection.scalar(text("SELECT COUNT(*) FROM wg_peers"))
        index_count = connection.scalar(
            text("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'uq_wg_peer_interface_id'")
        )
        columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(wg_interfaces)")).fetchall()
        }
        node_columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(nodes)")).fetchall()
        }

    assert peer_count == 1
    assert index_count == 1
    assert "deployed_config" in columns
    assert "runtime_status" in columns
    assert "endpoint_ips" in node_columns
    assert "agent_token_value" in node_columns
