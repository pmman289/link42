from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException, Response
from fastapi.testclient import TestClient
from link42_common.connection_types import (
    GRE_TASKS,
    LOOKING_GLASS_BIRD_PROTOCOL_DETAIL_TASK,
    LOOKING_GLASS_BIRD_PROTOCOLS_TASK,
    LOOKING_GLASS_BIRD_ROUTE_LOOKUP_TASK,
    LOOKING_GLASS_BIRD_ROUTES_BY_ORIGIN_AS_TASK,
    LOOKING_GLASS_PING_TASK,
    LOOKING_GLASS_TRACEROUTE_TASK,
    TASK_REQUIREMENTS,
    WIREGUARD_TASKS,
)
from pydantic import ValidationError
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from link42_api.database import Base
from link42_api import models
from link42_api.connection_drivers import connection_driver_for_interface
from link42_api.node_plugins.base import NodePluginContext
from link42_api.node_plugins.bird import BirdNodePlugin
from link42_api.main import (
    ADMIN_USERNAME,
    SETTING_ADMIN_PASSWORD_HASH,
    SETTING_ADMIN_SESSION_HASH,
    SETTING_ADMIN_USERNAME,
    SETTING_CONTROLLER_URL,
    app,
    create_managed_link,
    create_managed_connection,
    gre_connection_read,
    create_node,
    confirm_change_plan,
    delete_interface,
    delete_managed_link,
    delete_node,
    agent_poll,
    agent_link_monitor_poll,
    agent_link_monitor_result,
    agent_register,
    agent_task_result,
    build_agent_upgrade_plan,
    build_topology,
    enqueue_interface_task_once,
    ensure_unique_interface_name,
    expire_stale_running_agent_tasks,
    get_controller_settings,
    get_db,
    list_node_connections,
    get_setting,
    list_node_plugins_for_node,
    install_node_middleware,
    mark_import_candidate_available_for_interface,
    is_node_online,
    is_api_auth_exempt,
    list_import_candidates,
    list_nodes,
    login,
    mimic_endpoint_payloads,
    normalize_udp2raw_config,
    normalize_middleware_config,
    plan_apply,
    require_node_endpoint,
    require_mimic_supported,
    require_online_node,
    require_udp2raw_supported,
    request_import_scan,
    require_mimic_install_supported,
    set_setting,
    set_unique_peer,
    should_delete_node_config_file,
    start_interface,
    stop_managed_link,
    update_controller_settings,
    update_interface,
    update_managed_link,
    udp2raw_endpoint_payloads,
    request_agent_upgrade,
    request_node_plugin_action,
    create_port_inventory_entry,
    get_port_inventory,
    update_port_inventory_range,
    update_node_topology_position,
    create_looking_glass_token,
    delete_looking_glass_token,
    require_looking_glass_api_key,
    submit_looking_glass_bird_protocol_detail,
    submit_looking_glass_bird_protocols,
    submit_looking_glass_bird_route_lookup,
    submit_looking_glass_bird_routes_by_origin_as,
    submit_looking_glass_ping,
    submit_looking_glass_traceroute,
    get_looking_glass_query,
)
from link42_api.schemas import (
    AgentTaskResultRequest,
    ControllerSettingsUpdate,
    InterfaceCreate,
    InterfaceUpdate,
    InterfaceRead,
    LoginRequest,
    ManagedLinkCreate,
    ManagedLinkUpdate,
    MimicMiddlewareConfig,
    NodeCreate,
    PeerCreate,
    AgentPollRequest,
    AgentRegisterRequest,
    AgentLinkMonitorResultItem,
    AgentLinkMonitorResultRequest,
    AgentUpgradeRequest,
    GreManagedConnectionCreate,
    IntegrationApiTokenCreate,
    LookingGlassPingRequest,
    LookingGlassProtocolDetailRequest,
    LookingGlassQueryRead,
    LookingGlassRouteLookupRequest,
    LookingGlassRoutesByOriginAsRequest,
    LookingGlassTracerouteRequest,
    NodePluginActionRequest,
    PortInventoryEntryCreate,
    PortInventorySettingUpdate,
    LinkMonitorCreate,
    Udp2RawMiddlewareConfig,
    TopologyPositionUpdate,
)
from link42_common.security import hash_token, verify_token
from link42_api.wireguard_service import (
    build_apply_plan,
    build_diff,
    build_interface_rename_diff,
    count_enabled_peers,
    render_interface_config,
)
from link42_api.database import backup_sqlite_database_for_upgrade, ensure_sqlite_point_to_point_constraints


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


def test_wireguard_connection_driver_exposes_standard_tasks() -> None:
    """验证主控连接驱动先承载现有 WireGuard 任务，后续可替换为其他连接后端。"""

    interface = models.WireGuardInterface(
        id=1,
        node_id=1,
        name="wg0",
        tunnel_ips=["10.42.0.1/32"],
        private_key_value="private",
        managed=True,
    )
    interface.peers = [
        models.WireGuardPeer(
            interface_id=1,
            public_key="peer-public",
            allowed_ips=["10.42.0.2/32"],
            enabled=True,
        )
    ]

    driver = connection_driver_for_interface(interface)
    payload = driver.build_apply_payload(interface)

    assert driver.type == "wireguard"
    assert driver.tasks == WIREGUARD_TASKS


def test_node_plugin_status_reports_missing_capability() -> None:
    """验证节点插件宿主会报告 Agent 能力缺口。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            endpoint_ips=["203.0.113.1"],
            status="online",
            agent_token_hash="hash",
            agent_capabilities=["wireguard"],
            agent_version="0.5.9",
            last_seen_at=datetime.utcnow(),
        )
        session.add(node)
        session.commit()

        plugins = list_node_plugins_for_node(node.id, session)

    port_plugin = next(plugin for plugin in plugins if plugin["type"] == "port-inventory")
    assert port_plugin["available"] is False
    assert port_plugin["missing_capabilities"] == ["node_plugin.port_inventory"]


def test_node_plugin_status_checks_agent_version() -> None:
    """验证插件可用状态同时受 Agent 版本和 capability 约束。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            endpoint_ips=["203.0.113.1"],
            status="online",
            agent_token_hash="hash",
            agent_version="0.5.7",
            agent_capabilities=["node_plugin.port_inventory"],
            last_seen_at=datetime.utcnow(),
        )
        session.add(node)
        session.commit()

        plugins = list_node_plugins_for_node(node.id, session)

    port_plugin = next(plugin for plugin in plugins if plugin["type"] == "port-inventory")
    assert port_plugin["available"] is False
    assert port_plugin["version_supported"] is False
    assert port_plugin["missing_capabilities"] == []


def test_node_plugin_action_creates_agent_task() -> None:
    """验证节点插件 action 通过宿主 API 入队为 Agent 任务。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            endpoint_ips=["203.0.113.1"],
            status="online",
            agent_token_hash="hash",
            agent_version="0.6.0",
            agent_capabilities=["node_plugin.port_inventory"],
            last_seen_at=datetime.utcnow(),
        )
        session.add(node)
        session.commit()

        result = request_node_plugin_action(
            node.id,
            "port-inventory",
            "scan",
            NodePluginActionRequest(payload={"range_start": 23000, "range_end": 23099}),
            session,
        )
        task = session.get(models.AgentTask, result.task_id)

    assert result.status == "pending"
    assert task is not None
    assert task.type == "node_plugin.port_inventory.scan"
    assert task.payload["range_start"] == 23000
    assert task.payload["range_end"] == 23099


def test_node_plugin_action_rejects_offline_node() -> None:
    """验证插件 action 入口不只依赖前端禁用，后端也拒绝离线节点。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            endpoint_ips=["203.0.113.1"],
            status="offline",
            agent_token_hash="hash",
            agent_version="0.5.10",
            agent_capabilities=["node_plugin.port_inventory"],
        )
        session.add(node)
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            request_node_plugin_action(
                node.id,
                "port-inventory",
                "scan",
                NodePluginActionRequest(payload={"range_start": 23000, "range_end": 23099}),
                session,
            )

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "node is offline"


def test_bird_node_plugin_action_creates_agent_task() -> None:
    """验证 Bird 节点插件通过宿主 API 入队为 Agent 任务。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            endpoint_ips=["203.0.113.1"],
            status="online",
            agent_token_hash="hash",
            agent_version="0.5.9",
            agent_capabilities=["node_plugin.bird"],
            last_seen_at=datetime.utcnow(),
        )
        session.add(node)
        session.commit()

        result = request_node_plugin_action(
            node.id,
            "bird",
            "read",
            NodePluginActionRequest(payload={"resource_key": "/etc/bird/bird.conf"}),
            session,
        )
        task = session.get(models.AgentTask, result.task_id)

    assert result.status == "pending"
    assert task is not None
    assert task.type == "node_plugin.bird.read"
    assert task.payload["resource_key"] == "/etc/bird/bird.conf"


def test_port_inventory_range_entry_and_search() -> None:
    """验证端口台账范围、条目唯一性和搜索。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            endpoint_ips=["203.0.113.1"],
            status="online",
            agent_token_hash="hash",
        )
        session.add(node)
        session.commit()

        setting = update_port_inventory_range(
            node.id,
            PortInventorySettingUpdate(range_start=23000, range_end=23099),
            session,
        )
        entry = create_port_inventory_entry(
            node.id,
            PortInventoryEntryCreate(protocol="udp", port=23001, purpose="WireGuard"),
            session,
        )
        inventory = get_port_inventory(node.id, "wire", session)

        with pytest.raises(HTTPException) as duplicate_exc:
            create_port_inventory_entry(
                node.id,
                PortInventoryEntryCreate(protocol="UDP", port=23001, purpose="duplicate"),
                session,
            )
        with pytest.raises(HTTPException) as range_exc:
            create_port_inventory_entry(
                node.id,
                PortInventoryEntryCreate(protocol="TCP", port=24000, purpose="outside"),
                session,
            )

    assert setting.range_start == 23000
    assert setting.range_end == 23099
    assert entry.protocol == "UDP"
    assert [item.port for item in inventory.entries] == [23001]
    assert duplicate_exc.value.status_code == 409
    assert range_exc.value.status_code == 400


def test_bird_node_plugin_preserves_config_content_bytes() -> None:
    """验证 Controller 不会 trim BIRD 配置内容，避免原样应用也改变文件。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    content = "router id 10.0.0.1;\n\n"
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online")
        session.add(node)
        session.commit()
        plugin = BirdNodePlugin()

        cleaned = plugin.validate_payload(
            "apply",
            {
                "resource_key": " /etc/bird/bird.conf ",
                "content": content,
                "base_sha256": " abc123 ",
                "reload": False,
            },
            NodePluginContext(node=node, db=session),
        )

    assert cleaned["resource_key"] == "/etc/bird/bird.conf"
    assert cleaned["base_sha256"] == "abc123"
    assert cleaned["content"] == content


def test_bird_node_plugin_apply_many_preserves_all_config_content_bytes() -> None:
    """验证批量保存 payload 不 trim 任意文件内容。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online")
        session.add(node)
        session.commit()
        plugin = BirdNodePlugin()

        cleaned = plugin.validate_payload(
            "apply_many",
            {
                "files": [
                    {
                        "resource_key": " /etc/bird/bird.conf ",
                        "content": "router id 10.0.0.1;\n\n",
                        "base_sha256": " abc123 ",
                    },
                    {
                        "resource_key": "/etc/bird/conf.d/peer.conf",
                        "content": "\nprotocol device {}\n",
                        "base_sha256": " def456 ",
                    },
                ],
                "reload": False,
            },
            NodePluginContext(node=node, db=session),
        )

    assert cleaned["reload"] is False
    assert cleaned["files"][0]["resource_key"] == "/etc/bird/bird.conf"
    assert cleaned["files"][0]["content"] == "router id 10.0.0.1;\n\n"
    assert cleaned["files"][0]["base_sha256"] == "abc123"
    assert cleaned["files"][1]["content"] == "\nprotocol device {}\n"


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
    """验证受管连接监听端口和单侧 Endpoint 可留空，以支持被动和不对称出入口。"""

    payload = ManagedLinkCreate(
        peer_node_id=2,
        local_interface_name="wg-a",
        peer_interface_name="wg-b",
        local_tunnel_ips=["10.42.0.1/32", "fd42::1/64"],
        peer_tunnel_ips=["10.42.0.2/32", "fd42::2/64"],
        local_allowed_ips=["0.0.0.0/0", "::/0"],
        peer_allowed_ips=["172.20.0.0/14", "fd00::/8"],
        local_endpoint_host="198.51.100.10",
        local_endpoint_port=11451,
        peer_endpoint_host=None,
        peer_endpoint_port=11452,
        local_listen_port=None,
        peer_listen_port=None,
    )

    assert payload.local_listen_port is None
    assert payload.peer_listen_port is None
    assert payload.local_tunnel_ips == ["10.42.0.1/32", "fd42::1/64"]
    assert payload.local_allowed_ips == ["0.0.0.0/0", "::/0"]
    assert payload.peer_allowed_ips == ["172.20.0.0/14", "fd00::/8"]
    assert payload.local_endpoint_port == 11451
    assert payload.peer_endpoint_host is None
    assert payload.peer_endpoint_port == 11452


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


def test_web_login_replaces_previous_session_token() -> None:
    """验证最后一次登录会挤掉上一次 Web 会话。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        set_setting(session, SETTING_ADMIN_PASSWORD_HASH, hash_token("secret-pass"))
        session.commit()

        first = login(LoginRequest(username=ADMIN_USERNAME, password="secret-pass"), session)
        second = login(LoginRequest(username=ADMIN_USERNAME, password="secret-pass"), session)
        session_hash = get_setting(session, SETTING_ADMIN_SESSION_HASH)

    assert session_hash is not None
    assert not verify_token(first.token, session_hash)
    assert verify_token(second.token, session_hash)


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


def test_controller_settings_password_requires_six_characters() -> None:
    """验证设置页新密码至少需要 6 个字符。"""

    with pytest.raises(ValidationError):
        ControllerSettingsUpdate(
            controller_url="http://10.0.0.1:8000",
            username="admin",
            new_password="short",
        )


def test_openwrt_read_config_keeps_deployed_baseline_and_allows_start(monkeypatch) -> None:
    """验证 OpenWrt UCI 后端刷新配置时不会把文件式基线清空，且可继续下发启动任务。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "verify_token", lambda token, token_hash: token == "token")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="owrt",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["10.0.0.1"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.2.0",
            agent_capabilities=["wireguard", "wg_quick_import", "service:openwrt-uci"],
            agent_platform={"service_manager": "openwrt-uci"},
        )
        interface = models.WireGuardInterface(
            node=node,
            name="l42owrt91",
            source="created",
            managed=True,
            deployed_config="[Interface]\nAddress = 10.42.0.1/32\n",
            runtime_status="stopped",
        )
        read_task = models.AgentTask(
            node=node,
            type="wireguard.read_config",
            status="running",
            payload={},
        )
        session.add_all([node, interface, read_task])
        session.commit()
        read_task.payload = {"interface_id": interface.id, "interface_name": interface.name}
        session.commit()

        agent_task_result(
            read_task.id,
            AgentTaskResultRequest(
                node_id=node.id,
                token="token",
                status="succeeded",
                result={
                    "exists": False,
                    "config": "",
                    "config_backend": "openwrt-uci",
                    "service": {"runtime_status": "running"},
                },
            ),
            session,
        )
        refreshed = session.get(models.WireGuardInterface, interface.id)
        assert refreshed is not None
        assert refreshed.deployed_config == "[Interface]\nAddress = 10.42.0.1/32\n"

        refreshed.deployed_config = ""
        session.commit()
        start_interface(interface.id, session)
        tasks = list(session.scalars(select(models.AgentTask).where(models.AgentTask.type == "wireguard.start_interface")))

    assert len(tasks) == 1
    assert tasks[0].payload["interface_id"] == interface.id


def test_topology_returns_nodes_and_single_managed_edge() -> None:
    """验证拓扑只基于受管双向链路生成边，且同一链路不会重复。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node_a = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            region="广州",
            endpoint_ips=["198.51.100.10"],
            topology_endpoint="10.42.0.1",
            last_seen_at=datetime.utcnow(),
        )
        node_b = models.Node(
            name="node-b",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.20"],
            last_seen_at=datetime.utcnow(),
        )
        node_c = models.Node(
            name="node-c",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.30"],
            last_seen_at=datetime.utcnow(),
        )
        session.add_all([node_a, node_b, node_c])
        session.flush()
        wg_a = models.WireGuardInterface(
            node_id=node_a.id,
            name="wg-a",
            source="managed-node",
            runtime_status="running",
            extras={"middleware": {"enabled": True, "type": "mimic"}},
        )
        wg_b = models.WireGuardInterface(
            node_id=node_b.id,
            name="wg-b",
            source="managed-node",
            runtime_status="running",
            extras={"middleware": {"enabled": True, "type": "mimic"}},
        )
        unmanaged = models.WireGuardInterface(
            node_id=node_c.id,
            name="wg-imported",
            source="imported",
            runtime_status="running",
        )
        session.add_all([wg_a, wg_b, unmanaged])
        session.flush()
        session.add_all(
            [
                models.WireGuardPeer(
                    interface_id=wg_a.id,
                    peer_node_id=node_b.id,
                    peer_interface_id=wg_b.id,
                    public_key="b",
                    source="managed-node",
                ),
                models.WireGuardPeer(
                    interface_id=wg_b.id,
                    peer_node_id=node_a.id,
                    peer_interface_id=wg_a.id,
                    public_key="a",
                    source="managed-node",
                ),
                models.WireGuardPeer(
                    interface_id=unmanaged.id,
                    peer_node_id=node_a.id,
                    peer_interface_id=wg_a.id,
                    public_key="ignored",
                    source="created",
                ),
            ]
        )
        session.commit()

        topology = build_topology(session)

    assert [node.name for node in topology.nodes] == ["node-a", "node-b", "node-c"]
    assert topology.nodes[0].region == "广州"
    assert topology.nodes[0].topology_endpoint == "10.42.0.1"
    assert len(topology.edges) == 1
    assert topology.edges[0].local_interface_name == "wg-a"
    assert topology.edges[0].peer_interface_name == "wg-b"
    assert topology.edges[0].middleware_type == "mimic"


def test_topology_reports_stale_node_offline_without_persisting_status() -> None:
    """验证拓扑读取只计算离线展示状态，不在 GET 路径里写库。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            last_seen_at=datetime.utcnow() - timedelta(seconds=120),
        )
        session.add(node)
        session.commit()

        topology = build_topology(session)

        assert topology.nodes[0].status == "offline"
        assert node.status == "online"
        assert not session.is_modified(node)


def test_list_nodes_reports_stale_node_offline_without_dirtying_session() -> None:
    """验证节点列表读取不会为了展示离线状态污染当前会话。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            last_seen_at=datetime.utcnow() - timedelta(seconds=120),
        )
        session.add(node)
        session.commit()

        nodes = list_nodes(session)

        assert nodes[0].status == "offline"
        assert node.status == "online"
        assert not session.is_modified(node)


def test_update_node_topology_position_persists_coordinates() -> None:
    """验证拖拽拓扑节点后坐标会写回节点记录。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="offline", endpoint_ips=["10.0.0.1"])
        session.add(node)
        session.commit()

        updated = update_node_topology_position(
            node.id,
            TopologyPositionUpdate(x=123.5, y=456.25),
            session,
        )

    assert updated.topology_x == 123.5
    assert updated.topology_y == 456.25
    assert updated.topology_locked is True


def test_reset_topology_layout_clears_saved_coordinates() -> None:
    """验证还原拓扑布局会清空所有节点自定义坐标。"""

    from link42_api.main import reset_topology_layout

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="offline",
            endpoint_ips=["10.0.0.1"],
            topology_x=123.5,
            topology_y=456.25,
            topology_locked=True,
        )
        session.add(node)
        session.commit()

        topology = reset_topology_layout(session)
        refreshed = session.get(models.Node, node.id)

    assert refreshed is not None
    assert refreshed.topology_x is None
    assert refreshed.topology_y is None
    assert refreshed.topology_locked is False
    assert topology.nodes[0].topology_x is None
    assert topology.nodes[0].topology_y is None
    assert topology.nodes[0].topology_locked is False


def test_sqlite_migration_adds_topology_columns() -> None:
    """验证旧 SQLite nodes 表启动时会补齐拓扑坐标列。"""

    import link42_api.database as database

    engine = create_engine("sqlite:///:memory:")
    original_engine = database.engine
    try:
        database.engine = engine
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    CREATE TABLE nodes (
                        id INTEGER NOT NULL PRIMARY KEY,
                        name VARCHAR(80) NOT NULL,
                        agent_token_hash VARCHAR(128) NOT NULL
                    )
                    """
                )
            )
        ensure_sqlite_point_to_point_constraints()
        with engine.connect() as connection:
            columns = {row[1] for row in connection.execute(text("PRAGMA table_info(nodes)")).fetchall()}
    finally:
        database.engine = original_engine

    assert {"region", "topology_endpoint", "topology_x", "topology_y", "topology_locked"}.issubset(columns)


def test_api_auth_exemptions_keep_health_login_and_agent_public() -> None:
    """验证健康检查、登录和 Agent token 接口可匿名访问，业务 API 仍需鉴权。"""

    assert is_api_auth_exempt("/api/health")
    assert is_api_auth_exempt("/api/auth/login")
    assert is_api_auth_exempt("/api/agent/heartbeat")
    assert not is_api_auth_exempt("/api/tasks/1")
    assert not is_api_auth_exempt("/api/agent/tasks/1")
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


def test_interface_rename_is_included_in_next_apply_payload() -> None:
    """验证接口改名后下一次部署会要求 Agent 清理旧接口名。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        session.add(node)
        session.flush()
        interface = models.WireGuardInterface(
            name="wg-old",
            node_id=node.id,
            tunnel_ips=["10.42.0.1/32"],
            listen_port=23001,
            private_key_value="private",
            public_key="public",
            deployed_config="[Interface]\nPrivateKey = private\n",
        )
        session.add(interface)
        session.commit()

        updated = update_interface(
            interface.id,
            InterfaceUpdate(
                name="wg-new",
                tunnel_ips=["10.42.0.1/32"],
                listen_port=23001,
                private_key="private",
                public_key="public",
                mtu=1420,
                table_name="off",
            ),
            session,
        )

        payload = build_apply_plan(updated)

    assert updated.extras["previous_interface_name"] == "wg-old"
    assert payload["interface_name"] == "wg-new"
    assert payload["previous_interface_name"] == "wg-old"


def test_interface_rename_plan_can_be_confirmed_without_config_diff() -> None:
    """验证只改接口名时也会生成可确认部署计划，避免旧接口残留。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        session.add(node)
        session.flush()
        interface = models.WireGuardInterface(
            name="wg-old",
            node_id=node.id,
            tunnel_ips=["10.42.0.1/32"],
            listen_port=23001,
            private_key_value="private",
            public_key="public",
            mtu=1420,
            table_name="off",
        )
        session.add(interface)
        session.flush()
        session.add(
            models.WireGuardPeer(
                interface_id=interface.id,
                public_key="peer-public",
                allowed_ips=["10.42.0.2/32"],
                enabled=True,
            )
        )
        session.flush()
        interface.deployed_config = render_interface_config(interface)
        session.commit()

        updated = update_interface(
            interface.id,
            InterfaceUpdate(
                name="wg-new",
                tunnel_ips=["10.42.0.1/32"],
                listen_port=23001,
                private_key="private",
                public_key="public",
                mtu=1420,
                table_name="off",
            ),
            session,
        )
        assert build_diff(updated.deployed_config or "", render_interface_config(updated)) == ""
        assert "InterfaceName = wg-old" in build_interface_rename_diff(updated)

        plan = plan_apply(interface.id, session)
        confirmed = confirm_change_plan(plan.id, session)
        tasks = list(
            session.scalars(
                select(models.AgentTask)
                .where(models.AgentTask.change_plan_id == confirmed.id)
                .order_by(models.AgentTask.id)
            )
        )

    assert plan.diff.strip()
    assert "-InterfaceName = wg-old" in plan.diff
    assert "+InterfaceName = wg-new" in plan.diff
    assert [task.type for task in tasks] == [
        "wireguard.stop_interface",
        "wireguard.delete_config",
        "wireguard.apply_config",
    ]
    assert [task.payload["interface_name"] for task in tasks] == ["wg-old", "wg-old", "wg-new"]
    assert tasks[1].payload["depends_on_task_id"] == tasks[0].id
    assert tasks[2].payload["depends_on_task_id"] == tasks[1].id
    assert tasks[2].payload["previous_interface_name"] == "wg-old"


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


def test_managed_imported_config_can_delete_node_file_when_requested() -> None:
    """验证已接管导入配置具备节点文件清理资格，但是否清理由删除请求决定。"""

    interface = models.WireGuardInterface(
        name="wg0",
        node_id=1,
        source="imported",
        managed=True,
        import_path="/etc/wireguard/wg0.conf",
    )

    assert should_delete_node_config_file(interface) is True


def test_delete_managed_config_preserves_node_file_by_default() -> None:
    """验证删除 Link42 受管记录默认保留节点上的配置和服务，便于重新导入。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        interface = models.WireGuardInterface(
            node=node,
            name="wg0",
            source="created",
            managed=True,
            runtime_status="stopped",
        )
        session.add_all([node, interface])
        session.commit()
        interface_id = interface.id

        result = delete_interface(interface_id, db=session)
        remaining_interface = session.get(models.WireGuardInterface, interface_id)
        tasks = list(session.scalars(select(models.AgentTask)))

    assert result == {"status": "deleted"}
    assert remaining_interface is None
    assert tasks == []


def test_delete_managed_config_removes_node_file_when_requested() -> None:
    """验证勾选清理节点配置时才下发 wireguard.delete_config 任务。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        interface = models.WireGuardInterface(
            node=node,
            name="wg0",
            source="created",
            managed=True,
            runtime_status="stopped",
        )
        session.add_all([node, interface])
        session.commit()
        interface_id = interface.id

        result = delete_interface(interface_id, delete_node_config=True, db=session)
        tasks = list(session.scalars(select(models.AgentTask)))

    assert result == {"status": "deleted"}
    assert [task.type for task in tasks] == ["wireguard.delete_config"]


def test_schema_rejects_invalid_ports_and_cidrs() -> None:
    """验证 API schema 会拒绝明显错误的配置输入。"""

    with pytest.raises(ValueError):
        InterfaceCreate(name="wg0", tunnel_ips=["10.42.0.1"], listen_port=51820)

    with pytest.raises(ValueError):
        InterfaceCreate(name="wg0", tunnel_ips=["::./0"], listen_port=51820)

    with pytest.raises(ValueError):
        InterfaceCreate(name="wg0", tunnel_ips=["10.42.0.1/24"], listen_port=70000)

    with pytest.raises(ValueError):
        PeerCreate(public_key="peer", allowed_ips=["10.42.0.2/32"], endpoint_port=70000)

    with pytest.raises(ValueError):
        PeerCreate(public_key="peer", allowed_ips=["0.0.0.0/0", "::./0"])

    with pytest.raises(ValueError):
        ManagedLinkCreate(
            peer_node_id=2,
            local_interface_name="wg-a",
            local_tunnel_ips=["10.42.0.1/32"],
            peer_tunnel_ips=["10.42.0.2/32"],
            local_allowed_ips=["0.0.0.0/0", "::./0"],
        )


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


def test_create_node_stores_github_proxy_url() -> None:
    """验证节点级 GitHub 代理地址会保存，供 Agent 安装 GitHub release 插件使用。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        result = create_node(
            NodeCreate(
                name="node-a",
                endpoint_ips=["198.51.100.10"],
                github_proxy_url="https://gh.example.com/",
            ),
            session,
        )
        node = session.get(models.Node, result.node.id)

    assert node is not None
    assert node.github_proxy_url == "https://gh.example.com/"


def test_mimic_install_task_uses_github_latest_and_node_proxy() -> None:
    """验证主控安装 mimic 时下发官方 GitHub latest release 和节点代理 URL。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            last_seen_at=datetime.utcnow(),
            github_proxy_url="https://gh.example.com/",
            agent_version="0.5.2",
            agent_capabilities=[
                "wireguard",
                "middleware",
                "middleware.install",
                "middleware.install.mimic",
                "service:systemd",
            ],
            agent_platform={
                "os": "linux",
                "service_manager": "systemd",
                "kernel_version": "6.6.12",
                "is_openwrt": False,
            },
        )
        session.add(node)
        session.commit()

        result = install_node_middleware(node.id, "mimic", session)
        task = session.get(models.AgentTask, result.task_id)
        install_status = session.get(models.Node, node.id).middleware_install_status

    assert result.status == "pending"
    assert task is not None
    assert task.type == "middleware.install"
    assert task.payload == {
        "plugin": "mimic",
        "source": "github_latest",
        "repo": "hack3ric/mimic",
        "allow_prerelease": False,
        "github_proxy_url": "https://gh.example.com/",
    }
    assert install_status == "mimic_installing"


def test_mimic_install_reboot_required_is_persisted_across_heartbeat() -> None:
    """验证 mimic 安装成功但需重启时，主控保留节点需要重启提示。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash=hash_token("token"),
            status="online",
            last_seen_at=datetime.utcnow(),
            agent_version="0.5.8",
            agent_capabilities=["wireguard", "middleware.install.mimic", "service:systemd"],
            agent_platform={"os": "linux", "service_manager": "systemd", "kernel_version": "6.12.85"},
        )
        session.add(node)
        session.commit()
        task = models.AgentTask(
            node_id=node.id,
            type="middleware.install",
            status="running",
            payload={"plugin": "mimic"},
        )
        session.add(task)
        session.commit()

        agent_task_result(
            task.id,
            AgentTaskResultRequest(
                node_id=node.id,
                token="token",
                status="succeeded",
                result={"plugin": "mimic", "installed": True, "reboot_required": True},
            ),
            session,
        )

        refreshed = session.get(models.Node, node.id)
        assert refreshed.middleware_install_status == "mimic_reboot_required"
        assert refreshed.agent_platform["mimic_reboot_required"] is True

        agent_register(
            AgentRegisterRequest(
                node_id=node.id,
                token="token",
                agent_version="0.5.8",
                capabilities=["wireguard", "middleware.install.mimic", "service:systemd"],
                platform={"os": "linux", "service_manager": "systemd", "kernel_version": "6.12.85"},
            ),
            session,
        )

        refreshed = session.get(models.Node, node.id)
        assert refreshed.middleware_install_status == "mimic_reboot_required"
        assert refreshed.agent_platform["mimic_reboot_required"] is True

        agent_register(
            AgentRegisterRequest(
                node_id=node.id,
                token="token",
                agent_version="0.5.8",
                capabilities=["wireguard", "middleware.install.mimic", "middleware.mimic", "service:systemd"],
                platform={"os": "linux", "service_manager": "systemd", "kernel_version": "6.12.94"},
            ),
            session,
        )

        refreshed = session.get(models.Node, node.id)
        assert refreshed.middleware_install_status == "mimic_ready"
        assert "mimic_reboot_required" not in refreshed.agent_platform


def test_mimic_install_requires_plugin_specific_capability() -> None:
    """验证旧 Agent 只有通用 middleware.install 时不能安装 mimic。"""

    node = models.Node(
        name="node-a",
        agent_version="0.5.2",
        agent_capabilities=["wireguard", "middleware", "middleware.install", "service:systemd"],
        agent_platform={"os": "linux", "service_manager": "systemd", "kernel_version": "6.6.12"},
    )

    with pytest.raises(HTTPException) as exc_info:
        require_mimic_install_supported(node)

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "node does not support installing mimic"


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
                local_endpoint_port=30020,
                peer_endpoint_host="10.0.0.20",
                peer_endpoint_port=30021,
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
    assert local_peer.endpoint_port == 30021
    assert local_peer.allowed_ips == ["10.88.0.0/24"]
    assert remote_peer is not None
    assert remote_peer.public_key == "local-public"
    assert remote_peer.endpoint_host == "10.0.0.10"
    assert remote_peer.endpoint_port == 30020
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


def test_create_gre_managed_connection_creates_endpoints_and_tasks() -> None:
    """验证受管 GRE 连接会创建双方端点并下发 apply/start 任务。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node_a = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["203.0.113.10"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["wireguard", "gre"],
        )
        node_b = models.Node(
            name="node-b",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.20"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["wireguard", "gre"],
        )
        session.add_all([node_a, node_b])
        session.commit()

        result = create_managed_connection(
            node_a.id,
            GreManagedConnectionCreate(
                peer_node_id=node_b.id,
                local_interface_name="gre_a_b",
                peer_interface_name="gre_b_a",
                local_outer_ip="203.0.113.10",
                peer_outer_ip="198.51.100.20",
                local_tunnel_ips=["10.42.8.1/30", "fd42::1/64"],
                peer_tunnel_ips=["10.42.8.2/30", "fd42::2/64"],
                local_routes=["10.77.0.0/24", "fd77::/64"],
                peer_routes=["10.88.0.0/24", "fd88::/64"],
                mtu=1476,
                gre_key="42",
                ttl=255,
                pmtudisc=True,
                risk_accepted=True,
            ),
            session,
        )
        tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.id)))
        topology = build_topology(session)
        node_connections = list_node_connections(node_a.id, session)

    assert result.protocol_type == "gre"
    assert result.status == "changing"
    assert len(result.endpoints) == 2
    assert {endpoint.interface_name for endpoint in result.endpoints} == {"gre_a_b", "gre_b_a"}
    assert [task.type for task in tasks] == [
        GRE_TASKS.apply_config,
        GRE_TASKS.start,
        GRE_TASKS.apply_config,
        GRE_TASKS.start,
    ]
    assert tasks[0].payload["interface_name"] == "gre_a_b"
    assert tasks[0].payload["outer_local_ip"] == "203.0.113.10"
    assert tasks[0].payload["outer_remote_ip"] == "198.51.100.20"
    assert tasks[0].payload["tunnel_ips"] == ["10.42.8.1/30", "fd42::1/64"]
    assert tasks[0].payload["routes"] == ["10.77.0.0/24", "fd77::/64"]
    assert tasks[1].payload["depends_on_task_id"] == tasks[0].id
    assert tasks[2].payload["interface_name"] == "gre_b_a"
    assert tasks[2].payload["outer_local_ip"] == "198.51.100.20"
    assert tasks[2].payload["outer_remote_ip"] == "203.0.113.10"
    assert tasks[2].payload["tunnel_ips"] == ["10.42.8.2/30", "fd42::2/64"]
    assert tasks[2].payload["routes"] == ["10.88.0.0/24", "fd88::/64"]
    assert tasks[3].payload["depends_on_task_id"] == tasks[2].id
    assert any(edge.protocol_type == "gre" and edge.protocol_label == "GRE" for edge in topology.edges)
    assert any(connection.protocol_type == "gre" for connection in node_connections)


def test_create_gre_managed_connection_supports_nat_outer_mapping() -> None:
    """验证云 EIP/NAT 场景可单独指定两端 GRE local/remote 外层地址。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node_a = models.Node(
            name="tencguangzhou",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["1.14.226.49", "10.1.0.6"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["wireguard", "gre"],
        )
        node_b = models.Node(
            name="rcvps",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["38.76.191.46"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["wireguard", "gre"],
        )
        session.add_all([node_a, node_b])
        session.commit()

        create_managed_connection(
            node_a.id,
            GreManagedConnectionCreate(
                peer_node_id=node_b.id,
                local_interface_name="gre_t3_rcv",
                peer_interface_name="gre_t3_ten",
                local_outer_ip="1.14.226.49",
                peer_outer_ip="38.76.191.46",
                local_bind_ip="10.1.0.6",
                local_tunnel_ips=["10.42.8.1/30"],
                peer_tunnel_ips=["10.42.8.2/30"],
                risk_accepted=True,
            ),
            session,
        )
        tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.id)))

    assert tasks[0].payload["interface_name"] == "gre_t3_rcv"
    assert tasks[0].payload["outer_local_ip"] == "10.1.0.6"
    assert tasks[0].payload["outer_remote_ip"] == "38.76.191.46"
    assert tasks[2].payload["interface_name"] == "gre_t3_ten"
    assert tasks[2].payload["outer_local_ip"] == "38.76.191.46"
    assert tasks[2].payload["outer_remote_ip"] == "1.14.226.49"


def test_gre_interface_name_rejects_openwrt_unsafe_values() -> None:
    """验证 GRE 接口名只允许 OpenWrt 兼容的短下划线名称。"""

    with pytest.raises(ValidationError) as hyphen_error:
        GreManagedConnectionCreate(
            peer_node_id=2,
            local_interface_name="gre-a-b",
            peer_interface_name="gre_b_a",
            local_outer_ip="203.0.113.10",
            peer_outer_ip="198.51.100.20",
            local_tunnel_ips=["10.42.8.1/30"],
            peer_tunnel_ips=["10.42.8.2/30"],
            risk_accepted=True,
        )
    with pytest.raises(ValidationError) as length_error:
        GreManagedConnectionCreate(
            peer_node_id=2,
            local_interface_name="gre_name_123",
            peer_interface_name="gre_b_a",
            local_outer_ip="203.0.113.10",
            peer_outer_ip="198.51.100.20",
            local_tunnel_ips=["10.42.8.1/30"],
            peer_tunnel_ips=["10.42.8.2/30"],
            risk_accepted=True,
        )

    assert "GRE interface name can only contain letters, numbers, and underscores" in str(hyphen_error.value)
    assert "String should have at most 10 characters" in str(length_error.value)


def test_create_gre_managed_connection_rejects_same_endpoint_outer_mapping() -> None:
    """验证高级外层映射不能让单端 GRE local 和 remote 相同。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node_a = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["203.0.113.10"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["wireguard", "gre"],
        )
        node_b = models.Node(
            name="node-b",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.20"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["wireguard", "gre"],
        )
        session.add_all([node_a, node_b])
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            create_managed_connection(
                node_a.id,
                GreManagedConnectionCreate(
                    peer_node_id=node_b.id,
                    local_interface_name="gre_a_b",
                    peer_interface_name="gre_b_a",
                    local_outer_ip="203.0.113.10",
                    peer_outer_ip="198.51.100.20",
                    local_bind_ip="198.51.100.20",
                    local_tunnel_ips=["10.42.8.1/30"],
                    peer_tunnel_ips=["10.42.8.2/30"],
                    risk_accepted=True,
                ),
                session,
            )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "gre endpoint local and remote addresses must be different"


def test_create_gre_managed_connection_rejects_missing_capability() -> None:
    """验证没有 GRE 能力的在线节点也不能创建 GRE 连接。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node_a = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["203.0.113.10"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["wireguard"],
        )
        node_b = models.Node(
            name="node-b",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.20"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["wireguard", "gre"],
        )
        session.add_all([node_a, node_b])
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            create_managed_connection(
                node_a.id,
                GreManagedConnectionCreate(
                    peer_node_id=node_b.id,
                    local_interface_name="gre_a_b",
                    peer_interface_name="gre_b_a",
                    local_outer_ip="203.0.113.10",
                    peer_outer_ip="198.51.100.20",
                    local_tunnel_ips=["10.42.8.1/30"],
                    peer_tunnel_ips=["10.42.8.2/30"],
                    risk_accepted=True,
                ),
                session,
            )

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == f"agent does not support task: {GRE_TASKS.apply_config}"


def test_create_gre_managed_connection_rejects_ttl_without_pmtu_discovery() -> None:
    """验证主控拒绝 iproute2 不支持的 GRE TTL 和关闭 PMTU 组合。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node_a = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["203.0.113.10"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["wireguard", "gre"],
        )
        node_b = models.Node(
            name="node-b",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.20"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["wireguard", "gre"],
        )
        session.add_all([node_a, node_b])
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            create_managed_connection(
                node_a.id,
                GreManagedConnectionCreate(
                    peer_node_id=node_b.id,
                    local_interface_name="gre_a_b",
                    peer_interface_name="gre_b_a",
                    local_outer_ip="203.0.113.10",
                    peer_outer_ip="198.51.100.20",
                    local_tunnel_ips=["10.42.8.1/30"],
                    peer_tunnel_ips=["10.42.8.2/30"],
                    ttl=63,
                    pmtudisc=False,
                    risk_accepted=True,
                ),
                session,
            )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "gre ttl requires pmtu discovery"


def test_gre_apply_keeps_previous_name_until_start_cleanup(monkeypatch) -> None:
    """验证 GRE 改名只在启动任务确认旧配置清理后才清除旧接口名。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "verify_token", lambda token, token_hash: token == "token")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["gre"],
        )
        connection = models.Connection(
            protocol_type="gre",
            name="gre_new",
            source="managed-node",
            managed=True,
            status="starting",
        )
        endpoint = models.ConnectionEndpoint(
            connection=connection,
            node=node,
            role="local",
            interface_name="gre_new",
            tunnel_ips=["10.42.8.1/30"],
            mtu=1476,
            routes=[],
            runtime_status="starting",
            protocol_config={
                "outer_local_ip": "203.0.113.10",
                "outer_remote_ip": "198.51.100.20",
                "key": None,
                "ttl": None,
                "pmtudisc": True,
            },
            extras={"previous_interface_name": "gre_old"},
        )
        session.add_all([node, connection, endpoint])
        session.flush()
        apply_task = models.AgentTask(
            node_id=node.id,
            type=GRE_TASKS.apply_config,
            payload={
                "node_id": node.id,
                "connection_endpoint_id": endpoint.id,
                "interface_name": "gre_new",
                "previous_interface_name": "gre_old",
            },
        )
        session.add(apply_task)
        session.commit()

        agent_task_result(
            apply_task.id,
            AgentTaskResultRequest(node_id=node.id, token="token", status="succeeded", result={"changed": True}),
            session,
        )
        session.refresh(endpoint)
        assert endpoint.extras["previous_interface_name"] == "gre_old"

        start_task = models.AgentTask(
            node_id=node.id,
            type=GRE_TASKS.start,
            payload={
                "node_id": node.id,
                "connection_endpoint_id": endpoint.id,
                "interface_name": "gre_new",
                "previous_interface_name": "gre_old",
            },
        )
        session.add(start_task)
        session.commit()

        agent_task_result(
            start_task.id,
            AgentTaskResultRequest(
                node_id=node.id,
                token="token",
                status="succeeded",
                result={"previous_config_cleanup": {"interface_name": "gre_old", "deleted": True}},
            ),
            session,
        )
        session.refresh(endpoint)

    assert "previous_interface_name" not in (endpoint.extras or {})


def test_gre_start_failure_marks_endpoint_and_connection_failed(monkeypatch) -> None:
    """验证 GRE 单端启动失败时端点和连接聚合状态会明确展示失败。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "verify_token", lambda token, token_hash: token == "token")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["gre"],
        )
        connection = models.Connection(protocol_type="gre", name="gre_ab", source="managed-node", managed=True, status="starting")
        endpoint = models.ConnectionEndpoint(
            connection=connection,
            node=node,
            role="local",
            interface_name="gre_ab",
            tunnel_ips=["10.42.8.1/30"],
            mtu=1476,
            routes=[],
            runtime_status="starting",
            protocol_config={"outer_local_ip": "203.0.113.10", "outer_remote_ip": "198.51.100.20"},
        )
        peer_endpoint = models.ConnectionEndpoint(
            connection=connection,
            node=node,
            role="peer",
            interface_name="gre_ba",
            tunnel_ips=["10.42.8.2/30"],
            mtu=1476,
            routes=[],
            runtime_status="running",
            protocol_config={"outer_local_ip": "198.51.100.20", "outer_remote_ip": "203.0.113.10"},
        )
        session.add_all([node, connection, endpoint, peer_endpoint])
        session.flush()
        start_task = models.AgentTask(
            node_id=node.id,
            type=GRE_TASKS.start,
            payload={
                "node_id": node.id,
                "connection_endpoint_id": endpoint.id,
                "interface_name": "gre_ab",
            },
        )
        session.add(start_task)
        session.commit()

        agent_task_result(
            start_task.id,
            AgentTaskResultRequest(
                node_id=node.id,
                token="token",
                status="failed",
                result={"error": "systemd 203/EXEC"},
            ),
            session,
        )
        session.refresh(endpoint)
        session.refresh(connection)
        response = gre_connection_read(session, connection)

        assert endpoint.runtime_status == "failed"
        assert connection.status == "failed"
        assert endpoint.extras["last_error"] == "systemd 203/EXEC"
        assert response.endpoints[0].last_error == "systemd 203/EXEC"
        assert any("systemd 203/EXEC" in warning for warning in response.warnings)


def test_create_managed_link_allows_one_side_without_endpoint(monkeypatch) -> None:
    """验证 NAT 或出入口不对称时允许一侧 Peer 不写 Endpoint。"""

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
            endpoint_ips=[],
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

        result = create_managed_link(
            node_a.id,
            ManagedLinkCreate(
                peer_node_id=node_b.id,
                local_interface_name="wg-a",
                peer_interface_name="wg-b",
                local_tunnel_ips=["10.42.0.1/32"],
                peer_tunnel_ips=["10.42.0.2/32"],
                local_endpoint_host=None,
                peer_endpoint_host="198.51.100.20",
                local_listen_port=None,
                peer_listen_port=51821,
            ),
            session,
        )
        local_peer = session.scalar(
            select(models.WireGuardPeer).where(models.WireGuardPeer.interface_id == result.local_interface.id)
        )
        remote_peer = session.scalar(
            select(models.WireGuardPeer).where(models.WireGuardPeer.interface_id == result.peer_interface.id)
        )

    assert local_peer is not None
    assert local_peer.endpoint_host == "198.51.100.20"
    assert local_peer.endpoint_port == 51821
    assert remote_peer is not None
    assert remote_peer.endpoint_host is None
    assert remote_peer.endpoint_port is None


def test_delete_managed_link_preserves_node_configs_by_default() -> None:
    """验证删除受管双向链路默认只移除主控记录，不清理节点配置。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node_a = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        node_b = models.Node(name="node-b", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        local = models.WireGuardInterface(node=node_a, name="wg-a", source="managed-node", managed=True, runtime_status="stopped")
        peer = models.WireGuardInterface(node=node_b, name="wg-b", source="managed-node", managed=True, runtime_status="stopped")
        session.add_all([node_a, node_b, local, peer])
        session.flush()
        local_peer = models.WireGuardPeer(
            interface=local,
            peer_interface_id=peer.id,
            source="managed-node",
            public_key="peer-public",
            allowed_ips=["10.42.0.2/32"],
        )
        peer_peer = models.WireGuardPeer(
            interface=peer,
            peer_interface_id=local.id,
            source="managed-node",
            public_key="local-public",
            allowed_ips=["10.42.0.1/32"],
        )
        session.add_all([local_peer, peer_peer])
        session.commit()
        local_id = local.id
        peer_id = peer.id

        result = delete_managed_link(local_id, db=session)
        tasks = list(session.scalars(select(models.AgentTask)))
        remaining = [session.get(models.WireGuardInterface, local_id), session.get(models.WireGuardInterface, peer_id)]

    assert result == {"status": "deleted"}
    assert remaining == [None, None]
    assert tasks == []


def test_delete_managed_link_removes_node_configs_when_requested() -> None:
    """验证勾选清理节点配置时，受管双向链路会给双方下发删除任务。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node_a = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        node_b = models.Node(name="node-b", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        local = models.WireGuardInterface(node=node_a, name="wg-a", source="managed-node", managed=True, runtime_status="stopped")
        peer = models.WireGuardInterface(node=node_b, name="wg-b", source="managed-node", managed=True, runtime_status="stopped")
        session.add_all([node_a, node_b, local, peer])
        session.flush()
        session.add_all([
            models.WireGuardPeer(
                interface=local,
                peer_interface_id=peer.id,
                source="managed-node",
                public_key="peer-public",
                allowed_ips=["10.42.0.2/32"],
            ),
            models.WireGuardPeer(
                interface=peer,
                peer_interface_id=local.id,
                source="managed-node",
                public_key="local-public",
                allowed_ips=["10.42.0.1/32"],
            ),
        ])
        session.commit()

        result = delete_managed_link(local.id, delete_node_config=True, db=session)
        tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.node_id)))

    assert result == {"status": "deleted"}
    assert [task.type for task in tasks] == ["wireguard.delete_config", "wireguard.delete_config"]


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


def test_create_looking_glass_token_returns_plaintext_once() -> None:
    """验证管理端创建 Looking Glass Token 时只把明文放在创建响应中。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", endpoint_ips=["203.0.113.1"])
        session.add(node)
        session.commit()
        result = create_looking_glass_token(
            IntegrationApiTokenCreate(
                name="public-lg",
                scopes=["looking_glass.nodes.read", "looking_glass.bird.route"],
                allowed_node_ids=[node.id],
            ),
            session,
        )
        stored = session.get(models.IntegrationApiKey, result.id)

    assert result.token.startswith(f"{result.token_prefix}_")
    assert result.token_hint == result.token[-10:]
    assert stored is not None
    assert stored.token_hash != result.token
    assert verify_token(result.token, stored.token_hash)


def test_delete_looking_glass_token_revokes_even_with_query_audit() -> None:
    """验证删除 Looking Glass Token 等同吊销，不因已有查询审计记录阻止用户操作。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash")
        session.add(node)
        session.flush()
        api_key = models.IntegrationApiKey(
            name="public-lg",
            token_prefix="l42lg_test",
            token_hash="hash",
            token_hint="hint",
            scopes=["looking_glass.bird.route"],
            allowed_node_ids=[node.id],
            enabled=True,
        )
        session.add(api_key)
        session.flush()
        session.add(
            models.LookingGlassQuery(
                public_id="lgq_test",
                api_key_id=api_key.id,
                node_id=node.id,
                operation="bird.route_lookup",
                request={"ip": "1.1.1.1"},
                request_fingerprint="fingerprint",
                status="succeeded",
            )
        )
        session.commit()

        result = delete_looking_glass_token(api_key.id, session)
        stored = session.get(models.IntegrationApiKey, api_key.id)
        audit_count = session.scalar(select(models.LookingGlassQuery).where(models.LookingGlassQuery.api_key_id == api_key.id))

    assert result == {"status": "revoked"}
    assert stored is not None
    assert stored.enabled is False
    assert stored.revoked_at is not None
    assert audit_count is not None


def test_looking_glass_route_lookup_creates_query_task() -> None:
    """验证第三方 BIRD 查询会创建 query 队列任务并返回 opaque query_id。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            region="华南",
            management_ip="10.0.0.1",
            public_ip="203.0.113.1",
            endpoint_ips=["203.0.113.1"],
            agent_token_hash="hash",
            status="online",
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.0",
            agent_capabilities=["looking_glass.bird.route_lookup"],
        )
        session.add(node)
        session.flush()
        api_key = models.IntegrationApiKey(
            name="public-lg",
            token_prefix="l42lg_test",
            token_hash="hash",
            token_hint="hint",
            scopes=["looking_glass.bird.route"],
            allowed_node_ids=[node.id],
            enabled=True,
        )
        session.add(api_key)
        session.commit()

        response = Response()
        result = submit_looking_glass_bird_route_lookup(
            f"node_{node.id}",
            LookingGlassRouteLookupRequest(ip="1.1.1.1"),
            response,
            api_key,
            session,
        )
        task = session.scalar(select(models.AgentTask).where(models.AgentTask.node_id == node.id))

    assert response.status_code == 202
    assert response.headers["Location"] == f"/third-party-api/looking-glass/v1/queries/{result.query_id}"
    assert result.status == "queued"
    assert result.query_id.startswith("lgq_")
    assert task is not None
    assert task.type == LOOKING_GLASS_BIRD_ROUTE_LOOKUP_TASK
    assert task.queue == "query"
    assert task.payload["ip"] == "1.1.1.1"


def test_looking_glass_routes_by_origin_as_creates_query_task() -> None:
    """验证第三方 BIRD ASN 路由查询会创建 query 队列任务。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.6",
            agent_capabilities=["looking_glass.bird.routes_by_origin_as"],
        )
        session.add(node)
        session.flush()
        api_key = models.IntegrationApiKey(
            name="public-lg",
            token_prefix="l42lg_test",
            token_hash="hash",
            token_hint="hint",
            scopes=["looking_glass.bird.route"],
            allowed_node_ids=[node.id],
            enabled=True,
        )
        session.add(api_key)
        session.commit()

        response = Response()
        result = submit_looking_glass_bird_routes_by_origin_as(
            f"node_{node.id}",
            LookingGlassRoutesByOriginAsRequest(asn=64512),
            response,
            api_key,
            session,
        )
        task = session.scalar(select(models.AgentTask).where(models.AgentTask.node_id == node.id))

    assert response.status_code == 202
    assert result.operation == "bird.routes_by_origin_as"
    assert result.request == {"asn": 64512}
    assert task is not None
    assert task.type == LOOKING_GLASS_BIRD_ROUTES_BY_ORIGIN_AS_TASK
    assert task.payload["asn"] == 64512


def test_looking_glass_bird_protocol_queries_create_query_tasks() -> None:
    """验证第三方 BIRD 协议查询会创建对应 query 队列任务。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.6",
            agent_capabilities=["looking_glass.bird.protocols"],
        )
        session.add(node)
        session.flush()
        api_key = models.IntegrationApiKey(
            name="public-lg",
            token_prefix="l42lg_test",
            token_hash="hash",
            token_hint="hint",
            scopes=["looking_glass.bird.route"],
            allowed_node_ids=[node.id],
            enabled=True,
        )
        session.add(api_key)
        session.commit()

        protocols_response = Response()
        protocols_result = submit_looking_glass_bird_protocols(
            f"node_{node.id}",
            protocols_response,
            api_key,
            session,
        )
        detail_response = Response()
        detail_result = submit_looking_glass_bird_protocol_detail(
            f"node_{node.id}",
            LookingGlassProtocolDetailRequest(protocol_name="bgp_peer-1"),
            detail_response,
            api_key,
            session,
        )
        tasks = list(session.scalars(select(models.AgentTask).where(models.AgentTask.node_id == node.id).order_by(models.AgentTask.id)))

    assert protocols_response.status_code == 202
    assert detail_response.status_code == 202
    assert protocols_result.operation == "bird.protocols"
    assert detail_result.operation == "bird.protocol_detail"
    assert [task.type for task in tasks] == [LOOKING_GLASS_BIRD_PROTOCOLS_TASK, LOOKING_GLASS_BIRD_PROTOCOL_DETAIL_TASK]
    assert tasks[0].payload["command_timeout_seconds"] == 15
    assert tasks[1].payload["protocol_name"] == "bgp_peer-1"


def test_looking_glass_ping_and_traceroute_create_query_tasks() -> None:
    """验证第三方 ping/traceroute 查询会创建独立 query 队列任务。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            last_seen_at=datetime.utcnow(),
            agent_version="0.6.4",
            agent_capabilities=["looking_glass.ping", "looking_glass.traceroute"],
        )
        session.add(node)
        session.flush()
        api_key = models.IntegrationApiKey(
            name="public-lg",
            token_prefix="l42lg_test",
            token_hash="hash",
            token_hint="hint",
            scopes=["looking_glass.bird.route"],
            allowed_node_ids=[node.id],
            enabled=True,
        )
        session.add(api_key)
        session.commit()

        ping_response = Response()
        ping_result = submit_looking_glass_ping(
            f"node_{node.id}",
            LookingGlassPingRequest(target="Example.COM", count=3),
            ping_response,
            api_key,
            session,
        )
        trace_response = Response()
        trace_result = submit_looking_glass_traceroute(
            f"node_{node.id}",
            LookingGlassTracerouteRequest(target="2001:db8::1", max_hops=12, queries=1),
            trace_response,
            api_key,
            session,
        )
        tasks = list(session.scalars(select(models.AgentTask).where(models.AgentTask.node_id == node.id).order_by(models.AgentTask.id)))

    assert ping_response.status_code == 202
    assert trace_response.status_code == 202
    assert ping_result.operation == "ping"
    assert trace_result.operation == "traceroute"
    assert [task.type for task in tasks] == [LOOKING_GLASS_PING_TASK, LOOKING_GLASS_TRACEROUTE_TASK]
    assert tasks[0].payload["target"] == "example.com"
    assert tasks[0].payload["count"] == 3
    assert tasks[1].payload["target"] == "2001:db8::1"
    assert tasks[1].payload["max_hops"] == 12


def test_looking_glass_invalid_ip_uses_stable_error_response() -> None:
    """验证第三方 API 的请求校验错误使用文档约定的稳定错误格式。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        api_key = models.IntegrationApiKey(
            id=1,
            name="public-lg",
            token_prefix="l42lg_test",
            token_hash="hash",
            token_hint="hint",
            scopes=["looking_glass.bird.route"],
            allowed_node_ids=[1],
            enabled=True,
        )

        def override_api_key() -> models.IntegrationApiKey:
            """为 TestClient 请求提供已认证的第三方 Token。"""

            return api_key

        def override_db():
            """为 TestClient 请求提供临时数据库会话。"""

            yield session

        app.dependency_overrides[require_looking_glass_api_key] = override_api_key
        app.dependency_overrides[get_db] = override_db
        try:
            response = TestClient(app).post(
                "/third-party-api/looking-glass/v1/nodes/node_1/bird/routes:lookup",
                json={"ip": "1.1.1.1;uname -a"},
            )
        finally:
            app.dependency_overrides.pop(require_looking_glass_api_key, None)
            app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 400
    assert response.json() == {
        "error": {
            "code": "invalid_request",
            "message": "请求参数无效",
        }
    }


def test_looking_glass_invalid_protocol_name_uses_stable_error_response() -> None:
    """验证第三方 BIRD 协议详情接口的参数错误使用稳定错误格式。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        api_key = models.IntegrationApiKey(
            id=1,
            name="public-lg",
            token_prefix="l42lg_test",
            token_hash="hash",
            token_hint="hint",
            scopes=["looking_glass.bird.route"],
            allowed_node_ids=[1],
            enabled=True,
        )

        def override_api_key() -> models.IntegrationApiKey:
            """为 TestClient 请求提供已认证的第三方 Token。"""

            return api_key

        def override_db():
            """为 TestClient 请求提供临时数据库会话。"""

            yield session

        app.dependency_overrides[require_looking_glass_api_key] = override_api_key
        app.dependency_overrides[get_db] = override_db
        try:
            response = TestClient(app).post(
                "/third-party-api/looking-glass/v1/nodes/node_1/bird/protocols:lookup-detail",
                json={"protocol_name": "bgp peer"},
            )
        finally:
            app.dependency_overrides.pop(require_looking_glass_api_key, None)
            app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 400
    assert response.json() == {
        "error": {
            "code": "invalid_request",
            "message": "请求参数无效",
        }
    }


def test_looking_glass_invalid_asn_uses_stable_error_response() -> None:
    """验证第三方 BIRD ASN 路由接口的参数错误使用稳定错误格式。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        api_key = models.IntegrationApiKey(
            id=1,
            name="public-lg",
            token_prefix="l42lg_test",
            token_hash="hash",
            token_hint="hint",
            scopes=["looking_glass.bird.route"],
            allowed_node_ids=[1],
            enabled=True,
        )

        def override_api_key() -> models.IntegrationApiKey:
            """为 TestClient 请求提供已认证的第三方 Token。"""

            return api_key

        def override_db():
            """为 TestClient 请求提供临时数据库会话。"""

            yield session

        app.dependency_overrides[require_looking_glass_api_key] = override_api_key
        app.dependency_overrides[get_db] = override_db
        try:
            response = TestClient(app).post(
                "/third-party-api/looking-glass/v1/nodes/node_1/bird/routes:lookup-origin-as",
                json={"asn": "64512;uname"},
            )
        finally:
            app.dependency_overrides.pop(require_looking_glass_api_key, None)
            app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 400
    assert response.json() == {
        "error": {
            "code": "invalid_request",
            "message": "请求参数无效",
        }
    }


def test_looking_glass_diagnostic_target_rejects_invalid_hostname() -> None:
    """验证 ping/traceroute 目标只允许 IP 或普通域名。"""

    with pytest.raises(ValidationError):
        LookingGlassPingRequest(target="bad;uname -a")
    with pytest.raises(ValidationError):
        LookingGlassTracerouteRequest(target="-bad.example")


def test_looking_glass_protocol_name_rejects_invalid_value() -> None:
    """验证 BIRD 协议详情查询拒绝带空白或控制符的协议名。"""

    with pytest.raises(ValidationError):
        LookingGlassProtocolDetailRequest(protocol_name="bgp peer")
    with pytest.raises(ValidationError):
        LookingGlassProtocolDetailRequest(protocol_name="bgp;uname")


def test_looking_glass_asn_rejects_invalid_value() -> None:
    """验证 BIRD ASN 路由查询拒绝非法 ASN。"""

    with pytest.raises(ValidationError):
        LookingGlassRoutesByOriginAsRequest(asn=0)
    with pytest.raises(ValidationError):
        LookingGlassRoutesByOriginAsRequest(asn="64512;uname")


def test_looking_glass_query_returns_raw_agent_result() -> None:
    """验证 Looking Glass 查询完成后返回 Agent 上报的原始 stdout/stderr。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash")
        session.add(node)
        session.flush()
        api_key = models.IntegrationApiKey(
            name="public-lg",
            token_prefix="l42lg_test",
            token_hash="hash",
            token_hint="hint",
            scopes=["looking_glass.bird.route"],
            allowed_node_ids=[node.id],
            enabled=True,
        )
        task = models.AgentTask(
            node_id=node.id,
            type=LOOKING_GLASS_BIRD_ROUTE_LOOKUP_TASK,
            queue="query",
            status="succeeded",
            result={
                "command": "birdc show route for 1.1.1.1 all",
                "exit_code": 0,
                "stdout": "raw route output",
                "stderr": "",
                "truncated": False,
            },
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
        )
        session.add_all([api_key, task])
        session.flush()
        query = models.LookingGlassQuery(
            public_id="lgq_test",
            api_key_id=api_key.id,
            node_id=node.id,
            operation="bird.route_lookup",
            request={"ip": "1.1.1.1", "normalized_ip": "1.1.1.1"},
            request_fingerprint="fp",
            status="running",
            agent_task_id=task.id,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        session.add(query)
        session.commit()

        result = get_looking_glass_query("lgq_test", api_key, session)

    assert result.status == "succeeded"
    assert result.result is not None
    assert result.result["stdout"] == "raw route output"
    assert result.error is None


def test_looking_glass_query_response_datetimes_are_unix_timestamps() -> None:
    """验证第三方查询响应的时间是 Unix 时间戳，避免调用方解析时区。"""

    body = LookingGlassQueryRead(
        query_id="lgq_time",
        status="queued",
        node_ref="node_1",
        operation="bird.route_lookup",
        request={"ip": "1.1.1.1", "normalized_ip": "1.1.1.1"},
        created_at=datetime(2026, 7, 10, 5, 59, 31),
        deadline_at=datetime(2026, 7, 10, 6, 0, 31),
        expires_at=datetime(2026, 7, 10, 6, 9, 31),
    ).model_dump(mode="json")

    assert body["created_at"] == 1783663171
    assert body["deadline_at"] == 1783663231
    assert body["expires_at"] == 1783663771


def test_looking_glass_agent_result_updates_query_status() -> None:
    """验证 Agent 上报查询结果后会立即回写 Looking Glass query 状态。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash=hash_token("token"))
        session.add(node)
        session.flush()
        task = models.AgentTask(
            node_id=node.id,
            type=LOOKING_GLASS_BIRD_ROUTE_LOOKUP_TASK,
            queue="query",
            status="running",
            payload={"ip": "1.1.1.1"},
            started_at=datetime.utcnow(),
        )
        session.add(task)
        session.flush()
        query = models.LookingGlassQuery(
            public_id="lgq_report",
            api_key_id=1,
            node_id=node.id,
            operation="bird.route_lookup",
            request={"ip": "1.1.1.1", "normalized_ip": "1.1.1.1"},
            request_fingerprint="fp",
            status="running",
            agent_task_id=task.id,
            deadline_at=datetime.utcnow() + timedelta(seconds=60),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        session.add(query)
        session.commit()

        agent_task_result(
            task.id,
            AgentTaskResultRequest(
                node_id=node.id,
                token="token",
                status="succeeded",
                result={
                    "command": "birdc show route for 1.1.1.1 all",
                    "exit_code": 0,
                    "stdout": "raw route output",
                    "stderr": "",
                    "truncated": False,
                },
            ),
            session,
        )
        session.refresh(query)

    assert query.status == "succeeded"
    assert query.result is not None
    assert query.result["stdout"] == "raw route output"


def test_agent_poll_honors_task_dependencies(monkeypatch) -> None:
    """验证依赖任务失败后，后续 delete/apply 不会继续下发给 Agent。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "verify_token", lambda token, token_hash: token == "token")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash="hash",
            status="online",
            last_seen_at=datetime.utcnow(),
            agent_version="0.5.11",
            agent_capabilities=["wireguard"],
        )
        session.add(node)
        session.flush()
        interface = models.WireGuardInterface(name="wg-new", node_id=node.id)
        session.add(interface)
        session.flush()
        stop_task = models.AgentTask(
            node_id=node.id,
            type="wireguard.stop_interface",
            payload={"node_id": node.id, "interface_id": interface.id, "interface_name": "wg-old"},
        )
        session.add(stop_task)
        session.flush()
        delete_task = models.AgentTask(
            node_id=node.id,
            type="wireguard.delete_config",
            payload={
                "node_id": node.id,
                "interface_id": interface.id,
                "interface_name": "wg-old",
                "depends_on_task_id": stop_task.id,
            },
        )
        session.add(delete_task)
        session.flush()
        apply_task = models.AgentTask(
            node_id=node.id,
            type="wireguard.apply_config",
            payload={
                "node_id": node.id,
                "interface_id": interface.id,
                "interface_name": "wg-new",
                "config": "[Interface]\nPrivateKey = private\n",
                "depends_on_task_id": delete_task.id,
            },
        )
        session.add(apply_task)
        session.commit()

        first_poll = agent_poll(
            AgentPollRequest(
                node_id=node.id,
                token="token",
                agent_version="0.5.11",
                protocol_version=1,
                capabilities=["wireguard"],
            ),
            session,
        )
        agent_task_result(
            stop_task.id,
            AgentTaskResultRequest(node_id=node.id, token="token", status="failed", result={"error": "stop failed"}),
            session,
        )
        second_poll = agent_poll(
            AgentPollRequest(
                node_id=node.id,
                token="token",
                agent_version="0.5.11",
                protocol_version=1,
                capabilities=["wireguard"],
            ),
            session,
        )
        session.refresh(delete_task)
        session.refresh(apply_task)

    assert [task.type for task in first_poll.tasks] == ["wireguard.stop_interface"]
    assert second_poll.tasks == []
    assert delete_task.status == "failed"
    assert apply_task.status == "failed"


def test_stale_running_agent_tasks_are_expired() -> None:
    """验证长时间未上报结果的 running 任务会被回收，避免后续部署永久阻塞。"""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        session.add(node)
        session.flush()
        task = models.AgentTask(
            node_id=node.id,
            type="wireguard.import_scan",
            status="running",
            payload={"node_id": node.id},
            started_at=datetime.utcnow() - timedelta(hours=2, minutes=1),
        )
        session.add(task)
        session.commit()

        expired = expire_stale_running_agent_tasks(session, node_id=node.id)
        session.refresh(task)

    assert expired == 1
    assert task.status == "failed"
    assert "timed out" in task.result["error"]


def test_apply_result_keeps_previous_name_without_cleanup_evidence(monkeypatch) -> None:
    """验证 apply 成功但没有清理证据时不会过早清除旧接口名标记。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "verify_token", lambda token, token_hash: token == "token")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        session.add(node)
        session.flush()
        interface = models.WireGuardInterface(
            name="wg-new",
            node_id=node.id,
            extras={"previous_interface_name": "wg-old"},
        )
        session.add(interface)
        session.flush()
        task = models.AgentTask(
            node_id=node.id,
            type="wireguard.apply_config",
            payload={
                "node_id": node.id,
                "interface_id": interface.id,
                "interface_name": "wg-new",
                "previous_interface_name": "wg-old",
                "config": "[Interface]\nPrivateKey = private\n",
            },
        )
        session.add(task)
        session.commit()

        agent_task_result(
            task.id,
            AgentTaskResultRequest(node_id=node.id, token="token", status="succeeded", result={"changed": True}),
            session,
        )
        session.refresh(interface)

    assert interface.extras["previous_interface_name"] == "wg-old"


def test_link_monitor_agent_poll_and_result_updates_summary(monkeypatch) -> None:
    """验证链路监测目标会被 Agent 拉取、上报并生成摘要。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "verify_token", lambda token, token_hash: token == "token")
    monkeypatch.setattr(api_main, "refresh_node_runtime_status", lambda node: None)

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(name="node-a", agent_token_hash="hash", status="online", last_seen_at=datetime.utcnow())
        session.add(node)
        session.flush()
        interface = models.WireGuardInterface(
            node_id=node.id,
            name="wg0",
            tunnel_ips=["10.42.0.1/32"],
            runtime_status="running",
        )
        session.add(interface)
        session.commit()

        monitor = api_main.upsert_interface_link_monitor(
            interface.id,
            LinkMonitorCreate(target_host="10.42.0.2", interval_seconds=10, retention_days=7, enabled=True),
            session,
        )
        poll = agent_link_monitor_poll(AgentPollRequest(node_id=node.id, token="token"), session)
        assert [item.id for item in poll.monitors] == [monitor.id]

        agent_link_monitor_result(
            AgentLinkMonitorResultRequest(
                node_id=node.id,
                token="token",
                results=[
                    AgentLinkMonitorResultItem(monitor_id=monitor.id, success=True, latency_ms=21.5),
                    AgentLinkMonitorResultItem(monitor_id=monitor.id, success=False, error="timeout"),
                ],
            ),
            session,
        )
        summary = api_main.summarize_monitor(session, session.get(models.LinkMonitor, monitor.id))
        listed = api_main.list_interfaces(node.id, session)

    assert summary.sample_count == 2
    assert summary.last_latency_ms is None
    assert summary.packet_loss == 0.5
    assert listed[0].monitor_summary is not None
    assert listed[0].monitor_summary.monitor_id == monitor.id


def test_connection_endpoint_link_monitor_is_listed() -> None:
    """验证 GRE 等通用连接端点可以创建链路监测并在连接响应中展示摘要。"""

    import link42_api.main as api_main

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node_a = models.Node(name="node-a", agent_token_hash=hash_token("token"), status="online", last_seen_at=datetime.utcnow())
        node_b = models.Node(name="node-b", agent_token_hash="hash-b", status="online", last_seen_at=datetime.utcnow())
        session.add_all([node_a, node_b])
        session.flush()
        connection = models.Connection(protocol_type="gre", name="gre_a_b", source="managed-node", managed=True)
        endpoint_a = models.ConnectionEndpoint(
            connection=connection,
            node_id=node_a.id,
            role="local",
            interface_name="gre-a",
            tunnel_ips=["10.43.0.1/30"],
            routes=["172.21.0.0/24"],
            runtime_status="running",
        )
        endpoint_b = models.ConnectionEndpoint(
            connection=connection,
            node_id=node_b.id,
            role="peer",
            interface_name="gre-b",
            tunnel_ips=["10.43.0.2/30"],
            routes=["172.22.0.0/24"],
            runtime_status="running",
        )
        session.add_all([connection, endpoint_a, endpoint_b])
        session.commit()

        monitor = api_main.upsert_connection_endpoint_link_monitor(
            endpoint_a.id,
            LinkMonitorCreate(target_host="10.43.0.2", interval_seconds=10, retention_days=7, enabled=True),
            session,
        )
        poll = agent_link_monitor_poll(AgentPollRequest(node_id=node_a.id, token="token"), session)

        listed = api_main.list_node_connections(node_a.id, session)

    assert monitor.connection_endpoint_id == endpoint_a.id
    assert [item.id for item in poll.monitors] == [monitor.id]
    assert [item.target_host for item in poll.monitors] == ["10.43.0.2"]
    assert listed[0].endpoints[0].monitor_summary is not None
    assert listed[0].endpoints[0].monitor_summary.monitor_id == monitor.id


def test_link_monitor_samples_rejects_invalid_window(monkeypatch) -> None:
    """验证链路监测历史窗口只接受固定枚举。"""

    import link42_api.main as api_main

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        monitor = models.LinkMonitor(
            node_id=1,
            interface_id=None,
            name="latency",
            target_host="10.42.0.2",
            interval_seconds=10,
            retention_days=7,
            enabled=True,
        )
        session.add(monitor)
        session.commit()
        session.refresh(monitor)

        with pytest.raises(HTTPException) as exc_info:
            api_main.get_link_monitor_samples(monitor.id, "bad", session)

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == "invalid monitor window"


def test_mimic_requires_non_openwrt_kernel_newer_than_61_and_capability() -> None:
    """验证主控侧 mimic 门禁不只相信表单，必须满足平台和能力要求。"""

    node = models.Node(
        name="node-a",
        agent_version="0.5.2",
        agent_capabilities=["wireguard", "middleware.mimic", "service:systemd"],
        agent_platform={"os": "linux", "service_manager": "systemd", "kernel_version": "6.6.12", "is_openwrt": False},
    )
    require_mimic_supported(node)

    old_kernel = models.Node(
        name="node-b",
        agent_version="0.5.2",
        agent_capabilities=["wireguard", "middleware.mimic", "service:systemd"],
        agent_platform={"os": "linux", "service_manager": "systemd", "kernel_version": "6.1.90", "is_openwrt": False},
    )
    with pytest.raises(HTTPException) as old_exc:
        require_mimic_supported(old_kernel)
    assert old_exc.value.status_code == 409
    assert old_exc.value.detail == "mimic requires Linux kernel newer than 6.1"

    openwrt = models.Node(
        name="node-c",
        agent_version="0.5.2",
        agent_capabilities=["wireguard", "middleware.mimic", "service:openwrt-uci"],
        agent_platform={"os": "linux", "service_manager": "openwrt-uci", "kernel_version": "6.6.12", "is_openwrt": True},
    )
    with pytest.raises(HTTPException) as openwrt_exc:
        require_mimic_supported(openwrt)
    assert openwrt_exc.value.status_code == 409
    assert openwrt_exc.value.detail == "mimic is not supported on OpenWrt nodes"


def test_mimic_payloads_keep_wireguard_endpoint_direct() -> None:
    """验证 mimic 生成透明 filter 任务，不像 udp2raw 一样接管 WireGuard Endpoint。"""

    middleware = normalize_middleware_config(
        None,
        MimicMiddlewareConfig(
            enabled=True,
            local_bind_interface="eth0",
            peer_bind_interface="eth1",
            xdp_mode="skb",
        ),
    )
    local = models.WireGuardInterface(id=1, node_id=1, name="wg-a", listen_port=51820)
    peer = models.WireGuardInterface(id=2, node_id=2, name="wg-b", listen_port=51821)

    payloads = mimic_endpoint_payloads(
        middleware,
        local,
        peer,
        "203.0.113.10",
        "203.0.113.20",
    )

    assert middleware is not None
    assert middleware["type"] == "mimic"
    assert [task_type for _, task_type, _ in payloads] == ["middleware.mimic.apply", "middleware.mimic.apply"]
    assert payloads[0][2]["bind_interface"] == "eth0"
    assert payloads[0][2]["local_host"] == "203.0.113.10"
    assert payloads[0][2]["peer_host"] == "203.0.113.20"
    assert payloads[0][2]["filter_origin"] == "remote"
    assert payloads[1][2]["bind_interface"] == "eth1"


def test_mimic_rejects_domain_endpoint_for_filter_generation() -> None:
    """验证 mimic filter 只接受 IP 字面量，避免 Agent 生成无效配置。"""

    middleware = normalize_middleware_config(
        None,
        MimicMiddlewareConfig(
            enabled=True,
            local_bind_interface="eth0",
            peer_bind_interface="eth1",
        ),
    )
    local = models.WireGuardInterface(id=1, node_id=1, name="wg-a", listen_port=51820)
    peer = models.WireGuardInterface(id=2, node_id=2, name="wg-b", listen_port=51821)

    with pytest.raises(HTTPException) as exc_info:
        mimic_endpoint_payloads(
            middleware,
            local,
            peer,
            "203.0.113.10",
            "vpn.example.com",
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "mimic peer endpoint must be an IP address for mimic"


def test_create_managed_link_with_mimic_enqueues_mimic_tasks(monkeypatch) -> None:
    """验证创建受管连接启用 mimic 时下发 mimic 任务且保留真实 Endpoint。"""

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
            agent_version="0.5.2",
            agent_capabilities=["wireguard", "middleware.mimic", "service:systemd"],
            agent_platform={"os": "linux", "service_manager": "systemd", "kernel_version": "6.6.12", "is_openwrt": False},
        )
        node_b = models.Node(
            name="node-b",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.20"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.5.2",
            agent_capabilities=["wireguard", "middleware.mimic", "service:systemd"],
            agent_platform={"os": "linux", "service_manager": "systemd", "kernel_version": "6.6.12", "is_openwrt": False},
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
                local_listen_port=51820,
                peer_listen_port=51821,
                mimic=MimicMiddlewareConfig(
                    enabled=True,
                    local_bind_interface="eth0",
                    peer_bind_interface="eth1",
                    xdp_mode="skb",
                ),
            ),
            session,
        )
        local_peer = session.scalar(
            select(models.WireGuardPeer).where(models.WireGuardPeer.interface_id == result.local_interface.id)
        )
        tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.type, models.AgentTask.node_id)))

    assert local_peer is not None
    assert local_peer.endpoint_host == "198.51.100.20"
    assert local_peer.endpoint_port == 51821
    assert [task.type for task in tasks].count("middleware.mimic.apply") == 2
    assert [task.type for task in tasks].count("wireguard.apply_config") == 2
    mimic_payloads = [task.payload for task in tasks if task.type == "middleware.mimic.apply"]
    assert {payload["bind_interface"] for payload in mimic_payloads} == {"eth0", "eth1"}
    assert {payload["peer_host"] for payload in mimic_payloads} == {"198.51.100.10", "198.51.100.20"}


def test_create_managed_link_with_mimic_requires_both_endpoints(monkeypatch) -> None:
    """验证 mimic 必须知道双方真实 Endpoint，避免被动回包无法被透明处理。"""

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
            endpoint_ips=[],
            last_seen_at=datetime.utcnow(),
            agent_version="0.5.2",
            agent_capabilities=["wireguard", "middleware.mimic", "service:systemd"],
            agent_platform={"os": "linux", "service_manager": "systemd", "kernel_version": "6.6.12", "is_openwrt": False},
        )
        node_b = models.Node(
            name="node-b",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.20"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.5.2",
            agent_capabilities=["wireguard", "middleware.mimic", "service:systemd"],
            agent_platform={"os": "linux", "service_manager": "systemd", "kernel_version": "6.6.12", "is_openwrt": False},
        )
        session.add_all([node_a, node_b])
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            create_managed_link(
                node_a.id,
                ManagedLinkCreate(
                    peer_node_id=node_b.id,
                    local_interface_name="wg-a",
                    peer_interface_name="wg-b",
                    local_tunnel_ips=["10.42.0.1/32"],
                    peer_tunnel_ips=["10.42.0.2/32"],
                    local_endpoint_host=None,
                    peer_endpoint_host="198.51.100.20",
                    local_listen_port=51820,
                    peer_listen_port=51821,
                    mimic=MimicMiddlewareConfig(
                        enabled=True,
                        local_bind_interface="eth0",
                        peer_bind_interface="eth1",
                    ),
                ),
                session,
            )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "mimic requires endpoint address on both sides"


def test_update_managed_link_disabling_mimic_enqueues_cleanup_tasks(monkeypatch) -> None:
    """验证编辑受管连接禁用 mimic 时会清理节点上的旧 mimic 服务和配置。"""

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
            agent_version="0.5.2",
            agent_capabilities=["wireguard", "middleware.mimic", "service:systemd"],
            agent_platform={"os": "linux", "service_manager": "systemd", "kernel_version": "6.6.12", "is_openwrt": False},
        )
        node_b = models.Node(
            name="node-b",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.20"],
            last_seen_at=datetime.utcnow(),
            agent_version="0.5.2",
            agent_capabilities=["wireguard", "middleware.mimic", "service:systemd"],
            agent_platform={"os": "linux", "service_manager": "systemd", "kernel_version": "6.6.12", "is_openwrt": False},
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
                local_listen_port=51820,
                peer_listen_port=51821,
                mimic=MimicMiddlewareConfig(enabled=True, local_bind_interface="eth0", peer_bind_interface="eth1"),
            ),
            session,
        )
        session.query(models.AgentTask).delete()
        session.commit()

        update_managed_link(
            result.local_interface.id,
            ManagedLinkUpdate(
                local_interface_name="wg-a",
                peer_interface_name="wg-b",
                local_tunnel_ips=["10.42.0.1/32"],
                peer_tunnel_ips=["10.42.0.2/32"],
                local_endpoint_host="198.51.100.10",
                peer_endpoint_host="198.51.100.20",
                local_listen_port=51820,
                peer_listen_port=51821,
            ),
            session,
        )
        tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.type, models.AgentTask.node_id)))
        local_interface = session.get(models.WireGuardInterface, result.local_interface.id)

    assert local_interface is not None
    assert "middleware" not in (local_interface.extras or {})
    assert [task.type for task in tasks].count("middleware.mimic.stop") == 2
    assert [task.type for task in tasks].count("middleware.mimic.delete") == 2
    assert [task.type for task in tasks].count("wireguard.apply_config") == 2
    cleanup_payloads = [task.payload for task in tasks if task.type in {"middleware.mimic.stop", "middleware.mimic.delete"}]
    assert {payload["bind_interface"] for payload in cleanup_payloads} == {"eth0", "eth1"}


def test_middleware_config_rejects_udp2raw_and_mimic_together() -> None:
    """验证一次只能启用一种连接中间层。"""

    with pytest.raises(HTTPException) as exc_info:
        normalize_middleware_config(
            Udp2RawMiddlewareConfig(enabled=True, server_listen_port=30000, client_listen_port=30001),
            MimicMiddlewareConfig(enabled=True, local_bind_interface="eth0", peer_bind_interface="eth1"),
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "only one middleware can be enabled"


def test_mimic_padding_rejects_out_of_range_value() -> None:
    """验证 mimic padding 遵守官方 MAX_PADDING_LEN=16。"""

    with pytest.raises(ValidationError) as exc_info:
        MimicMiddlewareConfig(
            enabled=True,
            local_bind_interface="eth0",
            peer_bind_interface="eth1",
            padding=30,
        )

    assert "mimic padding must be between 0 and 16" in str(exc_info.value)


def test_sqlite_migration_creates_link_monitor_tables(monkeypatch, tmp_path) -> None:
    """验证旧 SQLite 启动迁移会补齐链路监测表。"""

    import link42_api.database as database

    db_path = tmp_path / "old.db"
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE nodes (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(80) NOT NULL)"))

    monkeypatch.setattr(database, "engine", engine)
    database.ensure_sqlite_point_to_point_constraints()

    with engine.begin() as connection:
        tables = {
            row[0]
            for row in connection.execute(text("SELECT name FROM sqlite_master WHERE type = 'table'")).fetchall()
        }

    assert "link_monitors" in tables
    assert "link_monitor_samples" in tables


def test_import_scan_request_rejects_openwrt_uci_node(monkeypatch) -> None:
    """验证 OpenWrt UCI 节点不会创建 wg-quick 导入扫描任务。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "verify_token", lambda token, token_hash: token == "token")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="owrt",
            agent_token_hash="hash",
            status="online",
            last_seen_at=datetime.utcnow(),
            agent_version="0.2.0",
            agent_capabilities=["wireguard", "service:openwrt-uci"],
            agent_platform={"service_manager": "openwrt-uci"},
        )
        session.add(node)
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            request_import_scan(node.id, session)
        tasks = list(session.scalars(select(models.AgentTask)))

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "OpenWrt UCI nodes do not support wg-quick import scan"
    assert tasks == []


def test_openwrt_udp2raw_capability_allows_middleware_tasks() -> None:
    """验证支持 udp2raw 的 OpenWrt Agent 可通过主控连接中间层门禁。"""

    node = models.Node(
        name="owrt",
        status="online",
        agent_version="0.2.0",
        agent_capabilities=[
            "wireguard",
            "service:openwrt-uci",
            "middleware",
            "middleware.install",
            "middleware.udp2raw",
            "middleware.udp2raw.openwrt-procd",
        ],
        agent_platform={"service_manager": "openwrt-uci"},
        last_seen_at=datetime.utcnow(),
    )

    require_udp2raw_supported(node)


def test_openwrt_without_udp2raw_capability_rejects_middleware_tasks() -> None:
    """验证旧 OpenWrt Agent 即使在线，也不能绕过 udp2raw 能力门禁。"""

    node = models.Node(
        name="owrt-old",
        status="online",
        agent_version="0.2.0",
        agent_capabilities=["wireguard", "service:openwrt-uci"],
        agent_platform={"service_manager": "openwrt-uci"},
        last_seen_at=datetime.utcnow(),
    )

    with pytest.raises(HTTPException) as exc_info:
        require_udp2raw_supported(node)

    assert exc_info.value.status_code == 409
    assert "does not support task" in str(exc_info.value.detail)


def test_agent_upgrade_plan_falls_back_to_manual_for_old_agent(monkeypatch, tmp_path) -> None:
    """验证旧 Agent 不支持自升级时，主控生成手动覆盖安装命令。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main.settings, "agent_release_dir", str(tmp_path))
    monkeypatch.setattr(api_main.settings, "agent_install_script_url", "https://example.com/link42-agent.sh")
    monkeypatch.setattr(api_main.settings, "agent_res_base_url", "https://example.com/res")
    (tmp_path / "manifest.json").write_text('{"latest":"0.2.0","releases":{}}', encoding="utf-8")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash="hash",
            agent_token_value="token&with space",
            status="online",
            agent_version="0.1.0",
            agent_capabilities=["wireguard", "wg_quick_import", "service:systemd"],
            agent_platform={"os": "linux", "arch": "x86_64", "service_manager": "systemd", "glibc": "2.31"},
            last_seen_at=datetime.utcnow(),
        )
        session.add(node)
        set_setting(session, SETTING_CONTROLLER_URL, "http://controller:8000")
        session.commit()

        plan = build_agent_upgrade_plan(node, session)

    assert plan.upgrade_mode == "manual"
    assert plan.reason == "当前 Agent 不支持自升级"
    assert plan.manual_command is not None
    assert "LINK42_AGENT_VERSION=0.2.0" in plan.manual_command
    assert "LINK42_NODE_ID=" in plan.manual_command
    assert "LINK42_AGENT_TOKEN='token&with space'" in plan.manual_command


def test_request_agent_upgrade_creates_self_upgrade_task(monkeypatch, tmp_path) -> None:
    """验证支持自升级的 Agent 会收到 agent.self_upgrade 任务。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main.settings, "agent_release_dir", str(tmp_path))
    (tmp_path / "agent.bin").write_text("binary", encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        """
        {
          "latest": "0.2.1",
          "releases": {
            "0.2.1": {
              "assets": {
                "linux-x64-glibc2.31": {
                  "path": "agent.bin",
                  "sha256": "abc123",
                  "size": 6
                }
              }
            }
          }
        }
        """,
        encoding="utf-8",
    )

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        node = models.Node(
            name="node-a",
            agent_token_hash="hash",
            agent_token_value="token",
            status="online",
            agent_version="0.2.0",
            agent_capabilities=["wireguard", "agent.self_upgrade", "service:systemd"],
            agent_platform={"os": "linux", "arch": "x86_64", "service_manager": "systemd", "glibc": "2.31"},
            last_seen_at=datetime.utcnow(),
        )
        session.add(node)
        set_setting(session, SETTING_CONTROLLER_URL, "http://controller:8000")
        session.commit()

        result = request_agent_upgrade(node.id, AgentUpgradeRequest(), session)
        task = session.scalar(select(models.AgentTask).where(models.AgentTask.node_id == node.id))
        node_after = session.get(models.Node, node.id)

    assert result.task_id is not None
    assert result.status == "pending"
    assert task is not None
    assert task.type == "agent.self_upgrade"
    assert node_after.agent_update_status == "queued"
    assert task.payload["target_version"] == "0.2.1"
    assert task.payload["download_url"] == "http://controller:8000/api/agent/releases/0.2.1/download?platform=linux-x64-glibc2.31"
    assert task.payload["sha256"] == "abc123"


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
                    server_connect_host="198.51.100.20",
                    server_listen_port=23002,
                    server_forward_host="127.0.0.1",
                    server_forward_port=11451,
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
    assert tasks[2].node_id == result.peer_interface.node_id
    assert tasks[2].payload["remote_host"] == "127.0.0.1"
    assert tasks[2].payload["remote_port"] == 11451
    assert tasks[3].payload["mode"] == "client"
    assert tasks[3].node_id == result.local_interface.node_id
    assert tasks[3].payload["remote_host"] == "198.51.100.20"


def test_update_udp2raw_direction_refreshes_pending_apply_tasks(monkeypatch) -> None:
    """验证未执行的 udp2raw apply 会随方向变更更新，避免本端缺少 client 进程。"""

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
                local_listen_port=51820,
                peer_listen_port=None,
                udp2raw=Udp2RawMiddlewareConfig(
                    enabled=True,
                    server_side="local",
                    server_connect_host="198.51.100.10",
                    server_listen_port=23002,
                    client_listen_port=12312,
                ),
            ),
            session,
        )

        update_managed_link(
            result.local_interface.id,
            ManagedLinkUpdate(
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
                    server_connect_host="198.51.100.20",
                    server_listen_port=23003,
                    client_listen_port=12313,
                ),
            ),
            session,
        )
        udp2raw_apply_tasks = list(
            session.scalars(
                select(models.AgentTask)
                .where(models.AgentTask.type == "middleware.udp2raw.apply")
                .order_by(models.AgentTask.node_id)
            )
        )
        local_task = next(task for task in udp2raw_apply_tasks if task.node_id == result.local_interface.node_id)
        peer_task = next(task for task in udp2raw_apply_tasks if task.node_id == result.peer_interface.node_id)

    assert len(udp2raw_apply_tasks) == 2
    assert local_task.payload["mode"] == "client"
    assert local_task.payload["listen_port"] == 12313
    assert local_task.payload["remote_host"] == "198.51.100.20"
    assert local_task.payload["remote_port"] == 23003
    assert peer_task.payload["mode"] == "server"
    assert peer_task.payload["listen_port"] == 23003


def test_update_managed_link_rename_queues_previous_interface_cleanup(monkeypatch) -> None:
    """验证受管连接改名会先下发旧接口清理任务，再应用新接口配置。"""

    private_keys = iter(["local-private", "peer-private"])
    public_keys = iter(["local-public", "peer-public"])

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "generate_wireguard_keypair", lambda: (next(private_keys), next(public_keys)))
    monkeypatch.setattr(api_main, "generate_preshared_key", lambda: "shared-key")
    monkeypatch.setattr(api_main, "generate_token", lambda prefix: f"{prefix}_secret")

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
        node_a_id = node_a.id
        node_b_id = node_b.id

        result = create_managed_link(
            node_a_id,
            ManagedLinkCreate(
                peer_node_id=node_b_id,
                local_interface_name="wg-old-a",
                peer_interface_name="wg-old-b",
                local_tunnel_ips=["10.42.0.1/32"],
                peer_tunnel_ips=["10.42.0.2/32"],
                local_endpoint_host="198.51.100.10",
                peer_endpoint_host="198.51.100.20",
                local_listen_port=51820,
                peer_listen_port=51821,
            ),
            session,
        )
        session.query(models.AgentTask).delete()
        session.commit()

        update_managed_link(
            result.local_interface.id,
            ManagedLinkUpdate(
                local_interface_name="wg-new-a",
                peer_interface_name="wg-new-b",
                local_tunnel_ips=["10.42.0.1/32"],
                peer_tunnel_ips=["10.42.0.2/32"],
                local_endpoint_host="198.51.100.10",
                peer_endpoint_host="198.51.100.20",
                local_listen_port=51820,
                peer_listen_port=51821,
            ),
            session,
        )
        tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.id)))

    local_tasks = [task for task in tasks if task.node_id == node_a_id]
    peer_tasks = [task for task in tasks if task.node_id == node_b_id]
    assert [task.type for task in local_tasks] == [
        "wireguard.stop_interface",
        "wireguard.delete_config",
        "wireguard.apply_config",
    ]
    assert [task.payload["interface_name"] for task in local_tasks] == ["wg-old-a", "wg-old-a", "wg-new-a"]
    assert local_tasks[1].payload["depends_on_task_id"] == local_tasks[0].id
    assert local_tasks[2].payload["depends_on_task_id"] == local_tasks[1].id
    assert local_tasks[-1].payload["previous_interface_name"] == "wg-old-a"
    assert [task.type for task in peer_tasks] == [
        "wireguard.stop_interface",
        "wireguard.delete_config",
        "wireguard.apply_config",
    ]
    assert [task.payload["interface_name"] for task in peer_tasks] == ["wg-old-b", "wg-old-b", "wg-new-b"]
    assert peer_tasks[1].payload["depends_on_task_id"] == peer_tasks[0].id
    assert peer_tasks[2].payload["depends_on_task_id"] == peer_tasks[1].id
    assert peer_tasks[-1].payload["previous_interface_name"] == "wg-old-b"


def test_update_managed_link_rename_cancels_stale_pending_apply(monkeypatch) -> None:
    """验证改名前已有 pending apply 时会取消旧任务，并把新 apply 排到清理任务之后。"""

    private_keys = iter(["local-private", "peer-private"])
    public_keys = iter(["local-public", "peer-public"])

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "generate_wireguard_keypair", lambda: (next(private_keys), next(public_keys)))
    monkeypatch.setattr(api_main, "generate_preshared_key", lambda: "shared-key")
    monkeypatch.setattr(api_main, "generate_token", lambda prefix: f"{prefix}_secret")

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
        result = create_managed_link(
            node_a.id,
            ManagedLinkCreate(
                peer_node_id=node_b.id,
                local_interface_name="wg-old-a",
                peer_interface_name="wg-old-b",
                local_tunnel_ips=["10.42.0.1/32"],
                peer_tunnel_ips=["10.42.0.2/32"],
                local_endpoint_host="198.51.100.10",
                peer_endpoint_host="198.51.100.20",
                local_listen_port=51820,
                peer_listen_port=51821,
            ),
            session,
        )

        update_managed_link(
            result.local_interface.id,
            ManagedLinkUpdate(
                local_interface_name="wg-new-a",
                peer_interface_name="wg-new-b",
                local_tunnel_ips=["10.42.0.1/32"],
                peer_tunnel_ips=["10.42.0.2/32"],
                local_endpoint_host="198.51.100.10",
                peer_endpoint_host="198.51.100.20",
                local_listen_port=51820,
                peer_listen_port=51821,
            ),
            session,
        )
        tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.id)))
        local_id = result.local_interface.node_id
        peer_id = result.peer_interface.node_id

    for node_id, old_name, new_name in [(local_id, "wg-old-a", "wg-new-a"), (peer_id, "wg-old-b", "wg-new-b")]:
        node_tasks = [task for task in tasks if task.node_id == node_id]
        assert [task.type for task in node_tasks] == [
            "wireguard.apply_config",
            "wireguard.stop_interface",
            "wireguard.delete_config",
            "wireguard.apply_config",
        ]
        assert node_tasks[0].status == "cancelled"
        assert node_tasks[0].result["reason"] == "interface rename cleanup must run before apply_config"
        assert [task.payload["interface_name"] for task in node_tasks[1:]] == [old_name, old_name, new_name]
        assert node_tasks[2].payload["depends_on_task_id"] == node_tasks[1].id
        assert node_tasks[3].payload["depends_on_task_id"] == node_tasks[2].id


def test_update_managed_link_disabling_udp2raw_enqueues_cleanup_tasks(monkeypatch) -> None:
    """验证编辑受管连接禁用 udp2raw 时会清理节点上的旧 udp2raw 服务和配置。"""

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
            agent_version="0.5.2",
            agent_capabilities=capabilities,
            last_seen_at=datetime.utcnow(),
        )
        node_b = models.Node(
            name="node-b",
            agent_token_hash="hash",
            status="online",
            endpoint_ips=["198.51.100.20"],
            agent_version="0.5.2",
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
                    server_connect_host="198.51.100.20",
                    server_listen_port=23002,
                    client_listen_port=12312,
                ),
            ),
            session,
        )
        session.query(models.AgentTask).delete()
        session.commit()

        update_managed_link(
            result.local_interface.id,
            ManagedLinkUpdate(
                local_interface_name="wg-a",
                peer_interface_name="wg-b",
                local_tunnel_ips=["10.42.0.1/32"],
                peer_tunnel_ips=["10.42.0.2/32"],
                local_endpoint_host="198.51.100.10",
                peer_endpoint_host="198.51.100.20",
                local_listen_port=None,
                peer_listen_port=51821,
            ),
            session,
        )
        tasks = list(session.scalars(select(models.AgentTask).order_by(models.AgentTask.type, models.AgentTask.node_id)))
        local_interface = session.get(models.WireGuardInterface, result.local_interface.id)

    assert local_interface is not None
    assert "middleware" not in (local_interface.extras or {})
    assert [task.type for task in tasks].count("middleware.udp2raw.stop") == 2
    assert [task.type for task in tasks].count("middleware.udp2raw.delete") == 2
    assert [task.type for task in tasks].count("wireguard.apply_config") == 2
    cleanup_payloads = [task.payload for task in tasks if task.type in {"middleware.udp2raw.stop", "middleware.udp2raw.delete"}]
    assert {payload["mode"] for payload in cleanup_payloads} == {"client", "server"}


def test_udp2raw_defaults_server_forward_to_wireguard_listen_port() -> None:
    """验证旧配置未显式填写 server 转发目的时，仍默认转发到 server 侧 WireGuard ListenPort。"""

    local_interface = models.WireGuardInterface(id=1, node_id=1, name="wg-a", listen_port=None)
    peer_interface = models.WireGuardInterface(id=2, node_id=2, name="wg-b", listen_port=51821)
    middleware = {
        "type": "udp2raw",
        "enabled": True,
        "server_side": "peer",
        "server_listen_host": "0.0.0.0",
        "server_connect_host": "198.51.100.20",
        "server_listen_port": 23002,
        "client_listen_host": "127.0.0.1",
        "client_listen_port": 12312,
        "raw_mode": "faketcp",
        "cipher_mode": "xor",
        "password": "u2r_secret",
        "auto_rule": True,
    }

    payloads = udp2raw_endpoint_payloads(
        middleware,
        local_interface,
        peer_interface,
        "198.51.100.10",
        "198.51.100.20",
    )

    server_payload = payloads[0][2]
    assert server_payload["mode"] == "server"
    assert server_payload["remote_host"] == "127.0.0.1"
    assert server_payload["remote_port"] == 51821


def test_udp2raw_requires_server_side_wireguard_listen_port() -> None:
    """验证启用 udp2raw 时，运行 server 的 WireGuard 端必须填写 ListenPort。"""

    local_interface = models.WireGuardInterface(id=1, node_id=1, name="wg-a", listen_port=51820)
    peer_interface = models.WireGuardInterface(id=2, node_id=2, name="wg-b", listen_port=None)
    middleware = {
        "type": "udp2raw",
        "enabled": True,
        "server_side": "peer",
        "server_listen_host": "0.0.0.0",
        "server_connect_host": "198.51.100.20",
        "server_listen_port": 23002,
        "server_forward_host": "127.0.0.1",
        "server_forward_port": 11451,
        "client_listen_host": "127.0.0.1",
        "client_listen_port": 12312,
        "raw_mode": "faketcp",
        "cipher_mode": "xor",
        "password": "u2r_secret",
        "auto_rule": True,
    }

    with pytest.raises(HTTPException) as exc_info:
        udp2raw_endpoint_payloads(
            middleware,
            local_interface,
            peer_interface,
            "198.51.100.10",
            "198.51.100.20",
        )

    assert exc_info.value.status_code == 400
    assert "requires WireGuard listen port" in str(exc_info.value.detail)


def test_udp2raw_rejects_domain_as_server_connect_host(monkeypatch) -> None:
    """验证 udp2raw 的 server 连接地址必须是 IP，不能使用域名。"""

    import link42_api.main as api_main

    monkeypatch.setattr(api_main, "generate_wireguard_keypair", lambda: ("private", "public"))
    monkeypatch.setattr(api_main, "generate_preshared_key", lambda: "shared-key")

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
            endpoint_ips=["vpn.example.com"],
            agent_version="0.2.0",
            agent_capabilities=capabilities,
            last_seen_at=datetime.utcnow(),
        )
        session.add_all([node_a, node_b])
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            create_managed_link(
                node_a.id,
                ManagedLinkCreate(
                    peer_node_id=node_b.id,
                    local_interface_name="wg-a",
                    peer_interface_name="wg-b",
                    local_tunnel_ips=["10.42.0.1/32"],
                    peer_tunnel_ips=["10.42.0.2/32"],
                    local_endpoint_host="198.51.100.10",
                    peer_endpoint_host="vpn.example.com",
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

    assert exc_info.value.status_code == 400
    assert "must be an IP address" in str(exc_info.value.detail)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("server_listen_host", "example.com"),
        ("server_forward_host", "forward.example.com"),
        ("client_listen_host", "client.example.com"),
    ],
)
def test_udp2raw_normalize_rejects_domain_ip_fields(field_name: str, value: str) -> None:
    """验证后端清洗 udp2raw 配置时兜底拒绝 udp2raw IP 字段域名。"""

    payload = Udp2RawMiddlewareConfig.model_construct(
        enabled=True,
        server_side="peer",
        server_listen_host="0.0.0.0",
        server_connect_host="198.51.100.20",
        server_listen_port=23002,
        server_forward_host="127.0.0.1",
        server_forward_port=11451,
        client_listen_host="127.0.0.1",
        client_listen_port=12312,
        raw_mode="faketcp",
        cipher_mode="xor",
        password=None,
        auto_rule=True,
    )
    setattr(payload, field_name, value)

    with pytest.raises(HTTPException) as exc_info:
        normalize_udp2raw_config(payload)

    assert exc_info.value.status_code == 400
    assert "must be an IP address" in str(exc_info.value.detail)


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


def test_sqlite_upgrade_backup_keeps_single_file(monkeypatch, tmp_path) -> None:
    """验证升级备份固定覆盖同一个 SQLite 备份文件，避免备份堆积。"""

    import sqlite3
    import link42_api.database as database

    db_path = tmp_path / "link42.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute("CREATE TABLE demo (value TEXT)")
        connection.execute("INSERT INTO demo (value) VALUES ('old')")
        connection.commit()

    engine = create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(database, "engine", engine)

    backup_path = backup_sqlite_database_for_upgrade()
    assert backup_path == tmp_path / "link42.previous-version.db"
    with sqlite3.connect(backup_path) as connection:
        assert connection.execute("SELECT value FROM demo").fetchone()[0] == "old"

    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE demo SET value = 'new'")
        connection.commit()

    backup_path_again = backup_sqlite_database_for_upgrade()
    assert backup_path_again == backup_path
    assert sorted(path.name for path in tmp_path.glob("*.previous-version.db")) == ["link42.previous-version.db"]
    with sqlite3.connect(backup_path) as connection:
        assert connection.execute("SELECT value FROM demo").fetchone()[0] == "new"


def test_sqlite_repair_upgrades_legacy_schema_columns(monkeypatch) -> None:
    """验证很早期 SQLite 库启动时会补齐当前模型需要的列。"""

    import link42_api.database as database

    engine = create_engine("sqlite:///:memory:")
    monkeypatch.setattr(database, "engine", engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE nodes (id INTEGER PRIMARY KEY, name VARCHAR(80) NOT NULL)"))
        connection.execute(text("CREATE TABLE wg_interfaces (id INTEGER PRIMARY KEY, node_id INTEGER, name VARCHAR(32) NOT NULL)"))
        connection.execute(text("CREATE TABLE wg_peers (id INTEGER PRIMARY KEY, interface_id INTEGER NOT NULL)"))
        connection.execute(text("CREATE TABLE import_candidates (id INTEGER PRIMARY KEY, node_id INTEGER, path VARCHAR(512), interface_name VARCHAR(32), parsed JSON)"))
        connection.execute(text("CREATE TABLE change_plans (id INTEGER PRIMARY KEY, title VARCHAR(255), summary TEXT)"))
        connection.execute(text("CREATE TABLE agent_tasks (id INTEGER PRIMARY KEY, node_id INTEGER, type VARCHAR(80))"))

    ensure_sqlite_point_to_point_constraints()

    with engine.connect() as connection:
        node_columns = {row[1] for row in connection.execute(text("PRAGMA table_info(nodes)")).fetchall()}
        interface_columns = {row[1] for row in connection.execute(text("PRAGMA table_info(wg_interfaces)")).fetchall()}
        peer_columns = {row[1] for row in connection.execute(text("PRAGMA table_info(wg_peers)")).fetchall()}
        candidate_columns = {row[1] for row in connection.execute(text("PRAGMA table_info(import_candidates)")).fetchall()}
        plan_columns = {row[1] for row in connection.execute(text("PRAGMA table_info(change_plans)")).fetchall()}
        task_columns = {row[1] for row in connection.execute(text("PRAGMA table_info(agent_tasks)")).fetchall()}

    assert {
        "endpoint_ips",
        "github_proxy_url",
        "agent_version",
        "agent_capabilities",
        "agent_platform",
        "agent_update_status",
    } <= node_columns
    assert {
        "tunnel_ips",
        "dns",
        "source",
        "managed",
        "enabled",
        "deployed_config",
        "runtime_status",
        "extras",
        "warnings",
    } <= interface_columns
    assert {
        "peer_node_id",
        "peer_interface_id",
        "endpoint_host",
        "allowed_ips",
        "enabled",
        "extras",
        "warnings",
    } <= peer_columns
    assert {"warnings", "imported"} <= candidate_columns
    assert {"status", "affected_node_ids", "diff", "payload", "confirmed_at"} <= plan_columns
    assert {"change_plan_id", "payload", "status", "result", "started_at", "finished_at"} <= task_columns
