from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from link42_agent import udpspeeder
from link42_api import schemas
from link42_api.main import normalize_middleware_config, udpspeeder_effective_wireguard_mtu, udpspeeder_endpoint_payloads


def test_udpspeeder_renders_ipv6_client_arguments() -> None:
    """验证 UDPspeeder 客户端参数支持 IPv6 且不会拼接成 shell 字符串。"""

    args = udpspeeder.render_udpspeeder_args(
        {
            "instance": "test-1",
            "mode": "client",
            "listen_host": "127.0.0.1",
            "listen_port": 24002,
            "remote_host": "2001:db8::20",
            "remote_port": 24000,
            "fec_data": 10,
            "fec_redundancy": 5,
            "fec_timeout_ms": 8,
            "fec_mode": 0,
            "fec_mtu": 1250,
            "fec_queue_len": 200,
            "decode_buffer": 2000,
        }
    )
    assert args[:6] == ["-c", "-l", "127.0.0.1:24002", "-r", "[2001:db8::20]:24000", "-f"]
    assert "10:5" in args


def test_udpspeeder_rejects_domain_and_invalid_fec() -> None:
    """验证地址和 FEC 边界不会进入 Agent 命令。"""

    payload = {
        "instance": "test-1",
        "mode": "server",
        "listen_host": "0.0.0.0",
        "listen_port": 24000,
        "remote_host": "127.0.0.1",
        "remote_port": 24001,
        "fec_data": 0,
        "fec_redundancy": 5,
        "fec_timeout_ms": 8,
        "fec_mode": 0,
        "fec_mtu": 1250,
        "fec_queue_len": 200,
        "decode_buffer": 2000,
    }
    with pytest.raises(ValueError):
        udpspeeder.render_udpspeeder_args(payload)
    payload["fec_data"] = 10
    payload["remote_host"] = "example.com"
    with pytest.raises(ValueError):
        udpspeeder.render_udpspeeder_args(payload)


def test_udpspeeder_schema_is_mutually_exclusive_with_existing_middleware() -> None:
    """验证新中间层不能与 udp2raw/mimic 同时启用。"""

    with pytest.raises(Exception):
        normalize_middleware_config(
            schemas.Udp2RawMiddlewareConfig(enabled=True, server_listen_port=24000, client_listen_port=24002),
            None,
            schemas.UdpSpeederMiddlewareConfig(enabled=True, server_listen_port=24000, client_listen_port=24002),
        )


def test_udpspeeder_endpoint_payloads_create_server_and_client_roles() -> None:
    """验证主控为 UDPspeeder 生成一端 server、一端 client 的任务。"""

    local = SimpleNamespace(id=11, node_id=1, listen_port=None)
    peer = SimpleNamespace(id=12, node_id=2, listen_port=51820)
    middleware = {
        "type": "udpspeeder",
        "server_side": "peer",
        "server_listen_host": "0.0.0.0",
        "server_connect_host": "198.51.100.20",
        "server_listen_port": 24000,
        "server_forward_host": "127.0.0.1",
        "server_forward_port": 51820,
        "client_listen_host": "127.0.0.1",
        "client_listen_port": 24002,
        "fec_data": 10,
        "fec_redundancy": 5,
        "fec_timeout_ms": 8,
        "fec_mode": 0,
        "fec_mtu": 1250,
        "fec_queue_len": 200,
        "decode_buffer": 2000,
    }
    payloads = udpspeeder_endpoint_payloads(middleware, local, peer, None, "198.51.100.20")
    assert [item[0].id for item in payloads] == [12, 11]
    assert [item[1] for item in payloads] == ["middleware.udpspeeder.apply"] * 2
    assert [item[2]["mode"] for item in payloads] == ["server", "client"]
    assert payloads[1][2]["remote_host"] == "198.51.100.20"


def test_udpspeeder_defaults_leave_room_for_ipv4_and_ipv6_wireguard() -> None:
    """验证 UDPspeeder 默认组合会把 WireGuard MTU 限制到 IPv4/IPv6 都可承载的范围。"""

    middleware = normalize_middleware_config(
        None,
        None,
        schemas.UdpSpeederMiddlewareConfig(
            enabled=True,
            server_listen_port=24000,
            client_listen_port=24002,
            server_connect_host="198.51.100.20",
        ),
    )
    assert middleware is not None
    assert middleware["fec_mtu"] == 1400
    assert udpspeeder_effective_wireguard_mtu(middleware, 1420) == 1280
    assert udpspeeder_effective_wireguard_mtu(middleware, 1280) == 1280


def test_udpspeeder_systemd_unit_loads_agent_environment(tmp_path, monkeypatch) -> None:
    """验证 UDPspeeder systemd 服务会加载正式 Agent 的连接环境。"""

    environment_file = tmp_path / "agent.env"
    environment_file.write_text("LINK42_SERVER_URL=http://controller\n", encoding="utf-8")
    monkeypatch.setenv("LINK42_AGENT_ENV_FILE", str(environment_file))

    unit = udpspeeder.render_udpspeeder_systemd_unit("client")

    assert f"EnvironmentFile=-{environment_file}" in unit
    assert "ExecStart=" in unit
    assert "udpspeeder-client-start %i" in unit


def test_udpspeeder_start_and_stop_return_task_result_objects(monkeypatch) -> None:
    """验证服务动作返回字典，符合 Agent 任务结果接口。"""

    monkeypatch.setattr(udpspeeder, "service_action", lambda *args, **kwargs: [{"command": ["systemctl"]}])

    assert udpspeeder.start_udpspeeder({"mode": "client", "instance": "test"}, dry_run=True) == {
        "changed": False,
        "commands": [{"command": ["systemctl"]}],
    }
    assert udpspeeder.stop_udpspeeder({"mode": "client", "instance": "test"}, dry_run=False) == {
        "changed": True,
        "commands": [{"command": ["systemctl"]}],
    }
