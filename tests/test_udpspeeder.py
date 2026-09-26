from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from link42_agent import udpspeeder
from link42_api import schemas
from link42_api.main import (
    normalize_middleware_config,
    udpspeeder_client_default_port,
    udpspeeder_effective_wireguard_mtu,
    udpspeeder_endpoint_payloads,
    validate_udpspeeder_port_conflicts,
)


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
            "socket_buffer_kib": 4096,
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
        "socket_buffer_kib": 4096,
    }
    with pytest.raises(ValueError):
        udpspeeder.render_udpspeeder_args(payload)
    payload["fec_data"] = 10
    payload["remote_host"] = "example.com"
    with pytest.raises(ValueError):
        udpspeeder.render_udpspeeder_args(payload)


def test_udpspeeder_accepts_upstream_parameter_boundaries() -> None:
    """验证 Agent 接受 UDPspeeder 上游允许的 FEC 边界值。"""

    payload = {
        "instance": "test-1",
        "mode": "client",
        "listen_host": "127.0.0.1",
        "listen_port": 24002,
        "remote_host": "198.51.100.20",
        "remote_port": 24000,
        "fec_data": 255,
        "fec_redundancy": 0,
        "fec_timeout_ms": 0,
        "fec_mode": 0,
        "fec_mtu": 100,
        "fec_queue_len": 1,
        "decode_buffer": 300,
        "socket_buffer_kib": 10,
    }

    config = udpspeeder.validate_udpspeeder_payload(payload)

    assert config["fec_timeout_ms"] == 0
    assert udpspeeder.render_udpspeeder_args(payload)[-6:] == ["-q", "1", "--decode-buf", "300", "--sock-buf", "10"]


def test_udpspeeder_rejects_fec_packet_count_above_upstream_limit() -> None:
    """验证 FEC 数据包和冗余包总数不能超过 UDPspeeder 的 255 包限制。"""

    payload = {
        "instance": "test-1",
        "mode": "client",
        "listen_host": "127.0.0.1",
        "listen_port": 24002,
        "remote_host": "198.51.100.20",
        "remote_port": 24000,
        "fec_data": 255,
        "fec_redundancy": 1,
        "fec_timeout_ms": 0,
        "fec_mode": 0,
        "fec_mtu": 100,
        "fec_queue_len": 1,
        "decode_buffer": 300,
        "socket_buffer_kib": 10,
    }

    with pytest.raises(ValueError, match="less than or equal to 255"):
        udpspeeder.render_udpspeeder_args(payload)


def test_udpspeeder_schema_accepts_upstream_parameter_boundaries() -> None:
    """验证主控 Schema 与 Agent 使用相同的 UDPspeeder 参数边界。"""

    config = schemas.UdpSpeederMiddlewareConfig(
        fec_data=255,
        fec_redundancy=0,
        fec_timeout_ms=0,
        fec_mtu=100,
        fec_queue_len=1,
        decode_buffer=300,
        socket_buffer_kib=10,
    )

    assert config.fec_timeout_ms == 0
    with pytest.raises(ValueError, match="less than or equal to 255"):
        schemas.UdpSpeederMiddlewareConfig(fec_data=255, fec_redundancy=1)


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
        "socket_buffer_kib": 4096,
    }
    payloads = udpspeeder_endpoint_payloads(middleware, local, peer, None, "198.51.100.20")
    assert [item[0].id for item in payloads] == [12, 11]
    assert [item[1] for item in payloads] == ["middleware.udpspeeder.apply"] * 2
    assert [item[2]["mode"] for item in payloads] == ["server", "client"]
    assert payloads[1][2]["remote_host"] == "198.51.100.20"
    assert payloads[0][2]["socket_buffer_kib"] == 4096
    assert payloads[1][2]["socket_buffer_kib"] == 4096


def test_udpspeeder_allows_client_wireguard_without_listen_port() -> None:
    """验证 UDPspeeder 客户端侧 WireGuard 可以使用临时源端口。"""

    middleware = {
        "type": "udpspeeder",
        "server_side": "peer",
        "server_listen_port": 24000,
        "client_listen_port": 24002,
    }

    validate_udpspeeder_port_conflicts(middleware, None, 51820)


def test_udpspeeder_requires_server_wireguard_listen_port() -> None:
    """验证 UDPspeeder 服务端所在节点必须有 WireGuard ListenPort。"""

    middleware = {
        "type": "udpspeeder",
        "server_side": "peer",
        "server_listen_port": 24000,
        "client_listen_port": 24002,
    }

    with pytest.raises(Exception, match="server side requires WireGuard listen port"):
        validate_udpspeeder_port_conflicts(middleware, 51820, None)


def test_udpspeeder_defaults_leave_room_for_ipv4_and_ipv6_wireguard() -> None:
    """验证 UDPspeeder 默认组合会把 WireGuard MTU 限制到 IPv4/IPv6 都可承载的范围。"""

    middleware = normalize_middleware_config(
        None,
        None,
        schemas.UdpSpeederMiddlewareConfig(
            enabled=True,
            server_listen_port=24000,
            server_connect_host="198.51.100.20",
        ),
    )
    assert middleware is not None
    assert middleware["client_listen_port"] == 23001
    assert middleware["fec_mtu"] == 1400
    assert udpspeeder_effective_wireguard_mtu(middleware, 1420) == 1280
    assert udpspeeder_effective_wireguard_mtu(middleware, 1280) == 1280


def test_udpspeeder_client_defaults_to_server_wireguard_port() -> None:
    """验证未填写客户端端口时复用服务端 WireGuard 监听端口。"""

    assert udpspeeder_client_default_port("peer", 51821, 51820) == 51820
    assert udpspeeder_client_default_port("local", 51821, None) == 51821
    middleware = normalize_middleware_config(
        None,
        None,
        schemas.UdpSpeederMiddlewareConfig(
            enabled=True,
            server_side="peer",
            server_listen_port=24000,
            server_connect_host="198.51.100.20",
        ),
        local_listen_port=None,
        peer_listen_port=51820,
    )
    assert middleware is not None
    assert middleware["client_listen_port"] == 51820
    assert middleware["socket_buffer_kib"] == 4096


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


def test_udpspeeder_service_rebuilds_args_for_legacy_config(tmp_path, monkeypatch) -> None:
    """验证旧版实例重启时会补上新的 socket 缓冲参数。"""

    config_dir = tmp_path / "udpspeeder"
    config_dir.mkdir()
    (config_dir / "legacy.json").write_text(
        '{"instance":"legacy","mode":"client","listen_host":"127.0.0.1",'
        '"listen_port":24002,"remote_host":"198.51.100.20","remote_port":24000,'
        '"fec_data":10,"fec_redundancy":5,"fec_timeout_ms":8,"fec_mode":0,'
        '"fec_mtu":1400,"fec_queue_len":200,"decode_buffer":2000,"args":[]}',
        encoding="utf-8",
    )
    captured: dict[str, object] = {}
    monkeypatch.setattr(udpspeeder, "UDPSPEEDER_DIR", config_dir)
    monkeypatch.setattr(udpspeeder, "ensure_udpspeeder_socket_buffer_limit", lambda value: captured.update(buffer=value))
    monkeypatch.setattr(udpspeeder.os, "execv", lambda path, args: captured.update(path=path, args=args))

    assert udpspeeder.run_udpspeeder_service_command(["agent", "udpspeeder-client-start", "legacy"])
    assert captured["buffer"] == 4096
    assert captured["args"][-2:] == ["--sock-buf", "4096"]
