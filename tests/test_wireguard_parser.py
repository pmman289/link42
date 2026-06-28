from link42_wireguard import parse_wg_quick, render_wg_quick


def test_parse_wg_quick_common_fields() -> None:
    """验证常见 wg-quick 字段可以被解析为结构化数据。"""
    parsed = parse_wg_quick(
        """
        [Interface]
        PrivateKey = private
        Address = 10.42.0.1/24, fd42::1/64
        ListenPort = 51820
        PostUp = iptables -A FORWARD -i wg0 -j ACCEPT

        [Peer]
        PublicKey = public
        AllowedIPs = 10.42.0.2/32
        Endpoint = example.com:51820
        PersistentKeepalive = 25
        """,
        name="wg0",
    )

    assert parsed.name == "wg0"
    assert parsed.private_key == "private"
    assert parsed.addresses == ["10.42.0.1/24", "fd42::1/64"]
    assert parsed.listen_port == 51820
    assert parsed.post_up == ["iptables -A FORWARD -i wg0 -j ACCEPT"]
    assert len(parsed.peers) == 1
    assert parsed.peers[0].public_key == "public"
    assert parsed.peers[0].allowed_ips == ["10.42.0.2/32"]


def test_render_wg_quick_is_deterministic() -> None:
    """验证渲染结果顺序稳定，便于展示配置 diff。"""
    rendered = render_wg_quick(
        {
            "private_key": "private",
            "tunnel_ips": ["10.42.0.1/24"],
            "listen_port": 51820,
        },
        [
            {
                "name": "b",
                "public_key": "key-b",
                "allowed_ips": ["10.42.0.3/32"],
            },
            {
                "name": "a",
                "public_key": "key-a",
                "allowed_ips": ["10.42.0.2/32"],
            },
        ],
    )

    assert rendered.index("key-a") < rendered.index("key-b")
    assert rendered.endswith("\n")


def test_render_wg_quick_supports_table_off_and_multiple_addresses() -> None:
    """验证双栈地址和 Table=off 会被稳定渲染。"""

    rendered = render_wg_quick(
        {
            "private_key": "private",
            "tunnel_ips": ["10.42.0.1/32", "fd42::1/64"],
            "table_name": "off",
        },
        [],
    )

    assert "Address = 10.42.0.1/32, fd42::1/64" in rendered
    assert "Table = off" in rendered


def test_render_wg_quick_inserts_custom_config_after_section_headers() -> None:
    """验证高级自定义配置会插入到对应 section 标题之后。"""

    rendered = render_wg_quick(
        {
            "private_key": "private",
            "custom_config": "PostUp = ip route add 10.0.0.0/8 dev wg0",
        },
        [
            {
                "public_key": "peer-public",
                "allowed_ips": ["10.42.0.2/32"],
                "custom_config": "PresharedKey = custom-shared",
            }
        ],
    )

    assert rendered.splitlines()[:3] == [
        "[Interface]",
        "PostUp = ip route add 10.0.0.0/8 dev wg0",
        "PrivateKey = private",
    ]
    assert "[Peer]\nPresharedKey = custom-shared\nPublicKey = peer-public" in rendered
