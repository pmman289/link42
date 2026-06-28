from __future__ import annotations

import difflib
from typing import Any

from link42_wireguard import parse_wg_quick, render_wg_quick

from . import models


def interface_to_render_dict(interface: models.WireGuardInterface) -> dict[str, Any]:
    """把数据库模型转换成渲染器需要的字典。

    私钥当前仍在本地数据库中保存，字段名刻意通过 service 层集中转换，
    后续替换为文件/Vault/KMS 时可以减少影响面。
    """

    inherited_private_key, inherited_preshared_keys = inherited_secrets(interface)
    return {
        "private_key": interface.private_key_value or inherited_private_key,
        "tunnel_ips": interface.tunnel_ips,
        "listen_port": interface.listen_port,
        "dns": interface.dns,
        "mtu": interface.mtu,
        "table_name": interface.table_name,
        "fwmark": interface.fwmark,
        "pre_up": interface.pre_up,
        "post_up": interface.post_up,
        "pre_down": interface.pre_down,
        "post_down": interface.post_down,
        "custom_config": (interface.extras or {}).get("custom_config"),
    }


def peer_to_render_dict(peer: models.WireGuardPeer) -> dict[str, Any]:
    """把 peer 模型转换成渲染器需要的字典。"""

    _, inherited_preshared_keys = inherited_secrets(peer.interface)
    return {
        "name": peer.name,
        "public_key": peer.public_key,
        "preshared_key": peer.preshared_key_value or inherited_preshared_keys.get(peer.public_key),
        "endpoint_host": peer.endpoint_host,
        "endpoint_port": peer.endpoint_port,
        "allowed_ips": peer.allowed_ips,
        "persistent_keepalive": peer.persistent_keepalive,
        "custom_config": (peer.extras or {}).get("custom_config"),
    }


def render_interface_config(interface: models.WireGuardInterface) -> str:
    """渲染某条点对点链路当前启用对端后的完整 wg-quick 配置。"""

    enabled_peers = [peer for peer in interface.peers if peer.enabled]
    return render_wg_quick(
        interface_to_render_dict(interface),
        [peer_to_render_dict(peer) for peer in enabled_peers],
    )


def inherited_secrets(interface: models.WireGuardInterface) -> tuple[str | None, dict[str, str]]:
    """从已部署配置继承导入密钥，避免脱敏扫描后重渲染时丢失密钥。"""

    if interface.private_key_value and all(peer.preshared_key_value for peer in interface.peers):
        return None, {}
    if not interface.deployed_config:
        return None, {}

    parsed = parse_wg_quick(interface.deployed_config, name=interface.name)
    preshared_keys = {
        peer.public_key: peer.preshared_key
        for peer in parsed.peers
        if peer.public_key and peer.preshared_key
    }
    return parsed.private_key, preshared_keys


def build_apply_plan(interface: models.WireGuardInterface) -> dict[str, Any]:
    """生成部署计划 payload。

    payload 会进入 AgentTask，因此只放 Agent 执行必需的信息。
    """

    rendered = render_interface_config(interface)
    return {
        "interface_id": interface.id,
        "node_id": interface.node_id,
        "interface_name": interface.name,
        "config": rendered,
        "managed": interface.managed,
        "import_path": interface.import_path,
    }


def count_enabled_peers(interface: models.WireGuardInterface) -> int:
    """统计当前链路配置中启用的对端数量。"""

    return len([peer for peer in interface.peers if peer.enabled])


def build_apply_payload_from_config(interface: models.WireGuardInterface, config: str) -> dict[str, Any]:
    """使用指定配置文本生成部署 payload，避免预览阶段提前修改数据库状态。"""

    return {
        "interface_id": interface.id,
        "node_id": interface.node_id,
        "interface_name": interface.name,
        "config": config,
        "managed": True,
        "import_path": interface.import_path,
    }


def build_diff(old_config: str, new_config: str, fromfile: str = "current", tofile: str = "link42") -> str:
    """生成统一 diff 文本，供前端确认页展示。"""

    return "".join(
        difflib.unified_diff(
            old_config.splitlines(keepends=True),
            new_config.splitlines(keepends=True),
            fromfile=fromfile,
            tofile=tofile,
        )
    )


def split_endpoint(endpoint: str | None) -> tuple[str | None, int | None]:
    """拆分 Endpoint 字段，兼容只有 host 没有端口的导入配置。"""

    if not endpoint:
        return None, None
    if ":" not in endpoint:
        return endpoint, None
    host, port_text = endpoint.rsplit(":", 1)
    try:
        return host, int(port_text)
    except ValueError:
        return host, None
