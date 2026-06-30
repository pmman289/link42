from __future__ import annotations

from collections.abc import Iterable
from typing import Optional


def render_wg_quick(interface: dict, peers: Iterable[dict]) -> str:
    """将接口和 peer 数据渲染成稳定顺序的 wg-quick 配置。"""
    # 渲染顺序保持稳定，方便前端展示 diff，也避免反复部署产生无意义变化。
    lines: list[str] = ["[Interface]"]
    _append_raw(lines, interface.get("custom_config"))
    _append(lines, "PrivateKey", interface.get("private_key"))
    _append_csv(lines, "Address", interface.get("tunnel_ips"))
    _append(lines, "ListenPort", interface.get("listen_port"))
    _append_csv(lines, "DNS", interface.get("dns"))
    _append(lines, "MTU", interface.get("mtu"))
    _append(lines, "Table", interface.get("table_name"))
    _append(lines, "FwMark", interface.get("fwmark"))
    _append_many(lines, "PreUp", interface.get("pre_up"))
    _append_many(lines, "PostUp", interface.get("post_up"))
    _append_many(lines, "PreDown", interface.get("pre_down"))
    _append_many(lines, "PostDown", interface.get("post_down"))

    sorted_peers = sorted(
        peers,
        key=lambda peer: (
            peer.get("name") or "",
            peer.get("public_key") or "",
        ),
    )
    for peer in sorted_peers:
        lines.append("")
        lines.append("[Peer]")
        _append_raw(lines, peer.get("custom_config"))
        _append(lines, "PublicKey", peer.get("public_key"))
        _append(lines, "PresharedKey", peer.get("preshared_key"))
        _append_csv(lines, "AllowedIPs", peer.get("allowed_ips"))
        endpoint_host = peer.get("endpoint_host")
        endpoint_port = peer.get("endpoint_port")
        if endpoint_host and endpoint_port:
            _append(lines, "Endpoint", f"{endpoint_host}:{endpoint_port}")
        _append(lines, "PersistentKeepalive", peer.get("persistent_keepalive"))

    return "\n".join(lines).rstrip() + "\n"


def _append(lines: list[str], key: str, value: Optional[object]) -> None:
    """追加单值字段，空值不输出。"""
    if value is None or value == "":
        return
    lines.append(f"{key} = {value}")


def _append_csv(lines: list[str], key: str, values: Optional[object]) -> None:
    """追加逗号分隔字段，兼容字符串和列表输入。"""
    if not values:
        return
    if isinstance(values, str):
        _append(lines, key, values)
        return
    values_list = [str(value) for value in values if value]
    if values_list:
        lines.append(f"{key} = {', '.join(values_list)}")


def _append_many(lines: list[str], key: str, values: Optional[object]) -> None:
    """追加可重复出现的 wg-quick 字段，例如 PostUp。"""
    if not values:
        return
    if isinstance(values, str):
        values = [values]
    for value in values:
        _append(lines, key, value)


def _append_raw(lines: list[str], value: Optional[object]) -> None:
    """追加用户自定义 wg-quick 行，保持原始顺序。"""
    if not value:
        return
    for raw_line in str(value).splitlines():
        line = raw_line.rstrip()
        if line:
            lines.append(line)
