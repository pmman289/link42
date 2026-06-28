from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# wg-quick 的 Interface 常见字段白名单；不在白名单里的字段会进入 extras 保留。
INTERFACE_FIELDS = {
    "privatekey",
    "address",
    "listenport",
    "dns",
    "mtu",
    "table",
    "fwmark",
    "preup",
    "postup",
    "predown",
    "postdown",
}

# wg-quick 的 Peer 常见字段白名单；不在白名单里的字段会进入 extras 保留。
PEER_FIELDS = {
    "publickey",
    "presharedkey",
    "allowedips",
    "endpoint",
    "persistentkeepalive",
}


@dataclass
class ParsedPeer:
    public_key: str | None = None
    preshared_key: str | None = None
    allowed_ips: list[str] = field(default_factory=list)
    endpoint: str | None = None
    persistent_keepalive: int | None = None
    extras: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class ParsedInterface:
    name: str
    private_key: str | None = None
    addresses: list[str] = field(default_factory=list)
    listen_port: int | None = None
    dns: list[str] = field(default_factory=list)
    mtu: int | None = None
    table: str | None = None
    fwmark: str | None = None
    pre_up: list[str] = field(default_factory=list)
    post_up: list[str] = field(default_factory=list)
    pre_down: list[str] = field(default_factory=list)
    post_down: list[str] = field(default_factory=list)
    peers: list[ParsedPeer] = field(default_factory=list)
    extras: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def parse_wg_quick(content: str, name: str = "wg0") -> ParsedInterface:
    """解析 wg-quick 配置文本，返回结构化接口和 peer 信息。"""
    parsed = ParsedInterface(name=name)
    section: str | None = None
    current_peer: ParsedPeer | None = None

    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section == "peer":
                current_peer = ParsedPeer()
                parsed.peers.append(current_peer)
            elif section == "interface":
                current_peer = None
            else:
                parsed.warnings.append(f"Line {line_no}: unsupported section [{section}]")
                current_peer = None
            continue

        if "=" not in line:
            parsed.warnings.append(f"Line {line_no}: ignored malformed line")
            continue

        key, value = [part.strip() for part in line.split("=", 1)]
        normalized = key.lower()

        if section == "interface":
            _apply_interface_field(parsed, normalized, key, value, line_no)
        elif section == "peer" and current_peer is not None:
            _apply_peer_field(current_peer, normalized, key, value, line_no)
        else:
            parsed.warnings.append(f"Line {line_no}: key outside supported section")

    return parsed


def parsed_interface_to_dict(parsed: ParsedInterface) -> dict[str, Any]:
    """将解析后的 dataclass 转为可通过 API 传输和落库的字典。"""

    return {
        "name": parsed.name,
        "private_key": parsed.private_key,
        "addresses": parsed.addresses,
        "listen_port": parsed.listen_port,
        "dns": parsed.dns,
        "mtu": parsed.mtu,
        "table": parsed.table,
        "fwmark": parsed.fwmark,
        "pre_up": parsed.pre_up,
        "post_up": parsed.post_up,
        "pre_down": parsed.pre_down,
        "post_down": parsed.post_down,
        "extras": parsed.extras,
        "warnings": parsed.warnings,
        "peers": [
            {
                "public_key": peer.public_key,
                "preshared_key": peer.preshared_key,
                "allowed_ips": peer.allowed_ips,
                "endpoint": peer.endpoint,
                "persistent_keepalive": peer.persistent_keepalive,
                "extras": peer.extras,
                "warnings": peer.warnings,
            }
            for peer in parsed.peers
        ],
    }


def _split_csv(value: str) -> list[str]:
    """解析 wg-quick 中逗号分隔的多值字段。"""
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_int(value: str, field_name: str, line_no: int, warnings: list[str]) -> int | None:
    """解析整数字段，失败时把警告写入解析结果而不是直接中断导入。"""
    try:
        return int(value)
    except ValueError:
        warnings.append(f"Line {line_no}: invalid integer for {field_name}")
        return None


def _apply_interface_field(
    parsed: ParsedInterface,
    normalized: str,
    original_key: str,
    value: str,
    line_no: int,
) -> None:
    """把 Interface 区块中的字段写入解析对象。"""
    if normalized not in INTERFACE_FIELDS:
        parsed.extras[original_key] = value
        parsed.warnings.append(f"Line {line_no}: preserved unsupported Interface field {original_key}")
        return

    if normalized == "privatekey":
        parsed.private_key = value
    elif normalized == "address":
        parsed.addresses.extend(_split_csv(value))
    elif normalized == "listenport":
        parsed.listen_port = _parse_int(value, "ListenPort", line_no, parsed.warnings)
    elif normalized == "dns":
        parsed.dns.extend(_split_csv(value))
    elif normalized == "mtu":
        parsed.mtu = _parse_int(value, "MTU", line_no, parsed.warnings)
    elif normalized == "table":
        parsed.table = value
    elif normalized == "fwmark":
        parsed.fwmark = value
    elif normalized == "preup":
        parsed.pre_up.append(value)
    elif normalized == "postup":
        parsed.post_up.append(value)
    elif normalized == "predown":
        parsed.pre_down.append(value)
    elif normalized == "postdown":
        parsed.post_down.append(value)


def _apply_peer_field(
    peer: ParsedPeer,
    normalized: str,
    original_key: str,
    value: str,
    line_no: int,
) -> None:
    """把 Peer 区块中的字段写入解析对象。"""
    if normalized not in PEER_FIELDS:
        peer.extras[original_key] = value
        peer.warnings.append(f"Line {line_no}: preserved unsupported Peer field {original_key}")
        return

    if normalized == "publickey":
        peer.public_key = value
    elif normalized == "presharedkey":
        peer.preshared_key = value
    elif normalized == "allowedips":
        peer.allowed_ips.extend(_split_csv(value))
    elif normalized == "endpoint":
        peer.endpoint = value
    elif normalized == "persistentkeepalive":
        peer.persistent_keepalive = _parse_int(
            value,
            "PersistentKeepalive",
            line_no,
            peer.warnings,
        )
