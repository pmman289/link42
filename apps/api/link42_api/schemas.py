from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import math
import re
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_serializer, field_validator


LOOKING_GLASS_TARGET_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
LOOKING_GLASS_BIRD_PROTOCOL_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}$")
MIN_BGP_ASN = 1
MAX_BGP_ASN = 4294967295


def _read_string_list(value: Any) -> list[str]:
    """把旧库中的 JSON 列字段安全转换为字符串列表。"""

    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _read_object(value: Any) -> dict[str, Any]:
    """把旧库中的 JSON 对象字段安全转换为对象。"""

    return value if isinstance(value, dict) else {}


def serialize_utc_timestamp(value: datetime | None) -> int | None:
    """把数据库里的 UTC 时间序列化成 Unix 秒级时间戳。"""

    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return int(value.timestamp())


def normalize_database_datetime(value: datetime | None) -> datetime | None:
    """把外部时间统一成数据库使用的 UTC naive datetime。"""

    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def redact_wireguard_response_secrets(value: Any) -> Any:
    """递归隐藏响应对象里的 WireGuard 私钥、预共享密钥和配置行。"""

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in {"private_key", "private_key_value", "preshared_key", "preshared_key_value"}:
                result[str(key)] = "<REDACTED>" if item else item
            else:
                result[str(key)] = redact_wireguard_response_secrets(item)
        return result
    if isinstance(value, list):
        return [redact_wireguard_response_secrets(item) for item in value]
    if isinstance(value, str):
        return re.sub(
            r"(?im)^([ +\-]*)(PrivateKey|PresharedKey)(\s*=\s*).*$",
            r"\1\2\3<REDACTED>",
            value,
        )
    return value


def normalize_looking_glass_target(value: str) -> str:
    """规范化第三方诊断目标，允许 IP 或普通域名。"""

    cleaned = value.strip()
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        pass
    if LOOKING_GLASS_TARGET_HOSTNAME_RE.fullmatch(cleaned) and ".." not in cleaned:
        return cleaned.rstrip(".").lower()
    raise ValueError("target must be a valid IP address or hostname")


def normalize_bird_protocol_name(value: str) -> str:
    """规范化 BIRD 协议名称，只允许 birdc 固定参数可安全接收的标识符。"""

    cleaned = value.strip()
    if LOOKING_GLASS_BIRD_PROTOCOL_NAME_RE.fullmatch(cleaned):
        return cleaned
    raise ValueError("protocol_name must use 1-64 characters: letters, numbers, _, ., :, -")


def normalize_bgp_asn(value: int | str) -> int:
    """规范化第三方 BIRD ASN 查询参数，只允许 32 位 BGP ASN。"""

    text = str(value).strip()
    if not re.fullmatch(r"\d+", text):
        raise ValueError("asn must be an integer between 1 and 4294967295")
    parsed = int(text)
    if MIN_BGP_ASN <= parsed <= MAX_BGP_ASN:
        return parsed
    raise ValueError("asn must be an integer between 1 and 4294967295")


def _validate_port(value: int | None) -> int | None:
    """校验 UDP 端口范围。"""

    if value is not None and not 1 <= value <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return value


def _validate_cidrs(values: list[str]) -> list[str]:
    """校验 CIDR 字段，避免无效地址进入部署计划。"""

    normalized = []
    for value in values:
        cidr = value.strip()
        if "/" not in cidr:
            raise ValueError("CIDR value must contain prefix length")
        if any(char.isspace() or ord(char) < 0x21 or ord(char) == 0x7F for char in cidr) or "%" in cidr:
            raise ValueError("CIDR value must not contain control characters or IPv6 zones")
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR value: {cidr}") from exc
        normalized.append(cidr)
    return normalized


def _validate_ipv4_address(value: str) -> str:
    """校验字段必须是 IPv4 字面量地址。"""

    cleaned = value.strip()
    try:
        address = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid IPv4 address: {cleaned}") from exc
    if address.version != 4:
        raise ValueError("address must be IPv4")
    return cleaned


def _validate_ip_address(value: str) -> str:
    """校验字段必须是 IPv4 或 IPv6 字面量地址。"""

    cleaned = value.strip()
    try:
        ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {cleaned}") from exc
    return cleaned


def _validate_optional_ipv4_address(value: str | None) -> str | None:
    """校验可选字段必须是 IPv4 字面量地址，空字符串归一为空。"""

    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return _validate_ipv4_address(cleaned)


def _validate_optional_ip_address(value: str | None) -> str | None:
    """校验可选字段必须是 IP 字面量地址，空字符串归一为空。"""

    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return _validate_ip_address(cleaned)


def _validate_linux_interface_name(value: str) -> str:
    """校验 Linux 接口名，避免超过内核限制或包含危险字符。"""

    cleaned = value.strip()
    if not cleaned:
        raise ValueError("interface name is required")
    if len(cleaned) > 15:
        raise ValueError("interface name must be 15 characters or fewer")
    if cleaned in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", cleaned, flags=re.ASCII):
        raise ValueError("interface name contains unsupported characters")
    return cleaned


def _validate_gre_interface_name(value: str) -> str:
    """校验 GRE 接口名，遵循 Linux 上限并兼容 OpenWrt UCI 标识符。"""

    cleaned = value.strip()
    if not cleaned:
        raise ValueError("interface name is required")
    if len(cleaned) > 15:
        raise ValueError("interface name must be 15 characters or fewer")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", cleaned, flags=re.ASCII):
        raise ValueError("interface name contains unsupported characters")
    return cleaned


def _validate_gre_outer_address(value: str) -> str:
    """校验 GRE 外层地址，并支持 IPv6 链路本地地址的 zone 标识。"""

    cleaned = value.strip()
    try:
        address = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid GRE outer address: {cleaned}") from exc
    scope_id = getattr(address, "scope_id", None)
    if scope_id is not None:
        if address.version != 6 or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", scope_id, flags=re.ASCII):
            raise ValueError("GRE IPv6 zone must be a valid interface name")
    return cleaned


def _validate_gre_key(value: str | None) -> str | None:
    """校验 GRE Key 为 32 位无符号整数。"""

    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if not cleaned.isdigit():
        raise ValueError("GRE key must be a number")
    number = int(cleaned)
    if not 0 <= number <= 4294967295:
        raise ValueError("GRE key must be between 0 and 4294967295")
    return cleaned


def _validate_optional_http_url(value: str | None) -> str | None:
    """校验可选 http(s) URL，空字符串归一为空。"""

    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F or char in "'\"\\" for char in value):
        raise ValueError("URL must not contain whitespace or quotes")
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("URL must be an HTTP(S) URL without credentials, query or fragment")
    try:
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("URL port must be between 1 and 65535")
    except ValueError as exc:
        raise ValueError("URL port is invalid") from exc
    return value


def _validate_optional_asset_url(value: str | None) -> str | None:
    """校验可用于图片展示的 URL，支持站内绝对路径和 http(s) 地址。"""

    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if any(char.isspace() or char in "'\"" for char in value):
        raise ValueError("URL must not contain whitespace or quotes")
    if value.startswith("/"):
        return value
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("URL must be an absolute path or start with http:// or https://")
    return value


def _validate_endpoint_host(value: str | None) -> str | None:
    """校验 WireGuard Endpoint 主机字段，阻止配置行注入。"""

    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > 255 or not re.fullmatch(r"[A-Za-z0-9_.:%\-\[\]]+", cleaned, flags=re.ASCII):
        raise ValueError("endpoint host contains unsupported characters")
    return cleaned


def _validate_wireguard_key(value: str | None, label: str) -> str | None:
    """拒绝会破坏 wg-quick 配置行的控制字符，同时保留导入测试和旧库兼容性。"""

    if value is None:
        return None
    if not value or len(value) > 128 or any(char.isspace() or ord(char) < 0x21 or ord(char) == 0x7F for char in value):
        raise ValueError(f"{label} contains unsupported characters")
    return value


def _validate_display_text(value: str | None, label: str) -> str | None:
    """Normalize operator-visible text and reject control characters.

    These fields are copied into logs and topology responses.  Keeping control
    characters out prevents log-line injection while preserving normal Unicode
    names and hostnames.
    """

    if value is None:
        return None
    cleaned = value.strip()
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in cleaned):
        raise ValueError(f"{label} must not contain control characters")
    return cleaned


def _validate_metadata_json(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> Any:
    """限制 Agent 平台元数据的深度、节点数和字符串大小。"""

    remaining = budget if budget is not None else [2048]
    remaining[0] -= 1
    if remaining[0] < 0 or depth > 8:
        raise ValueError("agent metadata is too deeply nested or too large")
    if isinstance(value, dict):
        if len(value) > 256:
            raise ValueError("agent metadata object has too many fields")
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 128 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in key):
                raise ValueError("agent metadata field name is invalid")
            _validate_metadata_json(child, depth=depth + 1, budget=remaining)
    elif isinstance(value, list):
        if len(value) > 256:
            raise ValueError("agent metadata array has too many items")
        for child in value:
            _validate_metadata_json(child, depth=depth + 1, budget=remaining)
    elif isinstance(value, str):
        if len(value.encode("utf-8")) > 8192 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            raise ValueError("agent metadata string is invalid or too large")
    elif isinstance(value, int) and not isinstance(value, bool):
        if len(str(abs(value))) > 128:
            raise ValueError("agent metadata integer is too large")
    elif value is None or isinstance(value, (bool, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("agent metadata contains a non-finite number")
    else:
        raise ValueError("agent metadata contains an unsupported value")
    return value


def _validate_capabilities(values: list[str]) -> list[str]:
    """限制 Agent 能力标识的长度并清除首尾空白。"""

    normalized: list[str] = []
    for value in values:
        cleaned = value.strip()
        if not cleaned or len(cleaned) > 128 or any(ord(char) < 0x21 or ord(char) == 0x7F for char in cleaned):
            raise ValueError("agent capability is invalid")
        normalized.append(cleaned)
    return sorted(set(normalized))


def _validate_plugin_payload(value: Any, *, depth: int = 0, budget: list[int] | None = None, bytes_budget: list[int] | None = None) -> Any:
    """限制节点插件任务 payload，避免大批量配置耗尽 API/Agent 内存。"""

    remaining = budget if budget is not None else [12000]
    remaining_bytes = bytes_budget if bytes_budget is not None else [3 * 1024 * 1024]
    remaining[0] -= 1
    if remaining[0] < 0 or depth > 8:
        raise ValueError("plugin payload is too deeply nested or too large")
    if isinstance(value, dict):
        if len(value) > 2000:
            raise ValueError("plugin payload object has too many fields")
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 128 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in key):
                raise ValueError("plugin payload field name is invalid")
            _validate_plugin_payload(child, depth=depth + 1, budget=remaining, bytes_budget=remaining_bytes)
    elif isinstance(value, list):
        if len(value) > 256:
            raise ValueError("plugin payload array has too many items")
        for child in value:
            _validate_plugin_payload(child, depth=depth + 1, budget=remaining, bytes_budget=remaining_bytes)
    elif isinstance(value, str):
        encoded_size = len(value.encode("utf-8"))
        if encoded_size > 512 * 1024 or any(ord(char) == 0 or ord(char) == 0x7F for char in value):
            raise ValueError("plugin payload string is invalid or too large")
        remaining_bytes[0] -= encoded_size
        if remaining_bytes[0] < 0:
            raise ValueError("plugin payload is too large")
    elif isinstance(value, int) and not isinstance(value, bool):
        if len(str(abs(value))) > 128:
            raise ValueError("plugin payload integer is too large")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("plugin payload contains a non-finite number")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise ValueError("plugin payload contains an unsupported value")
    return value


def _validate_internal_ipv4s(values: list[str]) -> list[str]:
    result = []
    for value in values:
        address = ipaddress.ip_interface(value.strip())
        if not isinstance(address, ipaddress.IPv4Interface) or address.network.prefixlen != 32:
            raise ValueError("节点固定内网地址必须是 IPv4 /32")
        normalized = str(address)
        if normalized in result:
            raise ValueError("节点固定内网地址重复")
        result.append(normalized)
    return result


class NodeCreate(BaseModel):
    """创建节点请求。"""

    internal_ipv4s: list[str] = Field(default_factory=list, max_length=128)
    _internal_ipv4s_validator = field_validator("internal_ipv4s")(_validate_internal_ipv4s)

    name: str = Field(min_length=1, max_length=80)
    hostname: str | None = Field(default=None, max_length=255)
    region: str | None = Field(default=None, max_length=80)
    management_ip: str | None = Field(default=None, max_length=64)
    public_ip: str | None = Field(default=None, max_length=64)
    endpoint_ips: list[str] = Field(min_length=1, max_length=32)
    topology_endpoint: str | None = Field(default=None, max_length=255)
    github_proxy_url: str | None = Field(default=None, max_length=500)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        cleaned = _validate_display_text(value, "node name") or ""
        if not cleaned:
            raise ValueError("node name is required")
        return cleaned

    @field_validator("hostname", "region", "management_ip", "public_ip", "topology_endpoint")
    @classmethod
    def validate_display_fields(cls, value: str | None) -> str | None:
        return _validate_display_text(value, "node field")

    @field_validator("endpoint_ips")
    @classmethod
    def validate_endpoint_ips(cls, values: list[str]) -> list[str]:
        """清洗节点入口地址并拒绝空值和配置控制字符。"""

        normalized = [_validate_endpoint_host(value) for value in values]
        if any(value is None for value in normalized):
            raise ValueError("endpoint address is required")
        return [value for value in normalized if value is not None]

    @field_validator("github_proxy_url")
    @classmethod
    def validate_github_proxy_url(cls, value: str | None) -> str | None:
        """校验节点 GitHub 代理地址。"""

        return _validate_optional_http_url(value)


class NodeUpdate(BaseModel):
    """更新节点基础信息请求。"""

    internal_ipv4s: list[str] = Field(default_factory=list, max_length=128)
    _internal_ipv4s_validator = field_validator("internal_ipv4s")(_validate_internal_ipv4s)

    name: str = Field(min_length=1, max_length=80)
    endpoint_ips: list[str] = Field(min_length=1, max_length=32)
    hostname: str | None = Field(default=None, max_length=255)
    region: str | None = Field(default=None, max_length=80)
    management_ip: str | None = Field(default=None, max_length=64)
    public_ip: str | None = Field(default=None, max_length=64)
    topology_endpoint: str | None = Field(default=None, max_length=255)
    github_proxy_url: str | None = Field(default=None, max_length=500)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        cleaned = _validate_display_text(value, "node name") or ""
        if not cleaned:
            raise ValueError("node name is required")
        return cleaned

    @field_validator("hostname", "region", "management_ip", "public_ip", "topology_endpoint")
    @classmethod
    def validate_display_fields(cls, value: str | None) -> str | None:
        return _validate_display_text(value, "node field")

    @field_validator("endpoint_ips")
    @classmethod
    def validate_endpoint_ips(cls, values: list[str]) -> list[str]:
        """清洗节点更新入口地址。"""

        normalized = [_validate_endpoint_host(value) for value in values]
        if any(value is None for value in normalized):
            raise ValueError("endpoint address is required")
        return [value for value in normalized if value is not None]

    @field_validator("github_proxy_url")
    @classmethod
    def validate_github_proxy_url(cls, value: str | None) -> str | None:
        """校验节点 GitHub 代理地址。"""

        return _validate_optional_http_url(value)


class NodeRead(BaseModel):
    """节点详情响应。"""

    internal_ipv4s: list[str] = Field(default_factory=list)
    id: int
    name: str
    hostname: str | None
    region: str | None = None
    management_ip: str | None
    public_ip: str | None
    endpoint_ips: list[str]
    topology_endpoint: str | None = None
    github_proxy_url: str | None = None
    topology_x: float | None = None
    topology_y: float | None = None
    topology_locked: bool = False
    agent_version: str | None = None
    agent_protocol_version: int | None = None
    agent_capabilities: list[str] = Field(default_factory=list)
    agent_platform: dict[str, Any] = Field(default_factory=dict)
    agent_update_status: str | None = None
    agent_last_error: str | None = None
    middleware_install_status: str | None = None
    status: str
    last_seen_at: datetime | None

    model_config = {"from_attributes": True}

    @field_validator("endpoint_ips", "agent_capabilities", mode="before")
    @classmethod
    def normalize_legacy_string_lists(cls, value: Any) -> list[str]:
        return _read_string_list(value)

    @field_validator("agent_platform", mode="before")
    @classmethod
    def normalize_legacy_platform(cls, value: Any) -> dict[str, Any]:
        return _read_object(value)


class NodeCreateResult(BaseModel):
    """创建节点响应，包含只返回一次的 Agent token。"""

    node: NodeRead
    agent_token: str


class PortInventorySettingRead(BaseModel):
    """端口台账范围设置响应。"""

    range_start: int | None = None
    range_end: int | None = None


class PortInventorySettingUpdate(BaseModel):
    """更新端口台账范围设置请求。"""

    range_start: int
    range_end: int

    @field_validator("range_start", "range_end")
    @classmethod
    def validate_range_port(cls, value: int) -> int:
        """校验范围端口号有效。"""

        return int(_validate_port(value) or value)


class PortInventoryEntryBase(BaseModel):
    """端口台账条目的公共字段。"""

    protocol: str = Field(pattern="^(?i:tcp|udp)$")
    port: int
    purpose: str = Field(default="", max_length=255)
    source: str = Field(default="manual", max_length=32)
    detected_process: str | None = Field(default=None, max_length=255)
    detected_pid: str | None = Field(default=None, max_length=64)
    detected_source: str | None = Field(default=None, max_length=255)

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str) -> str:
        """协议统一转为大写，便于查重和展示。"""

        return value.upper()

    @field_validator("port")
    @classmethod
    def validate_inventory_port(cls, value: int) -> int:
        """校验台账端口号有效。"""

        return int(_validate_port(value) or value)


class PortInventoryEntryCreate(PortInventoryEntryBase):
    """创建端口台账条目请求。"""

    pass


class PortInventoryEntryUpdate(BaseModel):
    """更新端口台账条目请求。"""

    protocol: str | None = Field(default=None, pattern="^(?i:tcp|udp)$")
    port: int | None = None
    purpose: str | None = Field(default=None, max_length=255)
    source: str | None = Field(default=None, max_length=32)
    detected_process: str | None = Field(default=None, max_length=255)
    detected_pid: str | None = Field(default=None, max_length=64)
    detected_source: str | None = Field(default=None, max_length=255)

    @field_validator("protocol", "port", "purpose", "source", mode="before")
    @classmethod
    def reject_required_field_null(cls, value: Any) -> Any:
        """PATCH 可省略必填列，但不能将其清空为 NULL。"""

        if value is None:
            raise ValueError("field must not be null")
        return value

    @field_validator("protocol")
    @classmethod
    def normalize_optional_protocol(cls, value: str | None) -> str | None:
        """可选协议存在时统一转为大写。"""

        return value.upper() if value else value

    @field_validator("port")
    @classmethod
    def validate_optional_inventory_port(cls, value: int | None) -> int | None:
        """校验可选台账端口号有效。"""

        return _validate_port(value)


class PortInventoryEntryRead(PortInventoryEntryBase):
    """端口台账条目响应。"""

    id: int
    node_id: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PortInventoryRead(BaseModel):
    """端口台账完整响应，包含范围设置和条目列表。"""

    setting: PortInventorySettingRead
    entries: list[PortInventoryEntryRead]


class LoginRequest(BaseModel):
    """登录请求。"""

    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=255)


class LoginResult(BaseModel):
    """登录成功响应。"""

    token: str
    username: str


class AuthStatus(BaseModel):
    """当前 Web 会话认证状态响应。"""

    authenticated: bool
    username: str | None = None


class BrandingRead(BaseModel):
    """站点品牌信息响应。"""

    site_title: str = "Link42"
    site_logo_url: str = "/logo.png"


class ControllerSettingsRead(BaseModel):
    """主控设置读取响应。"""

    controller_url: str
    username: str
    site_title: str = "Link42"
    site_logo_url: str = "/logo.png"


class ControllerSettingsUpdate(BaseModel):
    """主控设置更新请求。"""

    controller_url: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=80)
    site_title: str = Field(default="Link42", min_length=1, max_length=80)
    site_logo_url: str | None = Field(default=None, max_length=500)
    new_password: str | None = Field(default=None, min_length=6, max_length=255)

    @field_validator("controller_url")
    @classmethod
    def validate_controller_url(cls, value: str) -> str:
        """主控地址必须是 Agent 可访问的绝对 HTTP(S) URL。"""

        validated = _validate_optional_http_url(value)
        if not validated:
            raise ValueError("controller URL is required")
        if urlparse(validated).path not in {"", "/"}:
            raise ValueError("controller URL must not contain a path")
        return validated

    @field_validator("username", "site_title")
    @classmethod
    def validate_operator_text(cls, value: str) -> str:
        """用户名和站点标题会进入日志/HTML 文本，拒绝控制字符并统一空白。"""

        cleaned = _validate_display_text(value, "operator text")
        if not cleaned:
            raise ValueError("value must not be empty")
        return cleaned

    @field_validator("site_logo_url")
    @classmethod
    def validate_site_logo_url(cls, value: str | None) -> str | None:
        """校验站点 logo 地址。"""

        return _validate_optional_asset_url(value)


class InterfaceCreate(BaseModel):
    """创建单个 WireGuard 接口请求。"""

    ipv4_link_pool_id: int | None = Field(default=None, ge=1)

    name: str = Field(min_length=1, max_length=32)
    tunnel_ips: list[str] = Field(default_factory=list, max_length=128)
    listen_port: int | None = None
    private_key: str | None = None
    public_key: str | None = None
    mtu: int | None = 1420
    table_name: str | None = "off"
    dns: list[str] = Field(default_factory=list, max_length=64)
    interface_custom_config: str | None = Field(default=None, max_length=65536)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        """校验 WireGuard 接口名符合 Linux IFNAMSIZ 和文件路径限制。"""

        return _validate_linux_interface_name(value)

    @field_validator("listen_port")
    @classmethod
    def validate_listen_port(cls, value: int | None) -> int | None:
        """校验监听端口范围。"""

        return _validate_port(value)

    @field_validator("tunnel_ips")
    @classmethod
    def validate_tunnel_ips(cls, values: list[str]) -> list[str]:
        """校验接口地址应包含 CIDR 前缀。"""

        return _validate_cidrs(values)

    @field_validator("private_key", "public_key")
    @classmethod
    def validate_keys(cls, value: str | None) -> str | None:
        """校验接口密钥不会注入额外配置行。"""

        return _validate_wireguard_key(value, "WireGuard key")


class ManagedLinkCreate(BaseModel):
    """创建双端受管 WireGuard 连接请求。"""

    ipv4_link_pool_id: int | None = Field(default=None, ge=1)

    peer_node_id: int
    local_interface_name: str = Field(min_length=1, max_length=32)
    peer_interface_name: str | None = Field(default=None, min_length=1, max_length=32)
    local_tunnel_ips: list[str] = Field(min_length=1, max_length=128)
    peer_tunnel_ips: list[str] = Field(min_length=1, max_length=128)
    local_allowed_ips: list[str] | None = Field(default=None, max_length=256)
    peer_allowed_ips: list[str] | None = Field(default=None, max_length=256)
    local_endpoint_host: str | None = Field(default=None, max_length=255)
    local_endpoint_port: int | None = None
    peer_endpoint_host: str | None = Field(default=None, max_length=255)
    peer_endpoint_port: int | None = None
    local_listen_port: int | None = None
    peer_listen_port: int | None = None
    mtu: int | None = 1420
    table_name: str | None = "off"
    persistent_keepalive: int | None = 25
    local_interface_custom_config: str | None = Field(default=None, max_length=65536)
    local_peer_custom_config: str | None = Field(default=None, max_length=65536)
    peer_interface_custom_config: str | None = Field(default=None, max_length=65536)
    peer_peer_custom_config: str | None = Field(default=None, max_length=65536)
    replace_local_interface_id: int | None = None
    replace_peer_interface_id: int | None = None
    force_endpoint_mismatch: bool = False
    udp2raw: Udp2RawMiddlewareConfig | None = None
    mimic: MimicMiddlewareConfig | None = None

    @field_validator("local_interface_name", "peer_interface_name")
    @classmethod
    def validate_interface_names(cls, value: str | None) -> str | None:
        """校验受管 WireGuard 双端接口名。"""

        return _validate_linux_interface_name(value) if value is not None else None

    @field_validator("local_endpoint_host", "peer_endpoint_host")
    @classmethod
    def validate_endpoint_hosts(cls, value: str | None) -> str | None:
        """校验受管 WireGuard Endpoint 主机。"""

        return _validate_endpoint_host(value)

    @field_validator("local_endpoint_port", "peer_endpoint_port", "local_listen_port", "peer_listen_port")
    @classmethod
    def validate_listen_port(cls, value: int | None) -> int | None:
        """校验双方 Endpoint 和监听端口范围。"""

        return _validate_port(value)

    @field_validator("persistent_keepalive")
    @classmethod
    def validate_keepalive(cls, value: int | None) -> int | None:
        """校验 keepalive 范围。"""

        if value is not None and not 0 <= value <= 65535:
            raise ValueError("persistent_keepalive must be between 0 and 65535")
        return value

    @field_validator("local_tunnel_ips", "peer_tunnel_ips")
    @classmethod
    def validate_tunnel_ips(cls, values: list[str]) -> list[str]:
        """校验双方接口地址应包含 CIDR 前缀。"""

        return _validate_cidrs(values)

    @field_validator("local_allowed_ips", "peer_allowed_ips")
    @classmethod
    def validate_allowed_ips(cls, values: list[str] | None) -> list[str] | None:
        """校验双方 Peer AllowedIPs 应包含 CIDR 前缀。"""

        return _validate_cidrs(values or []) if values is not None else None


class InterfaceUpdate(BaseModel):
    """更新单个 WireGuard 接口请求。"""

    ipv4_link_pool_id: int | None = Field(default=None, ge=1)

    name: str = Field(min_length=1, max_length=32)
    tunnel_ips: list[str] = Field(default_factory=list, max_length=128)
    listen_port: int | None = None
    private_key: str | None = None
    clear_private_key: bool = False
    public_key: str | None = None
    mtu: int | None = 1420
    table_name: str | None = None
    dns: list[str] = Field(default_factory=list, max_length=64)
    interface_custom_config: str | None = Field(default=None, max_length=65536)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        """校验更新后的 WireGuard 接口名。"""

        return _validate_linux_interface_name(value)

    @field_validator("listen_port")
    @classmethod
    def validate_listen_port(cls, value: int | None) -> int | None:
        """校验监听端口范围。"""

        return _validate_port(value)

    @field_validator("tunnel_ips")
    @classmethod
    def validate_tunnel_ips(cls, values: list[str]) -> list[str]:
        """校验接口地址应包含 CIDR 前缀。"""

        return _validate_cidrs(values)

    @field_validator("private_key", "public_key")
    @classmethod
    def validate_keys(cls, value: str | None) -> str | None:
        """校验接口密钥不会注入额外配置行。"""

        return _validate_wireguard_key(value, "WireGuard key")


class LinkMonitorSummary(BaseModel):
    """链路监测统计摘要响应。"""

    monitor_id: int
    target_host: str
    last_latency_ms: float | None = None
    avg_latency_ms: float | None = None
    min_latency_ms: float | None = None
    max_latency_ms: float | None = None
    jitter_ms: float | None = None
    packet_loss: float
    stability_score: int
    status: str
    sample_count: int
    last_checked_at: datetime | None = None


class TopologyPositionUpdate(BaseModel):
    """更新拓扑节点位置请求。"""

    x: float | None = None
    y: float | None = None
    locked: bool | None = None


class TopologyNode(BaseModel):
    """拓扑图节点响应。"""

    id: int
    name: str
    status: str
    hostname: str | None = None
    region: str | None = None
    endpoint_ips: list[str] = Field(default_factory=list)
    topology_endpoint: str | None = None
    agent_version: str | None = None
    agent_platform: dict[str, Any] = Field(default_factory=dict)
    topology_x: float | None = None
    topology_y: float | None = None
    topology_locked: bool = False

    @field_validator("endpoint_ips", mode="before")
    @classmethod
    def normalize_legacy_endpoint_ips(cls, value: Any) -> list[str]:
        return _read_string_list(value)

    @field_validator("agent_platform", mode="before")
    @classmethod
    def normalize_legacy_platform(cls, value: Any) -> dict[str, Any]:
        return _read_object(value)


class TopologyEdge(BaseModel):
    """拓扑图链路响应。"""

    id: str
    connection_ref: str | None = None
    protocol_type: str = "wireguard"
    protocol_label: str = "WireGuard"
    local_node_id: int
    peer_node_id: int
    local_interface_id: int
    peer_interface_id: int
    local_interface_name: str
    peer_interface_name: str
    local_status: str
    peer_status: str
    middleware_type: str | None = None
    local_monitor: LinkMonitorSummary | None = None
    peer_monitor: LinkMonitorSummary | None = None


class TopologyRead(BaseModel):
    """拓扑图完整响应。"""

    nodes: list[TopologyNode]
    edges: list[TopologyEdge]


class LinkMonitorCreate(BaseModel):
    """创建链路监测目标请求。"""

    target_host: str = Field(min_length=1, max_length=255)
    name: str | None = Field(default=None, max_length=80)
    interval_seconds: int = 10
    retention_days: int = 7
    enabled: bool = True

    @field_validator("target_host")
    @classmethod
    def validate_target_host(cls, value: str) -> str:
        """校验监测目标必须是 IP 地址。"""

        cleaned = value.strip()
        try:
            ipaddress.ip_address(cleaned)
        except ValueError as exc:
            raise ValueError("monitor target must be an IPv4 or IPv6 address") from exc
        return cleaned

    @field_validator("interval_seconds")
    @classmethod
    def validate_interval(cls, value: int) -> int:
        """校验探测间隔范围。"""

        if not 1 <= value <= 300:
            raise ValueError("interval_seconds must be between 1 and 300")
        return value

    @field_validator("retention_days")
    @classmethod
    def validate_retention(cls, value: int) -> int:
        """校验监测样本保留天数范围。"""

        if not 1 <= value <= 90:
            raise ValueError("retention_days must be between 1 and 90")
        return value


class LinkMonitorUpdate(LinkMonitorCreate):
    """更新链路监测目标请求。"""

    pass


class LinkMonitorRead(BaseModel):
    """链路监测目标响应。"""

    id: int
    node_id: int
    interface_id: int | None
    connection_endpoint_id: int | None = None
    name: str
    target_host: str
    interval_seconds: int
    retention_days: int
    enabled: bool
    next_due_at: datetime | None
    last_checked_at: datetime | None
    summary: LinkMonitorSummary | None = None

    model_config = {"from_attributes": True}


class LinkMonitorSampleRead(BaseModel):
    """单条链路监测样本响应。"""

    checked_at: datetime
    success: bool
    latency_ms: float | None = None
    error: str | None = None

    model_config = {"from_attributes": True}


class LinkMonitorSamplesResponse(BaseModel):
    """链路监测目标和样本列表响应。"""

    monitor: LinkMonitorRead
    summary: LinkMonitorSummary | None
    samples: list[LinkMonitorSampleRead]


class AgentLinkMonitorRead(BaseModel):
    """Agent 轮询到的单个链路监测目标。"""

    id: int
    target_host: str
    timeout_seconds: float


class AgentLinkMonitorPollResponse(BaseModel):
    """Agent 轮询链路监测目标响应。"""

    monitors: list[AgentLinkMonitorRead]


class AgentLinkMonitorResultItem(BaseModel):
    """Agent 上报的单个链路监测结果。"""

    monitor_id: int
    checked_at: datetime | None = None
    success: bool
    latency_ms: float | None = None
    error: str | None = Field(default=None, max_length=500)

    @field_validator("latency_ms")
    @classmethod
    def validate_latency(cls, value: float | None) -> float | None:
        """拒绝 NaN/无穷值和异常大的延迟，避免污染统计结果。"""

        if value is not None and (not math.isfinite(value) or value < 0 or value > 3_600_000):
            raise ValueError("latency_ms must be a finite value between 0 and 3600000")
        return value

    @field_validator("error")
    @classmethod
    def validate_error(cls, value: str | None) -> str | None:
        """拒绝错误信息中的控制字符，避免日志注入。"""

        return _validate_display_text(value, "monitor error")


class AgentLinkMonitorResultRequest(BaseModel):
    """Agent 批量上报链路监测结果请求。"""

    node_id: int
    token: str
    results: list[AgentLinkMonitorResultItem] = Field(max_length=100)


class ConnectionProtocolRead(BaseModel):
    """前端可创建的连接协议描述。"""

    type: str
    label: str
    description: str
    managed: bool = True
    warnings: list[str] = Field(default_factory=list)


class ConnectionEndpointRead(BaseModel):
    """通用连接单端详情响应。"""

    id: int
    endpoint_ref: str
    node_id: int
    node_name: str | None = None
    role: str
    interface_name: str
    tunnel_ips: list[str] = Field(default_factory=list)
    mtu: int | None = None
    routes: list[str] = Field(default_factory=list)
    runtime_status: str
    protocol_config: dict[str, Any] = Field(default_factory=dict)
    last_error: str | None = None
    monitor_summary: LinkMonitorSummary | None = None

    @field_validator("tunnel_ips", "routes", mode="before")
    @classmethod
    def normalize_legacy_endpoint_lists(cls, value: Any) -> list[str]:
        return _read_string_list(value)

    @field_validator("protocol_config", mode="before")
    @classmethod
    def normalize_legacy_protocol_config(cls, value: Any) -> dict[str, Any]:
        return _read_object(value)


class ConnectionRead(BaseModel):
    """通用连接详情响应。"""

    id: int
    connection_ref: str
    protocol_type: str
    protocol_label: str
    name: str
    source: str
    managed: bool
    status: str
    endpoints: list[ConnectionEndpointRead]
    warnings: list[str] = Field(default_factory=list)


class GreManagedConnectionCreate(BaseModel):
    """创建受管 GRE 连接请求。"""

    ipv4_link_pool_id: int | None = Field(default=None, ge=1)

    protocol_type: str = "gre"
    peer_node_id: int
    local_interface_name: str = Field(min_length=1, max_length=15)
    peer_interface_name: str = Field(min_length=1, max_length=15)
    local_outer_ip: str
    peer_outer_ip: str
    local_bind_ip: str | None = None
    local_remote_ip: str | None = None
    peer_bind_ip: str | None = None
    peer_remote_ip: str | None = None
    local_tunnel_ips: list[str] = Field(min_length=1, max_length=128)
    peer_tunnel_ips: list[str] = Field(min_length=1, max_length=128)
    local_routes: list[str] = Field(default_factory=list, max_length=256)
    peer_routes: list[str] = Field(default_factory=list, max_length=256)
    mtu: int | None = None
    gre_key: str | None = None
    ttl: int | None = None
    pmtudisc: bool = True
    encaplimit: int | None = None
    risk_accepted: bool = False

    @field_validator("protocol_type")
    @classmethod
    def validate_protocol_type(cls, value: str) -> str:
        """校验当前通用创建接口只接受 GRE 新协议。"""

        if value != "gre":
            raise ValueError("protocol_type must be gre")
        return value

    @field_validator("local_interface_name", "peer_interface_name")
    @classmethod
    def validate_interface_name(cls, value: str) -> str:
        """校验 GRE 接口名符合 OpenWrt 和 Linux 双端限制。"""

        return _validate_gre_interface_name(value)

    @field_validator("local_outer_ip", "peer_outer_ip")
    @classmethod
    def validate_outer_ip(cls, value: str) -> str:
        """校验 GRE 外层地址为 IPv4 或 IPv6 字面量。"""

        return _validate_gre_outer_address(value)

    @field_validator("local_bind_ip", "local_remote_ip", "peer_bind_ip", "peer_remote_ip")
    @classmethod
    def validate_optional_outer_ip(cls, value: str | None) -> str | None:
        """校验 GRE 高级外层映射地址，并支持 IPv6 链路本地 zone。"""

        if value is None or not value.strip():
            return None
        return _validate_gre_outer_address(value)

    @field_validator("local_tunnel_ips", "peer_tunnel_ips", "local_routes", "peer_routes")
    @classmethod
    def validate_cidr_fields(cls, values: list[str]) -> list[str]:
        """校验 GRE 隧道地址和路由为合法 IPv4/IPv6 CIDR。"""

        return _validate_cidrs(values)

    @field_validator("mtu")
    @classmethod
    def validate_mtu(cls, value: int | None) -> int | None:
        """校验 GRE MTU 范围。"""

        if value is not None and not 576 <= value <= 9000:
            raise ValueError("MTU must be between 576 and 9000")
        return value

    @field_validator("gre_key")
    @classmethod
    def validate_gre_key(cls, value: str | None) -> str | None:
        """校验 GRE Key 范围。"""

        return _validate_gre_key(value)

    @field_validator("ttl")
    @classmethod
    def validate_ttl(cls, value: int | None) -> int | None:
        """校验 GRE TTL 范围。"""

        if value is not None and not 1 <= value <= 255:
            raise ValueError("TTL must be between 1 and 255")
        return value

    @field_validator("encaplimit")
    @classmethod
    def validate_encaplimit(cls, value: int | None) -> int | None:
        """校验 IP6GRE 封装限制范围，空值表示显式禁用限制。"""

        if value is not None and not 0 <= value <= 255:
            raise ValueError("encaplimit must be between 0 and 255")
        return value


class GreManagedConnectionUpdate(BaseModel):
    """更新受管 GRE 连接请求。"""

    ipv4_link_pool_id: int | None = Field(default=None, ge=1)

    local_interface_name: str = Field(min_length=1, max_length=15)
    peer_interface_name: str = Field(min_length=1, max_length=15)
    local_outer_ip: str
    peer_outer_ip: str
    local_bind_ip: str | None = None
    local_remote_ip: str | None = None
    peer_bind_ip: str | None = None
    peer_remote_ip: str | None = None
    local_tunnel_ips: list[str] = Field(min_length=1, max_length=128)
    peer_tunnel_ips: list[str] = Field(min_length=1, max_length=128)
    local_routes: list[str] = Field(default_factory=list, max_length=256)
    peer_routes: list[str] = Field(default_factory=list, max_length=256)
    mtu: int | None = None
    gre_key: str | None = None
    ttl: int | None = None
    pmtudisc: bool = True
    encaplimit: int | None = None
    risk_accepted: bool = False

    @field_validator("local_interface_name", "peer_interface_name")
    @classmethod
    def validate_interface_name(cls, value: str) -> str:
        """校验 GRE 接口名符合 OpenWrt 和 Linux 双端限制。"""

        return _validate_gre_interface_name(value)

    @field_validator("local_outer_ip", "peer_outer_ip")
    @classmethod
    def validate_outer_ip(cls, value: str) -> str:
        """校验 GRE 外层地址为 IPv4 或 IPv6 字面量。"""

        return _validate_gre_outer_address(value)

    @field_validator("local_bind_ip", "local_remote_ip", "peer_bind_ip", "peer_remote_ip")
    @classmethod
    def validate_optional_outer_ip(cls, value: str | None) -> str | None:
        """校验 GRE 高级外层映射地址，并支持 IPv6 链路本地 zone。"""

        if value is None or not value.strip():
            return None
        return _validate_gre_outer_address(value)

    @field_validator("local_tunnel_ips", "peer_tunnel_ips", "local_routes", "peer_routes")
    @classmethod
    def validate_cidr_fields(cls, values: list[str]) -> list[str]:
        """校验 GRE 隧道地址和路由为合法 IPv4/IPv6 CIDR。"""

        return _validate_cidrs(values)

    @field_validator("mtu")
    @classmethod
    def validate_mtu(cls, value: int | None) -> int | None:
        """校验 GRE MTU 范围。"""

        if value is not None and not 576 <= value <= 9000:
            raise ValueError("MTU must be between 576 and 9000")
        return value

    @field_validator("gre_key")
    @classmethod
    def validate_gre_key(cls, value: str | None) -> str | None:
        """校验 GRE Key 范围。"""

        return _validate_gre_key(value)

    @field_validator("ttl")
    @classmethod
    def validate_ttl(cls, value: int | None) -> int | None:
        """校验 GRE TTL 范围。"""

        if value is not None and not 1 <= value <= 255:
            raise ValueError("TTL must be between 1 and 255")
        return value

    @field_validator("encaplimit")
    @classmethod
    def validate_encaplimit(cls, value: int | None) -> int | None:
        """校验 IP6GRE 封装限制范围，空值表示显式禁用限制。"""

        if value is not None and not 0 <= value <= 255:
            raise ValueError("encaplimit must be between 0 and 255")
        return value


class GreManualConnectionCreate(BaseModel):
    """创建仅管理当前节点一端的 GRE 连接请求。"""

    ipv4_link_pool_id: int | None = Field(default=None, ge=1)

    protocol_type: str = "gre"
    interface_name: str = Field(min_length=1, max_length=15)
    peer_interface_name: str | None = Field(default=None, max_length=15)
    outer_local_ip: str
    outer_remote_ip: str
    tunnel_ips: list[str] = Field(min_length=1, max_length=128)
    peer_tunnel_ips: list[str] = Field(default_factory=list, max_length=128)
    routes: list[str] = Field(default_factory=list, max_length=256)
    mtu: int | None = None
    gre_key: str | None = None
    ttl: int | None = None
    pmtudisc: bool = True
    encaplimit: int | None = None
    risk_accepted: bool = False

    @field_validator("protocol_type")
    @classmethod
    def validate_protocol_type(cls, value: str) -> str:
        """校验手动连接接口当前只接受 GRE。"""

        if value != "gre":
            raise ValueError("protocol_type must be gre")
        return value

    @field_validator("interface_name")
    @classmethod
    def validate_interface_name(cls, value: str) -> str:
        """校验 GRE 接口名符合 OpenWrt 和 Linux 限制。"""

        return _validate_gre_interface_name(value)

    @field_validator("peer_interface_name")
    @classmethod
    def validate_peer_interface_name(cls, value: str | None) -> str | None:
        """校验可选的外部对端 GRE 接口名。"""

        if value is None or not value.strip():
            return None
        return _validate_gre_interface_name(value.strip())

    @field_validator("outer_local_ip", "outer_remote_ip")
    @classmethod
    def validate_outer_ip(cls, value: str) -> str:
        """校验 GRE 外层地址为 IPv4 或 IPv6 字面量。"""

        return _validate_gre_outer_address(value)

    @field_validator("tunnel_ips", "peer_tunnel_ips", "routes")
    @classmethod
    def validate_cidr_fields(cls, values: list[str]) -> list[str]:
        """校验 GRE 隧道地址和路由为合法 CIDR。"""

        return _validate_cidrs(values)

    @field_validator("mtu")
    @classmethod
    def validate_mtu(cls, value: int | None) -> int | None:
        """校验 GRE MTU 范围。"""

        if value is not None and not 576 <= value <= 9000:
            raise ValueError("MTU must be between 576 and 9000")
        return value

    @field_validator("gre_key")
    @classmethod
    def validate_gre_key(cls, value: str | None) -> str | None:
        """校验 GRE Key 范围。"""

        return _validate_gre_key(value)

    @field_validator("ttl")
    @classmethod
    def validate_ttl(cls, value: int | None) -> int | None:
        """校验 GRE TTL 范围。"""

        if value is not None and not 1 <= value <= 255:
            raise ValueError("TTL must be between 1 and 255")
        return value

    @field_validator("encaplimit")
    @classmethod
    def validate_encaplimit(cls, value: int | None) -> int | None:
        """校验 IP6GRE 封装限制范围，空值表示显式禁用限制。"""

        if value is not None and not 0 <= value <= 255:
            raise ValueError("encaplimit must be between 0 and 255")
        return value


class GreManualConnectionUpdate(GreManualConnectionCreate):
    """更新仅管理当前节点一端的 GRE 连接请求。"""

    protocol_type: str = "gre"


class InterfaceRead(BaseModel):
    """WireGuard 接口详情响应。"""

    id: int
    node_id: int
    name: str
    tunnel_ips: list[str]
    listen_port: int | None
    has_private_key: bool = False
    public_key: str | None
    mtu: int | None
    table_name: str | None
    dns: list[str]
    interface_custom_config: str | None = None
    source: str
    managed: bool
    enabled: bool
    runtime_status: str
    import_path: str | None
    primary_peer_endpoint_host: str | None = None
    primary_peer_endpoint_port: int | None = None
    primary_peer_allowed_ips: list[str] = Field(default_factory=list)
    monitor_summary: LinkMonitorSummary | None = None
    warnings: list[str]

    model_config = {"from_attributes": True}

    @field_validator("tunnel_ips", "dns", "primary_peer_allowed_ips", "warnings", mode="before")
    @classmethod
    def normalize_legacy_interface_lists(cls, value: Any) -> list[str]:
        return _read_string_list(value)


class PeerCreate(BaseModel):
    """创建 WireGuard Peer 请求。"""

    name: str | None = None
    public_key: str = Field(min_length=1)
    preshared_key: str | None = None
    clear_preshared_key: bool = False
    endpoint_host: str | None = None
    endpoint_port: int | None = None
    allowed_ips: list[str] = Field(default_factory=list, max_length=256)
    persistent_keepalive: int | None = None
    peer_custom_config: str | None = Field(default=None, max_length=65536)

    @field_validator("endpoint_port")
    @classmethod
    def validate_endpoint_port(cls, value: int | None) -> int | None:
        """校验 Endpoint 端口范围。"""

        return _validate_port(value)

    @field_validator("public_key", "preshared_key")
    @classmethod
    def validate_keys(cls, value: str | None) -> str | None:
        """校验 Peer 密钥不会注入额外配置行。"""

        return _validate_wireguard_key(value, "WireGuard key")

    @field_validator("endpoint_host")
    @classmethod
    def validate_endpoint_host(cls, value: str | None) -> str | None:
        """校验 WireGuard Endpoint 主机。"""

        return _validate_endpoint_host(value)

    @field_validator("persistent_keepalive")
    @classmethod
    def validate_keepalive(cls, value: int | None) -> int | None:
        """校验 keepalive 范围。"""

        if value is not None and not 0 <= value <= 65535:
            raise ValueError("persistent_keepalive must be between 0 and 65535")
        return value

    @field_validator("allowed_ips")
    @classmethod
    def validate_allowed_ips(cls, values: list[str]) -> list[str]:
        """校验 AllowedIPs 应包含 CIDR 前缀。"""

        return _validate_cidrs(values)


class PeerRead(BaseModel):
    """WireGuard Peer 详情响应。"""

    id: int
    interface_id: int
    peer_node_id: int | None
    peer_interface_id: int | None
    name: str | None
    public_key: str
    has_preshared_key: bool = False
    endpoint_host: str | None
    endpoint_port: int | None
    allowed_ips: list[str]
    persistent_keepalive: int | None
    source: str
    enabled: bool
    peer_custom_config: str | None = None
    warnings: list[str]

    model_config = {"from_attributes": True}

    @field_validator("allowed_ips", "warnings", mode="before")
    @classmethod
    def normalize_legacy_peer_lists(cls, value: Any) -> list[str]:
        return _read_string_list(value)


class Udp2RawMiddlewareConfig(BaseModel):
    """udp2raw 中间层配置。"""

    enabled: bool = False
    server_side: str = "peer"
    server_listen_host: str = "0.0.0.0"
    server_connect_host: str | None = None
    server_listen_port: int | None = None
    server_forward_host: str | None = None
    server_forward_port: int | None = None
    client_listen_host: str = "127.0.0.1"
    client_listen_port: int | None = None
    raw_mode: str = "faketcp"
    cipher_mode: str = "xor"
    auth_mode: str = "md5"
    password: str | None = None
    auto_rule: bool = True

    @field_validator("server_side")
    @classmethod
    def validate_server_side(cls, value: str) -> str:
        """校验 udp2raw server 所在端。"""

        if value not in ["local", "peer"]:
            raise ValueError("server_side must be local or peer")
        return value

    @field_validator("server_listen_port", "server_forward_port", "client_listen_port")
    @classmethod
    def validate_udp2raw_ports(cls, value: int | None) -> int | None:
        """校验 udp2raw 相关端口范围。"""

        return _validate_port(value)

    @field_validator("server_listen_host", "server_connect_host", "server_forward_host", "client_listen_host")
    @classmethod
    def validate_udp2raw_ip(cls, value: str | None) -> str | None:
        """校验 udp2raw 地址字段必须是 IP 字面量。"""

        if value is None or not value.strip():
            return value
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise ValueError("udp2raw ip fields must be IPv4 or IPv6 addresses, not domain names") from exc
        scope_id = getattr(address, "scope_id", None)
        if scope_id is not None:
            _validate_linux_interface_name(scope_id)
        return value.strip()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str | None) -> str | None:
        """udp2raw 实例配置按行读取，口令不能插入控制字符。"""

        if value is not None and any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("udp2raw password must not contain control characters")
        return value

    @field_validator("raw_mode")
    @classmethod
    def validate_raw_mode(cls, value: str) -> str:
        """校验 udp2raw raw-mode。"""

        if value not in ["faketcp", "udp", "icmp"]:
            raise ValueError("raw_mode must be faketcp, udp, or icmp")
        return value

    @field_validator("cipher_mode")
    @classmethod
    def validate_cipher_mode(cls, value: str) -> str:
        """校验 udp2raw cipher-mode。"""

        if value not in ["xor", "aes128cbc", "none"]:
            raise ValueError("cipher_mode must be xor, aes128cbc, or none")
        return value

    @field_validator("auth_mode")
    @classmethod
    def validate_auth_mode(cls, value: str) -> str:
        """校验 udp2raw auth-mode。"""

        if value not in ["hmac_sha1", "md5", "crc32", "simple", "none"]:
            raise ValueError("auth_mode must be hmac_sha1, md5, crc32, simple, or none")
        return value


class MimicMiddlewareConfig(BaseModel):
    """mimic 中间层配置。"""

    enabled: bool = False
    local_bind_interface: str | None = None
    peer_bind_interface: str | None = None
    xdp_mode: str = "skb"
    link_type: str = "eth"
    handshake_interval: int | None = None
    keepalive_interval: int | None = None
    padding: int | None = None

    @field_validator("local_bind_interface", "peer_bind_interface")
    @classmethod
    def validate_interface_name(cls, value: str | None) -> str | None:
        """校验 mimic 绑定接口名。"""

        if value is None or not value.strip():
            return value
        value = value.strip()
        return _validate_linux_interface_name(value)

    @field_validator("xdp_mode")
    @classmethod
    def validate_xdp_mode(cls, value: str) -> str:
        """校验 mimic XDP 模式。"""

        if value not in ["auto", "native", "skb"]:
            raise ValueError("xdp_mode must be auto, native, or skb")
        return value

    @field_validator("handshake_interval", "keepalive_interval")
    @classmethod
    def validate_optional_non_negative(cls, value: int | None) -> int | None:
        """校验 mimic 可选时间参数不能为负数。"""

        if value is not None and value < 0:
            raise ValueError("mimic numeric options must be non-negative")
        return value

    @field_validator("padding")
    @classmethod
    def validate_padding(cls, value: int | None) -> int | None:
        """校验 mimic padding 范围。"""

        if value is not None and not 0 <= value <= 16:
            raise ValueError("mimic padding must be between 0 and 16")
        return value


class ManagedLinkCreateResult(BaseModel):
    """创建受管连接响应。"""

    local_interface: InterfaceRead
    peer_interface: InterfaceRead

    model_config = {"from_attributes": True}


class ManagedLinkRead(BaseModel):
    """受管连接详情响应。"""

    local_interface: InterfaceRead
    peer_interface: InterfaceRead
    local_peer: PeerRead
    peer_peer: PeerRead
    middleware: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class ManagedLinkUpdate(BaseModel):
    """更新双端受管 WireGuard 连接请求。"""

    ipv4_link_pool_id: int | None = Field(default=None, ge=1)

    local_interface_name: str = Field(min_length=1, max_length=32)
    peer_interface_name: str = Field(min_length=1, max_length=32)
    local_tunnel_ips: list[str] = Field(min_length=1, max_length=128)
    peer_tunnel_ips: list[str] = Field(min_length=1, max_length=128)
    local_allowed_ips: list[str] | None = Field(default=None, max_length=256)
    peer_allowed_ips: list[str] | None = Field(default=None, max_length=256)
    local_endpoint_host: str | None = Field(default=None, max_length=255)
    local_endpoint_port: int | None = None
    peer_endpoint_host: str | None = Field(default=None, max_length=255)
    peer_endpoint_port: int | None = None
    local_listen_port: int | None = None
    peer_listen_port: int | None = None
    mtu: int | None = 1420
    table_name: str | None = None
    persistent_keepalive: int | None = 25
    local_interface_custom_config: str | None = Field(default=None, max_length=65536)
    local_peer_custom_config: str | None = Field(default=None, max_length=65536)
    peer_interface_custom_config: str | None = Field(default=None, max_length=65536)
    peer_peer_custom_config: str | None = Field(default=None, max_length=65536)
    udp2raw: Udp2RawMiddlewareConfig | None = None
    mimic: MimicMiddlewareConfig | None = None

    @field_validator("local_interface_name", "peer_interface_name")
    @classmethod
    def validate_interface_names(cls, value: str) -> str:
        """校验受管 WireGuard 改名请求。"""

        return _validate_linux_interface_name(value)

    @field_validator("local_endpoint_host", "peer_endpoint_host")
    @classmethod
    def validate_endpoint_hosts(cls, value: str | None) -> str | None:
        """校验受管连接更新的 Endpoint 主机。"""

        return _validate_endpoint_host(value)

    @field_validator("local_endpoint_port", "peer_endpoint_port", "local_listen_port", "peer_listen_port")
    @classmethod
    def validate_listen_port(cls, value: int | None) -> int | None:
        """校验双方 Endpoint 和监听端口范围。"""

        return _validate_port(value)

    @field_validator("persistent_keepalive")
    @classmethod
    def validate_keepalive(cls, value: int | None) -> int | None:
        """校验 keepalive 范围。"""

        if value is not None and not 0 <= value <= 65535:
            raise ValueError("persistent_keepalive must be between 0 and 65535")
        return value

    @field_validator("local_tunnel_ips", "peer_tunnel_ips")
    @classmethod
    def validate_tunnel_ips(cls, values: list[str]) -> list[str]:
        """校验双方接口地址应包含 CIDR 前缀。"""

        return _validate_cidrs(values)

    @field_validator("local_allowed_ips", "peer_allowed_ips")
    @classmethod
    def validate_allowed_ips(cls, values: list[str] | None) -> list[str] | None:
        """校验双方 Peer AllowedIPs 应包含 CIDR 前缀。"""

        return _validate_cidrs(values or []) if values is not None else None


class ImportCandidateRead(BaseModel):
    """Agent 扫描出的可导入 wg-quick 配置响应。"""

    id: int
    node_id: int
    path: str
    interface_name: str
    warnings: list[str]
    imported: bool

    model_config = {"from_attributes": True}

    @field_validator("warnings", mode="before")
    @classmethod
    def normalize_legacy_warnings(cls, value: Any) -> list[str]:
        return _read_string_list(value)


class ImportRequest(BaseModel):
    """导入候选 WireGuard 配置请求。"""

    candidate_id: int


class ChangePlanRead(BaseModel):
    """部署变更计划响应。"""

    id: int
    title: str
    status: str
    summary: str
    affected_node_ids: list[int]
    diff: str
    confirmed_at: datetime | None
    task_status: str | None = None
    task_result: dict[str, Any] | None = None

    model_config = {"from_attributes": True}

    @field_validator("affected_node_ids", mode="before")
    @classmethod
    def normalize_legacy_node_ids(cls, value: Any) -> list[int]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, int) and not isinstance(item, bool)]

    @field_validator("task_result", mode="before")
    @classmethod
    def normalize_legacy_task_result(cls, value: Any) -> dict[str, Any] | None:
        return _read_object(value) if value is not None else None

    @field_validator("diff", mode="before")
    @classmethod
    def redact_diff_secrets(cls, value: object) -> str:
        """隐藏部署 diff 中的 WireGuard 私钥和预共享密钥正文。"""

        text = str(redact_wireguard_response_secrets(str(value or "")))
        return re.sub(
            r'(?i)("(?:private_key|preshared_key)"\s*:\s*")[^"]*(")',
            r"\1<REDACTED>\2",
            text,
        )

    @field_validator("task_result", mode="before")
    @classmethod
    def redact_task_result_secrets(cls, value: Any) -> Any:
        """隐藏部署任务结果中回显的 WireGuard 密钥。"""

        return redact_wireguard_response_secrets(value)


class TaskRequestResult(BaseModel):
    """创建或复用任务后的统一响应。"""

    task_id: int | None
    status: str
    message: str
    result: dict[str, Any] | None = None

    @field_validator("result", mode="before")
    @classmethod
    def redact_result_secrets(cls, value: Any) -> Any:
        """隐藏复用任务响应里可能回显的 WireGuard 密钥。"""

        normalized = _read_object(value) if value is not None else None
        return redact_wireguard_response_secrets(normalized)


class NodePluginActionRead(BaseModel):
    """节点插件 action 元数据响应。"""

    name: str
    task_type: str
    risk: str = "read"
    requires_confirm: bool = False


class NodePluginRead(BaseModel):
    """节点插件元数据响应。"""

    type: str
    display_name: str
    description: str
    min_agent_version: str
    capabilities: list[str]
    actions: list[NodePluginActionRead]


class NodePluginStatusRead(NodePluginRead):
    """指定节点上的插件可用性响应。"""

    available: bool
    missing_capabilities: list[str] = Field(default_factory=list)
    agent_version: str | None = None
    version_supported: bool = False
    node_status: str


class NodePluginActionRequest(BaseModel):
    """触发节点插件 action 请求。"""

    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        """在任务入队前限制插件 payload 的结构和总大小。"""

        _validate_plugin_payload(value)
        return value


class NodePluginActionResult(BaseModel):
    """触发节点插件 action 后返回的任务信息。"""

    task_id: int
    plugin_type: str
    action: str
    status: str
    message: str


class AgentReleaseAsset(BaseModel):
    """单个 Agent 发布资产描述。"""

    path: str = Field(min_length=1, max_length=512)
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    size: int | None = Field(default=None, ge=0, le=512 * 1024 * 1024)
    install_mode: Literal["binary", "source"] = "binary"

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        """发布资产只能是 release 根目录下的相对普通路径。"""

        cleaned = value.strip()
        if (
            not cleaned
            or "\\" in cleaned
            or cleaned.startswith("/")
            or cleaned.startswith("~")
            or any(part in {"", ".", ".."} for part in cleaned.split("/"))
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in cleaned)
        ):
            raise ValueError("agent release asset path must be a relative safe path")
        return cleaned


class AgentReleaseInfo(BaseModel):
    """单个 Agent 版本的发布信息。"""

    released_at: str | None = None
    protocol_version: int | None = None
    notes: str | None = None
    assets: dict[str, AgentReleaseAsset] = Field(default_factory=dict)


class AgentReleaseManifest(BaseModel):
    """Agent 发布清单。"""

    latest: str | None = None
    minimum_supported: str | None = None
    releases: dict[str, AgentReleaseInfo] = Field(default_factory=dict)


class AgentUpgradePlan(BaseModel):
    """节点 Agent 升级计划响应。"""

    node_id: int
    current_version: str | None
    target_version: str | None
    upgrade_mode: str
    reason: str | None = None
    matched_platform: str | None = None
    matched_asset: AgentReleaseAsset | None = None
    manual_command: str | None = None
    status: str | None = None


class AgentUpgradeRequest(BaseModel):
    """触发 Agent 升级请求。"""

    target_version: str | None = None
    force: bool = False


class IntegrationApiTokenCreate(BaseModel):
    """创建第三方 Looking Glass API Token 请求。"""

    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def normalize_expiry(cls, value: datetime | None) -> datetime | None:
        return normalize_database_datetime(value)

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, values: list[str]) -> list[str]:
        """校验第三方 Token 权限范围只包含 Looking Glass 允许项。"""

        allowed = {"looking_glass.nodes.read", "looking_glass.bird.route"}
        cleaned = sorted({value.strip() for value in values if value.strip()})
        invalid = [value for value in cleaned if value not in allowed]
        if invalid:
            raise ValueError(f"unsupported scopes: {', '.join(invalid)}")
        if not cleaned:
            raise ValueError("at least one scope is required")
        return cleaned

class IntegrationApiTokenUpdate(BaseModel):
    """更新第三方 Looking Glass API Token 元数据请求。"""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    scopes: list[str] | None = None
    enabled: bool | None = None
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def normalize_expiry(cls, value: datetime | None) -> datetime | None:
        return normalize_database_datetime(value)

    @field_validator("scopes")
    @classmethod
    def validate_optional_scopes(cls, values: list[str] | None) -> list[str] | None:
        """校验可选权限范围，未传时不修改。"""

        if values is None:
            return None
        return IntegrationApiTokenCreate.validate_scopes(values)

class IntegrationApiTokenRead(BaseModel):
    """第三方 Looking Glass API Token 元数据响应，不包含明文 Token。"""

    id: int
    name: str
    token_prefix: str
    token_hint: str
    scopes: list[str]
    enabled: bool
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    last_used_ip: str | None = None
    created_at: datetime
    updated_at: datetime
    revoked_at: datetime | None = None

    model_config = {"from_attributes": True}


class IntegrationApiTokenCreateResult(IntegrationApiTokenRead):
    """创建或轮换 Token 响应，只有本响应包含明文 Token。"""

    token: str


class IntegrationApiTokenList(BaseModel):
    """第三方 Looking Glass API Token 列表响应。"""

    items: list[IntegrationApiTokenRead]


class LookingGlassNodeIps(BaseModel):
    """Looking Glass 节点 IP 信息响应。"""

    management_ip: str | None = None
    public_ip: str | None = None
    endpoint_ips: list[str] = Field(default_factory=list)


class LookingGlassNodeCapabilities(BaseModel):
    """Looking Glass 节点能力响应。"""

    bird: bool = False
    bird_route_lookup: bool = False
    bird_routes_by_origin_as: bool = False
    bird_protocols: bool = False
    ping: bool = False
    traceroute: bool = False


class LookingGlassNodeRead(BaseModel):
    """Looking Glass 节点信息响应。"""

    node_ref: str
    name: str
    region: str | None = None
    online: bool
    last_seen_at: datetime | None = None
    ips: LookingGlassNodeIps
    capabilities: LookingGlassNodeCapabilities

    @field_serializer("last_seen_at")
    def serialize_last_seen_at(self, value: datetime | None) -> int | None:
        """让第三方节点接口返回时间戳，避免调用方解析时区。"""

        return serialize_utc_timestamp(value)


class LookingGlassNodeList(BaseModel):
    """Looking Glass 节点列表响应。"""

    items: list[LookingGlassNodeRead]
    next_cursor: str | None = None


class LookingGlassRouteLookupRequest(BaseModel):
    """Looking Glass BIRD 路由查询请求。"""

    ip: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        """校验查询目标必须是 IPv4 或 IPv6 字面量。"""

        cleaned = value.strip()
        try:
            return str(ipaddress.ip_address(cleaned))
        except ValueError as exc:
            raise ValueError("ip must be a valid IPv4 or IPv6 address") from exc


class LookingGlassRoutesByOriginAsRequest(BaseModel):
    """Looking Glass BIRD ASN 路由查询请求。"""

    asn: int

    @field_validator("asn", mode="before")
    @classmethod
    def validate_asn(cls, value: int | str) -> int:
        """校验 ASN 必须是 1 到 4294967295 的整数。"""

        return normalize_bgp_asn(value)


class LookingGlassProtocolDetailRequest(BaseModel):
    """Looking Glass BIRD 协议详情查询请求。"""

    protocol_name: str

    @field_validator("protocol_name")
    @classmethod
    def validate_protocol_name(cls, value: str) -> str:
        """校验 BIRD 协议名不能包含空白、shell 控制符或超长内容。"""

        return normalize_bird_protocol_name(value)


class LookingGlassPingRequest(BaseModel):
    """Looking Glass ping 查询请求。"""

    target: str
    count: int = Field(default=4, ge=1, le=10)
    per_probe_timeout_seconds: int = Field(default=2, ge=1, le=10)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        """校验 ping 目标必须是 IP 或普通域名。"""

        return normalize_looking_glass_target(value)


class LookingGlassTracerouteRequest(BaseModel):
    """Looking Glass traceroute 查询请求。"""

    target: str
    max_hops: int = Field(default=30, ge=1, le=64)
    wait_seconds: int = Field(default=3, ge=1, le=10)
    queries: int = Field(default=3, ge=1, le=5)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        """校验 traceroute 目标必须是 IP 或普通域名。"""

        return normalize_looking_glass_target(value)


class LookingGlassQueryError(BaseModel):
    """Looking Glass 查询错误响应体。"""

    code: str
    message: str


class LookingGlassQueryRead(BaseModel):
    """Looking Glass 查询状态和结果响应。"""

    query_id: str
    status: str
    node_ref: str
    operation: str
    request: dict[str, Any]
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    deadline_at: datetime | None = None
    expires_at: datetime | None = None
    result: dict[str, Any] | None = None
    error: LookingGlassQueryError | None = None

    @field_validator("request", mode="before")
    @classmethod
    def normalize_legacy_request(cls, value: Any) -> dict[str, Any]:
        """旧库中的非对象请求统一为空对象，避免响应序列化失败。"""

        return _read_object(value)

    @field_validator("result", mode="before")
    @classmethod
    def normalize_legacy_result(cls, value: Any) -> dict[str, Any] | None:
        """旧库中的非对象结果统一为空对象。"""

        return _read_object(value) if value is not None else None

    @field_serializer("created_at", "started_at", "finished_at", "deadline_at", "expires_at")
    def serialize_query_datetime(self, value: datetime | None) -> int | None:
        """让第三方查询接口返回时间戳，避免调用方解析时区。"""

        return serialize_utc_timestamp(value)


class AgentTaskStatusRead(BaseModel):
    """Agent 任务状态响应。"""

    id: int
    node_id: int
    type: str
    status: str
    result: dict[str, Any] | None

    model_config = {"from_attributes": True}

    @field_validator("result", mode="before")
    @classmethod
    def redact_result_secrets(cls, value: Any) -> Any:
        """隐藏任务状态响应中的 WireGuard 密钥，同时保留业务输出结构。"""

        normalized = _read_object(value) if value is not None else None
        return redact_wireguard_response_secrets(normalized)


class AgentRegisterRequest(BaseModel):
    """Agent 注册请求。"""

    node_id: int
    token: str
    hostname: str | None = Field(default=None, max_length=255)
    management_ip: str | None = Field(default=None, max_length=64)
    public_ip: str | None = Field(default=None, max_length=64)
    agent_version: str | None = Field(default=None, max_length=32)
    protocol_version: int | None = None
    capabilities: list[str] = Field(default_factory=list, max_length=128)
    platform: dict[str, Any] = Field(default_factory=dict, max_length=256)

    @field_validator("hostname", "management_ip", "public_ip", "agent_version")
    @classmethod
    def validate_metadata_text(cls, value: str | None) -> str | None:
        return _validate_display_text(value, "agent metadata")

    @field_validator("capabilities")
    @classmethod
    def validate_capability_values(cls, value: list[str]) -> list[str]:
        return _validate_capabilities(value)

    @field_validator("platform")
    @classmethod
    def validate_platform_values(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_metadata_json(value)


class AgentHeartbeatRequest(BaseModel):
    """Agent 心跳请求。"""

    node_id: int
    token: str
    agent_version: str | None = Field(default=None, max_length=32)
    protocol_version: int | None = None
    capabilities: list[str] = Field(default_factory=list, max_length=128)
    platform: dict[str, Any] = Field(default_factory=dict, max_length=256)

    @field_validator("agent_version")
    @classmethod
    def validate_metadata_text(cls, value: str | None) -> str | None:
        return _validate_display_text(value, "agent metadata")

    @field_validator("capabilities")
    @classmethod
    def validate_capability_values(cls, value: list[str]) -> list[str]:
        return _validate_capabilities(value)

    @field_validator("platform")
    @classmethod
    def validate_platform_values(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_metadata_json(value)


class AgentPollRequest(BaseModel):
    """Agent 轮询任务请求。"""

    node_id: int
    token: str
    agent_version: str | None = Field(default=None, max_length=32)
    protocol_version: int | None = None
    capabilities: list[str] = Field(default_factory=list, max_length=128)
    platform: dict[str, Any] = Field(default_factory=dict, max_length=256)

    @field_validator("agent_version")
    @classmethod
    def validate_metadata_text(cls, value: str | None) -> str | None:
        return _validate_display_text(value, "agent metadata")

    @field_validator("capabilities")
    @classmethod
    def validate_capability_values(cls, value: list[str]) -> list[str]:
        return _validate_capabilities(value)

    @field_validator("platform")
    @classmethod
    def validate_platform_values(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_metadata_json(value)


class AgentTaskRead(BaseModel):
    """Agent 可执行任务响应。"""

    id: int
    type: str
    payload: dict[str, Any]


class AgentPollResponse(BaseModel):
    """Agent 轮询任务响应。"""

    tasks: list[AgentTaskRead]


class AgentTaskResultRequest(BaseModel):
    """Agent 上报任务结果请求。"""

    node_id: int
    token: str
    status: Literal["succeeded", "failed", "cancelled"]
    result: dict[str, Any] = Field(default_factory=dict)
