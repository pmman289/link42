from __future__ import annotations

from datetime import datetime
import ipaddress
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


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


def _validate_optional_ipv4_address(value: str | None) -> str | None:
    """校验可选字段必须是 IPv4 字面量地址，空字符串归一为空。"""

    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return _validate_ipv4_address(cleaned)


def _validate_linux_interface_name(value: str) -> str:
    """校验 Linux 接口名，避免超过内核限制或包含危险字符。"""

    cleaned = value.strip()
    if not cleaned:
        raise ValueError("interface name is required")
    if len(cleaned) > 15:
        raise ValueError("interface name must be 15 characters or fewer")
    if not all(char.isalnum() or char in "_.-" for char in cleaned):
        raise ValueError("interface name contains unsupported characters")
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
    if any(char.isspace() or char in "'\"" for char in value):
        raise ValueError("URL must not contain whitespace or quotes")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must start with http:// or https://")
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
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must be an absolute path or start with http:// or https://")
    return value


class NodeCreate(BaseModel):
    """创建节点请求。"""

    name: str = Field(min_length=1, max_length=80)
    hostname: str | None = None
    region: str | None = Field(default=None, max_length=80)
    management_ip: str | None = None
    public_ip: str | None = None
    endpoint_ips: list[str] = Field(min_length=1)
    topology_endpoint: str | None = Field(default=None, max_length=255)
    github_proxy_url: str | None = Field(default=None, max_length=500)

    @field_validator("github_proxy_url")
    @classmethod
    def validate_github_proxy_url(cls, value: str | None) -> str | None:
        """校验节点 GitHub 代理地址。"""

        return _validate_optional_http_url(value)


class NodeUpdate(BaseModel):
    """更新节点基础信息请求。"""

    name: str = Field(min_length=1, max_length=80)
    endpoint_ips: list[str] = Field(min_length=1)
    hostname: str | None = None
    region: str | None = Field(default=None, max_length=80)
    management_ip: str | None = None
    public_ip: str | None = None
    topology_endpoint: str | None = Field(default=None, max_length=255)
    github_proxy_url: str | None = Field(default=None, max_length=500)

    @field_validator("github_proxy_url")
    @classmethod
    def validate_github_proxy_url(cls, value: str | None) -> str | None:
        """校验节点 GitHub 代理地址。"""

        return _validate_optional_http_url(value)


class NodeRead(BaseModel):
    """节点详情响应。"""

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
    agent_token_value: str | None
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

    @field_validator("site_logo_url")
    @classmethod
    def validate_site_logo_url(cls, value: str | None) -> str | None:
        """校验站点 logo 地址。"""

        return _validate_optional_asset_url(value)


class InterfaceCreate(BaseModel):
    """创建单个 WireGuard 接口请求。"""

    name: str = Field(min_length=1, max_length=32)
    tunnel_ips: list[str] = Field(default_factory=list)
    listen_port: int | None = None
    private_key: str | None = None
    public_key: str | None = None
    mtu: int | None = 1420
    table_name: str | None = "off"
    dns: list[str] = Field(default_factory=list)
    interface_custom_config: str | None = None

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


class ManagedLinkCreate(BaseModel):
    """创建双端受管 WireGuard 连接请求。"""

    peer_node_id: int
    local_interface_name: str = Field(min_length=1, max_length=32)
    peer_interface_name: str | None = Field(default=None, min_length=1, max_length=32)
    local_tunnel_ips: list[str] = Field(min_length=1)
    peer_tunnel_ips: list[str] = Field(min_length=1)
    local_allowed_ips: list[str] | None = None
    peer_allowed_ips: list[str] | None = None
    local_endpoint_host: str | None = Field(default=None, max_length=255)
    local_endpoint_port: int | None = None
    peer_endpoint_host: str | None = Field(default=None, max_length=255)
    peer_endpoint_port: int | None = None
    local_listen_port: int | None = None
    peer_listen_port: int | None = None
    mtu: int | None = 1420
    table_name: str | None = "off"
    persistent_keepalive: int | None = 25
    local_interface_custom_config: str | None = None
    local_peer_custom_config: str | None = None
    peer_interface_custom_config: str | None = None
    peer_peer_custom_config: str | None = None
    replace_local_interface_id: int | None = None
    replace_peer_interface_id: int | None = None
    force_endpoint_mismatch: bool = False
    udp2raw: Udp2RawMiddlewareConfig | None = None
    mimic: MimicMiddlewareConfig | None = None

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

    name: str = Field(min_length=1, max_length=32)
    tunnel_ips: list[str] = Field(default_factory=list)
    listen_port: int | None = None
    private_key: str | None = None
    public_key: str | None = None
    mtu: int | None = 1420
    table_name: str | None = None
    dns: list[str] = Field(default_factory=list)
    interface_custom_config: str | None = None

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
    error: str | None = None


class AgentLinkMonitorResultRequest(BaseModel):
    """Agent 批量上报链路监测结果请求。"""

    node_id: int
    token: str
    results: list[AgentLinkMonitorResultItem]


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
    monitor_summary: LinkMonitorSummary | None = None


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
    local_tunnel_ips: list[str] = Field(min_length=1)
    peer_tunnel_ips: list[str] = Field(min_length=1)
    local_routes: list[str] = Field(default_factory=list)
    peer_routes: list[str] = Field(default_factory=list)
    mtu: int = 1476
    gre_key: str | None = None
    ttl: int | None = None
    pmtudisc: bool = True
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
        """校验 GRE 接口名符合 Linux 限制。"""

        return _validate_linux_interface_name(value)

    @field_validator("local_outer_ip", "peer_outer_ip")
    @classmethod
    def validate_outer_ip(cls, value: str) -> str:
        """校验 GRE 外层地址为 IPv4 字面量。"""

        return _validate_ipv4_address(value)

    @field_validator("local_bind_ip", "local_remote_ip", "peer_bind_ip", "peer_remote_ip")
    @classmethod
    def validate_optional_outer_ip(cls, value: str | None) -> str | None:
        """校验 GRE 高级外层映射地址为可选 IPv4 字面量。"""

        return _validate_optional_ipv4_address(value)

    @field_validator("local_tunnel_ips", "peer_tunnel_ips", "local_routes", "peer_routes")
    @classmethod
    def validate_cidr_fields(cls, values: list[str]) -> list[str]:
        """校验 GRE 隧道地址和路由为合法 IPv4/IPv6 CIDR。"""

        return _validate_cidrs(values)

    @field_validator("mtu")
    @classmethod
    def validate_mtu(cls, value: int) -> int:
        """校验 GRE MTU 范围。"""

        if not 576 <= value <= 9000:
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


class GreManagedConnectionUpdate(BaseModel):
    """更新受管 GRE 连接请求。"""

    local_interface_name: str = Field(min_length=1, max_length=15)
    peer_interface_name: str = Field(min_length=1, max_length=15)
    local_outer_ip: str
    peer_outer_ip: str
    local_bind_ip: str | None = None
    local_remote_ip: str | None = None
    peer_bind_ip: str | None = None
    peer_remote_ip: str | None = None
    local_tunnel_ips: list[str] = Field(min_length=1)
    peer_tunnel_ips: list[str] = Field(min_length=1)
    local_routes: list[str] = Field(default_factory=list)
    peer_routes: list[str] = Field(default_factory=list)
    mtu: int = 1476
    gre_key: str | None = None
    ttl: int | None = None
    pmtudisc: bool = True
    risk_accepted: bool = False

    @field_validator("local_interface_name", "peer_interface_name")
    @classmethod
    def validate_interface_name(cls, value: str) -> str:
        """校验 GRE 接口名符合 Linux 限制。"""

        return _validate_linux_interface_name(value)

    @field_validator("local_outer_ip", "peer_outer_ip")
    @classmethod
    def validate_outer_ip(cls, value: str) -> str:
        """校验 GRE 外层地址为 IPv4 字面量。"""

        return _validate_ipv4_address(value)

    @field_validator("local_bind_ip", "local_remote_ip", "peer_bind_ip", "peer_remote_ip")
    @classmethod
    def validate_optional_outer_ip(cls, value: str | None) -> str | None:
        """校验 GRE 高级外层映射地址为可选 IPv4 字面量。"""

        return _validate_optional_ipv4_address(value)

    @field_validator("local_tunnel_ips", "peer_tunnel_ips", "local_routes", "peer_routes")
    @classmethod
    def validate_cidr_fields(cls, values: list[str]) -> list[str]:
        """校验 GRE 隧道地址和路由为合法 IPv4/IPv6 CIDR。"""

        return _validate_cidrs(values)

    @field_validator("mtu")
    @classmethod
    def validate_mtu(cls, value: int) -> int:
        """校验 GRE MTU 范围。"""

        if not 576 <= value <= 9000:
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


class InterfaceRead(BaseModel):
    """WireGuard 接口详情响应。"""

    id: int
    node_id: int
    name: str
    tunnel_ips: list[str]
    listen_port: int | None
    private_key_value: str | None
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


class PeerCreate(BaseModel):
    """创建 WireGuard Peer 请求。"""

    name: str | None = None
    public_key: str = Field(min_length=1)
    preshared_key: str | None = None
    endpoint_host: str | None = None
    endpoint_port: int | None = None
    allowed_ips: list[str] = Field(default_factory=list)
    persistent_keepalive: int | None = None
    peer_custom_config: str | None = None

    @field_validator("endpoint_port")
    @classmethod
    def validate_endpoint_port(cls, value: int | None) -> int | None:
        """校验 Endpoint 端口范围。"""

        return _validate_port(value)

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
    preshared_key_value: str | None
    endpoint_host: str | None
    endpoint_port: int | None
    allowed_ips: list[str]
    persistent_keepalive: int | None
    source: str
    enabled: bool
    peer_custom_config: str | None = None
    warnings: list[str]

    model_config = {"from_attributes": True}


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
            ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise ValueError("udp2raw ip fields must be IPv4 or IPv6 addresses, not domain names") from exc
        return value.strip()

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
        if not all(char.isalnum() or char in "_.:-" for char in value):
            raise ValueError("mimic interface name contains unsupported characters")
        return value

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

    local_interface_name: str = Field(min_length=1, max_length=32)
    peer_interface_name: str = Field(min_length=1, max_length=32)
    local_tunnel_ips: list[str] = Field(min_length=1)
    peer_tunnel_ips: list[str] = Field(min_length=1)
    local_allowed_ips: list[str] | None = None
    peer_allowed_ips: list[str] | None = None
    local_endpoint_host: str | None = Field(default=None, max_length=255)
    local_endpoint_port: int | None = None
    peer_endpoint_host: str | None = Field(default=None, max_length=255)
    peer_endpoint_port: int | None = None
    local_listen_port: int | None = None
    peer_listen_port: int | None = None
    mtu: int | None = 1420
    table_name: str | None = None
    persistent_keepalive: int | None = 25
    local_interface_custom_config: str | None = None
    local_peer_custom_config: str | None = None
    peer_interface_custom_config: str | None = None
    peer_peer_custom_config: str | None = None
    udp2raw: Udp2RawMiddlewareConfig | None = None
    mimic: MimicMiddlewareConfig | None = None

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
    parsed: dict[str, Any]
    warnings: list[str]
    imported: bool

    model_config = {"from_attributes": True}


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
    payload: dict[str, Any]
    confirmed_at: datetime | None
    task_status: str | None = None
    task_result: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class TaskRequestResult(BaseModel):
    """创建或复用任务后的统一响应。"""

    task_id: int | None
    status: str
    message: str
    result: dict[str, Any] | None = None


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


class NodePluginActionResult(BaseModel):
    """触发节点插件 action 后返回的任务信息。"""

    task_id: int
    plugin_type: str
    action: str
    status: str
    message: str


class AgentReleaseAsset(BaseModel):
    """单个 Agent 发布资产描述。"""

    path: str
    sha256: str
    size: int | None = None


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


class AgentTaskStatusRead(BaseModel):
    """Agent 任务状态响应。"""

    id: int
    node_id: int
    type: str
    status: str
    result: dict[str, Any] | None

    model_config = {"from_attributes": True}


class AgentRegisterRequest(BaseModel):
    """Agent 注册请求。"""

    node_id: int
    token: str
    hostname: str | None = None
    management_ip: str | None = None
    public_ip: str | None = None
    agent_version: str | None = None
    protocol_version: int | None = None
    capabilities: list[str] = Field(default_factory=list)
    platform: dict[str, Any] = Field(default_factory=dict)


class AgentHeartbeatRequest(BaseModel):
    """Agent 心跳请求。"""

    node_id: int
    token: str
    agent_version: str | None = None
    protocol_version: int | None = None
    capabilities: list[str] = Field(default_factory=list)
    platform: dict[str, Any] = Field(default_factory=dict)


class AgentPollRequest(BaseModel):
    """Agent 轮询任务请求。"""

    node_id: int
    token: str
    agent_version: str | None = None
    protocol_version: int | None = None
    capabilities: list[str] = Field(default_factory=list)
    platform: dict[str, Any] = Field(default_factory=dict)


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
    status: str
    result: dict[str, Any] = Field(default_factory=dict)
