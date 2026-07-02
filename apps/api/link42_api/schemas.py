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
    """轻量校验 CIDR 字段形态，避免明显错误进入部署计划。"""

    for value in values:
        if "/" not in value:
            raise ValueError("CIDR value must contain prefix length")
    return values


def _validate_optional_http_url(value: str | None) -> str | None:
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
        return _validate_optional_http_url(value)


class NodeUpdate(BaseModel):
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
        return _validate_optional_http_url(value)


class NodeRead(BaseModel):
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
    node: NodeRead
    agent_token: str


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=255)


class LoginResult(BaseModel):
    token: str
    username: str


class AuthStatus(BaseModel):
    authenticated: bool
    username: str | None = None


class BrandingRead(BaseModel):
    site_title: str = "Link42"
    site_logo_url: str = "/logo.png"


class ControllerSettingsRead(BaseModel):
    controller_url: str
    username: str
    site_title: str = "Link42"
    site_logo_url: str = "/logo.png"


class ControllerSettingsUpdate(BaseModel):
    controller_url: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=80)
    site_title: str = Field(default="Link42", min_length=1, max_length=80)
    site_logo_url: str | None = Field(default=None, max_length=500)
    new_password: str | None = Field(default=None, min_length=6, max_length=255)

    @field_validator("site_logo_url")
    @classmethod
    def validate_site_logo_url(cls, value: str | None) -> str | None:
        return _validate_optional_asset_url(value)


class InterfaceCreate(BaseModel):
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
    x: float | None = None
    y: float | None = None
    locked: bool | None = None


class TopologyNode(BaseModel):
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
    id: str
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
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]


class LinkMonitorCreate(BaseModel):
    target_host: str = Field(min_length=1, max_length=255)
    name: str | None = Field(default=None, max_length=80)
    interval_seconds: int = 10
    retention_days: int = 7
    enabled: bool = True

    @field_validator("target_host")
    @classmethod
    def validate_target_host(cls, value: str) -> str:
        cleaned = value.strip()
        try:
            ipaddress.ip_address(cleaned)
        except ValueError as exc:
            raise ValueError("monitor target must be an IPv4 or IPv6 address") from exc
        return cleaned

    @field_validator("interval_seconds")
    @classmethod
    def validate_interval(cls, value: int) -> int:
        if not 1 <= value <= 300:
            raise ValueError("interval_seconds must be between 1 and 300")
        return value

    @field_validator("retention_days")
    @classmethod
    def validate_retention(cls, value: int) -> int:
        if not 1 <= value <= 90:
            raise ValueError("retention_days must be between 1 and 90")
        return value


class LinkMonitorUpdate(LinkMonitorCreate):
    pass


class LinkMonitorRead(BaseModel):
    id: int
    node_id: int
    interface_id: int | None
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
    checked_at: datetime
    success: bool
    latency_ms: float | None = None
    error: str | None = None

    model_config = {"from_attributes": True}


class LinkMonitorSamplesResponse(BaseModel):
    monitor: LinkMonitorRead
    summary: LinkMonitorSummary | None
    samples: list[LinkMonitorSampleRead]


class AgentLinkMonitorRead(BaseModel):
    id: int
    target_host: str
    timeout_seconds: float


class AgentLinkMonitorPollResponse(BaseModel):
    monitors: list[AgentLinkMonitorRead]


class AgentLinkMonitorResultItem(BaseModel):
    monitor_id: int
    checked_at: datetime | None = None
    success: bool
    latency_ms: float | None = None
    error: str | None = None


class AgentLinkMonitorResultRequest(BaseModel):
    node_id: int
    token: str
    results: list[AgentLinkMonitorResultItem]


class InterfaceRead(BaseModel):
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
        if value not in ["local", "peer"]:
            raise ValueError("server_side must be local or peer")
        return value

    @field_validator("server_listen_port", "server_forward_port", "client_listen_port")
    @classmethod
    def validate_udp2raw_ports(cls, value: int | None) -> int | None:
        return _validate_port(value)

    @field_validator("server_listen_host", "server_connect_host", "server_forward_host", "client_listen_host")
    @classmethod
    def validate_udp2raw_ip(cls, value: str | None) -> str | None:
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
        if value not in ["faketcp", "udp", "icmp"]:
            raise ValueError("raw_mode must be faketcp, udp, or icmp")
        return value

    @field_validator("cipher_mode")
    @classmethod
    def validate_cipher_mode(cls, value: str) -> str:
        if value not in ["xor", "aes128cbc", "none"]:
            raise ValueError("cipher_mode must be xor, aes128cbc, or none")
        return value


class MimicMiddlewareConfig(BaseModel):
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
        if value is None or not value.strip():
            return value
        value = value.strip()
        if not all(char.isalnum() or char in "_.:-" for char in value):
            raise ValueError("mimic interface name contains unsupported characters")
        return value

    @field_validator("xdp_mode")
    @classmethod
    def validate_xdp_mode(cls, value: str) -> str:
        if value not in ["auto", "native", "skb"]:
            raise ValueError("xdp_mode must be auto, native, or skb")
        return value

    @field_validator("handshake_interval", "keepalive_interval")
    @classmethod
    def validate_optional_non_negative(cls, value: int | None) -> int | None:
        if value is not None and value < 0:
            raise ValueError("mimic numeric options must be non-negative")
        return value

    @field_validator("padding")
    @classmethod
    def validate_padding(cls, value: int | None) -> int | None:
        if value is not None and not 0 <= value <= 16:
            raise ValueError("mimic padding must be between 0 and 16")
        return value


class ManagedLinkCreateResult(BaseModel):
    local_interface: InterfaceRead
    peer_interface: InterfaceRead

    model_config = {"from_attributes": True}


class ManagedLinkRead(BaseModel):
    local_interface: InterfaceRead
    peer_interface: InterfaceRead
    local_peer: PeerRead
    peer_peer: PeerRead
    middleware: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class ManagedLinkUpdate(BaseModel):
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
        return _validate_port(value)

    @field_validator("persistent_keepalive")
    @classmethod
    def validate_keepalive(cls, value: int | None) -> int | None:
        if value is not None and not 0 <= value <= 65535:
            raise ValueError("persistent_keepalive must be between 0 and 65535")
        return value

    @field_validator("local_tunnel_ips", "peer_tunnel_ips")
    @classmethod
    def validate_tunnel_ips(cls, values: list[str]) -> list[str]:
        return _validate_cidrs(values)

    @field_validator("local_allowed_ips", "peer_allowed_ips")
    @classmethod
    def validate_allowed_ips(cls, values: list[str] | None) -> list[str] | None:
        return _validate_cidrs(values or []) if values is not None else None


class ImportCandidateRead(BaseModel):
    id: int
    node_id: int
    path: str
    interface_name: str
    parsed: dict[str, Any]
    warnings: list[str]
    imported: bool

    model_config = {"from_attributes": True}


class ImportRequest(BaseModel):
    candidate_id: int


class ChangePlanRead(BaseModel):
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
    task_id: int | None
    status: str
    message: str
    result: dict[str, Any] | None = None


class AgentReleaseAsset(BaseModel):
    path: str
    sha256: str
    size: int | None = None


class AgentReleaseInfo(BaseModel):
    released_at: str | None = None
    protocol_version: int | None = None
    notes: str | None = None
    assets: dict[str, AgentReleaseAsset] = Field(default_factory=dict)


class AgentReleaseManifest(BaseModel):
    latest: str | None = None
    minimum_supported: str | None = None
    releases: dict[str, AgentReleaseInfo] = Field(default_factory=dict)


class AgentUpgradePlan(BaseModel):
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
    target_version: str | None = None
    force: bool = False


class AgentTaskStatusRead(BaseModel):
    id: int
    node_id: int
    type: str
    status: str
    result: dict[str, Any] | None

    model_config = {"from_attributes": True}


class AgentRegisterRequest(BaseModel):
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
    node_id: int
    token: str
    agent_version: str | None = None
    protocol_version: int | None = None
    capabilities: list[str] = Field(default_factory=list)
    platform: dict[str, Any] = Field(default_factory=dict)


class AgentPollRequest(BaseModel):
    node_id: int
    token: str
    agent_version: str | None = None
    protocol_version: int | None = None
    capabilities: list[str] = Field(default_factory=list)
    platform: dict[str, Any] = Field(default_factory=dict)


class AgentTaskRead(BaseModel):
    id: int
    type: str
    payload: dict[str, Any]


class AgentPollResponse(BaseModel):
    tasks: list[AgentTaskRead]


class AgentTaskResultRequest(BaseModel):
    node_id: int
    token: str
    status: str
    result: dict[str, Any] = Field(default_factory=dict)
