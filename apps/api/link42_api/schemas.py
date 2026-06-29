from __future__ import annotations

from datetime import datetime
from typing import Any

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


class NodeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    hostname: str | None = None
    management_ip: str | None = None
    public_ip: str | None = None
    endpoint_ips: list[str] = Field(min_length=1)


class NodeUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    endpoint_ips: list[str] = Field(min_length=1)
    hostname: str | None = None
    management_ip: str | None = None
    public_ip: str | None = None


class NodeRead(BaseModel):
    id: int
    name: str
    hostname: str | None
    management_ip: str | None
    public_ip: str | None
    endpoint_ips: list[str]
    agent_token_value: str | None
    status: str
    last_seen_at: datetime | None

    model_config = {"from_attributes": True}


class NodeCreateResult(BaseModel):
    node: NodeRead
    agent_token: str


class InterfaceCreate(BaseModel):
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


class ManagedLinkCreate(BaseModel):
    peer_node_id: int
    local_interface_name: str = Field(min_length=1, max_length=32)
    peer_interface_name: str | None = Field(default=None, min_length=1, max_length=32)
    local_tunnel_ips: list[str] = Field(min_length=1)
    peer_tunnel_ips: list[str] = Field(min_length=1)
    local_endpoint_host: str = Field(min_length=1, max_length=255)
    peer_endpoint_host: str = Field(min_length=1, max_length=255)
    local_listen_port: int
    peer_listen_port: int
    mtu: int | None = 1420
    table_name: str | None = None
    persistent_keepalive: int | None = 25
    local_interface_custom_config: str | None = None
    local_peer_custom_config: str | None = None
    peer_interface_custom_config: str | None = None
    peer_peer_custom_config: str | None = None
    replace_local_interface_id: int | None = None
    replace_peer_interface_id: int | None = None
    force_endpoint_mismatch: bool = False

    @field_validator("local_listen_port", "peer_listen_port")
    @classmethod
    def validate_listen_port(cls, value: int) -> int:
        """校验双方监听端口范围。"""

        checked = _validate_port(value)
        assert checked is not None
        return checked

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


class ManagedLinkCreateResult(BaseModel):
    local_interface: InterfaceRead
    peer_interface: InterfaceRead

    model_config = {"from_attributes": True}


class ManagedLinkRead(BaseModel):
    local_interface: InterfaceRead
    peer_interface: InterfaceRead
    local_peer: PeerRead
    peer_peer: PeerRead

    model_config = {"from_attributes": True}


class ManagedLinkUpdate(BaseModel):
    local_interface_name: str = Field(min_length=1, max_length=32)
    peer_interface_name: str = Field(min_length=1, max_length=32)
    local_tunnel_ips: list[str] = Field(min_length=1)
    peer_tunnel_ips: list[str] = Field(min_length=1)
    local_endpoint_host: str = Field(min_length=1, max_length=255)
    peer_endpoint_host: str = Field(min_length=1, max_length=255)
    local_listen_port: int
    peer_listen_port: int
    mtu: int | None = 1420
    table_name: str | None = None
    persistent_keepalive: int | None = 25
    local_interface_custom_config: str | None = None
    local_peer_custom_config: str | None = None
    peer_interface_custom_config: str | None = None
    peer_peer_custom_config: str | None = None

    @field_validator("local_listen_port", "peer_listen_port")
    @classmethod
    def validate_listen_port(cls, value: int) -> int:
        checked = _validate_port(value)
        assert checked is not None
        return checked

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


class AgentHeartbeatRequest(BaseModel):
    node_id: int
    token: str
    agent_version: str | None = None


class AgentPollRequest(BaseModel):
    node_id: int
    token: str
    agent_version: str | None = None
    capabilities: list[str] = Field(default_factory=list)


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
