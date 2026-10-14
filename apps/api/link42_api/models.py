from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, and_, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from .database import Base
from .secret_store import EncryptedJSON, EncryptedText


class IPAMLock(Base):
    __tablename__ = "ipam_lock"
    id: Mapped[int] = mapped_column(primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, default=0)


class IPAMNodeAddress(Base):
    __tablename__ = "ipam_node_addresses"
    __table_args__ = (UniqueConstraint("node_id", "address"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), index=True)
    address: Mapped[str] = mapped_column(String(18))


class IPAMPool(Base):
    __tablename__ = "ipam_pools"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    cidr: Mapped[str] = mapped_column(String(18), unique=True)
    kind: Mapped[str] = mapped_column(String(16))
    link_prefix: Mapped[int] = mapped_column(Integer, default=30)


class IPAMAddress(Base):
    __tablename__ = "ipam_addresses"
    ip: Mapped[int] = mapped_column(BigInteger, primary_key=True)


class IPAMClaim(Base):
    """Durable references survive removal of the corresponding configuration."""
    __tablename__ = "ipam_claims"
    __table_args__ = (UniqueConstraint("source", "ip"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[int] = mapped_column(BigInteger, ForeignKey("ipam_addresses.ip"), index=True)
    prefix: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(160), index=True)
    owner: Mapped[str] = mapped_column(String(80), index=True)
    node_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    node_name: Mapped[str | None] = mapped_column(String(80), nullable=True)
    interface_name: Mapped[str | None] = mapped_column(String(32), nullable=True)
    kind: Mapped[str] = mapped_column(String(24))
    state: Mapped[str] = mapped_column(String(24), default="assigned")
    note: Mapped[str] = mapped_column(Text, default="")
    cleanup_task_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)


class IPAMRange(Base):
    __tablename__ = "ipam_ranges"
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(255), unique=True)
    cidr: Mapped[str] = mapped_column(String(18))
    start: Mapped[int] = mapped_column(BigInteger, index=True)
    end: Mapped[int] = mapped_column(BigInteger)
    kind: Mapped[str] = mapped_column(String(24))
    owners: Mapped[list[str]] = mapped_column(JSON, default=list)
    note: Mapped[str] = mapped_column(Text, default="")


class TimestampMixin:
    """为业务表提供统一的创建和更新时间字段。"""

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )


class Node(TimestampMixin, Base):
    """一台受管服务器。

    管理员先在面板创建节点，随后节点上的 Agent 使用生成的 token 注册并上报心跳。
    """

    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    region: Mapped[str | None] = mapped_column(String(80), nullable=True)
    management_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    public_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    endpoint_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    topology_endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    github_proxy_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    topology_x: Mapped[float | None] = mapped_column(Float, nullable=True)
    topology_y: Mapped[float | None] = mapped_column(Float, nullable=True)
    topology_locked: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    agent_token_hash: Mapped[str] = mapped_column(String(128))
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    agent_protocol_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    agent_capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    agent_platform: Mapped[dict] = mapped_column(JSON, default=dict)
    agent_update_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    agent_last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    middleware_install_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    interfaces: Mapped[list[WireGuardInterface]] = relationship(
        back_populates="node",
        cascade="all, delete-orphan",
    )
    connection_endpoints: Mapped[list[ConnectionEndpoint]] = relationship(
        back_populates="node",
        cascade="all, delete-orphan",
    )
    tasks: Mapped[list[AgentTask]] = relationship(back_populates="node")

    ipv4_addresses: Mapped[list[IPAMNodeAddress]] = relationship(cascade="all, delete-orphan")

    @property
    def internal_ipv4s(self) -> list[str]:
        return [item.address for item in self.ipv4_addresses]

    @internal_ipv4s.setter
    def internal_ipv4s(self, values: list[str]) -> None:
        existing = {item.address: item for item in self.ipv4_addresses}
        self.ipv4_addresses = [existing.get(value) or IPAMNodeAddress(address=value) for value in values]


class WireGuardInterface(TimestampMixin, Base):
    """节点本地的一条 WireGuard 点对点链路配置，例如 wg0。

    产品语义上，一个配置就是一根虚拟网线，只允许连接一个对端。
    底层仍保留 peers 关系，是为了贴合 wg-quick 的文件格式并兼容导入。
    """

    __tablename__ = "wg_interfaces"
    __table_args__ = (
        UniqueConstraint("node_id", "name", name="uq_wg_interface_node_name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), index=True)
    name: Mapped[str] = mapped_column(String(32))
    tunnel_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    listen_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    private_key_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    private_key_value: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    public_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mtu: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fwmark: Mapped[str | None] = mapped_column(String(64), nullable=True)
    table_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dns: Mapped[list[str]] = mapped_column(JSON, default=list)
    pre_up: Mapped[list[str]] = mapped_column(JSON, default=list)
    post_up: Mapped[list[str]] = mapped_column(JSON, default=list)
    pre_down: Mapped[list[str]] = mapped_column(JSON, default=list)
    post_down: Mapped[list[str]] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(32), default="created")
    managed: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    deployed_config: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    runtime_status: Mapped[str] = mapped_column(String(32), default="stopped")
    import_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    extras: Mapped[dict] = mapped_column(JSON, default=dict)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)

    node: Mapped[Node] = relationship(back_populates="interfaces")
    peers: Mapped[list[WireGuardPeer]] = relationship(
        back_populates="interface",
        cascade="all, delete-orphan",
        foreign_keys="WireGuardPeer.interface_id",
    )
    link_monitors: Mapped[list[LinkMonitor]] = relationship(
        back_populates="interface",
        cascade="all, delete-orphan",
    )

    @property
    def interface_custom_config(self) -> str | None:
        """返回导入或编辑时保留的 Interface 自定义配置片段。"""

        extras = self.extras if isinstance(self.extras, dict) else {}
        return extras.get("custom_config")

    @property
    def has_private_key(self) -> bool:
        """仅返回是否保存私钥，避免普通 API 暴露密钥正文。"""

        return bool(self.private_key_value)

    @property
    def primary_peer_endpoint_host(self) -> str | None:
        """返回第一个 Peer 的原始 Endpoint host，供导入受管连接时预填。"""

        for peer in self.peers or []:
            if peer.endpoint_host:
                return peer.endpoint_host
        return None

    @property
    def primary_peer_endpoint_port(self) -> int | None:
        """返回第一个 Peer 的原始 Endpoint port，供界面展示和后续扩展。"""

        for peer in self.peers or []:
            if peer.endpoint_port:
                return peer.endpoint_port
        return None

    @property
    def primary_peer_allowed_ips(self) -> list[str]:
        """返回第一个 Peer 的原始 AllowedIPs，供导入受管连接时预填。"""

        for peer in self.peers or []:
            if peer.allowed_ips:
                return peer.allowed_ips
        return []


class WireGuardPeer(TimestampMixin, Base):
    """节点本地 WireGuard 链路配置下的唯一对端配置。"""

    __tablename__ = "wg_peers"
    # 新建数据库应从结构上限制一个配置只有一个对端；旧数据库仍由业务校验兜底。
    __table_args__ = (UniqueConstraint("interface_id", name="uq_wg_peer_interface_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    interface_id: Mapped[int] = mapped_column(ForeignKey("wg_interfaces.id"), index=True)
    peer_node_id: Mapped[int | None] = mapped_column(ForeignKey("nodes.id"), nullable=True)
    peer_interface_id: Mapped[int | None] = mapped_column(
        ForeignKey("wg_interfaces.id"),
        nullable=True,
    )
    name: Mapped[str | None] = mapped_column(String(80), nullable=True)
    public_key: Mapped[str] = mapped_column(String(128))
    preshared_key_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    preshared_key_value: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    endpoint_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    endpoint_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    allowed_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    persistent_keepalive: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="created")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    extras: Mapped[dict] = mapped_column(JSON, default=dict)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)

    interface: Mapped[WireGuardInterface] = relationship(
        back_populates="peers",
        foreign_keys=[interface_id],
    )

    @property
    def peer_custom_config(self) -> str | None:
        """返回导入或编辑时保留的 Peer 自定义配置片段。"""

        extras = self.extras if isinstance(self.extras, dict) else {}
        return extras.get("custom_config")

    @property
    def has_preshared_key(self) -> bool:
        """仅返回是否保存预共享密钥，避免普通 API 暴露密钥正文。"""

        return bool(self.preshared_key_value)


class Connection(TimestampMixin, Base):
    """跨协议的点对点连接记录。

    WireGuard 暂时保留旧表，本表第一阶段用于 GRE 等新协议。
    """

    __tablename__ = "connections"

    id: Mapped[int] = mapped_column(primary_key=True)
    protocol_type: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(120))
    source: Mapped[str] = mapped_column(String(32), default="managed-node")
    managed: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(32), default="stopped")
    extras: Mapped[dict] = mapped_column(JSON, default=dict)

    endpoints: Mapped[list[ConnectionEndpoint]] = relationship(
        back_populates="connection",
        cascade="all, delete-orphan",
        order_by="ConnectionEndpoint.id",
    )


class ConnectionEndpoint(TimestampMixin, Base):
    """跨协议连接在单个节点上的本地端点。"""

    __tablename__ = "connection_endpoints"
    __table_args__ = (
        UniqueConstraint("node_id", "interface_name", name="uq_connection_endpoint_node_interface"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    connection_id: Mapped[int] = mapped_column(ForeignKey("connections.id"), index=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), index=True)
    role: Mapped[str] = mapped_column(String(32))
    interface_name: Mapped[str] = mapped_column(String(32))
    tunnel_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    mtu: Mapped[int | None] = mapped_column(Integer, nullable=True)
    routes: Mapped[list[str]] = mapped_column(JSON, default=list)
    runtime_status: Mapped[str] = mapped_column(String(32), default="stopped")
    deployed_config: Mapped[str | None] = mapped_column(Text, nullable=True)
    protocol_config: Mapped[dict] = mapped_column(JSON, default=dict)
    extras: Mapped[dict] = mapped_column(JSON, default=dict)

    connection: Mapped[Connection] = relationship(back_populates="endpoints")
    node: Mapped[Node] = relationship(back_populates="connection_endpoints")
    link_monitors: Mapped[list[LinkMonitor]] = relationship(
        back_populates="connection_endpoint",
        cascade="all, delete-orphan",
    )


class ImportCandidate(TimestampMixin, Base):
    """Agent 扫描后返回的、已解析但尚未导入的 wg-quick 配置。"""

    __tablename__ = "import_candidates"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), index=True)
    path: Mapped[str] = mapped_column(String(512))
    interface_name: Mapped[str] = mapped_column(String(32))
    parsed: Mapped[dict] = mapped_column(EncryptedJSON())
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    imported: Mapped[bool] = mapped_column(Boolean, default=False)


class PortInventorySetting(TimestampMixin, Base):
    """节点端口台账的可用入口端口范围。"""

    __tablename__ = "port_inventory_settings"
    __table_args__ = (UniqueConstraint("node_id", name="uq_port_inventory_setting_node_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), index=True)
    range_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    range_end: Mapped[int | None] = mapped_column(Integer, nullable=True)


class PortInventoryEntry(TimestampMixin, Base):
    """用户维护的节点入口端口占用记录。"""

    __tablename__ = "port_inventory_entries"
    __table_args__ = (UniqueConstraint("node_id", "protocol", "port", name="uq_port_inventory_node_protocol_port"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), index=True)
    protocol: Mapped[str] = mapped_column(String(8))
    port: Mapped[int] = mapped_column(Integer)
    purpose: Mapped[str] = mapped_column(String(255), default="")
    source: Mapped[str] = mapped_column(String(32), default="manual")
    detected_process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detected_pid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detected_source: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ChangePlan(TimestampMixin, Base):
    """用户可审阅的部署计划。

    Change Plan 是“修改期望状态”和“真正触碰节点配置”之间的安全闸门。
    只有用户确认后，系统才会创建 Agent 任务。
    """

    __tablename__ = "change_plans"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="draft")
    summary: Mapped[str] = mapped_column(Text)
    affected_node_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    diff: Mapped[str] = mapped_column(EncryptedText(), default="")
    payload: Mapped[dict] = mapped_column(EncryptedJSON(), default=dict)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    tasks: Mapped[list[AgentTask]] = relationship(
        back_populates="change_plan",
        order_by="AgentTask.id",
    )

    @property
    def status_task(self) -> AgentTask | None:
        """优先返回失败原因或未完成任务，避免末尾任务掩盖整个计划状态。"""

        if not getattr(self, "tasks", None):
            return None
        for status in ("failed", "cancelled", "running", "pending"):
            for task in self.tasks:
                if task.status == status:
                    return task
        return self.tasks[-1]

    @property
    def task_status(self) -> str | None:
        """返回代表整个计划执行状态的任务状态。"""

        task = self.status_task
        return task.status if task is not None else None

    @property
    def task_result(self) -> dict | None:
        """返回与汇总状态对应的任务结果，优先展示实际失败原因。"""

        task = self.status_task
        if task is None:
            return None
        result = task.result
        return result if isinstance(result, dict) else None


class AgentTask(TimestampMixin, Base):
    """由节点 Agent 主动拉取执行的任务。"""

    __tablename__ = "agent_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), index=True)
    change_plan_id: Mapped[int | None] = mapped_column(
        ForeignKey("change_plans.id"),
        nullable=True,
    )
    type: Mapped[str] = mapped_column(String(80))
    payload: Mapped[dict] = mapped_column(EncryptedJSON(), default=dict)
    queue: Mapped[str] = mapped_column(String(32), default="control", index=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    result: Mapped[dict | None] = mapped_column(EncryptedJSON(), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # 接口任务的幂等键。仅由 enqueue_interface_task_once 填写；普通/历史任务为空。
    # 部分唯一索引只约束 pending，允许运行中的任务之后排队一次。
    dedup_key: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)

    __table_args__ = (
        Index(
            "uq_agent_tasks_pending_dedup_key",
            "dedup_key",
            unique=True,
            sqlite_where=and_(status == "pending", dedup_key.is_not(None)),
            postgresql_where=and_(status == "pending", dedup_key.is_not(None)),
        ),
    )

    node: Mapped[Node] = relationship(back_populates="tasks")
    change_plan: Mapped[ChangePlan | None] = relationship(back_populates="tasks")


class IntegrationApiKey(TimestampMixin, Base):
    """第三方集成 API Token 元数据，明文 token 只在创建或轮换时返回一次。"""

    __tablename__ = "integration_api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    token_prefix: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    token_hash: Mapped[str] = mapped_column(String(128))
    token_hint: Mapped[str] = mapped_column(String(16))
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    # 保留旧列以兼容现有数据库；节点访问已改为始终允许全部节点。
    allowed_node_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    looking_glass_queries: Mapped[list[LookingGlassQuery]] = relationship(back_populates="api_key")


class LookingGlassQuery(TimestampMixin, Base):
    """Looking Glass 外部查询记录，隔离外部 query_id 和内部 AgentTask ID。"""

    __tablename__ = "looking_glass_queries"

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    api_key_id: Mapped[int] = mapped_column(ForeignKey("integration_api_keys.id"), index=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), index=True)
    operation: Mapped[str] = mapped_column(String(80))
    request: Mapped[dict] = mapped_column(JSON, default=dict)
    request_fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    agent_task_id: Mapped[int | None] = mapped_column(ForeignKey("agent_tasks.id"), nullable=True, index=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        # 同一集成 key 的相同请求在排队或执行中只允许一个任务；完成后
        # 仍可按缓存窗口重新发起查询。
        Index(
            "uq_looking_glass_active_fingerprint",
            "api_key_id",
            "node_id",
            "request_fingerprint",
            unique=True,
            sqlite_where=status.in_(["queued", "running"]),
            postgresql_where=status.in_(["queued", "running"]),
        ),
    )

    api_key: Mapped[IntegrationApiKey] = relationship(back_populates="looking_glass_queries")
    node: Mapped[Node] = relationship()
    agent_task: Mapped[AgentTask | None] = relationship()


class LinkMonitor(TimestampMixin, Base):
    """从节点本机发起的链路延迟监测目标。"""

    __tablename__ = "link_monitors"
    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), index=True)
    interface_id: Mapped[int | None] = mapped_column(ForeignKey("wg_interfaces.id"), index=True, nullable=True)
    connection_endpoint_id: Mapped[int | None] = mapped_column(
        ForeignKey("connection_endpoints.id"),
        index=True,
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(80))
    target_host: Mapped[str] = mapped_column(String(255))
    interval_seconds: Mapped[int] = mapped_column(Integer, default=10)
    retention_days: Mapped[int] = mapped_column(Integer, default=7)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        Index(
            "uq_link_monitor_interface_id",
            "interface_id",
            unique=True,
            sqlite_where=(interface_id.is_not(None)),
            postgresql_where=(interface_id.is_not(None)),
        ),
        Index(
            "uq_link_monitor_connection_endpoint_id",
            "connection_endpoint_id",
            unique=True,
            sqlite_where=(connection_endpoint_id.is_not(None)),
            postgresql_where=(connection_endpoint_id.is_not(None)),
        ),
    )

    interface: Mapped[WireGuardInterface | None] = relationship(back_populates="link_monitors")
    connection_endpoint: Mapped[ConnectionEndpoint | None] = relationship(back_populates="link_monitors")
    samples: Mapped[list[LinkMonitorSample]] = relationship(
        back_populates="monitor",
        cascade="all, delete-orphan",
    )


class LinkMonitorSample(Base):
    """单次链路探测结果。"""

    __tablename__ = "link_monitor_samples"

    id: Mapped[int] = mapped_column(primary_key=True)
    monitor_id: Mapped[int] = mapped_column(ForeignKey("link_monitors.id"), index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    success: Mapped[bool] = mapped_column(Boolean)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    monitor: Mapped[LinkMonitor] = relationship(back_populates="samples")


class SystemSetting(TimestampMixin, Base):
    """主控级系统设置和单用户认证状态。"""

    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
