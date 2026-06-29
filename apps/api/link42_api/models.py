from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from .database import Base


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
    management_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    public_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    endpoint_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    agent_token_hash: Mapped[str] = mapped_column(String(128))
    agent_token_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    agent_protocol_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    agent_capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    agent_platform: Mapped[dict] = mapped_column(JSON, default=dict)
    agent_update_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    agent_last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    interfaces: Mapped[list[WireGuardInterface]] = relationship(
        back_populates="node",
        cascade="all, delete-orphan",
    )
    tasks: Mapped[list[AgentTask]] = relationship(back_populates="node")


class WireGuardInterface(TimestampMixin, Base):
    """节点本地的一条 WireGuard 点对点链路配置，例如 wg0。

    产品语义上，一个配置就是一根虚拟网线，只允许连接一个对端。
    底层仍保留 peers 关系，是为了贴合 wg-quick 的文件格式并兼容导入。
    """

    __tablename__ = "wg_interfaces"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), index=True)
    name: Mapped[str] = mapped_column(String(32))
    tunnel_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    listen_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    private_key_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    private_key_value: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    deployed_config: Mapped[str | None] = mapped_column(Text, nullable=True)
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

    @property
    def interface_custom_config(self) -> str | None:
        return (self.extras or {}).get("custom_config")

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
    preshared_key_value: Mapped[str | None] = mapped_column(Text, nullable=True)
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
        return (self.extras or {}).get("custom_config")


class ImportCandidate(TimestampMixin, Base):
    """Agent 扫描后返回的、已解析但尚未导入的 wg-quick 配置。"""

    __tablename__ = "import_candidates"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), index=True)
    path: Mapped[str] = mapped_column(String(512))
    interface_name: Mapped[str] = mapped_column(String(32))
    parsed: Mapped[dict] = mapped_column(JSON)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    imported: Mapped[bool] = mapped_column(Boolean, default=False)


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
    diff: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    tasks: Mapped[list[AgentTask]] = relationship(
        back_populates="change_plan",
        order_by="AgentTask.id",
    )

    @property
    def task_status(self) -> str | None:
        """返回该计划最近一个 Agent 任务状态，便于前端展示部署进度。"""

        if not getattr(self, "tasks", None):
            return None
        return self.tasks[-1].status

    @property
    def task_result(self) -> dict | None:
        """返回该计划最近一个 Agent 任务结果，便于定位部署失败原因。"""

        if not getattr(self, "tasks", None):
            return None
        return self.tasks[-1].result


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
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    node: Mapped[Node] = relationship(back_populates="tasks")
    change_plan: Mapped[ChangePlan | None] = relationship(back_populates="tasks")


class SystemSetting(TimestampMixin, Base):
    """主控级系统设置和单用户认证状态。"""

    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
