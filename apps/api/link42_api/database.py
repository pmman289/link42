from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


# SQLAlchemy 连接参数，不同数据库后端可以在这里做少量兼容处理。
connect_args = {}
if settings.database_url.startswith("sqlite"):
    # FastAPI 在线程中处理请求时，SQLite 需要关闭同线程限制。
    connect_args["check_same_thread"] = False

# 全局数据库引擎，由 FastAPI 请求生命周期复用。
engine = create_engine(settings.database_url, connect_args=connect_args)
# 请求级 Session 工厂；关闭 autoflush 可以让写入时机更明确，便于审阅。
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    """所有 SQLAlchemy 模型的基类。"""

    pass


def get_db() -> Generator[Session, None, None]:
    """为 FastAPI 依赖注入提供请求级数据库会话。"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """初始化数据库表结构。"""
    # 后续应由 Alembic 管理迁移；第一版先启动时建表，降低本地试用门槛。
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    ensure_sqlite_point_to_point_constraints()


def ensure_sqlite_point_to_point_constraints() -> None:
    """为旧 SQLite 数据库补齐点对点约束。

    SQLAlchemy 的 create_all 不会修改已存在表结构。第一版暂不引入 Alembic，
    因此在启动时用轻量修复保证旧库也满足“一个配置最多一个对端”。
    """

    if engine.dialect.name != "sqlite":
        return

    with engine.begin() as connection:
        def table_exists(name: str) -> bool:
            return bool(
                connection.scalar(
                    text("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = :name"),
                    {"name": name},
                )
            )

        def table_columns(name: str) -> set[str]:
            if not table_exists(name):
                return set()
            return {
                row[1]
                for row in connection.execute(text(f"PRAGMA table_info({name})")).fetchall()
            }

        def add_column(table: str, columns: set[str], name: str, definition: str) -> None:
            if name not in columns:
                connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))
                columns.add(name)

        node_columns = table_columns("nodes")
        if node_columns:
            add_column("nodes", node_columns, "hostname", "VARCHAR(255)")
            add_column("nodes", node_columns, "region", "VARCHAR(80)")
            add_column("nodes", node_columns, "management_ip", "VARCHAR(64)")
            add_column("nodes", node_columns, "public_ip", "VARCHAR(64)")
            add_column("nodes", node_columns, "endpoint_ips", "JSON DEFAULT '[]'")
            add_column("nodes", node_columns, "topology_endpoint", "VARCHAR(255)")
            add_column("nodes", node_columns, "github_proxy_url", "VARCHAR(500)")
            add_column("nodes", node_columns, "topology_x", "FLOAT")
            add_column("nodes", node_columns, "topology_y", "FLOAT")
            add_column("nodes", node_columns, "topology_locked", "BOOLEAN DEFAULT 0")
            add_column("nodes", node_columns, "status", "VARCHAR(32) DEFAULT 'offline'")
            add_column("nodes", node_columns, "agent_token_hash", "VARCHAR(128) DEFAULT ''")
            add_column("nodes", node_columns, "agent_token_value", "TEXT")
            add_column("nodes", node_columns, "agent_version", "VARCHAR(32)")
            add_column("nodes", node_columns, "agent_protocol_version", "INTEGER")
            add_column("nodes", node_columns, "agent_capabilities", "JSON DEFAULT '[]'")
            add_column("nodes", node_columns, "agent_platform", "JSON DEFAULT '{}'")
            add_column("nodes", node_columns, "agent_update_status", "VARCHAR(32)")
            add_column("nodes", node_columns, "agent_last_error", "TEXT")
            add_column("nodes", node_columns, "middleware_install_status", "VARCHAR(64)")
            add_column("nodes", node_columns, "last_seen_at", "DATETIME")

        interface_columns = table_columns("wg_interfaces")
        if interface_columns:
            add_column("wg_interfaces", interface_columns, "node_id", "INTEGER")
            add_column("wg_interfaces", interface_columns, "tunnel_ips", "JSON DEFAULT '[]'")
            add_column("wg_interfaces", interface_columns, "listen_port", "INTEGER")
            add_column("wg_interfaces", interface_columns, "private_key_ref", "VARCHAR(255)")
            add_column("wg_interfaces", interface_columns, "private_key_value", "TEXT")
            add_column("wg_interfaces", interface_columns, "public_key", "VARCHAR(128)")
            add_column("wg_interfaces", interface_columns, "mtu", "INTEGER")
            add_column("wg_interfaces", interface_columns, "fwmark", "VARCHAR(64)")
            add_column("wg_interfaces", interface_columns, "table_name", "VARCHAR(64)")
            add_column("wg_interfaces", interface_columns, "dns", "JSON DEFAULT '[]'")
            add_column("wg_interfaces", interface_columns, "pre_up", "JSON DEFAULT '[]'")
            add_column("wg_interfaces", interface_columns, "post_up", "JSON DEFAULT '[]'")
            add_column("wg_interfaces", interface_columns, "pre_down", "JSON DEFAULT '[]'")
            add_column("wg_interfaces", interface_columns, "post_down", "JSON DEFAULT '[]'")
            add_column("wg_interfaces", interface_columns, "source", "VARCHAR(32) DEFAULT 'created'")
            add_column("wg_interfaces", interface_columns, "managed", "BOOLEAN DEFAULT 1")
            add_column("wg_interfaces", interface_columns, "enabled", "BOOLEAN DEFAULT 1")
            add_column("wg_interfaces", interface_columns, "deployed_config", "TEXT")
            add_column("wg_interfaces", interface_columns, "runtime_status", "VARCHAR(32) DEFAULT 'stopped'")
            add_column("wg_interfaces", interface_columns, "import_path", "VARCHAR(512)")
            add_column("wg_interfaces", interface_columns, "extras", "JSON DEFAULT '{}'")
            add_column("wg_interfaces", interface_columns, "warnings", "JSON DEFAULT '[]'")

        peer_columns = table_columns("wg_peers")
        if peer_columns:
            add_column("wg_peers", peer_columns, "peer_node_id", "INTEGER")
            add_column("wg_peers", peer_columns, "peer_interface_id", "INTEGER")
            add_column("wg_peers", peer_columns, "name", "VARCHAR(80)")
            add_column("wg_peers", peer_columns, "public_key", "VARCHAR(128) DEFAULT ''")
            add_column("wg_peers", peer_columns, "preshared_key_ref", "VARCHAR(255)")
            add_column("wg_peers", peer_columns, "preshared_key_value", "TEXT")
            add_column("wg_peers", peer_columns, "endpoint_host", "VARCHAR(255)")
            add_column("wg_peers", peer_columns, "endpoint_port", "INTEGER")
            add_column("wg_peers", peer_columns, "allowed_ips", "JSON DEFAULT '[]'")
            add_column("wg_peers", peer_columns, "persistent_keepalive", "INTEGER")
            add_column("wg_peers", peer_columns, "source", "VARCHAR(32) DEFAULT 'created'")
            add_column("wg_peers", peer_columns, "enabled", "BOOLEAN DEFAULT 1")
            add_column("wg_peers", peer_columns, "extras", "JSON DEFAULT '{}'")
            add_column("wg_peers", peer_columns, "warnings", "JSON DEFAULT '[]'")

        candidate_columns = table_columns("import_candidates")
        if candidate_columns:
            add_column("import_candidates", candidate_columns, "warnings", "JSON DEFAULT '[]'")
            add_column("import_candidates", candidate_columns, "imported", "BOOLEAN DEFAULT 0")

        plan_columns = table_columns("change_plans")
        if plan_columns:
            add_column("change_plans", plan_columns, "status", "VARCHAR(32) DEFAULT 'draft'")
            add_column("change_plans", plan_columns, "affected_node_ids", "JSON DEFAULT '[]'")
            add_column("change_plans", plan_columns, "diff", "TEXT DEFAULT ''")
            add_column("change_plans", plan_columns, "payload", "JSON DEFAULT '{}'")
            add_column("change_plans", plan_columns, "confirmed_at", "DATETIME")

        task_columns = table_columns("agent_tasks")
        if task_columns:
            add_column("agent_tasks", task_columns, "change_plan_id", "INTEGER")
            add_column("agent_tasks", task_columns, "payload", "JSON DEFAULT '{}'")
            add_column("agent_tasks", task_columns, "status", "VARCHAR(32) DEFAULT 'pending'")
            add_column("agent_tasks", task_columns, "result", "JSON")
            add_column("agent_tasks", task_columns, "started_at", "DATETIME")
            add_column("agent_tasks", task_columns, "finished_at", "DATETIME")

        if table_exists("wg_peers"):
            # 先清理历史遗留的重复对端，保留每个配置最早创建的一条记录。
            connection.execute(
                text(
                    """
                    DELETE FROM wg_peers
                    WHERE id NOT IN (
                        SELECT MIN(id)
                        FROM wg_peers
                        GROUP BY interface_id
                    )
                    """
                )
            )
            # 再补唯一索引，让旧 SQLite 库也能在数据库层阻止重复对端。
            connection.execute(
                text(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS uq_wg_peer_interface_id
                    ON wg_peers(interface_id)
                    """
                )
            )
        has_import_candidates_table = connection.scalar(
            text("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'import_candidates'")
        )
        if has_import_candidates_table:
            connection.execute(
                text(
                    """
                    DELETE FROM import_candidates
                    WHERE imported = 0
                      AND EXISTS (
                          SELECT 1
                          FROM import_candidates AS already_imported
                          WHERE already_imported.node_id = import_candidates.node_id
                            AND already_imported.path = import_candidates.path
                            AND already_imported.imported = 1
                      )
                    """
                )
            )
            connection.execute(
                text(
                    """
                    DELETE FROM import_candidates
                    WHERE imported = 0
                      AND EXISTS (
                          SELECT 1
                          FROM wg_interfaces
                          WHERE wg_interfaces.node_id = import_candidates.node_id
                            AND wg_interfaces.name = import_candidates.interface_name
                      )
                    """
                )
            )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS system_settings (
                    "key" VARCHAR(80) NOT NULL PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS link_monitors (
                    id INTEGER NOT NULL PRIMARY KEY,
                    node_id INTEGER NOT NULL,
                    interface_id INTEGER,
                    name VARCHAR(80) NOT NULL,
                    target_host VARCHAR(255) NOT NULL,
                    interval_seconds INTEGER DEFAULT 10,
                    retention_days INTEGER DEFAULT 7,
                    enabled BOOLEAN DEFAULT 1,
                    next_due_at DATETIME,
                    last_checked_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_link_monitors_node_id ON link_monitors(node_id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_link_monitors_interface_id ON link_monitors(interface_id)"))
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS link_monitor_samples (
                    id INTEGER NOT NULL PRIMARY KEY,
                    monitor_id INTEGER NOT NULL,
                    checked_at DATETIME NOT NULL,
                    success BOOLEAN NOT NULL,
                    latency_ms FLOAT,
                    error TEXT
                )
                """
            )
        )
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_link_monitor_samples_monitor_id ON link_monitor_samples(monitor_id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_link_monitor_samples_checked_at ON link_monitor_samples(checked_at)"))
        if node_columns:
            fallback_columns = [name for name in ["public_ip", "management_ip", "hostname"] if name in node_columns]
            if fallback_columns:
                fallback_expr = f"COALESCE({', '.join(fallback_columns)})"
                connection.execute(
                    text(
                        f"""
                        UPDATE nodes
                        SET endpoint_ips = json_array({fallback_expr})
                        WHERE (endpoint_ips IS NULL OR endpoint_ips = '[]')
                          AND {fallback_expr} IS NOT NULL
                        """
                    )
                )
