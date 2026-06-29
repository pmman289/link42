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
        # 旧库补齐部署状态字段，用于生成真实 diff 和限制删除运行中的接口。
        columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(wg_interfaces)")).fetchall()
        }
        if "deployed_config" not in columns:
            connection.execute(text("ALTER TABLE wg_interfaces ADD COLUMN deployed_config TEXT"))
        if "runtime_status" not in columns:
            connection.execute(
                text("ALTER TABLE wg_interfaces ADD COLUMN runtime_status VARCHAR(32) DEFAULT 'stopped'")
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
                CREATE TABLE IF NOT EXISTS system_settings (
                    "key" VARCHAR(80) NOT NULL PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        has_nodes_table = connection.scalar(
            text("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'nodes'")
        )
        if has_nodes_table:
            node_columns = {
                row[1]
                for row in connection.execute(text("PRAGMA table_info(nodes)")).fetchall()
            }
            if "endpoint_ips" not in node_columns:
                connection.execute(text("ALTER TABLE nodes ADD COLUMN endpoint_ips JSON DEFAULT '[]'"))
            if "agent_token_value" not in node_columns:
                connection.execute(text("ALTER TABLE nodes ADD COLUMN agent_token_value TEXT"))
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
