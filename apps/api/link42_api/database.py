from __future__ import annotations

from collections.abc import Generator
import logging
import json
from pathlib import Path
import shutil
import sqlite3

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings
from .secret_store import ENCRYPTED_PREFIX, encrypt_text, protect_json_value


logger = logging.getLogger("link42.api.database")


# SQLAlchemy 连接参数，不同数据库后端可以在这里做少量兼容处理。
connect_args = {}
if settings.database_url.startswith("sqlite"):
    # FastAPI 在线程中处理请求时，SQLite 需要关闭同线程限制。
    connect_args["check_same_thread"] = False
    # SQLite 默认只等待 5 秒，Agent 心跳和监测结果集中上报时容易误报 database is locked。
    connect_args["timeout"] = 30

# 全局数据库引擎，由 FastAPI 请求生命周期复用。
engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
# 请求级 Session 工厂；关闭 autoflush 可以让写入时机更明确，便于审阅。
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# 升级前数据库备份文件名；固定一个文件，避免长期运行后堆积备份。
UPGRADE_BACKUP_SUFFIX = ".previous-version.db"
SENSITIVE_TEXT_COLUMNS = {
    "wg_interfaces": ["private_key_value", "deployed_config"],
    "wg_peers": ["preshared_key_value"],
}
SENSITIVE_JSON_COLUMNS = {
    "import_candidates": ["parsed"],
    "change_plans": ["diff", "payload"],
    "agent_tasks": ["payload", "result"],
}


class Base(DeclarativeBase):
    """所有 SQLAlchemy 模型的基类。"""

    pass


def purge_deleted_looking_glass_tokens(connection) -> None:
    """清理旧版本软删除遗留的 Looking Glass Token 和关联查询记录。"""

    connection.execute(
        text(
            """
            DELETE FROM looking_glass_queries
            WHERE api_key_id IN (
                SELECT id
                FROM integration_api_keys
                WHERE enabled = 0 AND revoked_at IS NOT NULL
            )
            """
        )
    )
    connection.execute(
        text(
            """
            DELETE FROM integration_api_keys
            WHERE enabled = 0 AND revoked_at IS NOT NULL
            """
        )
    )


@event.listens_for(engine, "connect")
def configure_sqlite_connection(dbapi_connection, _connection_record) -> None:
    """为 SQLite 连接设置并发读写相关参数。"""

    if engine.dialect.name != "sqlite":
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError as exc:
            logger.warning("SQLite WAL 模式启用失败 error=%s", exc)
    finally:
        cursor.close()


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


def sqlite_database_path() -> Path | None:
    """从 SQLAlchemy URL 中解析 SQLite 文件路径，内存库或非文件库返回空。"""

    if engine.dialect.name != "sqlite":
        return None
    database = engine.url.database
    if not database:
        return None
    if database == ":memory:":
        return None
    path = Path(database)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def backup_sqlite_database_for_upgrade() -> Path | None:
    """在版本升级前备份 SQLite 数据库，并只保留一个升级备份。"""

    source = sqlite_database_path()
    if source is None or not source.exists():
        return None
    backup_path = source.with_name(f"{source.stem}{UPGRADE_BACKUP_SUFFIX}")
    temporary_path = backup_path.with_suffix(f"{backup_path.suffix}.tmp")
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    if temporary_path.exists():
        temporary_path.unlink()
    with sqlite3.connect(source) as source_connection:
        with sqlite3.connect(temporary_path) as backup_connection:
            source_connection.backup(backup_connection)
    shutil.copystat(source, temporary_path)
    temporary_path.replace(backup_path)
    return backup_path


def protect_sqlite_sensitive_values(path: Path) -> int:
    """加密指定 SQLite 文件中的旧敏感明文，并清除可恢复 Agent Token。"""

    changed = 0
    with sqlite3.connect(path) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        }
        if "nodes" in tables:
            node_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(nodes)").fetchall()
            }
        else:
            node_columns = set()
        if "agent_token_value" in node_columns:
            changed += connection.execute(
                "UPDATE nodes SET agent_token_value = NULL WHERE agent_token_value IS NOT NULL"
            ).rowcount
        for table, columns in SENSITIVE_TEXT_COLUMNS.items():
            if table not in tables:
                continue
            existing_columns = {
                row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for column in columns:
                if column not in existing_columns:
                    continue
                rows = connection.execute(
                    f"SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL"
                ).fetchall()
                for row_id, value in rows:
                    text_value = str(value)
                    if text_value.startswith(ENCRYPTED_PREFIX):
                        continue
                    connection.execute(
                        f"UPDATE {table} SET {column} = ? WHERE id = ?",
                        (encrypt_text(text_value), row_id),
                    )
                    changed += 1
        for table, columns in SENSITIVE_JSON_COLUMNS.items():
            if table not in tables:
                continue
            existing_columns = {
                row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for column in columns:
                if column not in existing_columns:
                    continue
                rows = connection.execute(
                    f"SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL"
                ).fetchall()
                for row_id, value in rows:
                    try:
                        parsed = json.loads(str(value))
                    except json.JSONDecodeError:
                        parsed = str(value)
                    protected = protect_json_value(parsed)
                    if protected == parsed:
                        continue
                    connection.execute(
                        f"UPDATE {table} SET {column} = ? WHERE id = ?",
                        (json.dumps(protected, ensure_ascii=False, separators=(",", ":")), row_id),
                    )
                    changed += 1
        connection.commit()
    return changed


def protect_sensitive_database_values(backup_path: Path | None = None) -> int:
    """迁移当前 SQLite 数据库及升级备份，确保备份中也不保留敏感明文。"""

    source = sqlite_database_path()
    if source is None:
        return 0
    engine.dispose()
    changed = protect_sqlite_sensitive_values(source)
    if backup_path and backup_path.exists():
        changed += protect_sqlite_sensitive_values(backup_path)
    return changed


def ensure_sqlite_point_to_point_constraints() -> None:
    """为旧 SQLite 数据库补齐点对点约束。

    SQLAlchemy 的 create_all 不会修改已存在表结构。第一版暂不引入 Alembic，
    因此在启动时用轻量修复保证旧库也满足“一个配置最多一个对端”。
    """

    if engine.dialect.name != "sqlite":
        return

    with engine.begin() as connection:
        def table_exists(name: str) -> bool:
            """判断指定表是否已经存在。"""

            return bool(
                connection.scalar(
                    text("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = :name"),
                    {"name": name},
                )
            )

        def table_columns(name: str) -> set[str]:
            """读取指定表已有列名，表不存在时返回空集合。"""

            if not table_exists(name):
                return set()
            return {
                row[1]
                for row in connection.execute(text(f"PRAGMA table_info({name})")).fetchall()
            }

        def add_column(table: str, columns: set[str], name: str, definition: str) -> None:
            """在旧表缺少字段时追加列，并同步本地列集合。"""

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

        if not table_exists("port_inventory_settings"):
            connection.execute(
                text(
                    """
                    CREATE TABLE port_inventory_settings (
                        id INTEGER NOT NULL PRIMARY KEY,
                        node_id INTEGER NOT NULL,
                        range_start INTEGER,
                        range_end INTEGER,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT uq_port_inventory_setting_node_id UNIQUE (node_id)
                    )
                    """
                )
            )
            connection.execute(text("CREATE INDEX ix_port_inventory_settings_node_id ON port_inventory_settings(node_id)"))

        if not table_exists("port_inventory_entries"):
            connection.execute(
                text(
                    """
                    CREATE TABLE port_inventory_entries (
                        id INTEGER NOT NULL PRIMARY KEY,
                        node_id INTEGER NOT NULL,
                        protocol VARCHAR(8) NOT NULL,
                        port INTEGER NOT NULL,
                        purpose VARCHAR(255) DEFAULT '',
                        source VARCHAR(32) DEFAULT 'manual',
                        detected_process VARCHAR(255),
                        detected_pid VARCHAR(64),
                        detected_source VARCHAR(255),
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT uq_port_inventory_node_protocol_port UNIQUE (node_id, protocol, port)
                    )
                    """
                )
            )
            connection.execute(text("CREATE INDEX ix_port_inventory_entries_node_id ON port_inventory_entries(node_id)"))

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
            add_column("agent_tasks", task_columns, "queue", "VARCHAR(32) DEFAULT 'control'")
            add_column("agent_tasks", task_columns, "priority", "INTEGER DEFAULT 100")
            add_column("agent_tasks", task_columns, "status", "VARCHAR(32) DEFAULT 'pending'")
            add_column("agent_tasks", task_columns, "result", "JSON")
            add_column("agent_tasks", task_columns, "started_at", "DATETIME")
            add_column("agent_tasks", task_columns, "finished_at", "DATETIME")
            add_column("agent_tasks", task_columns, "deadline_at", "DATETIME")

        if not table_exists("integration_api_keys"):
            connection.execute(
                text(
                    """
                    CREATE TABLE integration_api_keys (
                        id INTEGER NOT NULL PRIMARY KEY,
                        name VARCHAR(120) NOT NULL,
                        token_prefix VARCHAR(80) NOT NULL,
                        token_hash VARCHAR(128) NOT NULL,
                        token_hint VARCHAR(16) NOT NULL,
                        scopes JSON DEFAULT '[]' NOT NULL,
                        allowed_node_ids JSON DEFAULT '[]' NOT NULL,
                        enabled BOOLEAN DEFAULT 1 NOT NULL,
                        expires_at DATETIME,
                        last_used_at DATETIME,
                        last_used_ip VARCHAR(64),
                        created_by VARCHAR(80),
                        revoked_at DATETIME,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT uq_integration_api_keys_token_prefix UNIQUE (token_prefix)
                    )
                    """
                )
            )
            connection.execute(text("CREATE INDEX ix_integration_api_keys_token_prefix ON integration_api_keys(token_prefix)"))

        if not table_exists("looking_glass_queries"):
            connection.execute(
                text(
                    """
                    CREATE TABLE looking_glass_queries (
                        id INTEGER NOT NULL PRIMARY KEY,
                        public_id VARCHAR(64) NOT NULL,
                        api_key_id INTEGER NOT NULL,
                        node_id INTEGER NOT NULL,
                        operation VARCHAR(80) NOT NULL,
                        request JSON DEFAULT '{}' NOT NULL,
                        request_fingerprint VARCHAR(128) NOT NULL,
                        status VARCHAR(32) DEFAULT 'queued' NOT NULL,
                        agent_task_id INTEGER,
                        result JSON,
                        error_code VARCHAR(80),
                        error_message TEXT,
                        started_at DATETIME,
                        finished_at DATETIME,
                        deadline_at DATETIME,
                        expires_at DATETIME,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT uq_looking_glass_queries_public_id UNIQUE (public_id)
                    )
                    """
                )
            )
            connection.execute(text("CREATE INDEX ix_looking_glass_queries_public_id ON looking_glass_queries(public_id)"))
            connection.execute(text("CREATE INDEX ix_looking_glass_queries_api_key_id ON looking_glass_queries(api_key_id)"))
            connection.execute(text("CREATE INDEX ix_looking_glass_queries_node_id ON looking_glass_queries(node_id)"))
            connection.execute(text("CREATE INDEX ix_looking_glass_queries_agent_task_id ON looking_glass_queries(agent_task_id)"))
            connection.execute(text("CREATE INDEX ix_looking_glass_queries_status ON looking_glass_queries(status)"))
            connection.execute(text("CREATE INDEX ix_looking_glass_queries_request_fingerprint ON looking_glass_queries(request_fingerprint)"))

        if table_exists("integration_api_keys") and table_exists("looking_glass_queries"):
            purge_deleted_looking_glass_tokens(connection)

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
        if table_exists("link_monitor_samples"):
            connection.execute(
                text(
                    """
                    CREATE INDEX IF NOT EXISTS ix_link_monitor_samples_monitor_checked_at
                    ON link_monitor_samples(monitor_id, checked_at)
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
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER NOT NULL PRIMARY KEY,
                    protocol_type VARCHAR(32) NOT NULL,
                    name VARCHAR(120) NOT NULL,
                    source VARCHAR(32) DEFAULT 'managed-node',
                    managed BOOLEAN DEFAULT 1,
                    status VARCHAR(32) DEFAULT 'stopped',
                    extras JSON DEFAULT '{}',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_connections_protocol_type ON connections(protocol_type)"))
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS connection_endpoints (
                    id INTEGER NOT NULL PRIMARY KEY,
                    connection_id INTEGER NOT NULL,
                    node_id INTEGER NOT NULL,
                    role VARCHAR(32) NOT NULL,
                    interface_name VARCHAR(32) NOT NULL,
                    tunnel_ips JSON DEFAULT '[]',
                    mtu INTEGER,
                    routes JSON DEFAULT '[]',
                    runtime_status VARCHAR(32) DEFAULT 'stopped',
                    deployed_config TEXT,
                    protocol_config JSON DEFAULT '{}',
                    extras JSON DEFAULT '{}',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT uq_connection_endpoint_node_interface UNIQUE (node_id, interface_name)
                )
                """
            )
        )
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_connection_endpoints_connection_id ON connection_endpoints(connection_id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_connection_endpoints_node_id ON connection_endpoints(node_id)"))
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
                    connection_endpoint_id INTEGER,
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
        link_monitor_columns = table_columns("link_monitors")
        add_column("link_monitors", link_monitor_columns, "connection_endpoint_id", "INTEGER")
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_link_monitors_connection_endpoint_id ON link_monitors(connection_endpoint_id)"))
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
