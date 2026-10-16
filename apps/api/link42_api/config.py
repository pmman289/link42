from __future__ import annotations

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """运行时配置。

    默认使用 SQLite，保证第一版部署足够轻量。后续如果要切换到 MySQL，
    应尽量只修改 DATABASE_URL，因为业务代码统一通过 SQLAlchemy 访问数据库。
    """

    model_config = SettingsConfigDict(env_prefix="LINK42_", env_file=".env")

    database_url: str = "sqlite:///./link42.db"
    admin_username: str = "admin"
    admin_password: str = "admin"
    # 前端构建产物目录；设置后主控可在同一端口托管 Web 面板。
    web_dist_dir: str | None = None
    # 预留给容器和后续部署读取配置文件的目录。
    config_dir: str = "/link42/config"
    # 主控内置或挂载的 Agent 发布资产目录。
    agent_release_dir: str = "/opt/link42/releases/agent"
    # 废弃配置，仅兼容旧 .env；下载地址始终从主控地址推导。
    agent_install_script_url: str | None = None
    agent_res_base_url: str | None = None
    # Agent 心跳超过该秒数后视为离线，前端和部署确认都会据此拦截。
    agent_offline_after_seconds: int = 60
    # SQLite 写锁只短暂等待，避免数据库争用把 Agent 请求挂过在线窗口。
    sqlite_busy_timeout_ms: int = 5000
    # bcrypt 登录校验允许少量并行，避免面板多个请求互相触发 429。
    login_concurrency: int = 8
    # 主控日志等级；排查问题时可设为 DEBUG。
    log_level: str = "INFO"
    # Web 会话空闲和绝对有效期；Bearer 与 Cookie 会话使用同一服务端状态。
    web_session_idle_seconds: int = 8 * 60 * 60
    web_session_absolute_seconds: int = 7 * 24 * 60 * 60
    # HTTPS 部署应保持自动模式；仅明确设为 true/false 时强制 Cookie Secure 属性。
    web_cookie_secure: str = "auto"
    # 仅信任这些直连代理的来源头，多个 CIDR 用逗号分隔。
    trusted_proxy_cidrs: str = ""
    # 需要跨源访问时显式配置，多个来源用逗号分隔；默认仅允许同源。
    cors_allowed_origins: str = ""

    @field_validator("web_session_idle_seconds", "web_session_absolute_seconds")
    @classmethod
    def validate_positive_timeout(cls, value: int) -> int:
        """拒绝无效会话时长，避免误配置成永久会话。"""

        if value < 60:
            raise ValueError("session timeout must be at least 60 seconds")
        return value

    @field_validator("agent_offline_after_seconds", "sqlite_busy_timeout_ms", "login_concurrency")
    @classmethod
    def validate_database_and_agent_timeout(cls, value: int) -> int:
        """拒绝非正的在线窗口和 SQLite 锁等待时间。"""

        if value <= 0:
            raise ValueError("timeout must be positive")
        return value


# 全局配置实例，应用启动后各模块通过它读取运行参数。
settings = Settings()
