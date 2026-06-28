from __future__ import annotations

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
    # Agent 心跳超过该秒数后视为离线，前端和部署确认都会据此拦截。
    agent_offline_after_seconds: int = 15


# 全局配置实例，应用启动后各模块通过它读取运行参数。
settings = Settings()
