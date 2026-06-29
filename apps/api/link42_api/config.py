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
    # 前端构建产物目录；设置后主控可在同一端口托管 Web 面板。
    web_dist_dir: str | None = None
    # 预留给容器和后续部署读取配置文件的目录。
    config_dir: str = "/link42/config"
    # 主控内置或挂载的 Agent 发布资产目录。
    agent_release_dir: str = "/opt/link42/releases/agent"
    # 外部一键安装脚本地址；节点不支持自升级时由前端展示。
    agent_install_script_url: str = "https://get.pmman.tech/sh/link42-agent.sh"
    # 外部 Agent 资源地址；安装脚本会使用该地址下载版本化二进制。
    agent_res_base_url: str = "https://get.pmman.tech/res/link42"
    # Agent 心跳超过该秒数后视为离线，前端和部署确认都会据此拦截。
    agent_offline_after_seconds: int = 15


# 全局配置实例，应用启动后各模块通过它读取运行参数。
settings = Settings()
