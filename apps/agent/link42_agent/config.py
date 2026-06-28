from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass
class AgentConfig:
    """Agent 运行配置。"""

    server_url: str
    node_id: int
    token: str
    poll_interval: int = 5
    wireguard_dir: str = "/etc/wireguard"
    dry_run: bool = False


def load_config_from_env() -> AgentConfig:
    """从环境变量读取 Agent 配置，便于 systemd 和容器复用同一入口。"""

    return AgentConfig(
        server_url=os.environ["LINK42_SERVER_URL"].rstrip("/"),
        node_id=int(os.environ["LINK42_NODE_ID"]),
        token=os.environ["LINK42_AGENT_TOKEN"],
        poll_interval=int(os.environ.get("LINK42_POLL_INTERVAL", "5")),
        wireguard_dir=os.environ.get("LINK42_WIREGUARD_DIR", "/etc/wireguard"),
        dry_run=os.environ.get("LINK42_AGENT_DRY_RUN", "0") == "1",
    )
