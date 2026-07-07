from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from link42_common.connection_types import CONNECTION_TYPE_WIREGUARD, ConnectionTaskSet, WIREGUARD_TASKS

from . import models
from .wireguard_service import build_apply_plan, render_interface_config


@dataclass(frozen=True)
class ConnectionDriver:
    """主控任务层需要的连接后端差异化行为。"""

    type: str
    display_name: str
    tasks: ConnectionTaskSet

    def render_config(self, interface: models.WireGuardInterface) -> str:
        """把接口期望状态渲染为后端原生配置文本。"""

        raise NotImplementedError

    def build_apply_payload(self, interface: models.WireGuardInterface, enable_on_boot: bool = True) -> dict[str, Any]:
        """把接口期望状态转换为 Agent apply 任务 payload。"""

        raise NotImplementedError


class WireGuardConnectionDriver(ConnectionDriver):
    """WireGuard/wg-quick 连接后端实现。"""

    def __init__(self) -> None:
        """初始化 WireGuard 后端的任务映射。"""

        super().__init__(
            type=CONNECTION_TYPE_WIREGUARD,
            display_name="WireGuard",
            tasks=WIREGUARD_TASKS,
        )

    def render_config(self, interface: models.WireGuardInterface) -> str:
        """渲染 wg-quick 配置文本。"""

        return render_interface_config(interface)

    def build_apply_payload(self, interface: models.WireGuardInterface, enable_on_boot: bool = True) -> dict[str, Any]:
        """生成 WireGuard apply_config 任务 payload。"""

        payload = build_apply_plan(interface)
        payload.update(
            {
                "managed": True,
                "enable_on_boot": enable_on_boot,
                "auto_start": True,
            }
        )
        return payload


WIREGUARD_DRIVER = WireGuardConnectionDriver()
CONNECTION_DRIVERS: dict[str, ConnectionDriver] = {
    WIREGUARD_DRIVER.type: WIREGUARD_DRIVER,
}


def connection_driver_for_interface(interface: models.WireGuardInterface) -> ConnectionDriver:
    """返回接口对应的连接后端。

    当前数据库仍以 WireGuard 为中心，所以现有接口都会解析为 WireGuard 后端。
    把入口收敛在这里，可以给后续新增连接表或适配字段留下清晰迁移点。
    """

    return WIREGUARD_DRIVER
