from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from link42_common.connection_types import CONNECTION_TYPE_WIREGUARD, ConnectionTaskSet, WIREGUARD_TASKS

from . import models
from .wireguard_service import build_apply_plan, render_interface_config


@dataclass(frozen=True)
class ConnectionDriver:
    """Backend-specific behavior needed by the controller task layer."""

    type: str
    display_name: str
    tasks: ConnectionTaskSet

    def render_config(self, interface: models.WireGuardInterface) -> str:
        raise NotImplementedError

    def build_apply_payload(self, interface: models.WireGuardInterface, enable_on_boot: bool = True) -> dict[str, Any]:
        raise NotImplementedError


class WireGuardConnectionDriver(ConnectionDriver):
    def __init__(self) -> None:
        super().__init__(
            type=CONNECTION_TYPE_WIREGUARD,
            display_name="WireGuard",
            tasks=WIREGUARD_TASKS,
        )

    def render_config(self, interface: models.WireGuardInterface) -> str:
        return render_interface_config(interface)

    def build_apply_payload(self, interface: models.WireGuardInterface, enable_on_boot: bool = True) -> dict[str, Any]:
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
    """Return the connection backend for an interface.

    The database is still WireGuard-specific today, so every existing interface
    resolves to the WireGuard driver. Keeping this function in one place gives
    future connection tables or adapter fields a narrow migration point.
    """

    return WIREGUARD_DRIVER
