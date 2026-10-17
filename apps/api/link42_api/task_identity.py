"""Match delayed task results to the same configuration instance, even after ID reuse."""
from __future__ import annotations

import uuid

from . import models


def config_identity(item: models.WireGuardInterface | models.ConnectionEndpoint) -> str:
    extras = item.extras if isinstance(item.extras, dict) else {}
    # Reuse identities issued before the address pool feature was removed.
    token = extras.get("config_instance") or extras.get("ipam_incarnation")
    if not isinstance(token, str) or not token:
        token = uuid.uuid4().hex
        item.extras = {**extras, "config_instance": token}
    prefix = "wg" if isinstance(item, models.WireGuardInterface) else "gre"
    return f"{prefix}:{item.id}:{token}"


def task_targets(
    task: models.AgentTask,
    item: models.WireGuardInterface | models.ConnectionEndpoint | None,
) -> bool:
    if item is None or item.node_id != task.node_id:
        return False
    payload = task.payload if isinstance(task.payload, dict) else {}
    identity = payload.get("config_identity") or payload.get("ipam_owner")
    return not identity or identity == config_identity(item)
