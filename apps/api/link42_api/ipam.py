"""IPv4 inventory, serialized allocation and conservative configuration retirement.

Configuration writes enter ``transaction`` before touching business records. The
commit listener reconciles their final state in the SAME database transaction.
Only authenticated, non-dry-run cleanup results can retire deployed references.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
import inspect
import json
import ipaddress
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy import event, select, update, inspect as sa_inspect
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.exc import OperationalError

from link42_common.connection_types import GRE_TASKS, WIREGUARD_TASKS
from . import models


@dataclass(frozen=True)
class Reference:
    source: str
    owner: str
    ip: int
    prefix: int
    node_id: int | None
    node_name: str | None
    interface_name: str | None
    kind: str


def ipv4s(values: Any) -> list[ipaddress.IPv4Interface]:
    result = []
    for value in values if isinstance(values, list) else []:
        try:
            address = ipaddress.ip_interface(str(value))
        except ValueError:
            continue  # Existing invalid observations must not break inventory.
        if isinstance(address, ipaddress.IPv4Interface):
            result.append(address)
    return result


def config_addresses(config: Any) -> list[str]:
    if isinstance(config, dict):
        return config.get("tunnel_ips", [])
    if not isinstance(config, str):
        return []
    try:
        parsed = json.loads(config)
        if isinstance(parsed, dict):
            return parsed.get("tunnel_ips", [])
    except ValueError:
        pass
    addresses = []
    in_interface = False
    for line in config.splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("["):
            in_interface = line.lower() == "[interface]"
        elif in_interface and "=" in line:
            key, value = line.split("=", 1)
            if key.strip().lower() == "address":
                addresses.extend(value.replace(",", " ").split())
    return addresses


def config_owner(item: models.WireGuardInterface | models.ConnectionEndpoint) -> str:
    """SQLite can reuse row IDs. Allocation ownership follows an incarnation."""
    extras = item.extras if isinstance(item.extras, dict) else {}
    token = extras.get("ipam_incarnation")
    if not isinstance(token, str) or not token:
        token = uuid.uuid4().hex
        item.extras = {**extras, "ipam_incarnation": token}
    prefix = "wg" if isinstance(item, models.WireGuardInterface) else "gre"
    return f"{prefix}:{item.id}:{token}"


def inventory(db: Session) -> dict[tuple[str, int], Reference]:
    result: dict[tuple[str, int], Reference] = {}
    nodes = {node.id: node for node in db.scalars(select(models.Node).options(selectinload(models.Node.ipv4_addresses)))}
    interfaces = {item.id: item for item in db.scalars(select(models.WireGuardInterface))}
    endpoints = {item.id: item for item in db.scalars(select(models.ConnectionEndpoint))}

    def add(source: str, owner: str, node_id: int | None, name: str | None, kind: str, values: Any) -> None:
        node = nodes.get(node_id)
        for address in ipv4s(values):
            ref = Reference(source, owner, int(address.ip), address.network.prefixlen,
                            node_id, node.name if node else None, name, kind)
            result[(source, ref.ip)] = ref

    for node in nodes.values():
        add(f"node:{node.id}", f"node:{node.id}", node.id, None, "fixed", node.internal_ipv4s)
    for item in interfaces.values():
        owner = config_owner(item)
        add(f"wg:{item.id}:desired", owner, item.node_id, item.name, "tunnel", item.tunnel_ips)
        add(f"wg:{item.id}:deployed", owner, item.node_id, item.name, "deployed", config_addresses(item.deployed_config))
    for item in endpoints.values():
        owner = config_owner(item)
        add(f"gre:{item.id}:desired", owner, item.node_id, item.interface_name, "tunnel", item.tunnel_ips)
        add(f"gre:{item.id}:deployed", owner, item.node_id, item.interface_name, "deployed", config_addresses(item.deployed_config))
        protocol = item.protocol_config if isinstance(item.protocol_config, dict) else {}
        add(f"gre:{item.id}:external", f"{owner}:external", None, protocol.get("peer_interface_name"),
            "external_peer", protocol.get("peer_tunnel_ips", []))
    for item in db.scalars(select(models.ImportCandidate).where(models.ImportCandidate.imported.is_(False))):
        existing = next((wg for wg in interfaces.values() if wg.node_id == item.node_id
                         and (wg.name == item.interface_name or wg.name + ".conf" == item.path.rsplit("/", 1)[-1])), None)
        if existing:
            continue
        parsed = item.parsed if isinstance(item.parsed, dict) else {}
        add(f"candidate:{item.id}", f"candidate:{item.id}", item.node_id, item.interface_name,
            "observed", parsed.get("addresses", []))
    for task in db.scalars(select(models.AgentTask).where(models.AgentTask.status.in_(["pending", "running"]))):
        payload = task.payload if isinstance(task.payload, dict) else {}
        # Cache the incarnation for legacy stop/read/status tasks as well, so
        # a delayed report cannot act on a row whose SQLite ID was reused.
        owner = task_owner(task, db) if (payload.get("interface_id") or payload.get("connection_endpoint_id")) else f"task:{task.id}"
        if task.type not in {WIREGUARD_TASKS.apply_config, WIREGUARD_TASKS.start, GRE_TASKS.apply_config, GRE_TASKS.start}:
            continue
        values = config_addresses(payload.get("config")) if task.type == WIREGUARD_TASKS.apply_config else payload.get("tunnel_ips", [])
        if not values and task.type == WIREGUARD_TASKS.start:
            item = interfaces.get(payload.get("interface_id"))
            values = (config_addresses(item.deployed_config) or item.tunnel_ips) if item else []
        add(f"task:{task.id}", owner, task.node_id, payload.get("interface_name"), "task", values)
    return result


def task_owner(task: models.AgentTask, db: Session | None = None) -> str:
    if not isinstance(task.payload, dict):
        return f"task:{task.id}"  # Do not turn corrupt legacy payloads into valid JSON objects.
    payload = task.payload if isinstance(task.payload, dict) else {}
    owner = payload.get("ipam_owner")
    if isinstance(owner, str) and owner:
        return owner
    item = None
    if db is not None:
        if payload.get("connection_endpoint_id"):
            item = db.get(models.ConnectionEndpoint, payload["connection_endpoint_id"])
        elif payload.get("interface_id"):
            item = db.get(models.WireGuardInterface, payload["interface_id"])
    owner = config_owner(item) if item is not None else f"task:{task.id}"
    task.payload = {**payload, "ipam_owner": owner}
    return owner


def task_targets(task: models.AgentTask, item: models.WireGuardInterface | models.ConnectionEndpoint | None) -> bool:
    if item is None or item.node_id != task.node_id:
        return False
    payload = task.payload if isinstance(task.payload, dict) else {}
    owner = payload.get("ipam_owner")
    return not owner or owner == config_owner(item)


def lock(db: Session) -> None:
    """UPDATE locks on SQLite and row-locking databases; never use process locks."""
    if db.get_transaction() is not None and db.info.get("ipam_locked") is db.get_transaction():
        return
    changed = db.execute(update(models.IPAMLock).where(models.IPAMLock.id == 1)
                         .values(revision=models.IPAMLock.revision + 1))
    if not changed.rowcount:
        # Startup seeds this row before serving requests. Also supports fresh test databases.
        db.add(models.IPAMLock(id=1, revision=1))
        db.flush()
    db.info["ipam_locked"] = db.get_transaction()


def compatible(ref: Reference, claim: models.IPAMClaim, fixed: set[tuple[int | None, int]]) -> bool:
    if claim.owner == ref.owner:
        return True
    if claim.owner.startswith("retired:"):
        return False
    # Importing an already-observed device transfers the reference, not the IP.
    if (claim.kind == "observed" or ref.kind == "observed") and claim.node_id == ref.node_id and claim.interface_name == ref.interface_name:
        return True
    return (ref.node_id is not None and ref.node_id == claim.node_id
            and ref.prefix == claim.prefix == 32 and (ref.node_id, ref.ip) in fixed)


def conflict_details(db: Session, refs: list[Reference]) -> list[dict]:
    claims = list(db.scalars(select(models.IPAMClaim)))
    ranges = list(db.scalars(select(models.IPAMRange)))
    fixed = {(item.node_id, item.ip) for item in claims if item.kind == "fixed" and item.state == "assigned"}
    # Allow designation of an existing same-node /32 as its fixed address.
    fixed.update((ref.node_id, ref.ip) for ref in refs if ref.kind == "fixed")
    problems = []
    for ref in refs:
        for claim in claims:
            if claim.ip == ref.ip and not compatible(ref, claim, fixed):
                problems.append({"address": str(ipaddress.IPv4Address(ref.ip)), "claim_id": claim.id,
                                 "node_id": claim.node_id, "node_name": claim.node_name,
                                 "interface_name": claim.interface_name, "state": claim.state, "note": claim.note})
        for item in ranges:
            if item.start <= ref.ip <= item.end and ref.owner not in (item.owners or []):
                problems.append({"address": str(ipaddress.IPv4Address(ref.ip)), "cidr": item.cidr, "note": item.note})
    return problems


def reconcile(db: Session, before: dict[tuple[str, int], Reference], *, validate: bool = True,
              completed: set[int] | None = None, transfers: dict[str, str] | None = None) -> None:
    db.flush()
    after = inventory(db)
    claims = {(item.source, item.ip): item for item in db.scalars(select(models.IPAMClaim))}
    before = {**{key: Reference(item.source, item.owner, item.ip, item.prefix, item.node_id,
                               item.node_name, item.interface_name, item.kind)
                 for key, item in claims.items() if item.state == "assigned"}, **before}
    removed = set(before) - set(after)
    tasks = list(db.scalars(select(models.AgentTask).where(
        ((models.AgentTask.type.in_([WIREGUARD_TASKS.delete_config, GRE_TASKS.delete_config]))
         & models.AgentTask.status.in_(["pending", "running"])) | models.AgentTask.id.in_(completed or set())
    )))
    owners_now = {ref.owner for ref in after.values() if ref.kind != "task"}
    new_task_ids = {ref.source for key, ref in after.items() if key not in before and ref.kind == "task"}
    checked = [ref for key, ref in after.items() if ((key not in before or before[key].prefix != ref.prefix) and ref.kind in {"fixed", "tunnel", "external_peer"})
               or ref.source in new_task_ids]

    # First transfer all current references. Validation sees both sides of a pair.
    for key, ref in after.items():
        item = claims.get(key)
        if item is None:
            if db.get(models.IPAMAddress, ref.ip) is None:
                db.add(models.IPAMAddress(ip=ref.ip))
                db.flush()
            item = models.IPAMClaim(source=ref.source, ip=ref.ip)
            db.add(item)
            claims[key] = item
        for attr in ("owner", "prefix", "node_id", "node_name", "interface_name", "kind"):
            setattr(item, attr, getattr(ref, attr))
        item.state = "assigned"
        item.note = ""
    for key in removed:
        item = claims.get(key)
        if item is None:
            continue
        ref = before[key]
        # Candidate -> imported interface is a provenance transfer.
        successors = [new for new in after.values() if new.node_id == ref.node_id
                      and new.interface_name == ref.interface_name and new.ip == ref.ip
                      and new.owner != ref.owner and (new.kind == "observed" or ref.kind == "observed")]
        transferred = bool(successors)
        if transferred:
            for block in db.scalars(select(models.IPAMRange).where(models.IPAMRange.kind == "link")):
                if block.start <= ref.ip <= block.end and ref.owner in (block.owners or []):
                    block.owners = list(set(block.owners + [successor.owner for successor in successors]))
            db.delete(item)
        else:
            item.state = "retained"
            item.note = "原配置已删除或改址，尚未确认主机清理"

    # Explicit imported-interface replacement keeps the allocation while its
    # old-file cleanup and new deployment execute in dependency order.
    for item in claims.values():
        successor = (transfers or {}).get(item.owner)
        if successor and not sa_inspect(item).deleted:
            old_owner = item.owner
            item.owner = successor
            for block in db.scalars(select(models.IPAMRange).where(models.IPAMRange.kind == "link")):
                if block.start <= item.ip <= block.end and old_owner in (block.owners or []):
                    block.owners = list(set(block.owners + [successor]))

    db.flush()
    if transfers:
        sync_link_ranges(db, after)
        db.flush()
    if validate:
        problems = conflict_details(db, checked)
        if problems:
            raise HTTPException(409, detail={"message": "IPv4 地址已被占用", "conflicts": problems})

    # Persist claim/task associations BEFORE deletion results; no business FK needed.
    for task in tasks:
        if task.type not in {WIREGUARD_TASKS.delete_config, GRE_TASKS.delete_config} or task.status not in {"pending", "running"}:
            continue
        payload = task.payload if isinstance(task.payload, dict) else {}
        owner = task_owner(task, db)
        for key, item in claims.items():
            original = before.get(key)
            if not sa_inspect(item).deleted and ((item.owner == owner or (original and original.owner == owner)
                    or (item.kind == "observed" and item.node_id == task.node_id))
                    and item.interface_name == payload.get("interface_name") and item.kind != "external_peer"):
                item.cleanup_task_id = task.id
    db.flush()
    # Only a newly completed success can release its associated generation.
    for task in tasks:
        result = task.result if isinstance(task.result, dict) else {}
        if task.id not in (completed or set()) or task.status != "succeeded" or has_dry_run(result):
            continue
        if task.type in {WIREGUARD_TASKS.delete_config, GRE_TASKS.delete_config}:
            targets = list(db.scalars(select(models.IPAMClaim).where(models.IPAMClaim.cleanup_task_id == task.id)))
            for item in targets:
                if item.kind == "observed" and item.source.startswith("candidate:"):
                    # A later scan may describe a recreated file. Keep that newer
                    # observation rather than trusting an older cleanup result.
                    newer_scan = db.scalar(select(models.AgentTask.id).where(
                        models.AgentTask.node_id == task.node_id,
                        models.AgentTask.type == WIREGUARD_TASKS.import_scan,
                        models.AgentTask.id > task.id,
                    ).limit(1))
                    candidate = db.get(models.ImportCandidate, int(item.source.split(":")[1]))
                    if candidate is not None and not newer_scan:
                        db.delete(candidate)
                        after = {key: ref for key, ref in after.items() if ref.source != item.source}
                # Current desired or newer in-flight configuration always protects the host.
                live = [ref for ref in after.values() if ref.ip == item.ip and ref.source == item.source]
                if not live:
                    db.delete(item)
        elif task.type in {WIREGUARD_TASKS.apply_config, GRE_TASKS.start}:
            # A successful replacement removes addresses from the former deployed baseline.
            owner = task_owner(task, db)
            payload = task.payload if isinstance(task.payload, dict) else {}
            target = db.get(models.WireGuardInterface, payload.get("interface_id")) if payload.get("interface_id") else None
            if task.type == GRE_TASKS.start:
                target = db.get(models.ConnectionEndpoint, payload.get("connection_endpoint_id")) if payload.get("connection_endpoint_id") else None
            if not task_targets(task, target):
                # A finished apply on a deleted incarnation may have left a
                # live config on the host. It is not evidence of cleanup.
                continue
            if payload.get("previous_interface_name") and not previous_cleanup_confirmed(db, task, result):
                continue
            for item in list(db.scalars(select(models.IPAMClaim).where(models.IPAMClaim.owner == owner, models.IPAMClaim.state == "retained"))):
                if item.kind in {"tunnel", "deployed", "task"} and not any(ref.owner == owner and ref.ip == item.ip for ref in after.values()):
                    db.delete(item)
    db.flush()
    retirement_tokens: dict[str, str] = {}
    for key, item in claims.items():
        if (key not in after and not sa_inspect(item).deleted and item.owner not in owners_now
                and not item.owner.startswith("retired:")):
            old_owner = item.owner
            token = retirement_tokens.setdefault(old_owner, uuid.uuid4().hex)
            item.owner = f"retired:{token}"
            item.source = f"retired:{token}:{key[0]}"
            for block in db.scalars(select(models.IPAMRange).where(models.IPAMRange.kind == "link")):
                if block.start <= item.ip <= block.end and old_owner in (block.owners or []):
                    block.owners = [*block.owners, item.owner]
    db.flush()
    sync_link_ranges(db, after, validate_owners={ref.owner for ref in checked} if validate else set())


def has_dry_run(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value.get("dry_run")) or any(has_dry_run(item) for item in value.values())
    if isinstance(value, list):
        return any(has_dry_run(item) for item in value)
    return False


def previous_cleanup_confirmed(db: Session, task: models.AgentTask, result: dict) -> bool:
    if task.type == GRE_TASKS.start:
        cleanup = result.get("previous_config_cleanup")
        return isinstance(cleanup, dict) and not has_dry_run(cleanup)
    payload = task.payload if isinstance(task.payload, dict) else {}
    dependency = db.get(models.AgentTask, payload.get("depends_on_task_id")) if payload.get("depends_on_task_id") else None
    return bool(dependency and dependency.type == WIREGUARD_TASKS.delete_config and dependency.status == "succeeded"
                and not has_dry_run(dependency.result))


def link_groups(db: Session) -> dict[str, list[str]]:
    groups = {}
    interfaces = {item.id: item for item in db.scalars(select(models.WireGuardInterface).options(selectinload(models.WireGuardInterface.peers)))}
    for item in interfaces.values():
        peer = next((p.peer_interface_id for p in item.peers if p.peer_interface_id), None)
        owner = config_owner(item)
        members = sorted({owner, config_owner(interfaces[peer])} if peer in interfaces else {owner})
        groups[owner] = members
    for item in db.scalars(select(models.ConnectionEndpoint).options(selectinload(models.ConnectionEndpoint.connection).selectinload(models.Connection.endpoints))):
        owner = config_owner(item)
        members = sorted(config_owner(ep) for ep in item.connection.endpoints)
        if isinstance(item.protocol_config, dict) and item.protocol_config.get("peer_tunnel_ips"):
            members.append(f"{owner}:external")
        groups[owner] = members
        groups[f"{owner}:external"] = members
    return groups


def sync_link_ranges(db: Session, refs: dict[tuple[str, int], Reference], *, validate_owners: set[str] | None = None) -> None:
    pools = list(db.scalars(select(models.IPAMPool).where(models.IPAMPool.kind == "link")))
    ranges = {item.source: item for item in db.scalars(select(models.IPAMRange).where(models.IPAMRange.kind == "link"))}
    groups = link_groups(db)
    fixed = {(ref.node_id, ref.ip) for ref in refs.values() if ref.kind == "fixed"}
    for ref in refs.values():
        if ref.kind == "fixed" or (ref.prefix == 32 and (ref.node_id, ref.ip) in fixed):
            continue
        for pool in pools:
            network = ipaddress.ip_network(pool.cidr)
            if ipaddress.IPv4Address(ref.ip) not in network:
                continue
            subnet = ipaddress.ip_network(f"{ipaddress.IPv4Address(ref.ip)}/{pool.link_prefix}", strict=False)
            owners = groups.get(ref.owner, [ref.owner])
            source = "link:" + ",".join(owners) + ":" + str(subnet)
            overlapping = list(db.scalars(select(models.IPAMRange).where(models.IPAMRange.start <= int(subnet.broadcast_address), models.IPAMRange.end >= int(subnet.network_address))))
            validate = ref.owner in (validate_owners or set())
            member_claims = list(db.scalars(select(models.IPAMClaim).where(models.IPAMClaim.ip >= int(subnet.network_address), models.IPAMClaim.ip <= int(subnet.broadcast_address))))
            same_blocks = [item for item in overlapping if item.kind == "link" and item.cidr == str(subnet)
                           and all(claim.owner in owners for claim in member_claims)]
            same_block = same_blocks[0] if same_blocks else None
            for duplicate in same_blocks[1:]:
                ranges.pop(duplicate.source, None)
                db.delete(duplicate)
            if len(same_blocks) > 1:
                db.flush()
                overlapping = [item for item in overlapping if not sa_inspect(item).deleted]
            if same_block and same_block.source != source:
                ranges.pop(same_block.source, None)
                same_block.source = source
                same_block.owners = owners
                ranges[source] = same_block
            if validate and any(item.source != source for item in overlapping):
                raise HTTPException(409, "链路子网已被占用或预留")
            if validate and any(subnet.network_address <= ipaddress.IPv4Address(item.ip) <= subnet.broadcast_address and item.owner not in owners
                                for item in db.scalars(select(models.IPAMClaim))):
                raise HTTPException(409, "链路子网内已有其他地址占用")
            if source not in ranges:
                item = models.IPAMRange(source=source, cidr=str(subnet), start=int(subnet.network_address),
                                        end=int(subnet.broadcast_address), kind="link", owners=owners, note="链路专用子网")
                db.add(item)
                ranges[source] = item
                db.flush()
    claims = list(db.scalars(select(models.IPAMClaim)))
    for item in ranges.values():
        # Retained references preserve the complete block, including deleted owners.
        if not any(item.start <= claim.ip <= item.end for claim in claims):
            db.delete(item)


def validate_pool_hint(db: Session, payload: Any) -> None:
    pool_id = getattr(payload, "ipv4_link_pool_id", None)
    if pool_id is None:
        return
    pool = db.get(models.IPAMPool, pool_id)
    if pool is None or pool.kind != "link":
        raise HTTPException(422, "请选择链路地址池")
    values = list(getattr(payload, "local_tunnel_ips", getattr(payload, "tunnel_ips", [])))
    values.extend(getattr(payload, "peer_tunnel_ips", []))
    addresses = ipv4s(values)
    if not addresses:
        raise HTTPException(422, "链路池分配必须包含 IPv4 地址")
    network = ipaddress.ip_network(pool.cidr)
    subnets = {str(item.network) for item in addresses}
    if (len(subnets) != 1 or len({int(item.ip) for item in addresses}) != len(addresses)
            or any(item.ip not in network or item.network.prefixlen != pool.link_prefix for item in addresses)):
        raise HTTPException(422, "双方 IPv4 地址必须属于所选地址池的同一个链路子网")
    if pool.link_prefix == 30 and any(item.ip in {item.network.network_address, item.network.broadcast_address} for item in addresses):
        raise HTTPException(422, "/30 链路不能使用网络地址或广播地址")


def transaction(function=None, *, observe: bool = False, authorize=None):
    """Wrap address-writing API functions, including direct calls in regression tests."""
    if function is None:
        return lambda fn: transaction(fn, observe=observe, authorize=authorize)
    signature = inspect.signature(function)

    @wraps(function)
    def wrapped(*args, **kwargs):
        bound = signature.bind(*args, **kwargs)
        db = bound.arguments["db"]
        if authorize is not None:
            authorize(bound.arguments)
        try:
            lock(db)
        except OperationalError as exc:
            db.rollback()
            if not any(marker in str(exc.orig).lower() for marker in
                       ("database is locked", "database table is locked", "database is busy",
                        "lock wait timeout", "could not obtain lock", "deadlock detected")):
                raise
            raise HTTPException(409, "地址分配忙，请重试") from exc
        before = inventory(db)
        task_states = dict(db.execute(select(models.AgentTask.id, models.AgentTask.status)
                                      .where(models.AgentTask.status.in_(["pending", "running"]))).all())
        # Backfill a fresh/legacy database without rejecting observed duplicates.
        reconcile(db, before, validate=False)
        db.flush()

        finalized = False

        def finalize(session):
            nonlocal finalized
            # Task enqueue helpers commit their own savepoints. Reconciliation
            # must see the COMPLETE operation at the outer transaction commit.
            if finalized or session.in_nested_transaction():
                return
            session.flush()
            completed = {task_id for task_id, status in session.execute(select(models.AgentTask.id, models.AgentTask.status)
                                                                      .where(models.AgentTask.id.in_(task_states)))
                         if status == "succeeded" and task_states.get(task_id) != "succeeded"}
            transfers = replacement_transfers(session, bound.arguments, before)
            reconcile(session, before, validate=not observe, completed=completed, transfers=transfers)
            finalized = True

        validate_pool_hint(db, bound.arguments.get("payload"))
        savepoint = db.begin_nested()
        event.listen(db, "before_commit", finalize)
        try:
            return function(*args, **kwargs)
        except Exception:
            if savepoint.is_active:
                savepoint.rollback()
            else:
                db.rollback()
            raise
        finally:
            event.remove(db, "before_commit", finalize)
            db.info.pop("ipam_locked", None)
    # FastAPI evaluates postponed annotations in the wrapper module's globals.
    wrapped.__signature__ = signature.replace(
        parameters=[parameter.replace(annotation=inspect.get_annotations(function, eval_str=True).get(name, parameter.annotation))
                    for name, parameter in signature.parameters.items()],
        return_annotation=inspect.get_annotations(function, eval_str=True).get("return", signature.return_annotation),
    )
    return wrapped


def replacement_transfers(db: Session, arguments: dict, before: dict[tuple[str, int], Reference]) -> dict[str, str]:
    payload = arguments.get("payload")
    result = {}
    for side in ("local", "peer"):
        old_id = getattr(payload, f"replace_{side}_interface_id", None)
        if not old_id:
            continue
        node_id = arguments.get("node_id") if side == "local" else payload.peer_node_id
        name = getattr(payload, f"{side}_interface_name", None) or payload.local_interface_name
        successor = db.scalar(select(models.WireGuardInterface).where(models.WireGuardInterface.node_id == node_id,
                                                                       models.WireGuardInterface.name == name))
        if successor:
            for ref in before.values():
                if ref.source.startswith(f"wg:{old_id}:"):
                    result[ref.owner] = config_owner(successor)
    return result


def recommend(db: Session, pool: models.IPAMPool) -> dict:
    network = ipaddress.IPv4Network(pool.cidr)
    block = 1 if pool.kind == "node" else 1 << (32 - pool.link_prefix)
    occupied = [(item.ip, item.ip) for item in db.scalars(select(models.IPAMClaim))]
    occupied.extend((item.start, item.end) for item in db.scalars(select(models.IPAMRange)))
    candidate = int(network.network_address)
    end = int(network.broadcast_address)
    if pool.kind == "node" and network.prefixlen < 31:
        candidate += 1
        end -= 1
    for start, finish in sorted(occupied):
        if finish < candidate or start > end:
            continue
        if start > candidate + block - 1:
            break
        candidate = finish + 1
        if block > 1:
            candidate = ((candidate + block - 1) // block) * block
    if candidate + block - 1 > end:
        raise HTTPException(409, "地址池没有可用地址")
    if pool.kind == "node":
        addresses = [f"{ipaddress.IPv4Address(candidate)}/32"]
        subnet = addresses[0]
    else:
        subnet = str(ipaddress.ip_network(f"{ipaddress.IPv4Address(candidate)}/{pool.link_prefix}"))
        offset = 1 if pool.link_prefix == 30 else 0
        addresses = [f"{ipaddress.IPv4Address(candidate + offset + side)}/{pool.link_prefix}" for side in (0, 1)]
    return {"pool_id": pool.id, "subnet": subnet, "addresses": addresses}
