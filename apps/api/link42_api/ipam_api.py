from __future__ import annotations

import ipaddress
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import ipam, models
from .database import get_db

router = APIRouter(prefix="/api/ipam", tags=["IPv4 地址管理"])


class PoolInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    cidr: str
    kind: Literal["node", "link"]
    link_prefix: Literal[30, 31] = 30

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("地址池名称不能为空")
        return value

    @field_validator("cidr")
    @classmethod
    def network(cls, value: str) -> str:
        network = ipaddress.ip_network(value.strip(), strict=True)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("地址池必须是 IPv4 网段")
        return str(network)


class ReservationInput(BaseModel):
    cidr: str
    note: str = Field(min_length=1, max_length=500)

    @field_validator("cidr")
    @classmethod
    def network(cls, value: str) -> str:
        return PoolInput.network(value)

    @field_validator("note")
    @classmethod
    def clean_note(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("请填写外部占用用途或所属设备")
        return value


class ReleaseInput(BaseModel):
    confirmed_cleaned: Literal[True]


class CheckInput(BaseModel):
    addresses: list[str] = Field(max_length=128)
    node_id: int | None = None
    owner: str = "check"

    @field_validator("addresses")
    @classmethod
    def valid_addresses(cls, values: list[str]) -> list[str]:
        for value in values:
            if not isinstance(ipaddress.ip_interface(value), ipaddress.IPv4Interface):
                raise ValueError("必须是 IPv4 地址")
        return values


def pool_read(item: models.IPAMPool) -> dict:
    return {"id": item.id, "name": item.name, "cidr": item.cidr, "kind": item.kind, "link_prefix": item.link_prefix}


def get_pool(db: Session, pool_id: int) -> models.IPAMPool:
    item = db.get(models.IPAMPool, pool_id)
    if item is None:
        raise HTTPException(404, "地址池不存在")
    return item


@router.get("/pools")
def pools(db: Session = Depends(get_db)) -> list[dict]:
    return [pool_read(item) for item in db.scalars(select(models.IPAMPool).order_by(models.IPAMPool.id))]


@router.post("/pools")
@ipam.transaction
def create_pool(payload: PoolInput, db: Session = Depends(get_db)) -> dict:
    network = ipaddress.ip_network(payload.cidr)
    if payload.kind == "link" and network.prefixlen > payload.link_prefix:
        raise HTTPException(422, "链路池必须容纳至少一个链路子网")
    if any(network.overlaps(ipaddress.ip_network(item.cidr)) for item in db.scalars(select(models.IPAMPool))):
        raise HTTPException(409, "地址池网段重叠")
    item = models.IPAMPool(**payload.model_dump())
    db.add(item)
    db.commit()
    return pool_read(item)


@router.delete("/pools/{pool_id}")
@ipam.transaction
def delete_pool(pool_id: int, db: Session = Depends(get_db)) -> dict:
    item = get_pool(db, pool_id)
    network = ipaddress.ip_network(item.cidr)
    occupied = db.scalar(select(models.IPAMClaim.id).where(models.IPAMClaim.ip >= int(network.network_address), models.IPAMClaim.ip <= int(network.broadcast_address)).limit(1))
    reserved = db.scalar(select(models.IPAMRange.id).where(models.IPAMRange.start <= int(network.broadcast_address), models.IPAMRange.end >= int(network.network_address)).limit(1))
    if occupied or reserved:
        raise HTTPException(409, "地址池仍有占用或预留，不能删除")
    db.delete(item)
    db.commit()
    return {"status": "deleted"}


@router.get("/pools/{pool_id}/recommend")
def recommendation(pool_id: int, db: Session = Depends(get_db)) -> dict:
    return ipam.recommend(db, get_pool(db, pool_id))


@router.post("/check")
def check(payload: CheckInput, db: Session = Depends(get_db)) -> dict:
    refs = [ipam.Reference("check", payload.owner, int(item.ip), item.network.prefixlen, payload.node_id, None, None, "tunnel")
            for item in ipam.ipv4s(payload.addresses)]
    conflicts = ipam.conflict_details(db, refs)
    return {"available": not conflicts, "conflicts": conflicts}


@router.get("/inventory")
def inventory(q: str = "", offset: Annotated[int, Query(ge=0)] = 0, limit: Annotated[int, Query(ge=1, le=500)] = 100,
              state: Literal["all", "conflict", "retained", "assigned", "reserved", "external"] = "all",
              node_id: int | None = None, pool_id: int | None = None, db: Session = Depends(get_db)) -> dict:
    claims = list(db.scalars(select(models.IPAMClaim).order_by(models.IPAMClaim.ip, models.IPAMClaim.id)))
    fixed = {(item.node_id, item.ip) for item in claims if item.kind == "fixed" and item.state == "assigned"}
    ranges = list(db.scalars(select(models.IPAMRange)))
    rows = []
    by_ip: dict[int, list[models.IPAMClaim]] = {}
    for item in claims:
        by_ip.setdefault(item.ip, []).append(item)
    for item in claims:
        ref = ipam.Reference(item.source, item.owner, item.ip, item.prefix, item.node_id, item.node_name, item.interface_name, item.kind)
        conflict = any(other.id != item.id and not ipam.compatible(ref, other, fixed) for other in by_ip[item.ip])
        conflict = conflict or any(block.start <= item.ip <= block.end and item.owner not in (block.owners or []) for block in ranges)
        row_state = displayed_state(db, item)
        siblings = [other for other in by_ip[item.ip] if other.owner == item.owner]
        rows.append({"id": item.id, "type": "address", "address": f"{ipaddress.IPv4Address(item.ip)}/{item.prefix}",
                     "source": item.source.split(":", 1)[0],
                     "node_id": item.node_id, "node_name": item.node_name, "interface_name": item.interface_name,
                     "kind": item.kind, "state": row_state, "conflict": conflict,
                     "note": item.note or ("任务已结束，主机地址尚未确认清理" if row_state != item.state else ""),
                     "can_release": row_state == "retained" and all(displayed_state(db, other) == "retained" and not pending_cleanup(db, other) for other in siblings)})
    for item in ranges:
        rows.append({"id": item.id, "type": "range", "address": item.cidr, "node_id": None, "node_name": None, "interface_name": None,
                     "source": "external" if item.kind == "external" else "link",
                     "kind": item.kind, "state": "reserved", "conflict": False, "note": item.note,
                     "can_release": item.kind == "external"})
    address_rows = [item for item in rows if item["type"] == "address"]
    def host_count(items: list[dict]) -> int:
        return len({item["address"].split("/")[0] for item in items})
    summary = {"addresses": host_count(address_rows),
               "conflicts": host_count([item for item in address_rows if item["conflict"]]),
               "retained": host_count([item for item in address_rows if item["state"] == "retained"]),
               "reservations": sum(item["kind"] == "external" for item in rows)}
    node_names = {item["node_id"]: item["node_name"] for item in address_rows if item["node_id"] is not None}
    if node_names:
        node_names.update(db.execute(select(models.Node.id, models.Node.name).where(models.Node.id.in_(node_names))).all())
    if state != "all":
        if state == "conflict":
            rows = [item for item in rows if item["conflict"]]
        elif state == "external":
            rows = [item for item in rows if item["kind"] == "external"]
        else:
            rows = [item for item in rows if item["state"] == state]
    if node_id is not None:
        rows = [item for item in rows if item["node_id"] == node_id]
    if pool_id is not None:
        network = ipaddress.ip_network(get_pool(db, pool_id).cidr)
        rows = [item for item in rows if (ipaddress.ip_network(item["address"], strict=False).overlaps(network)
                if item["type"] == "range" else ipaddress.ip_interface(item["address"]).ip in network)]
    query = q.strip().lower()
    if query:
        try:
            query_network = ipaddress.IPv4Network(query, strict=False)
        except ValueError:
            query_network = None
        def matches(item: dict) -> bool:
            if query in " ".join(str(item.get(field) or "") for field in ("address", "node_name", "interface_name", "note")).lower():
                return True
            if query_network is None:
                return False
            if item["type"] == "range":
                return ipaddress.IPv4Network(item["address"]).overlaps(query_network)
            return ipaddress.IPv4Interface(item["address"]).ip in query_network
        rows = [item for item in rows if matches(item)]
    return {"items": rows[offset:offset + limit], "total": len(rows), "summary": summary,
            "nodes": [{"id": identifier, "name": node_names[identifier]} for identifier in sorted(node_names)]}


@router.post("/reservations")
@ipam.transaction
def reserve(payload: ReservationInput, db: Session = Depends(get_db)) -> dict:
    network = ipaddress.ip_network(payload.cidr)
    start, end = int(network.network_address), int(network.broadcast_address)
    if db.scalar(select(models.IPAMClaim.id).where(models.IPAMClaim.ip >= start, models.IPAMClaim.ip <= end).limit(1)):
        raise HTTPException(409, "预留范围内已有地址占用")
    if db.scalar(select(models.IPAMRange.id).where(models.IPAMRange.start <= end, models.IPAMRange.end >= start).limit(1)):
        raise HTTPException(409, "预留网段重叠")
    item = models.IPAMRange(source=f"external:{uuid.uuid4().hex}", cidr=str(network), start=start, end=end,
                            kind="external", owners=[], note=payload.note.strip())
    db.add(item)
    db.commit()
    return {"id": item.id, "cidr": item.cidr}


def pending_cleanup(db: Session, item: models.IPAMClaim) -> bool:
    task = db.get(models.AgentTask, item.cleanup_task_id) if item.cleanup_task_id else None
    return bool(task and task.status in {"pending", "running"})


def displayed_state(db: Session, item: models.IPAMClaim) -> str:
    # Poll-time task expiry does not acquire the allocation lock. Reflect it
    # read-only here; the release transaction reconciles the durable reference.
    if item.state == "assigned" and item.source.startswith("task:"):
        task = db.get(models.AgentTask, int(item.source.split(":")[1]))
        if task is None or task.status not in {"pending", "running"}:
            return "retained"
    return item.state


@router.post("/claims/{claim_id}/release")
@ipam.transaction
def release_claim(claim_id: int, payload: ReleaseInput, db: Session = Depends(get_db)) -> dict:
    item = db.get(models.IPAMClaim, claim_id)
    if item is None:
        raise HTTPException(404, "占用记录不存在")
    current = ipam.inventory(db)
    siblings = list(db.scalars(select(models.IPAMClaim).where(models.IPAMClaim.owner == item.owner, models.IPAMClaim.ip == item.ip)))
    if item.state != "retained" or any(sibling.state != "retained" or pending_cleanup(db, sibling) for sibling in siblings) or any(ref.ip == item.ip and ref.owner == item.owner for ref in current.values()):
        raise HTTPException(409, "地址仍被配置或未完成任务引用")
    for sibling in siblings:
        db.delete(sibling)
    db.commit()
    return {"status": "released"}


@router.post("/reservations/{reservation_id}/release")
@ipam.transaction
def release_reservation(reservation_id: int, payload: ReleaseInput, db: Session = Depends(get_db)) -> dict:
    item = db.get(models.IPAMRange, reservation_id)
    if item is None:
        raise HTTPException(404, "预留不存在")
    if item.kind != "external":
        raise HTTPException(409, "链路子网必须等待双方地址释放")
    db.delete(item)
    db.commit()
    return {"status": "released"}
