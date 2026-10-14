from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import ipaddress

from fastapi import HTTPException
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session

from link42_api import ipam, models, schemas
from link42_api.database import Base
from link42_api.ipam_api import (PoolInput, ReservationInput, ReleaseInput, create_pool, reserve,
                                 release_claim, release_reservation, inventory as read_inventory)
from link42_api.main import create_node, update_node, agent_task_result, delete_interface
from link42_common.connection_types import WIREGUARD_TASKS


@pytest.fixture
def engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'ipam.db'}", connect_args={"timeout": 5})
    @event.listens_for(engine, "connect")
    def configure(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(models.IPAMLock(id=1, revision=0))
        db.commit()
    yield engine
    engine.dispose()


def node(db, name="a", addresses=None):
    result = create_node(schemas.NodeCreate(name=name, endpoint_ips=["192.0.2.1"], internal_ipv4s=addresses or []), db)
    return db.get(models.Node, result.node.id)


@ipam.transaction
def tunnel(db, node_id, addresses, name="wg0"):
    item = models.WireGuardInterface(node_id=node_id, name=name, tunnel_ips=addresses, runtime_status="stopped")
    db.add(item)
    db.commit()
    return item.id


@ipam.transaction
def change_tunnel(db, interface_id, addresses):
    item = db.get(models.WireGuardInterface, interface_id)
    item.tunnel_ips = addresses
    db.commit()


@ipam.transaction
def enqueue(db, node_id, interface_id, task_type, payload=None):
    item = db.get(models.WireGuardInterface, interface_id)
    task = models.AgentTask(node_id=node_id, type=task_type, status="running",
                            payload={"interface_id": interface_id, "interface_name": item.name, **(payload or {})})
    db.add(task)
    db.commit()
    return task.id


def occupied(db):
    return {str(ipaddress.IPv4Address(claim.ip)) for claim in db.scalars(select(models.IPAMClaim))}


def test_fixed_addresses_are_independent_from_entrypoint_and_patch_omission(engine):
    with Session(engine) as db:
        item = node(db, addresses=["10.0.0.1"])
        assert item.internal_ipv4s == ["10.0.0.1/32"]
        assert item.endpoint_ips == ["192.0.2.1"]
        update_node(item.id, schemas.NodeUpdate(name="renamed", endpoint_ips=["192.0.2.2"]), db)
        assert item.internal_ipv4s == ["10.0.0.1/32"]
        assert schemas.NodeRead.model_validate(item).internal_ipv4s == ["10.0.0.1/32"]


@pytest.mark.parametrize("values", [["10.0.0.1/24"], ["::1/128"], ["10.0.0.1", "10.0.0.1/32"]])
def test_invalid_fixed_addresses(values):
    with pytest.raises(ValidationError):
        schemas.NodeCreate(name="a", endpoint_ips=["192.0.2.1"], internal_ipv4s=values)


def test_same_node_fixed_reuse_and_cross_node_rejection(engine):
    with Session(engine) as db:
        a = node(db, "a", ["10.0.0.1/32"])
        b = node(db, "b")
        tunnel(db, a.id, ["10.0.0.1/32"], "wg1")
        tunnel(db, a.id, ["10.0.0.1/32"], "wg2")
        with pytest.raises(HTTPException) as error:
            tunnel(db, b.id, ["10.0.0.1/32"], "wg3")
        assert error.value.status_code == 409
        assert error.value.detail["conflicts"][0]["node_name"] == "a"
        assert db.scalar(select(models.WireGuardInterface).where(models.WireGuardInterface.name == "wg3")) is None


def test_same_host_different_mask_conflicts_but_different_hosts_do_not(engine):
    with Session(engine) as db:
        a, b = node(db, "a"), node(db, "b")
        tunnel(db, a.id, ["10.1.1.1/24"], "wg1")
        tunnel(db, b.id, ["10.1.1.2/24"], "wg2")
        with pytest.raises(HTTPException):
            tunnel(db, b.id, ["10.1.1.1/32"], "wg3")
        with pytest.raises(HTTPException):
            tunnel(db, a.id, ["10.1.1.1/24"], "wg4")


@pytest.mark.parametrize("prefix,expected", [(30, ["10.2.0.1/30", "10.2.0.2/30"]), (31, ["10.2.0.0/31", "10.2.0.1/31"])])
def test_link_recommendations_and_full_block_occupation(engine, prefix, expected):
    with Session(engine) as db:
        pool_data = create_pool(PoolInput(name="links", cidr="10.2.0.0/24", kind="link", link_prefix=prefix), db)
        pool = db.get(models.IPAMPool, pool_data["id"])
        assert ipam.recommend(db, pool)["addresses"] == expected
        assert ipam.recommend(db, pool)["addresses"] == expected  # Recommendations don't reserve.
        a = node(db)
        tunnel(db, a.id, [expected[0]])
        next_ip = "10.2.0.5/30" if prefix == 30 else "10.2.0.2/31"
        assert ipam.recommend(db, pool)["addresses"][0] == next_ip


def test_reservations_overlap_exhaustion_and_large_pool(engine):
    with Session(engine) as db:
        data = create_pool(PoolInput(name="nodes", cidr="10.0.0.0/8", kind="node"), db)
        pool = db.get(models.IPAMPool, data["id"])
        reserve(ReservationInput(cidr="10.0.0.0/9", note="external"), db)
        assert ipam.recommend(db, pool)["addresses"] == ["10.128.0.0/32"]
        with pytest.raises(HTTPException):
            create_pool(PoolInput(name="overlap", cidr="10.1.0.0/16", kind="link"), db)
        reserve(ReservationInput(cidr="10.128.0.0/9", note="external"), db)
        with pytest.raises(HTTPException):
            ipam.recommend(db, pool)
        with pytest.raises(HTTPException):
            node(db, addresses=["10.0.0.1/32"])


def test_pool_hint_rejects_invalid_pair(engine):
    with Session(engine) as db:
        pool = create_pool(PoolInput(name="links", cidr="10.2.0.0/24", kind="link"), db)
        for values in [["10.2.0.0/30"], ["10.2.0.1/32"], ["10.3.0.1/30"], ["10.2.0.1/30", "10.2.0.5/30"]]:
            payload = schemas.InterfaceCreate(name="wg0", tunnel_ips=values, ipv4_link_pool_id=pool["id"])
            with pytest.raises(HTTPException):
                ipam.validate_pool_hint(db, payload)


def test_concurrent_allocation_is_atomic(engine):
    with Session(engine) as db:
        a_id, b_id = node(db, "a").id, node(db, "b").id
    def allocate(node_id):
        with Session(engine) as db:
            try:
                tunnel(db, node_id, ["10.4.0.1/32"])
                return "success"
            except HTTPException as error:
                return error.status_code
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(allocate, [a_id, b_id]), key=str) == [409, "success"]
    with Session(engine) as db:
        assert len(list(db.scalars(select(models.WireGuardInterface)))) == 1


def test_legacy_duplicates_backfill_idempotently_and_unrelated_edits_work(engine):
    with Session(engine) as db:
        a, b = node(db, "a"), node(db, "b")
        db.add_all([models.WireGuardInterface(node_id=a.id, name="wg1", tunnel_ips=["10.5.0.1/32"]),
                    models.WireGuardInterface(node_id=b.id, name="wg2", tunnel_ips=["10.5.0.1/32"])])
        db.commit()
        ipam.lock(db)
        ipam.reconcile(db, {}, validate=False)
        db.commit()
        count = len(list(db.scalars(select(models.IPAMClaim))))
        ipam.reconcile(db, {}, validate=False)
        db.commit()
        assert len(list(db.scalars(select(models.IPAMClaim)))) == count
        assert all(row["conflict"] for row in read_inventory(db=db)["items"])
        update_node(a.id, schemas.NodeUpdate(name="a-new", endpoint_ips=["192.0.2.3"]), db)
        assert a.name == "a-new"


def test_import_candidate_transfer_does_not_double_count(engine):
    with Session(engine) as db:
        a = node(db)
        candidate = models.ImportCandidate(node_id=a.id, path="/etc/wireguard/wg0.conf", interface_name="wg0",
                                           parsed={"addresses": ["10.6.0.1/32"]}, warnings=[])
        db.add(candidate)
        db.commit()
        ipam.reconcile(db, {}, validate=False)
        db.commit()
        @ipam.transaction(observe=True)
        def transfer(db):
            candidate.imported = True
            db.add(models.WireGuardInterface(node_id=a.id, name="wg0", tunnel_ips=["10.6.0.1/32"]))
            db.commit()
        transfer(db)
        assert len(list(db.scalars(select(models.IPAMClaim)))) == 1


def test_inventory_reads_existing_sources_and_filters_without_mask_or_snapshot_inflation(engine):
    with Session(engine) as db:
        a = node(db, "existing-a", ["10.40.0.1/32"])
        b = node(db, "existing-b")
        # Bypass new-allocation validation to simulate legacy configurations.
        db.add_all([
            models.WireGuardInterface(node_id=a.id, name="wg-legacy", tunnel_ips=["10.41.0.1/24", "fd42::1/64"],
                                      deployed_config="[Interface]\nAddress = 10.41.0.1/24, fd42::1/64"),
            models.WireGuardInterface(node_id=b.id, name="wg-duplicate", tunnel_ips=["10.41.0.1/32"]),
            models.ImportCandidate(node_id=a.id, path="/etc/wireguard/wg-scan.conf", interface_name="wg-scan",
                                   parsed={"addresses": ["10.41.0.2/32"]}),
        ])
        connection = models.Connection(protocol_type="gre", name="legacy-gre")
        db.add(connection)
        db.flush()
        db.add(models.ConnectionEndpoint(connection_id=connection.id, node_id=b.id, role="local",
                                        interface_name="gre-legacy", tunnel_ips=["10.41.0.3/30"]))
        db.commit()
        ipam.lock(db)
        ipam.reconcile(db, {}, validate=False)
        db.commit()
        pool = create_pool(PoolInput(name="legacy", cidr="10.41.0.0/24", kind="node"), db)
        reserve(ReservationInput(cidr="10.42.0.0/24", note="external-router"), db)

        result = read_inventory(db=db)
        assert result["summary"] == {"addresses": 4, "conflicts": 1, "retained": 0, "reservations": 1}
        assert result["nodes"] == [{"id": a.id, "name": "existing-a"}, {"id": b.id, "name": "existing-b"}]
        assert {row["source"] for row in result["items"]} == {"node", "wg", "gre", "candidate", "external"}
        assert "192.0.2.1" not in occupied(db)
        filtered = read_inventory(state="conflict", pool_id=pool["id"], node_id=b.id, db=db)
        assert filtered["total"] == 1
        assert filtered["items"][0]["interface_name"] == "wg-duplicate"
        assert filtered["summary"] == result["summary"]  # Global counts remain stable across filters.
        assert read_inventory(state="external", q="external-router", db=db)["total"] == 1
        page = read_inventory(pool_id=pool["id"], offset=1, limit=2, db=db)
        assert page["total"] == 5 and len(page["items"]) == 2
        assert all(row["address"].startswith("10.41.") for row in page["items"])
        assert not db.new and not db.dirty and not db.deleted


def test_pool_inventory_matches_host_not_interface_network_and_includes_overlapping_reservation(engine):
    with Session(engine) as db:
        a = node(db)
        tunnel(db, a.id, ["10.43.0.129/24"])
        pool = create_pool(PoolInput(name="first-half", cidr="10.43.0.0/25", kind="node"), db)
        reserve(ReservationInput(cidr="10.43.0.0/26", note="reserved"), db)
        result = read_inventory(pool_id=pool["id"], db=db)
        assert result["total"] == 1
        assert result["items"][0]["address"] == "10.43.0.0/26"
        assert read_inventory(q="10.43.0.10", db=db)["items"][0]["address"] == "10.43.0.0/26"
        assert read_inventory(q="10.43.0.0/25", db=db)["total"] == 1
        assert read_inventory(q="10.43.0.129", db=db)["total"] == 1
        assert read_inventory(q="10.43.0.80", db=db)["total"] == 0


def test_edit_retains_old_address_until_replacement_succeeds(engine, monkeypatch):
    monkeypatch.setattr("link42_api.main.verify_token", lambda *_: True)
    with Session(engine) as db:
        a = node(db)
        interface_id = tunnel(db, a.id, ["10.7.0.1/32"])
        item = db.get(models.WireGuardInterface, interface_id)
        item.deployed_config = "[Interface]\nAddress = 10.7.0.1/32\n"
        db.commit()
        change_tunnel(db, interface_id, ["10.7.0.2/32"])
        assert occupied(db) == {"10.7.0.1", "10.7.0.2"}
        task_id = enqueue(db, a.id, interface_id, WIREGUARD_TASKS.apply_config,
                          {"config": "[Interface]\nAddress = 10.7.0.2/32\n"})
        agent_task_result(task_id, schemas.AgentTaskResultRequest(node_id=a.id, token="token", status="succeeded", result={}), db)
        assert occupied(db) == {"10.7.0.2"}


@pytest.mark.parametrize("status,result,expected", [("succeeded", {}, set()), ("failed", {"error": "failed"}, {"10.8.0.1"}),
                                                       ("succeeded", {"dry_run": True}, {"10.8.0.1"})])
def test_deletion_releases_only_after_real_cleanup(engine, monkeypatch, status, result, expected):
    monkeypatch.setattr("link42_api.main.verify_token", lambda *_: True)
    with Session(engine) as db:
        a = node(db)
        a.status = "online"
        a.last_seen_at = datetime.utcnow()
        a.agent_version = "0.6.23"
        a.agent_capabilities = ["wireguard"]
        db.commit()
        interface_id = tunnel(db, a.id, ["10.8.0.1/32"])
        delete_interface(interface_id, db, delete_node_config=True)
        assert occupied(db) == {"10.8.0.1"}
        task = db.scalar(select(models.AgentTask).where(models.AgentTask.type == WIREGUARD_TASKS.delete_config))
        assert task is not None
        claim = db.scalar(select(models.IPAMClaim))
        with pytest.raises(HTTPException):
            release_claim(claim.id, ReleaseInput(confirmed_cleaned=True), db)
        task.status = "running"
        db.commit()
        agent_task_result(task.id, schemas.AgentTaskResultRequest(node_id=a.id, token="token", status=status, result=result), db)
        assert occupied(db) == expected
        agent_task_result(task.id, schemas.AgentTaskResultRequest(node_id=a.id, token="token", status=status, result=result), db)
        assert occupied(db) == expected


def test_panel_only_deletion_and_manual_release(engine):
    with Session(engine) as db:
        a = node(db)
        interface_id = tunnel(db, a.id, ["10.9.0.1/32"])
        item = db.get(models.WireGuardInterface, interface_id)
        item.source = "imported"
        item.managed = False
        db.commit()
        delete_interface(interface_id, db)
        assert occupied(db) == {"10.9.0.1"}
        claim = db.scalar(select(models.IPAMClaim))
        release_claim(claim.id, ReleaseInput(confirmed_cleaned=True), db)
        assert occupied(db) == set()


def test_external_reservation_release_requires_confirmation(engine):
    with Session(engine) as db:
        item = reserve(ReservationInput(cidr="10.10.0.1", note="external host"), db)
        with pytest.raises(ValidationError):
            ReleaseInput(confirmed_cleaned=False)
        release_reservation(item["id"], ReleaseInput(confirmed_cleaned=True), db)
        assert not list(db.scalars(select(models.IPAMRange)))


def test_link_network_and_broadcast_are_protected(engine):
    with Session(engine) as db:
        create_pool(PoolInput(name="links", cidr="10.11.0.0/24", kind="link"), db)
        a, b = node(db, "a"), node(db, "b")
        tunnel(db, a.id, ["10.11.0.1/30"])
        with pytest.raises(HTTPException):
            tunnel(db, b.id, ["10.11.0.0/32"], "wg2")
        with pytest.raises(HTTPException):
            tunnel(db, b.id, ["10.11.0.3/32"], "wg3")


def test_failed_task_retains_address_and_cannot_be_overlooked_by_backfill(engine):
    with Session(engine) as db:
        a = node(db)
        interface_id = tunnel(db, a.id, ["10.12.0.1/32"])
        task_id = enqueue(db, a.id, interface_id, WIREGUARD_TASKS.apply_config,
                          {"config": "[Interface]\nAddress = 10.12.0.2/32"})
        task = db.get(models.AgentTask, task_id)
        task.status = "failed"  # Poll-time expiry, outside the result handler.
        db.commit()
        rows = read_inventory(db=db)["items"]
        expired = next(row for row in rows if row["address"] == "10.12.0.2/32")
        assert expired["state"] == "retained" and expired["can_release"]
        update_node(a.id, schemas.NodeUpdate(name="a", endpoint_ips=["192.0.2.1"]), db)
        claim = db.scalar(select(models.IPAMClaim).where(models.IPAMClaim.ip == int(ipaddress.IPv4Address("10.12.0.2"))))
        assert claim.state == "retained"
        assert occupied(db) == {"10.12.0.1", "10.12.0.2"}


def test_historical_conflict_blocks_deployment(engine):
    with Session(engine) as db:
        a, b = node(db, "a"), node(db, "b")
        first = models.WireGuardInterface(node_id=a.id, name="wg1", tunnel_ips=["10.13.0.1/32"])
        db.add_all([first, models.WireGuardInterface(node_id=b.id, name="wg2", tunnel_ips=["10.13.0.1/32"])])
        db.commit()
        with pytest.raises(HTTPException) as error:
            enqueue(db, a.id, first.id, WIREGUARD_TASKS.apply_config,
                    {"config": "[Interface]\nAddress = 10.13.0.1/32"})
        assert error.value.status_code == 409
        assert not list(db.scalars(select(models.AgentTask)))


def test_deleted_node_identity_is_not_reused_to_bypass_retained_addresses(engine):
    from link42_api.main import delete_node
    with Session(engine) as db:
        a = node(db, "a", ["10.14.0.1/32"])
        delete_node(a.id, db)
        with pytest.raises(HTTPException):
            node(db, "b", ["10.14.0.1/32"])
        assert occupied(db) == {"10.14.0.1"}


def test_repeated_old_result_cannot_release_new_assignment(engine, monkeypatch):
    monkeypatch.setattr("link42_api.main.verify_token", lambda *_: True)
    with Session(engine) as db:
        a = node(db, "a")
        a.status, a.last_seen_at = "online", datetime.utcnow()
        db.commit()
        interface_id = tunnel(db, a.id, ["10.15.0.1/32"])
        delete_interface(interface_id, db, delete_node_config=True)
        task = db.scalar(select(models.AgentTask))
        task.status = "running"
        db.commit()
        report = schemas.AgentTaskResultRequest(node_id=a.id, token="token", status="succeeded", result={})
        agent_task_result(task.id, report, db)
        b = node(db, "b", ["10.15.0.1/32"])
        agent_task_result(task.id, report, db)
        assert occupied(db) == {"10.15.0.1"}
        assert db.scalar(select(models.IPAMClaim)).node_id == b.id


def test_ipv4_http_routes_and_authentication(engine, monkeypatch):
    import time
    from fastapi.testclient import TestClient
    from link42_api import main as api_main
    from link42_api.database import get_db
    from link42_common.security import hash_token
    def test_db():
        with Session(engine) as db:
            yield db
    monkeypatch.setattr(api_main, "get_db", test_db)
    with Session(engine) as db:
        api_main.set_setting(db, api_main.SETTING_ADMIN_SESSION_HASH, hash_token("test-web-token"))
        api_main.set_setting(db, api_main.SETTING_ADMIN_SESSION_ISSUED_AT, str(time.time()))
        api_main.set_setting(db, api_main.SETTING_ADMIN_SESSION_LAST_USED_AT, str(time.time()))
        db.commit()
    api_main.app.dependency_overrides[get_db] = test_db
    try:
        client = TestClient(api_main.app)
        assert client.get("/api/ipam/pools").status_code == 401
        client.headers["Authorization"] = "Bearer test-web-token"
        response = client.post("/api/ipam/pools", json={"name": "nodes", "cidr": "10.16.0.0/24", "kind": "node"})
        assert response.status_code == 200, response.text
        pool_id = response.json()["id"]
        address = client.get(f"/api/ipam/pools/{pool_id}/recommend").json()["addresses"][0]
        assert address == "10.16.0.1/32"
        payload = {"name": "http-node", "endpoint_ips": ["192.0.2.1"], "internal_ipv4s": [address]}
        response = client.post("/api/nodes", json=payload)
        assert response.status_code == 200, response.text
        assert response.json()["node"]["internal_ipv4s"] == [address]
        assert client.post("/api/nodes", json={**payload, "name": "conflicting-node"}).status_code == 409
        response = client.get("/api/ipam/inventory?q=10.16.0.1")
        assert response.json()["total"] == 1
        assert client.get("/api/ipam/inventory?limit=1000").status_code == 422
        assert not client.post("/api/ipam/check", json={"addresses": [address]}).json()["available"]
    finally:
        api_main.app.dependency_overrides.pop(get_db, None)


def test_nested_task_savepoints_cannot_finalize_partial_address_changes(engine):
    with Session(engine) as db:
        a, b = node(db, "a"), node(db, "b")
        @ipam.transaction
        def pair(db):
            with db.begin_nested():
                db.add(models.WireGuardInterface(node_id=a.id, name="wg1", tunnel_ips=["10.17.0.1/32"]))
                db.flush()
            # This occurs AFTER the internal savepoint committed. It still must
            # participate in final validation and rollback the first endpoint.
            db.add(models.WireGuardInterface(node_id=b.id, name="wg2", tunnel_ips=["10.17.0.1/32"]))
            db.commit()
        with pytest.raises(HTTPException):
            pair(db)
        assert not list(db.scalars(select(models.WireGuardInterface)))
        assert not list(db.scalars(select(models.IPAMClaim)))


def test_cleanup_of_taken_over_import_removes_observed_candidate(engine, monkeypatch):
    monkeypatch.setattr("link42_api.main.verify_token", lambda *_: True)
    with Session(engine) as db:
        a = node(db)
        a.status, a.last_seen_at = "online", datetime.utcnow()
        db.commit()
        interface_id = tunnel(db, a.id, ["10.18.0.1/32"])
        item = db.get(models.WireGuardInterface, interface_id)
        item.source, item.managed = "imported", True
        item.import_path = "/etc/wireguard/wg0.conf"
        item.deployed_config = "[Interface]\nAddress = 10.18.0.1/32\n"
        db.add(models.ImportCandidate(node_id=a.id, path=item.import_path, interface_name="wg0",
                                      parsed={"addresses": ["10.18.0.1/32"]}, warnings=[], imported=True))
        db.commit()
        delete_interface(interface_id, db, delete_node_config=True)
        task = db.scalar(select(models.AgentTask))
        task.status = "running"
        db.commit()
        agent_task_result(task.id, schemas.AgentTaskResultRequest(node_id=a.id, token="token", status="succeeded", result={}), db)
        assert occupied(db) == set()
        assert not list(db.scalars(select(models.ImportCandidate)))


def test_retired_desired_and_deployed_are_one_physical_owner(engine):
    with Session(engine) as db:
        a = node(db)
        interface_id = tunnel(db, a.id, ["10.19.0.1/32"])
        item = db.get(models.WireGuardInterface, interface_id)
        item.deployed_config = "[Interface]\nAddress = 10.19.0.1/32\n"
        item.source, item.managed = "imported", False
        db.commit()
        delete_interface(interface_id, db)
        assert all(not row["conflict"] for row in read_inventory(db=db)["items"])
        claim = db.scalar(select(models.IPAMClaim))
        release_claim(claim.id, ReleaseInput(confirmed_cleaned=True), db)
        assert occupied(db) == set()


def online_node(db, name):
    item = node(db, name)
    item.status, item.last_seen_at = "online", datetime.utcnow()
    item.agent_version = "0.6.23"
    item.agent_capabilities = ["wireguard", "gre"]
    db.commit()
    return item


def test_managed_gre_pair_and_partial_cleanup_keep_whole_subnet(engine, monkeypatch):
    from link42_api.main import create_managed_connection, delete_connection
    from link42_common.connection_types import GRE_TASKS
    monkeypatch.setattr("link42_api.main.verify_token", lambda *_: True)
    with Session(engine) as db:
        pool = create_pool(PoolInput(name="links", cidr="10.20.0.0/24", kind="link"), db)
        a, b = online_node(db, "a"), online_node(db, "b")
        result = create_managed_connection(a.id, schemas.GreManagedConnectionCreate(
            peer_node_id=b.id, local_interface_name="gre_a", peer_interface_name="gre_b",
            local_outer_ip="192.0.2.1", peer_outer_ip="192.0.2.2", local_tunnel_ips=["10.20.0.1/30"],
            peer_tunnel_ips=["10.20.0.2/30"], ipv4_link_pool_id=pool["id"], risk_accepted=True), db)
        assert len(list(db.scalars(select(models.IPAMRange)))) == 1
        delete_connection(result.connection_ref, db)
        for node_id in [a.id, b.id]:
            tasks = list(db.scalars(select(models.AgentTask).where(models.AgentTask.node_id == node_id,
                models.AgentTask.type.in_([GRE_TASKS.stop, GRE_TASKS.delete_config])).order_by(models.AgentTask.id)))
            for task in tasks:
                task.status = "running"
                db.commit()
                agent_task_result(task.id, schemas.AgentTaskResultRequest(node_id=node_id, token="token", status="succeeded", result={}), db)
            if node_id == a.id:
                assert occupied(db) == {"10.20.0.2"}
                assert list(db.scalars(select(models.IPAMRange)))
        assert occupied(db) == set()
        assert not list(db.scalars(select(models.IPAMRange)))


def test_manual_gre_cleanup_keeps_external_peer_reserved(engine, monkeypatch):
    from link42_api.main import create_manual_connection, delete_connection
    from link42_common.connection_types import GRE_TASKS
    monkeypatch.setattr("link42_api.main.verify_token", lambda *_: True)
    with Session(engine) as db:
        pool = create_pool(PoolInput(name="links", cidr="10.21.0.0/24", kind="link"), db)
        a = online_node(db, "a")
        result = create_manual_connection(a.id, schemas.GreManualConnectionCreate(
            interface_name="gre_a", outer_local_ip="192.0.2.1", outer_remote_ip="192.0.2.2",
            tunnel_ips=["10.21.0.1/30"], peer_tunnel_ips=["10.21.0.2/30"], ipv4_link_pool_id=pool["id"], risk_accepted=True), db)
        delete_connection(result.connection_ref, db)
        tasks = list(db.scalars(select(models.AgentTask).where(models.AgentTask.type.in_([GRE_TASKS.stop, GRE_TASKS.delete_config])).order_by(models.AgentTask.id)))
        for task in tasks:
            task.status = "running"
            db.commit()
            agent_task_result(task.id, schemas.AgentTaskResultRequest(node_id=a.id, token="token", status="succeeded", result={}), db)
        assert occupied(db) == {"10.21.0.2"}
        assert list(db.scalars(select(models.IPAMRange)))
        claim = db.scalar(select(models.IPAMClaim))
        release_claim(claim.id, ReleaseInput(confirmed_cleaned=True), db)
        assert not list(db.scalars(select(models.IPAMRange)))


def test_wg_managed_pair_and_imported_replacement_keep_assignments(engine, monkeypatch):
    from link42_api.main import create_managed_link
    monkeypatch.setattr("link42_api.main.generate_wireguard_keypair", lambda: ("private", "public"))
    monkeypatch.setattr("link42_api.main.generate_preshared_key", lambda: "shared")
    with Session(engine) as db:
        pool = create_pool(PoolInput(name="links", cidr="10.22.0.0/24", kind="link"), db)
        a, b = online_node(db, "a"), online_node(db, "b")
        originals = []
        for item, ip in [(a, "10.22.0.1/30"), (b, "10.22.0.2/30")]:
            interface = models.WireGuardInterface(node_id=item.id, name="wg_old", tunnel_ips=[ip], source="imported", managed=False)
            db.add(interface)
            db.flush()
            db.add(models.WireGuardPeer(interface_id=interface.id, public_key="oldkey", endpoint_host="192.0.2.1"))
            originals.append(interface.id)
        db.commit()
        result = create_managed_link(a.id, schemas.ManagedLinkCreate(
            peer_node_id=b.id, local_interface_name="wg_old", peer_interface_name="wg_old",
            local_tunnel_ips=["10.22.0.1/30"], peer_tunnel_ips=["10.22.0.2/30"], ipv4_link_pool_id=pool["id"],
            local_endpoint_host="192.0.2.1", peer_endpoint_host="192.0.2.1",
            replace_local_interface_id=originals[0], replace_peer_interface_id=originals[1]), db)
        assert occupied(db) == {"10.22.0.1", "10.22.0.2"}
        assert len(list(db.scalars(select(models.IPAMRange)))) == 1
        for interface_id in [result.local_interface.id, result.peer_interface.id]:
            task = db.scalar(select(models.AgentTask).where(models.AgentTask.type == WIREGUARD_TASKS.apply_config,
                                                           models.AgentTask.node_id == db.get(models.WireGuardInterface, interface_id).node_id))
            dependency = db.get(models.AgentTask, task.payload["depends_on_task_id"])
            assert dependency.type == WIREGUARD_TASKS.delete_config


def test_link_pool_tracks_manually_entered_masks_and_routes_are_not_occupancy(engine):
    with Session(engine) as db:
        create_pool(PoolInput(name="links", cidr="10.23.0.0/24", kind="link"), db)
        a, b = node(db, "a"), node(db, "b")
        interface_id = tunnel(db, a.id, ["10.23.0.1/32", "fd42::1/64"])
        db.add(models.WireGuardPeer(interface_id=interface_id, public_key="peer", allowed_ips=["10.24.0.0/16"]))
        db.commit()
        with pytest.raises(HTTPException):
            tunnel(db, b.id, ["10.23.0.2/32"], "wg2")
        tunnel(db, b.id, ["10.24.0.1/32"], "wg3")


def test_retained_failed_task_cannot_be_reassigned_through_reused_interface_id(engine, monkeypatch):
    monkeypatch.setattr("link42_api.main.verify_token", lambda *_: True)
    with Session(engine) as db:
        a = online_node(db, "a")
        interface_id = tunnel(db, a.id, ["10.25.0.1/32"])
        task_id = enqueue(db, a.id, interface_id, WIREGUARD_TASKS.apply_config,
                          {"config": "[Interface]\nAddress = 10.25.0.2/32"})
        agent_task_result(task_id, schemas.AgentTaskResultRequest(node_id=a.id, token="token", status="failed", result={"error": "partially applied"}), db)
        delete_interface(interface_id, db, delete_node_config=False)
        with pytest.raises(HTTPException):
            tunnel(db, a.id, ["10.25.0.2/32"], "wg0")
        assert occupied(db) == {"10.25.0.1", "10.25.0.2"}


def test_old_running_apply_cannot_update_reused_interface_or_free_orphan_address(engine, monkeypatch):
    monkeypatch.setattr("link42_api.main.verify_token", lambda *_: True)
    with Session(engine) as db:
        a, b = online_node(db, "a"), online_node(db, "b")
        interface_id = tunnel(db, a.id, ["10.26.0.1/32"])
        task_id = enqueue(db, a.id, interface_id, WIREGUARD_TASKS.apply_config,
                          {"config": "[Interface]\nAddress = 10.26.0.2/32"})
        delete_interface(interface_id, db, delete_node_config=False)
        successor_id = tunnel(db, b.id, ["10.26.0.3/32"], "wg0")
        assert successor_id == interface_id  # SQLite reuses the actual row ID.
        agent_task_result(task_id, schemas.AgentTaskResultRequest(node_id=a.id, token="token", status="succeeded", result={}), db)
        successor = db.get(models.WireGuardInterface, successor_id)
        assert successor.deployed_config is None
        assert successor.tunnel_ips == ["10.26.0.3/32"]
        assert occupied(db) == {"10.26.0.1", "10.26.0.2", "10.26.0.3"}
