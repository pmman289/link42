"""Address data compatibility after removal of automatic address allocation."""
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from link42_api import database, main, models, schemas
from link42_common.connection_types import GRE_TASKS, WIREGUARD_TASKS


@pytest.fixture
def engine(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'controller.db'}")
    monkeypatch.setattr(database, "engine", engine)
    database.init_db()
    yield engine
    engine.dispose()


def test_existing_addresses_survive_startup_and_unrelated_edits(engine):
    with engine.begin() as connection:
        # Seed the old storage directly, including obsolete pool data.
        connection.execute(models.Node.__table__.insert().values(id=1, name="old", agent_token_hash="hash"))
        connection.execute(text("INSERT INTO ipam_node_addresses (node_id, address) VALUES (1, '10.0.0.1/32')"))
        connection.execute(text("CREATE TABLE ipam_pools (id INTEGER PRIMARY KEY, name TEXT, cidr TEXT, kind TEXT, link_prefix INTEGER)"))
        connection.execute(text("INSERT INTO ipam_pools VALUES (1, 'old pool', '10.0.0.0/24', 'node', 30)"))
    database.init_db()
    database.init_db()
    with Session(engine) as db:
        node = main.update_node(1, schemas.NodeUpdate(name="renamed", endpoint_ips=["192.0.2.1"]), db)
        assert node.internal_ipv4s == ["10.0.0.1/32"]
        assert schemas.NodeRead.model_validate(node).internal_ipv4s == ["10.0.0.1/32"]
        assert db.execute(text("SELECT cidr FROM ipam_pools WHERE id=1")).scalar_one() == "10.0.0.0/24"


def test_manual_addresses_work_without_allocation_tables(engine):
    assert not {"ipam_lock", "ipam_pools", "ipam_addresses", "ipam_claims", "ipam_ranges"}.intersection(inspect(engine).get_table_names())
    with Session(engine) as db:
        # Allocation policy no longer blocks manually selected addresses.
        for name in ("a", "b"):
            result = main.create_node(schemas.NodeCreate(endpoint_ips=["192.0.2.1"], name=name, internal_ipv4s=["10.0.0.1"]), db)
            assert result.node.internal_ipv4s == ["10.0.0.1/32"]
            main.touch_node_heartbeat(db.get(models.Node, result.node.id))
            db.commit()
            interface = main.create_interface(result.node.id, schemas.InterfaceCreate(name="wg0", tunnel_ips=["10.0.0.1/32"]), db)
            assert interface.tunnel_ips == ["10.0.0.1/32"]


def test_manual_addresses_can_be_replaced_cleared_and_deleted(engine):
    with Session(engine) as db:
        node = main.create_node(schemas.NodeCreate(endpoint_ips=["192.0.2.1"], name="a", internal_ipv4s=["10.0.0.1"]), db).node
        node_id = node.id
        for values in (["10.0.0.2/32", "10.0.0.3/32"], []):
            updated = main.update_node(node_id, schemas.NodeUpdate(name="a", endpoint_ips=["192.0.2.1"], internal_ipv4s=values), db)
            assert updated.internal_ipv4s == values
        main.update_node(node_id, schemas.NodeUpdate(name="a", endpoint_ips=["192.0.2.1"], internal_ipv4s=["10.0.0.4"]), db)
        main.delete_node(node_id, db)
        assert db.query(models.NodeIPv4Address).count() == 0


@pytest.mark.parametrize("values", [["10.0.0.1/24"], ["::1/128"], ["10.0.0.1", "10.0.0.1/32"]])
def test_invalid_fixed_addresses(values):
    with pytest.raises(ValidationError):
        schemas.NodeCreate(endpoint_ips=["192.0.2.1"], name="a", internal_ipv4s=values)


@pytest.mark.parametrize("protocol", ["wireguard", "gre"])
@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("replace", [False, True])
def test_task_results_keep_configuration_identity_protection(engine, monkeypatch, protocol, legacy, replace):
    monkeypatch.setattr(main, "verify_token", lambda *_: True)
    with Session(engine) as db:
        node = main.create_node(schemas.NodeCreate(endpoint_ips=["192.0.2.1"], name="a"), db).node
        node_id = node.id
        connection = models.Connection(protocol_type="gre", name="gre0")
        db.add(connection)
        db.flush()

        def config():
            if protocol == "wireguard":
                item = models.WireGuardInterface(node_id=node_id, name="wg0", runtime_status="stopped")
            else:
                item = models.ConnectionEndpoint(node_id=node_id, connection_id=connection.id, role="local", interface_name="gre0", runtime_status="stopped")
            db.add(item)
            db.flush()
            return item

        item = config()
        if legacy:
            item.extras = {"ipam_incarnation": "existing-instance"}
        if protocol == "wireguard":
            task = main.create_interface_task(item, WIREGUARD_TASKS.start)
        else:
            task = models.AgentTask(node_id=node_id, type=GRE_TASKS.start, payload=main.gre_task_payload(item))
        if legacy:
            payload = dict(task.payload)
            payload["ipam_owner"] = payload.pop("config_identity")
            task.payload = payload
        task.status = "running"
        db.add(task)
        db.commit()
        original_id = item.id
        if replace:
            db.delete(item)
            db.commit()
            item = config()
            db.commit()
            assert item.id == original_id  # Same node, same SQLite ID, different instance.
        main.agent_task_result(task.id, schemas.AgentTaskResultRequest(node_id=node_id, token="token", status="succeeded", result={}), db)
        db.refresh(item)
        assert task.status == "succeeded"
        assert item.runtime_status == ("stopped" if replace else "running")
