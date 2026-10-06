import os
import sys
import tempfile
from pathlib import Path
from typing import Generator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker

# Ensure backend and repository root directories are in sys.path
backend_dir = Path(__file__).resolve().parent.parent
repo_root = backend_dir.parent
for p in [backend_dir, repo_root]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from app.db.seed import seed_database, main as seed_main
from app.models.alert import Alert
from app.models.attribution import Attribution
from app.models.entity import Entity
from app.models.event import Event
from app.models.incident import Incident
from app.models.user import User


@pytest.fixture
def migration_test_db() -> Generator[dict, None, None]:
    """
    Creates an isolated temporary SQLite database for migration & seeding testing.
    Cleans up all database handles and files upon teardown.
    """
    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tf.close()
    db_file = Path(tf.name)
    db_url = f"sqlite:///{db_file.as_posix()}"

    ini_path = backend_dir / "alembic.ini"
    alembic_cfg = Config(str(ini_path))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    SessionMaker = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Backup existing environment variable
    old_db_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = db_url

    yield {
        "db_url": db_url,
        "db_file": db_file,
        "alembic_cfg": alembic_cfg,
        "engine": engine,
        "SessionMaker": SessionMaker,
    }

    # Teardown
    engine.dispose()
    if old_db_url is not None:
        os.environ["DATABASE_URL"] = old_db_url
    else:
        os.environ.pop("DATABASE_URL", None)

    try:
        if db_file.exists():
            db_file.unlink()
    except Exception:
        pass


def test_alembic_migration_upgrade_and_downgrade(migration_test_db):
    """
    Validates that Alembic applies 001_initial_schema to create all 9 tables,
    can roll back completely to base, and upgrade back to head without errors.
    """
    cfg = migration_test_db["alembic_cfg"]
    engine = migration_test_db["engine"]

    # 1. Upgrade to head
    command.upgrade(cfg, "head")

    inspector = inspect(engine)
    tables = set(inspector.get_table_names())

    expected_tables = {
        "events",
        "entities",
        "alerts",
        "event_alerts",
        "incidents",
        "incident_alerts",
        "attributions",
        "users",
        "audit_logs",
        "alembic_version",
    }
    for expected in expected_tables:
        assert expected in tables, f"Expected table '{expected}' not found after migration upgrade"

    # Verify key columns in events table
    event_cols = {col["name"] for col in inspector.get_columns("events")}
    assert {"id", "tenant_id", "source_layer", "event_type", "observed_at", "payload", "severity"}.issubset(event_cols)

    # Verify key columns in attributions table
    attr_cols = {col["name"] for col in inspector.get_columns("attributions")}
    assert {"id", "tenant_id", "incident_id", "actor_name", "campaign", "confidence_score", "tactics_techniques"}.issubset(attr_cols)

    # 2. Downgrade to base
    command.downgrade(cfg, "base")
    inspector_down = inspect(engine)
    tables_down = set(inspector_down.get_table_names())
    for t in expected_tables - {"alembic_version"}:
        assert t not in tables_down, f"Table '{t}' should have been dropped on downgrade"

    # 3. Upgrade back to head
    command.upgrade(cfg, "head")
    inspector_up = inspect(engine)
    tables_reup = set(inspector_up.get_table_names())
    assert expected_tables.issubset(tables_reup)


def test_seed_database_fixture_ingestion(migration_test_db):
    """
    Validates that seed_database populates records from fixtures into the migrated schema
    and correctly wires up Many-to-Many relationships and foreign keys.
    """
    cfg = migration_test_db["alembic_cfg"]
    command.upgrade(cfg, "head")

    session: Session = migration_test_db["SessionMaker"]()
    try:
        stats = seed_database(session)

        # Verify creation counts
        assert stats["events_created"] == 4
        assert stats["entities_created"] >= 6
        assert stats["alerts_created"] == 3
        assert stats["incidents_created"] == 2
        assert stats["attributions_created"] == 1
        assert stats["users_created"] == 1

        # Verify Events
        events = session.query(Event).all()
        assert len(events) == 4
        evt_ids = {e.id for e in events}
        assert evt_ids == {"evt-1001", "evt-1002", "evt-1003", "evt-1004"}

        evt1 = session.query(Event).filter(Event.id == "evt-1001").first()
        assert evt1 is not None
        assert evt1.source_layer == "endpoint"
        assert evt1.event_type == "process_execution"
        assert evt1.tenant_id == "tenant-default-001"

        # Verify Entities
        entities = session.query(Entity).all()
        assert len(entities) >= 6
        identifiers = {ent.identifier for ent in entities}
        assert "workstation-01.corp.internal" in identifiers
        assert "c2-command-node.badactor.org" in identifiers

        # Verify Alerts & M2M event links
        alerts = session.query(Alert).all()
        assert len(alerts) == 3
        alt1 = session.query(Alert).filter(Alert.id == "alt-5001").first()
        assert alt1 is not None
        assert alt1.rule_id == "RULE-WIN-001"
        assert len(alt1.events) == 1
        assert alt1.events[0].id == "evt-1001"

        # Verify Incidents & M2M alert links
        incidents = session.query(Incident).all()
        assert len(incidents) == 2
        inc1 = session.query(Incident).filter(Incident.id == "inc-9001").first()
        assert inc1 is not None
        assert inc1.severity == "critical"
        assert len(inc1.alerts) == 3
        inc1_alt_ids = {a.id for a in inc1.alerts}
        assert inc1_alt_ids == {"alt-5001", "alt-5002", "alt-5003"}

        # Verify Attribution
        attributions = session.query(Attribution).all()
        assert len(attributions) == 1
        att1 = attributions[0]
        assert att1.id == "att-7001"
        assert att1.incident_id == "inc-9001"
        assert att1.actor_name == "APT29 (Cozy Bear)"
        assert att1.confidence_score == 0.89
        assert len(att1.tactics_techniques) == 3

        # Verify Default User
        user = session.query(User).filter(User.username == "analyst").first()
        assert user is not None
        assert user.role == "analyst"
    finally:
        session.close()


def test_seed_database_idempotency(migration_test_db):
    """
    Validates that running seed_database a second time on an already-seeded database
    is completely idempotent: skips all existing records with 0 duplicate key collisions.
    """
    cfg = migration_test_db["alembic_cfg"]
    command.upgrade(cfg, "head")

    session: Session = migration_test_db["SessionMaker"]()
    try:
        # First execution
        first_stats = seed_database(session)
        assert first_stats["events_created"] == 4
        assert first_stats["alerts_created"] == 3
        assert first_stats["incidents_created"] == 2
        assert first_stats["attributions_created"] == 1
        assert first_stats["users_created"] == 1

        # Second execution
        second_stats = seed_database(session)
        assert second_stats["events_created"] == 0
        assert second_stats["events_skipped"] == 4
        assert second_stats["entities_created"] == 0
        assert second_stats["entities_skipped"] >= 6
        assert second_stats["alerts_created"] == 0
        assert second_stats["alerts_skipped"] == 3
        assert second_stats["incidents_created"] == 0
        assert second_stats["incidents_skipped"] == 2
        assert second_stats["attributions_created"] == 0
        assert second_stats["attributions_skipped"] == 1
        assert second_stats["users_created"] == 0
        assert second_stats["users_skipped"] == 1

        # Confirm counts remain unchanged
        assert session.query(Event).count() == 4
        assert session.query(Alert).count() == 3
        assert session.query(Incident).count() == 2
        assert session.query(Attribution).count() == 1
        assert session.query(User).count() == 1
    finally:
        session.close()


def test_seed_main_cli_execution(migration_test_db):
    """
    Validates that seed_main CLI entrypoint executes end-to-end without unhandled errors.
    """
    cfg = migration_test_db["alembic_cfg"]
    command.upgrade(cfg, "head")

    # seed_main will read DATABASE_URL from os.environ
    seed_main()

    session: Session = migration_test_db["SessionMaker"]()
    try:
        assert session.query(Event).count() == 4
        assert session.query(Alert).count() == 3
        assert session.query(Incident).count() == 2
        assert session.query(Attribution).count() == 1
    finally:
        session.close()
