import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add backend directory and repo root to sys.path
backend_dir = Path(__file__).resolve().parents[2]
repo_root = Path(__file__).resolve().parents[3]
for p in [backend_dir, repo_root]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.base import Base
from app.models.event import Event
from app.models.entity import Entity
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.attribution import Attribution
from app.models.user import User

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed")


def get_fixtures_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[3]
    candidates = [
        repo_root / "data" / "fixtures",
        Path.cwd() / "data" / "fixtures",
        Path.cwd() / "backend" / "data" / "fixtures",
        Path.cwd().parent / "data" / "fixtures",
    ]
    for c in candidates:
        if c.exists() and c.is_dir():
            return c
    return candidates[0]


def load_fixture_data(filename: str) -> List[Dict[str, Any]]:
    fdir = get_fixtures_dir()
    fpath = fdir / filename
    if not fpath.exists():
        logger.warning("Fixture file not found: %s", fpath)
        return []
    with open(fpath, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_datetime(dt_val: Any) -> datetime:
    if isinstance(dt_val, datetime):
        dt = dt_val
    elif isinstance(dt_val, str):
        dt = datetime.fromisoformat(dt_val.replace("Z", "+00:00"))
    else:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def ensure_aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def seed_database(db: Session) -> Dict[str, int]:
    """
    Ingests fixture objects safely into the database via SQLAlchemy session.
    Idempotent: updates or skips existing records without raising primary key collisions.
    """
    stats = {
        "events_created": 0,
        "events_skipped": 0,
        "entities_created": 0,
        "entities_skipped": 0,
        "alerts_created": 0,
        "alerts_skipped": 0,
        "incidents_created": 0,
        "incidents_skipped": 0,
        "attributions_created": 0,
        "attributions_skipped": 0,
        "users_created": 0,
        "users_skipped": 0,
    }

    # 1. Ingest Events & Extract Entities
    events_data = load_fixture_data("events.json")
    for fe in events_data:
        evt_id = fe.get("event_id") or fe.get("id")
        obs_dt = parse_datetime(fe.get("observed_at"))
        tenant_id = fe.get("tenant_id", "tenant-default-001")

        existing_evt = db.query(Event).filter(Event.id == evt_id).first()
        if not existing_evt:
            new_evt = Event(
                id=evt_id,
                tenant_id=tenant_id,
                source_layer=fe.get("source_layer"),
                event_type=fe.get("event_type"),
                observed_at=obs_dt,
                severity=fe.get("severity", "info"),
                payload=fe.get("payload", {}),
            )
            db.add(new_evt)
            stats["events_created"] += 1
        else:
            stats["events_skipped"] += 1

        # Synchronize entities
        for ent in fe.get("entities", []):
            ident = ent.get("identifier")
            e_type = ent.get("entity_type")
            existing_ent = (
                db.query(Entity)
                .filter(Entity.tenant_id == tenant_id, Entity.identifier == ident)
                .first()
            )
            if not existing_ent:
                ent_hash = hashlib.sha256(f"{tenant_id}:{ident}".encode()).hexdigest()[:8]
                new_ent = Entity(
                    id=f"ent-{e_type}-{ent_hash}",
                    tenant_id=tenant_id,
                    entity_type=e_type,
                    identifier=ident,
                    properties={"source_layer": fe.get("source_layer")},
                    first_seen=obs_dt,
                    last_seen=obs_dt,
                )
                db.add(new_ent)
                stats["entities_created"] += 1
            else:
                db_last_seen = ensure_aware(existing_ent.last_seen)
                if db_last_seen and obs_dt > db_last_seen:
                    existing_ent.last_seen = obs_dt
                db_first_seen = ensure_aware(existing_ent.first_seen)
                if db_first_seen and obs_dt < db_first_seen:
                    existing_ent.first_seen = obs_dt
                stats["entities_skipped"] += 1

    db.commit()

    # 2. Ingest Alerts & Link Events
    alerts_data = load_fixture_data("alerts.json")
    for fa in alerts_data:
        alt_id = fa.get("id")
        obs_dt = parse_datetime(fa.get("observed_at"))
        created_dt = parse_datetime(fa.get("created_at"))
        tenant_id = fa.get("tenant_id", "tenant-default-001")

        alert = db.query(Alert).filter(Alert.id == alt_id).first()
        if not alert:
            alert = Alert(
                id=alt_id,
                tenant_id=tenant_id,
                rule_id=fa.get("rule_id"),
                title=fa.get("title"),
                description=fa.get("description"),
                severity=fa.get("severity", "medium"),
                status=fa.get("status", "open"),
                observed_at=obs_dt,
                created_at=created_dt,
            )
            db.add(alert)
            db.flush()
            stats["alerts_created"] += 1
        else:
            stats["alerts_skipped"] += 1

        # Link related events
        linked_event_ids = {e.id for e in alert.events}
        for evt_id in fa.get("event_ids", []):
            if evt_id not in linked_event_ids:
                evt = db.query(Event).filter(Event.id == evt_id).first()
                if evt:
                    alert.events.append(evt)
                    linked_event_ids.add(evt.id)

    db.commit()

    # 3. Ingest Incidents & Link Alerts
    incidents_data = load_fixture_data("incidents.json")
    for fi in incidents_data:
        inc_id = fi.get("id")
        created_dt = parse_datetime(fi.get("created_at"))
        updated_dt = parse_datetime(fi.get("updated_at"))
        tenant_id = fi.get("tenant_id", "tenant-default-001")

        incident = db.query(Incident).filter(Incident.id == inc_id).first()
        if not incident:
            incident = Incident(
                id=inc_id,
                tenant_id=tenant_id,
                title=fi.get("title"),
                description=fi.get("description"),
                severity=fi.get("severity", "high"),
                status=fi.get("status", "open"),
                assigned_to=fi.get("assigned_to"),
                created_at=created_dt,
                updated_at=updated_dt,
            )
            db.add(incident)
            db.flush()
            stats["incidents_created"] += 1
        else:
            stats["incidents_skipped"] += 1

        # Link related alerts
        linked_alert_ids = {a.id for a in incident.alerts}
        for alt_id in fi.get("alert_ids", []):
            if alt_id not in linked_alert_ids:
                alt = db.query(Alert).filter(Alert.id == alt_id).first()
                if alt:
                    incident.alerts.append(alt)
                    linked_alert_ids.add(alt.id)

    db.commit()

    # 4. Ingest Attributions
    attributions_data = load_fixture_data("attribution.json")
    for fa in attributions_data:
        attr_id = fa.get("id")
        created_dt = parse_datetime(fa.get("created_at"))
        tenant_id = fa.get("tenant_id", "tenant-default-001")
        inc_id = fa.get("incident_id")

        existing_attr = db.query(Attribution).filter(Attribution.id == attr_id).first()
        if not existing_attr:
            new_attr = Attribution(
                id=attr_id,
                tenant_id=tenant_id,
                incident_id=inc_id,
                actor_name=fa.get("actor_name"),
                campaign=fa.get("campaign"),
                confidence_score=float(fa.get("confidence_score", 0.0)),
                tactics_techniques=fa.get("tactics_techniques", []),
                created_at=created_dt,
            )
            db.add(new_attr)
            stats["attributions_created"] += 1
        else:
            stats["attributions_skipped"] += 1

    db.commit()

    # 5. Ingest Default Analyst User
    existing_user = db.query(User).filter(User.username == "analyst").first()
    if not existing_user:
        new_user = User(
            id="usr-default-001",
            tenant_id="tenant-default-001",
            username="analyst",
            email="analyst@corp.internal",
            hashed_password="mock-pbkdf2-sha256-hash",
            role="analyst",
            is_active=True,
        )
        db.add(new_user)
        stats["users_created"] += 1
    else:
        stats["users_skipped"] += 1

    db.commit()
    logger.info("Database seeding completed: %s", stats)
    return stats


def get_engine():
    """
    Resolves the database engine for seed execution.
    1. DATABASE_URL environment variable if provided.
    2. Default PostgreSQL engine from app.core.database if connection succeeds.
    3. Graceful fallback to local SQLite database (threat_platform.db).
    """
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        is_sqlite = env_url.startswith("sqlite")
        engine_args = {}
        if is_sqlite:
            engine_args["connect_args"] = {"check_same_thread": False}
            if ":memory:" in env_url:
                engine_args["poolclass"] = StaticPool
        return create_engine(env_url, **engine_args)

    try:
        from app.core.database import engine as default_engine
        with default_engine.connect() as conn:
            pass
        return default_engine
    except Exception as e:
        logger.warning(
            "Primary database connection unavailable: %s. Using local SQLite threat_platform.db",
            e,
        )
        sqlite_url = "sqlite:///threat_platform.db"
        return create_engine(sqlite_url, connect_args={"check_same_thread": False})


def main():
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    SessionMaker = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionMaker()

    try:
        stats = seed_database(session)
        print("Database seed execution summary:")
        for k, v in stats.items():
            print(f"  {k}: {v}")
    except Exception as e:
        logger.error("Database seeding failed: %s", e)
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
