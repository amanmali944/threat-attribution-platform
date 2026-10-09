import logging
import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.core.config import settings
from app.models.base import Base

logger = logging.getLogger(__name__)


def resolve_sqlite_path(raw_url: str) -> str:
    """
    Resolves relative sqlite URLs (e.g. sqlite:///./threat_platform.db)
    to a canonical shared file location across both backend/ and repo root.
    """
    if os.getenv("TESTING", "0") == "1":
        return "sqlite:///:memory:"
    if ":memory:" in raw_url:
        return raw_url
    if "threat_platform.db" in raw_url:
        backend_dir = Path(__file__).resolve().parents[2]
        repo_root = backend_dir.parent
        target_file = (repo_root / "threat_platform.db").resolve()
        return f"sqlite:///{target_file.as_posix()}"
    return raw_url


def get_engine_args(url: str) -> dict:
    args = {}
    if url.startswith("sqlite"):
        args["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url or os.getenv("TESTING", "0") == "1":
            args["poolclass"] = StaticPool
    return args


def create_initial_engine():
    """
    Creates and tests initial database engine with graceful fallback to persistent SQLite.
    """
    if os.getenv("TESTING", "0") == "1":
        return create_engine("sqlite:///:memory:", **get_engine_args("sqlite:///:memory:"))

    target_url = settings.DATABASE_URL or settings.FALLBACK_DATABASE_URL
    if target_url.startswith("sqlite"):
        resolved_url = resolve_sqlite_path(target_url)
        return create_engine(resolved_url, **get_engine_args(resolved_url))

    # Try PostgreSQL first; fall back immediately if unreachable or auth fails
    try:
        pg_engine = create_engine(target_url)
        with pg_engine.connect() as conn:
            pass
        return pg_engine
    except Exception as exc:
        logger.warning(
            f"Primary database connection unavailable ({exc}). "
            "Falling back to persistent local SQLite threat_platform.db."
        )
        fallback_url = resolve_sqlite_path(settings.FALLBACK_DATABASE_URL)
        return create_engine(fallback_url, **get_engine_args(fallback_url))


engine = create_initial_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def ensure_seed_users():
    """
    Ensures default analyst and admin accounts exist in the persistent database
    with valid bcrypt hashes so both UI quick-fill logins and analyst@corp.internal succeed.
    """
    try:
        from app.models.user import User
        from app.core.security import get_password_hash
        from datetime import datetime, timezone

        db = SessionLocal()
        try:
            # 1. Default analyst account
            analyst = db.query(User).filter(User.username == "analyst").first()
            if not analyst:
                analyst = User(
                    id="usr-default-001",
                    tenant_id="tenant-default-001",
                    username="analyst",
                    email="analyst@corp.internal",
                    hashed_password=get_password_hash("Analyst123!"),
                    role="analyst",
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(analyst)
            else:
                analyst.hashed_password = get_password_hash("Analyst123!")

            # 2. Email alias account for analyst@corp.internal
            analyst_email = db.query(User).filter(User.username == "analyst@corp.internal").first()
            if not analyst_email:
                analyst_email = User(
                    id="usr-default-001-email",
                    tenant_id="tenant-default-001",
                    username="analyst@corp.internal",
                    email="analyst.login@corp.internal",
                    hashed_password=get_password_hash("Analyst123!"),
                    role="analyst",
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(analyst_email)
            else:
                analyst_email.hashed_password = get_password_hash("Analyst123!")

            # 3. Default admin account
            admin = db.query(User).filter(User.username == "admin").first()
            if not admin:
                admin = User(
                    id="usr-admin-001",
                    tenant_id="tenant-default-001",
                    username="admin",
                    email="admin@corp.internal",
                    hashed_password=get_password_hash("Admin123!"),
                    role="admin",
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(admin)
            else:
                admin.hashed_password = get_password_hash("Admin123!")

            # 4. Default viewer account
            viewer = db.query(User).filter(User.username == "viewer").first()
            if not viewer:
                viewer = User(
                    id="usr-viewer-001",
                    tenant_id="tenant-default-001",
                    username="viewer",
                    email="viewer@corp.internal",
                    hashed_password=get_password_hash("Viewer123!"),
                    role="read_only",
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(viewer)
            else:
                viewer.hashed_password = get_password_hash("Viewer123!")

            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Could not sync default seed users: {e}")
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"Seed user setup error: {e}")


def init_db():
    """
    Initializes database tables. Catches database operational and authentication
    errors cleanly without crashing application startup, falling back to a persistent
    local SQLite database file (threat_platform.db).
    """
    global engine, SessionLocal
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:
        logger.warning(
            f"Database initialization failed on primary engine ({exc}). "
            "Falling back to persistent local SQLite threat_platform.db."
        )
        try:
            fallback_url = resolve_sqlite_path(settings.FALLBACK_DATABASE_URL)
            engine = create_engine(fallback_url, **get_engine_args(fallback_url))
            SessionLocal.configure(bind=engine)
            Base.metadata.create_all(bind=engine)
            logger.info("Resilient persistent local SQLite database initialized successfully.")
        except Exception as fallback_err:
            logger.error(f"Critical failure initializing fallback database: {fallback_err}")

    # Synchronize default seed accounts in persistent local mode
    if os.getenv("TESTING", "0") != "1":
        ensure_seed_users()


