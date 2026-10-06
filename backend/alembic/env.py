import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Ensure backend root and app package are in sys.path
backend_dir = Path(__file__).resolve().parent.parent
repo_root = backend_dir.parent
for p in [backend_dir, repo_root]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# Import all 7 ORM models and association tables for autogenerate/metadata tracking
from app.models import (  # noqa: E402
    Base,
    Event,
    Entity,
    Alert,
    Incident,
    Attribution,
    User,
    AuditLog,
    event_alerts,
    incident_alerts,
)
from app.core.config import settings  # noqa: E402

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    """
    Retrieve database connection URL.
    Pulls dynamically from DATABASE_URL environment variable,
    falling back to application settings, then alembic.ini config.
    """
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url
    try:
        return settings.DATABASE_URL
    except Exception:
        fallback = config.get_main_option("sqlalchemy.url")
        return fallback or "postgresql://threat_user:threat_secure_password_2026@localhost:5432/threat_platform"


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    url = get_url()
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = url

    is_sqlite = url.startswith("sqlite")
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=is_sqlite,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
